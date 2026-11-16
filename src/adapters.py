"""Evidence source adapters and the registry that wires them to evidence kinds.

Each kind of evidence can come from a different source:

  EVIDENCE_BACKEND=splunk                                   one source for everything, or
  EVIDENCE_SOURCES=failed_logins=splunk,account_events=splunk,entra_failures=graph

A kind can also list several sources, tried in order, so a second source answers when the first cannot:

  EVIDENCE_SOURCES=entra_failures=loganalytics+graph

Operators can turn any source off while the service runs, with SOURCES_DISABLED or the switch file
(see Switches). A switch can only take a source away. It can never add one that deployment did not configure.

Adding a source means adding one class here (or in its own module), one line in REGISTRY, its settings in
config/settings.json, and passing the shared contract tests in tests/test_adapters.py. Nothing else changes.

Every adapter here except "file" has been tested against fake responses only, never a live system.
"""
import csv
import io
import json
import os
import re
import time
import urllib.parse
from datetime import timedelta

import backends
import querypack
from backends import Backend, NoSigninName, normalize, secret_from_env, urllib_transport

HEALTH_KIND = {"windows": "failed_logins", "entra": "entra_failures"}
GUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


class NullBackend(Backend):
    """Stands in for a kind of evidence that has no source yet. The report says so instead of guessing."""
    name = "none"
    kinds = ()

    def health_counts(self, source, start, end):
        return "not_configured"


class RoutedBackend(Backend):
    """Sends each kind of evidence to the source configured for it."""
    name = "routed"

    def __init__(self, routes):
        self.routes = routes

    def query(self, kind, account, start, end, scope_set, signin_name=None):
        return self.routes[kind].query(kind, account, start, end, scope_set, signin_name)

    def health(self, start, end):
        out = {}
        for source, kind in HEALTH_KIND.items():
            one = self.routes[kind].health(start, end)
            out[source] = one.get(source) if isinstance(one, dict) else None
        return out


class Switches:
    """Operator switches for evidence sources, read while the service runs.

    Two inputs, both optional: the SOURCES_DISABLED setting, and a small JSON file in the data store,
    {"disabled_sources": ["graph"]}, re-read at most once a minute. Both can only turn sources off. A source
    that deployment did not configure cannot be switched on from here. No file means nothing extra is off. A
    file that exists but cannot be read or understood turns every switchable source off, because an operator
    who tried to pull a source and made a typo must not find it still running.
    """
    TTL = 60

    def __init__(self, store=None, key="", env_disabled="", known=(), clock=time.time):
        self.store, self.key, self.known, self.clock = store, key.strip().lstrip("/"), frozenset(known), clock
        self.static = self._names(env_disabled.split(","))
        self._cached, self._until = (frozenset(), None), 0

    def _names(self, items):
        names = frozenset(str(i).strip().lower() for i in items if str(i).strip())
        unknown = names - self.known
        if unknown:
            raise ValueError("unknown source in switch: %s" % sorted(unknown)[0][:40])
        return names

    def _from_file(self):
        if not (self.store and self.key):
            return frozenset(), None
        if self.clock() < self._until:
            return self._cached
        try:
            data = json.loads(self.store.get(self.key))
            if not isinstance(data, dict) or not isinstance(data.get("disabled_sources", []), list):
                raise ValueError("switch file has the wrong shape")
            self._cached = (self._names(data.get("disabled_sources", [])), None)
        except KeyError:
            self._cached = (frozenset(), None)
        except Exception as e:                        # unreadable or malformed: fail toward off
            self._cached = (self.known, "switch_file_invalid: %s" % type(e).__name__)
        self._until = self.clock() + self.TTL
        return self._cached

    def state(self):
        """(names that are off right now, a problem with the switch file or None)."""
        off, problem = self._from_file()
        return self.static | off, problem

    def is_off(self, name):
        return name in self.state()[0]


class ChainBackend(Backend):
    """One or more sources for a kind of evidence, tried in order.

    The first source that is switched on and answers wins. An answer with no rows is an answer, so a quiet
    account never causes a second lookup. Only a source that is off, failing or unable to answer this kind is
    passed over. The query id in the result names the source that answered.
    """
    name = "chain"

    def __init__(self, members, switches=None):
        self.members, self.switches = list(members), switches or Switches()

    def _live(self):
        off, problem = self.switches.state()
        return [(n, b) for n, b in self.members if n not in off], problem

    def query(self, kind, account, start, end, scope_set, signin_name=None):
        if account not in scope_set:                  # before the switch file or any source is touched
            raise backends.scope.Denied("out_of_scope", "You can only investigate accounts you own.")
        live, problem = self._live()
        last, passed = None, []
        for name, member in live:
            result = member.query(kind, account, start, end, scope_set, signin_name)
            if result.get("error") not in ("source_unavailable", "source_not_configured"):
                if passed:                            # for the audit line: a later source covered for an earlier one
                    result["passed_over"] = passed
                return result
            passed.append("%s:%s" % (name, result["error"]))
            last = result
        if last is not None:
            return last
        return {"query_id": "off:%s:%s" % (kind, account), "rows": [], "truncated": False,
                "error": problem or "source_switched_off"}

    def health(self, start, end):
        live, _ = self._live()
        out = {}
        for source in ("windows", "entra"):
            out[source] = "not_configured" if not live else None
            for _, member in live:
                one = member.health(start, end).get(source)
                if one is not None:
                    out[source] = one
                    break
        return out


class ExportBackend(Backend):
    """Reads scheduled report exports that another tool drops into the data store.

    Layout: {prefix}/{kind}/{YYYY-MM-DD}.jsonl, .json or .csv, one file per UTC day. Suits audit and reporting
    products that can schedule an export but offer no query API the workload may call. Evidence is only as fresh
    as the export schedule. A day with no file is treated as absent. A file that exists but cannot be read is an
    error, so a permission problem is never mistaken for a quiet day.
    """
    name = "export"
    MAX_BYTES = 20 * 1024 * 1024

    def __init__(self, store, prefix="exports", field_map=None):
        self.store, self.prefix = store, prefix.strip("/")
        self.field_map = field_map or backends.load_field_map()

    def _days(self, start, end):
        day = start.date()
        while day <= end.date():
            yield day.isoformat()
            day += timedelta(days=1)

    def _read_day(self, kind, day):
        for ext in ("jsonl", "json", "csv"):
            try:
                text = self.store.get("%s/%s/%s.%s" % (self.prefix, kind, day, ext))
            except KeyError:                          # no file in this format for this day
                continue
            if len(text) > self.MAX_BYTES:
                raise RuntimeError("export file for %s is larger than this adapter will read" % day)
            if ext == "jsonl":
                return [json.loads(line) for line in text.splitlines() if line.strip()]
            if ext == "json":
                data = json.loads(text)
                return data if isinstance(data, list) else data.get("rows", [])
            return list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
        return None

    def _raw(self, kind, start, end):
        rows, found = [], 0
        for day in self._days(start, end):
            day_rows = self._read_day(kind, day)
            if day_rows is not None:
                found += 1
                rows.extend(r for r in day_rows if isinstance(r, dict))
        return rows, found

    def _in_window(self, rows, start, end):
        lo, hi = backends.to_utc_z(start.isoformat()), backends.to_utc_z(end.isoformat())
        return [r for r in rows if lo <= r["time"] < hi]

    def fetch(self, kind, account, start, end, scope_set, signin_name=None):
        raw, found = self._raw(kind, start, end)
        if not found:
            return [], "source_missing"
        wanted = {account, signin_name} - {None}
        fields = self.field_map.get("account_fields", ["account", "user"])
        mine = [r for r in raw if any(str(r.get(f, "")).strip().lower() in wanted for f in fields)]
        rows, dropped = normalize(kind, mine, self.field_map)
        return self._in_window(rows, start, end), ("rows_dropped_no_time:%d" % dropped if dropped else None)

    def health_counts(self, source, start, end):
        kind = HEALTH_KIND[source]
        raw, _ = self._raw(kind, start, end)
        rows = self._in_window(normalize(kind, raw, self.field_map)[0], start, end)
        hosts = {r.get("dc_host") for r in rows if r.get("dc_host")}
        return {"events": len(rows), "reporting_hosts": len(hosts) if source == "windows" else None,
                "newest": max((r["time"] for r in rows), default=None)}


class _ClientCredentials:
    """Read-only application identity for the cloud identity provider's APIs. Token is cached until it nears expiry."""

    def __init__(self, tenant, client_id, secret, transport, timeout, login_base="https://login.microsoftonline.com"):
        if not GUID_RE.fullmatch(tenant) or not GUID_RE.fullmatch(client_id):
            raise ValueError("tenant and client identifiers must be GUIDs")
        if not login_base.lower().startswith("https://"):
            raise ValueError("login endpoint must use https")
        self.url = "%s/%s/oauth2/v2.0/token" % (login_base.rstrip("/"), tenant)
        self.client_id, self.secret, self.transport, self.timeout = client_id, secret, transport, timeout
        self._token, self._until = None, 0

    def token(self, scope_url):
        if self._token and time.time() < self._until:
            return self._token
        body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                       "client_secret": self.secret, "scope": scope_url}).encode()
        status, data = self.transport("POST", self.url, {"Content-Type": "application/x-www-form-urlencoded"}, body, self.timeout)
        if status != 200:
            raise RuntimeError("token endpoint http %s" % status)
        resp = json.loads(data)
        self._token, self._until = resp["access_token"], time.time() + max(60, int(resp.get("expires_in", 300)) - 120)
        return self._token


def _flatten(obj):
    """One level of nesting to dotted keys, so 'status': {'errorCode': 1} is found as 'status.errorCode'."""
    out = {}
    for k, v in obj.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                out["%s.%s" % (k, k2)] = v2
        else:
            out[k] = v
    return out


class GraphSignInBackend(Backend):
    """Cloud sign-in failures straight from the identity provider's sign-in log API.

    Freshest option and needs no log pipeline, but the permission it needs reads every sign-in in the tenant,
    so this adapter is the only thing standing between that permission and one account. It asks for one
    sign-in name and one window, and nothing else.
    """
    name = "graph"
    kinds = ("entra_failures",)
    SCOPE = "https://graph.microsoft.com/.default"
    MAX_PAGES = 12

    def __init__(self, credentials, base_url="https://graph.microsoft.com", field_map=None, transport=urllib_transport, timeout=60):
        if not base_url.lower().startswith("https://"):
            raise ValueError("sign-in log API base URL must use https")
        self.cred, self.base, self.transport, self.timeout = credentials, base_url.rstrip("/"), transport, timeout
        self.field_map = field_map or backends.load_field_map()

    def _get(self, url):
        status, data = self.transport("GET", url, {"Authorization": "Bearer " + self.cred.token(self.SCOPE)}, None, self.timeout)
        if status != 200:
            raise RuntimeError("sign-in log API http %s" % status)
        return json.loads(data)

    def _url(self, flt, top, newest_first=False):
        params = {"$filter": flt, "$top": str(top)}
        if newest_first:
            params["$orderby"] = "createdDateTime desc"
        return self.base + "/v1.0/auditLogs/signIns?" + urllib.parse.urlencode(params)

    def fetch(self, kind, account, start, end, scope_set, signin_name=None):
        if not signin_name:
            raise NoSigninName()
        flt = ("userPrincipalName eq '%s' and createdDateTime ge %sZ and createdDateTime lt %sZ and status/errorCode ne 0"
               % (signin_name, querypack._utc(start), querypack._utc(end)))
        url, raw, note = self._url(flt, 500), [], None
        for _ in range(self.MAX_PAGES):
            page = self._get(url)
            raw.extend(_flatten(r) for r in page.get("value", []) if isinstance(r, dict))
            url = page.get("@odata.nextLink")
            if not url:
                break
            if not url.startswith(self.base + "/"):       # never follow a link to another host
                raise RuntimeError("paging link left the API host")
        else:
            note = "truncated_by_source"
        rows, dropped = normalize(kind, raw, self.field_map)
        return rows, note or ("rows_dropped_no_time:%d" % dropped if dropped else None)

    def health_counts(self, source, start, end):
        if source != "entra":
            raise NotImplementedError
        flt = "createdDateTime ge %sZ and createdDateTime lt %sZ" % (querypack._utc(start), querypack._utc(end))
        rows = [r for r in self._get(self._url(flt, 1, newest_first=True)).get("value", []) if isinstance(r, dict)]
        return {"events": len(rows), "reporting_hosts": None, "newest": rows[0].get("createdDateTime") if rows else None}


class LogAnalyticsBackend(Backend):
    """Cloud sign-in failures from a log workspace the identity provider already exports to.

    Slower than the sign-in log API by the export delay, but access can be limited to the sign-in tables of one
    workspace, and it includes non-interactive and service sign-ins.
    """
    name = "loganalytics"
    kinds = ("entra_failures",)
    SCOPE = "https://api.loganalytics.io/.default"

    def __init__(self, credentials, workspace_id, base_url="https://api.loganalytics.azure.com", field_map=None,
                 transport=urllib_transport, timeout=60):
        if not GUID_RE.fullmatch(workspace_id):
            raise ValueError("workspace identifier must be a GUID")
        if not base_url.lower().startswith("https://"):
            raise ValueError("log workspace API base URL must use https")
        self.cred, self.transport, self.timeout = credentials, transport, timeout
        self.url = "%s/v1/workspaces/%s/query" % (base_url.rstrip("/"), workspace_id)
        self.field_map = field_map or backends.load_field_map()

    def _run(self, q):
        body = json.dumps({"query": q["text"], "timespan": q["params"]["timespan"]}).encode()
        status, data = self.transport("POST", self.url, {"Authorization": "Bearer " + self.cred.token(self.SCOPE),
                                                         "Content-Type": "application/json"}, body, self.timeout)
        if status != 200:
            raise RuntimeError("log workspace API http %s" % status)
        tables = json.loads(data).get("tables") or [{}]
        cols = [c["name"] for c in tables[0].get("columns", [])]
        return [dict(zip(cols, r, strict=False)) for r in tables[0].get("rows", [])]

    def fetch(self, kind, account, start, end, scope_set, signin_name=None):
        if not signin_name:
            raise NoSigninName()
        raw = self._run(querypack.render("entra_failures.kql", account, start, end, scope_set, signin_name))
        rows, dropped = normalize(kind, raw, self.field_map)
        return rows, ("rows_dropped_no_time:%d" % dropped if dropped else None)

    def health_counts(self, source, start, end):
        if source != "entra":
            raise NotImplementedError
        raw = self._run(querypack.render_health("source_health_entra.kql", start, end))
        row = raw[0] if raw else {}
        return {"events": int(float(row.get("events") or 0)), "reporting_hosts": None, "newest": row.get("newest")}


# ---------- registry ----------

def _credentials():
    return _ClientCredentials(os.environ["ENTRA_TENANT_ID"], os.environ["ENTRA_CLIENT_ID"],
                              secret_from_env("ENTRA_CLIENT_SECRET_ARN", "ENTRA_CLIENT_SECRET"), urllib_transport, 30)


REGISTRY = {
    "file": lambda store: backends.FileBackend(store),
    "none": lambda store: NullBackend(),
    "splunk": lambda store: backends.SplunkBackend(os.environ["SPLUNK_BASE_URL"], secret_from_env("SPLUNK_TOKEN_SECRET_ARN", "SPLUNK_TOKEN")),
    "databricks": lambda store: backends.DatabricksBackend(os.environ["DATABRICKS_HOST"], os.environ["DATABRICKS_WAREHOUSE_ID"],
                                                           secret_from_env("DATABRICKS_TOKEN_SECRET_ARN", "DATABRICKS_TOKEN")),
    "export": lambda store: ExportBackend(store, os.environ.get("EXPORT_PREFIX", "exports")),
    "graph": lambda store: GraphSignInBackend(_credentials()),
    "loganalytics": lambda store: LogAnalyticsBackend(_credentials(), os.environ["LOGANALYTICS_WORKSPACE_ID"]),
}


UNSWITCHED = ("file", "none")       # synthetic data and the explicit "no source" marker are not switchable


def parse_routes(default, spec):
    """'failed_logins=splunk,entra_failures=loganalytics+graph' on top of a default.

    Returns {kind: (source, ...)} with sources in the order they are tried. Unknown kinds or sources are an error.
    """
    def chain(text, where):
        names = tuple(n.strip().lower() for n in text.split("+"))
        if not names or any(n not in REGISTRY for n in names) or len(set(names)) != len(names):
            raise ValueError("bad evidence route: %s" % where)
        if len(names) > 1 and "none" in names:
            raise ValueError("bad evidence route: %s" % where)
        return names

    if default not in REGISTRY:
        raise ValueError("unknown evidence source: %s" % default)
    routes = {k: (default,) for k in querypack.KINDS}
    for part in filter(None, (p.strip() for p in (spec or "").split(","))):
        kind, _, sources = part.partition("=")
        if kind.strip() not in routes:
            raise ValueError("bad evidence route: %s" % part)
        routes[kind.strip()] = chain(sources, part)
    return routes


def make_backend(store):
    routes = parse_routes(os.environ.get("EVIDENCE_BACKEND", "file").lower(), os.environ.get("EVIDENCE_SOURCES", ""))
    switches = Switches(store, os.environ.get("SOURCE_SWITCH_KEY", ""), os.environ.get("SOURCES_DISABLED", ""),
                        known=set(REGISTRY) - set(UNSWITCHED))
    built = {name: REGISTRY[name](store) for names in routes.values() for name in names}
    chains = {}
    for names in set(routes.values()):
        if len(names) == 1 and names[0] in UNSWITCHED:
            chains[names] = built[names[0]]
        else:
            chains[names] = ChainBackend([(n, built[n]) for n in names], switches)
    if len(chains) == 1:
        return next(iter(chains.values()))
    return RoutedBackend({kind: chains[names] for kind, names in routes.items()})

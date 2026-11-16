"""Evidence backends. Each one answers the same question: rows of one kind for one account in one window.

  FileBackend        synthetic JSON from the data bucket (prototype default)
  SplunkBackend      Splunk REST search export
  DatabricksBackend  Databricks SQL Statement Execution API

Splunk and Databricks are exercised by unit tests with a fake transport. They have not been run against live
systems. Read-only by construction: the only requests made are a search export and a SELECT.
A backend never raises to the pipeline. Any failure becomes an empty result with an error, which the findings
engine reports as a gap.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import querypack
import scope

ROW_CAP = {"failed_logins": 5000, "account_events": 1000, "entra_failures": 5000}
INT_FIELDS = {"event_code", "logon_type"}
_HERE = os.path.dirname(os.path.abspath(__file__))


# ---------- shared helpers ----------

def load_field_map():
    for cand in (os.environ.get("FIELD_MAP_PATH"), os.path.join(_HERE, "config", "field_map.json"),
                 os.path.join(_HERE, "..", "config", "field_map.json")):
        if cand and os.path.isfile(cand):
            return json.load(open(cand))
    raise FileNotFoundError("config/field_map.json not found")


def to_utc_z(value):
    """Accepts ISO strings with or without offset, 'YYYY-MM-DD HH:MM:SS' (taken as UTC), or epoch seconds."""
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.replace(".", "", 1).isdigit()):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00").replace(" ", "T", 1))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    if not 2000 <= dt.year <= 2100:                   # a log time outside this century is corruption, not evidence
        raise ValueError("implausible time")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_value(field, value):
    if isinstance(value, list):                       # Splunk multivalue field: take the first
        value = value[0] if value else None
    if value is None:
        return None
    if field == "time":
        return to_utc_z(value)
    text = str(value).strip()
    if field in INT_FIELDS:
        try:
            return int(float(text))
        except ValueError:
            return None
    if field == "src_ip" and text.lower().startswith("::ffff:"):
        text = text[7:]                               # Kerberos events log IPv4 as an IPv6-mapped address
    if field in ("src_host", "caller_host"):
        text = text.lstrip("\\")                      # NTLM events often log \\HOST
    return text


def normalize(kind, raw_rows, field_map):
    """Map source rows to the internal shape. Rows without a usable time are dropped and counted."""
    mapping, skip = field_map[kind], set(field_map.get("skip_values", []))
    rows, dropped = [], 0
    for raw in raw_rows:
        row = {}
        for field, candidates in mapping.items():
            for name in candidates:
                if name in raw and str(raw[name] if not isinstance(raw[name], list) else (raw[name] or [""])[0]).strip() not in skip:
                    try:
                        row[field] = _clean_value(field, raw[name])
                    except (ValueError, OverflowError, OSError, TypeError):   # absurd timestamps and the like
                        row[field] = None
                    break
        if not row.get("time"):
            dropped += 1
            continue
        rows.append(row)
    rows.sort(key=lambda r: r["time"])
    return rows, dropped


def urllib_transport(method, url, headers, body, timeout):
    if not url.lower().startswith("https://"):                          # no file:, ftp: or plain http, ever
        raise ValueError("only https URLs are allowed")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        # Scheme is checked above and TLS verification stays on.
        with urllib.request.urlopen(req, timeout=timeout) as resp:      # nosec B310
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def secret_from_env(arn_var, plain_var):
    """Token from Secrets Manager (preferred) or, for local runs only, a plain environment variable."""
    arn = os.environ.get(arn_var)
    if arn:
        import boto3
        return boto3.client("secretsmanager").get_secret_value(SecretId=arn)["SecretString"]
    return os.environ.get(plain_var, "")


# ---------- backends ----------

def _newest(value):
    """The newest event time a source reported, or None when it gave none or gave something implausible."""
    if isinstance(value, list):
        value = value[0] if value else None
    if value in (None, ""):
        return None
    try:
        return to_utc_z(value)
    except (ValueError, OverflowError, OSError):
        return None


class NoSigninName(LookupError):
    """The source needs the account's cloud sign-in name and the ownership source did not give one."""


class Backend:
    """One evidence source. Subclasses implement fetch and health_counts. See docs/SOURCES.md for the contract."""
    name = "base"
    kinds = ("failed_logins", "account_events", "entra_failures")     # what this source can answer

    def fetch(self, kind, account, start, end, scope_set, signin_name=None):
        raise NotImplementedError

    def query(self, kind, account, start, end, scope_set, signin_name=None):
        if account not in scope_set:                  # re-check inside every tool, before any I/O
            raise scope.Denied("out_of_scope", "You can only investigate accounts you own.")
        qid = "%s:%s:%s" % (self.name, kind, account)
        if kind not in self.kinds:
            return {"query_id": qid, "rows": [], "truncated": False, "error": "source_not_configured"}
        try:
            rows, note = self.fetch(kind, account, start, end, scope_set, scope.signin_name(signin_name))
        except scope.Denied:
            raise
        except NoSigninName:
            return {"query_id": qid, "rows": [], "truncated": False, "error": "no_cloud_signin_name_for_account"}
        except Exception as e:                        # never crash the pipeline on a source problem
            return {"query_id": qid, "rows": [], "truncated": False, "error": "source_unavailable",
                    "error_detail": "%s: %s" % (type(e).__name__, str(e)[:200])}
        cap = ROW_CAP[kind]
        out = {"query_id": qid, "rows": rows[:cap], "truncated": len(rows) >= cap}
        if note:
            out["error"] = note
        return out

    def health_counts(self, source, start, end):
        """Return {"events": int, "reporting_hosts": int or None} for one source. Backends override this."""
        raise NotImplementedError

    def health(self, start, end):
        """Was each source collecting anything at all in this window? None means it could not be checked."""
        out = {}
        for source in ("windows", "entra"):
            try:
                counts = self.health_counts(source, start, end)
                if counts == "not_configured":
                    out[source] = "not_configured"
                    continue
                out[source] = {"events": int(counts["events"]),
                               "reporting_hosts": int(counts["reporting_hosts"]) if counts.get("reporting_hosts") is not None else None}
                newest = _newest(counts.get("newest"))
                if newest:                            # lets the report say how far behind the source is running
                    out[source]["newest"] = newest
            except Exception:
                out[source] = None
        return out


class FileBackend(Backend):
    name = "file"

    def __init__(self, store):
        self.store = store

    def query(self, kind, account, start, end, scope_set, signin_name=None):
        out = super().query(kind, account, start, end, scope_set, signin_name)
        out["query_id"] = "file:evidence/%s.json#%s" % (account, kind)
        out["truncated"] = len(out["rows"]) > ROW_CAP[kind]
        return out

    def fetch(self, kind, account, start, end, scope_set, signin_name=None):
        rows = json.loads(self.store.get("evidence/%s.json" % account)).get(kind)
        if rows is None:
            return [], "source_missing"
        ts = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
        rows = sorted((r for r in rows if start <= ts(r["time"]) < end), key=lambda r: r["time"])
        return rows, None

    def health_counts(self, source, start, end):
        return json.loads(self.store.get("evidence/_source_health.json"))[source]


class SplunkBackend(Backend):
    """POST {base}/services/search/jobs/export with a rendered template. Token needs a read-only role."""
    name = "splunk"

    def __init__(self, base_url, token, field_map=None, transport=urllib_transport, timeout=60):
        if not base_url.lower().startswith("https://"):
            raise ValueError("Splunk base URL must use https")
        self.base, self.token, self.transport, self.timeout = base_url.rstrip("/"), token, transport, timeout
        self.field_map = field_map or load_field_map()

    def _export(self, q):
        form = dict(q["params"], search=q["text"], output_mode="json")
        status, data = self.transport("POST", self.base + "/services/search/jobs/export",
                                      {"Authorization": "Bearer " + self.token,
                                       "Content-Type": "application/x-www-form-urlencoded"},
                                      urllib.parse.urlencode(form).encode(), self.timeout)
        if status != 200:
            raise RuntimeError("splunk http %s" % status)
        raw = []
        for line in data.decode("utf-8", "replace").splitlines():   # export streams one JSON object per line
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj.get("result"), dict):
                raw.append(obj["result"])
        return raw

    def fetch(self, kind, account, start, end, scope_set, signin_name=None):
        raw = self._export(querypack.render(kind + ".spl", account, start, end, scope_set, signin_name))
        rows, dropped = normalize(kind, raw, self.field_map)
        return rows, ("rows_dropped_no_time:%d" % dropped if dropped else None)

    def health_counts(self, source, start, end):
        raw = self._export(querypack.render_health("source_health_%s.spl" % source, start, end))
        row = raw[0] if raw else {}
        return {"events": int(float(row.get("events") or 0)), "newest": row.get("newest"),
                "reporting_hosts": int(float(row["reporting_hosts"])) if row.get("reporting_hosts") not in (None, "") else None}


class DatabricksBackend(Backend):
    """POST {host}/api/2.0/sql/statements with named parameters. Token needs SELECT on three views only."""
    name = "databricks"

    def __init__(self, host, warehouse_id, token, field_map=None, transport=urllib_transport, timeout=60):
        if not host.lower().startswith("https://"):
            raise ValueError("Databricks host must use https")
        self.host, self.warehouse, self.token = host.rstrip("/"), warehouse_id, token
        self.transport, self.timeout = transport, timeout
        self.field_map = field_map or load_field_map()

    def _statement(self, q):
        types = {"account": "STRING", "signin_name": "STRING", "start": "TIMESTAMP", "end": "TIMESTAMP"}
        payload = {"statement": q["text"], "warehouse_id": self.warehouse, "wait_timeout": "50s",
                   "on_wait_timeout": "CANCEL", "format": "JSON_ARRAY", "disposition": "INLINE",
                   "parameters": [{"name": k, "value": v, "type": types[k]} for k, v in q["params"].items()]}
        status, data = self.transport("POST", self.host + "/api/2.0/sql/statements",
                                      {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
                                      json.dumps(payload).encode(), self.timeout)
        if status != 200:
            raise RuntimeError("databricks http %s" % status)
        resp = json.loads(data)
        state = (resp.get("status") or {}).get("state")
        if state != "SUCCEEDED":
            raise RuntimeError("databricks statement state %s" % state)
        cols = [c["name"] for c in resp["manifest"]["schema"]["columns"]]
        raw = [dict(zip(cols, r, strict=False)) for r in (resp.get("result") or {}).get("data_array") or []]
        return raw, bool(resp["manifest"].get("truncated"))

    def fetch(self, kind, account, start, end, scope_set, signin_name=None):
        raw, truncated = self._statement(querypack.render(kind + ".sql", account, start, end, scope_set, signin_name))
        rows, dropped = normalize(kind, raw, self.field_map)
        note = "rows_dropped_no_time:%d" % dropped if dropped else None
        return rows, ("truncated_by_source" if truncated else note)

    def health_counts(self, source, start, end):
        raw, _ = self._statement(querypack.render_health("source_health_%s.sql" % source, start, end))
        row = raw[0] if raw else {}
        return {"events": int(float(row.get("events") or 0)), "newest": row.get("newest"),
                "reporting_hosts": int(float(row["reporting_hosts"])) if row.get("reporting_hosts") is not None else None}


def make_backend(store):
    import adapters
    return adapters.make_backend(store)

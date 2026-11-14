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
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
                    except (ValueError, OverflowError):
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

class Backend:
    name = "base"

    def fetch(self, kind, account, start, end, scope_set):
        raise NotImplementedError

    def query(self, kind, account, start, end, scope_set):
        if account not in scope_set:                  # re-check inside every tool, before any I/O
            raise scope.Denied("out_of_scope", "You can only investigate accounts you own.")
        qid = "%s:%s:%s" % (self.name, kind, account)
        try:
            rows, note = self.fetch(kind, account, start, end, scope_set)
        except scope.Denied:
            raise
        except Exception as e:                        # never crash the pipeline on a source problem
            return {"query_id": qid, "rows": [], "truncated": False, "error": "source_unavailable",
                    "error_detail": "%s: %s" % (type(e).__name__, str(e)[:200])}
        cap = ROW_CAP[kind]
        out = {"query_id": qid, "rows": rows[:cap], "truncated": len(rows) >= cap}
        if note:
            out["error"] = note
        return out


class FileBackend(Backend):
    name = "file"

    def __init__(self, store):
        self.store = store

    def query(self, kind, account, start, end, scope_set):
        out = super().query(kind, account, start, end, scope_set)
        out["query_id"] = "file:evidence/%s.json#%s" % (account, kind)
        out["truncated"] = len(out["rows"]) > ROW_CAP[kind]
        return out

    def fetch(self, kind, account, start, end, scope_set):
        rows = json.loads(self.store.get("evidence/%s.json" % account)).get(kind)
        if rows is None:
            return [], "source_missing"
        ts = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
        rows = sorted((r for r in rows if start <= ts(r["time"]) < end), key=lambda r: r["time"])
        return rows, None


class SplunkBackend(Backend):
    """POST {base}/services/search/jobs/export with a rendered template. Token needs a read-only role."""
    name = "splunk"

    def __init__(self, base_url, token, field_map=None, transport=urllib_transport, timeout=60):
        if not base_url.lower().startswith("https://"):
            raise ValueError("Splunk base URL must use https")
        self.base, self.token, self.transport, self.timeout = base_url.rstrip("/"), token, transport, timeout
        self.field_map = field_map or load_field_map()

    def fetch(self, kind, account, start, end, scope_set):
        q = querypack.render(kind + ".spl", account, start, end, scope_set)
        body = urllib.parse.urlencode({"search": q["text"], "output_mode": "json"}).encode()
        status, data = self.transport("POST", self.base + "/services/search/jobs/export",
                                      {"Authorization": "Bearer " + self.token,
                                       "Content-Type": "application/x-www-form-urlencoded"}, body, self.timeout)
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
        rows, dropped = normalize(kind, raw, self.field_map)
        return rows, ("rows_dropped_no_time:%d" % dropped if dropped else None)


class DatabricksBackend(Backend):
    """POST {host}/api/2.0/sql/statements with named parameters. Token needs SELECT on three views only."""
    name = "databricks"

    def __init__(self, host, warehouse_id, token, field_map=None, transport=urllib_transport, timeout=60):
        if not host.lower().startswith("https://"):
            raise ValueError("Databricks host must use https")
        self.host, self.warehouse, self.token = host.rstrip("/"), warehouse_id, token
        self.transport, self.timeout = transport, timeout
        self.field_map = field_map or load_field_map()

    def fetch(self, kind, account, start, end, scope_set):
        q = querypack.render(kind + ".sql", account, start, end, scope_set)
        payload = {"statement": q["text"], "warehouse_id": self.warehouse, "wait_timeout": "50s",
                   "on_wait_timeout": "CANCEL", "format": "JSON_ARRAY", "disposition": "INLINE",
                   "parameters": [{"name": "account", "value": q["params"]["account"], "type": "STRING"},
                                  {"name": "start", "value": q["params"]["start"], "type": "TIMESTAMP"},
                                  {"name": "end", "value": q["params"]["end"], "type": "TIMESTAMP"}]}
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
        rows, dropped = normalize(kind, raw, self.field_map)
        note = "rows_dropped_no_time:%d" % dropped if dropped else None
        if resp["manifest"].get("truncated"):
            note = "truncated_by_source"
        return rows, note


def make_backend(store):
    kind = os.environ.get("EVIDENCE_BACKEND", "file").lower()
    if kind == "file":
        return FileBackend(store)
    if kind == "splunk":
        return SplunkBackend(os.environ["SPLUNK_BASE_URL"], secret_from_env("SPLUNK_TOKEN_SECRET_ARN", "SPLUNK_TOKEN"))
    if kind == "databricks":
        return DatabricksBackend(os.environ["DATABRICKS_HOST"], os.environ["DATABRICKS_WAREHOUSE_ID"],
                                 secret_from_env("DATABRICKS_TOKEN_SECRET_ARN", "DATABRICKS_TOKEN"))
    raise ValueError("unknown EVIDENCE_BACKEND")

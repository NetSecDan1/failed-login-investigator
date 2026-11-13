"""Read tools. Fixed shapes only: (account, start, end). No free-text queries.

Backend 'file' reads synthetic evidence from S3. Splunk and Databricks backends plug in
behind the same three functions later; they are intentionally not implemented here.
"""
import json, os
from datetime import datetime

import scope

ROW_CAP = 5000


class S3Store:
    def __init__(self, bucket):
        import boto3
        self.bucket, self.s3 = bucket, boto3.client("s3")

    def get(self, key):
        return self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read().decode()


class DictStore:  # tests
    def __init__(self, d):
        self.d = d

    def get(self, key):
        return self.d[key]


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _query(kind, account, start, end, scope_set, store):
    if account not in scope_set:  # re-check inside every tool
        raise scope.Denied("out_of_scope", "You can only investigate accounts you own.")
    backend = os.environ.get("EVIDENCE_BACKEND", "file")
    if backend != "file":
        raise NotImplementedError("backend %s not wired in this prototype" % backend)
    key = "evidence/%s.json" % account
    qid = "file:%s#%s" % (key, kind)
    try:
        rows = json.loads(store.get(key)).get(kind)
    except Exception:
        return {"query_id": qid, "rows": [], "truncated": False, "error": "source_unavailable"}
    if rows is None:
        return {"query_id": qid, "rows": [], "truncated": False, "error": "source_missing"}
    rows = [r for r in rows if start <= _ts(r["time"]) < end]
    rows.sort(key=lambda r: r["time"])
    return {"query_id": qid, "rows": rows[:ROW_CAP], "truncated": len(rows) > ROW_CAP}


def get_failed_logins(account, start, end, scope_set, store):
    return _query("failed_logins", account, start, end, scope_set, store)


def get_account_events(account, start, end, scope_set, store):
    return _query("account_events", account, start, end, scope_set, store)


def get_entra_failures(account, start, end, scope_set, store):
    return _query("entra_failures", account, start, end, scope_set, store)


def collect(account, start, end, scope_set, store):
    pack = {
        "failed_logins": get_failed_logins(account, start, end, scope_set, store),
        "account_events": get_account_events(account, start, end, scope_set, store),
        "entra_failures": get_entra_failures(account, start, end, scope_set, store),
    }
    pack["query_ids"] = [pack[k]["query_id"] for k in ("failed_logins", "account_events", "entra_failures")]
    return pack

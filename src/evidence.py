"""Read tools. Fixed shapes only: (account, start, end). No free-text queries.

The three functions below are the whole tool surface. Which system answers them is chosen by
EVIDENCE_BACKEND (file, splunk or databricks) in src/backends.py.
"""
import backends


class S3Store:
    def __init__(self, bucket):
        import boto3
        self.bucket, self.s3 = bucket, boto3.client("s3")

    def get(self, key):
        return self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read().decode()


class DictStore:  # tests and local runs
    def __init__(self, d):
        self.d = d

    def get(self, key):
        return self.d[key]


def _backend(source):
    return source if isinstance(source, backends.Backend) else backends.FileBackend(source)


def get_failed_logins(account, start, end, scope_set, source):
    return _backend(source).query("failed_logins", account, start, end, scope_set)


def get_account_events(account, start, end, scope_set, source):
    return _backend(source).query("account_events", account, start, end, scope_set)


def get_entra_failures(account, start, end, scope_set, source):
    return _backend(source).query("entra_failures", account, start, end, scope_set)


def collect(account, start, end, scope_set, source):
    pack = {
        "failed_logins": get_failed_logins(account, start, end, scope_set, source),
        "account_events": get_account_events(account, start, end, scope_set, source),
        "entra_failures": get_entra_failures(account, start, end, scope_set, source),
    }
    pack["query_ids"] = [pack[k]["query_id"] for k in ("failed_logins", "account_events", "entra_failures")]
    return pack

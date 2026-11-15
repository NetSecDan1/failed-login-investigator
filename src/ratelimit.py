"""Per-caller rate limit for investigations. Fails closed.

RATE_LIMIT_PER_HOUR=0 turns it off (prototype default). With a limit set, every investigation attempt counts,
including ones that end in a denial, so probing for accounts spends the caller's own allowance.

  RATE_LIMIT_TABLE set      one atomic counter per caller per clock hour in a key-value table, shared by all instances
  RATE_LIMIT_TABLE not set  a counter in this process only. Fine for local runs and tests, weak when many instances run

The table is the only thing this service ever writes to, and it holds a caller identifier, an hour and a count.
"""
import os
import time

import scope

_memory = {}


def _bucket(caller, now):
    return "%s#%s" % (caller.lower(), time.strftime("%Y%m%d%H", time.gmtime(now)))


def check(caller, now=None, table_client=None):
    """Count one attempt. Raises scope.Denied('rate_limited') over the limit, or 'rate_limit_unavailable' on failure."""
    try:
        limit = int(os.environ.get("RATE_LIMIT_PER_HOUR", "0") or 0)
    except ValueError:
        raise scope.Denied("rate_limit_unavailable", "Rate limit is misconfigured. Try again later.") from None
    if limit <= 0:
        return None
    now = time.time() if now is None else now
    key, table = _bucket(caller, now), os.environ.get("RATE_LIMIT_TABLE", "")
    try:
        if table:
            if table_client is None:
                import boto3
                table_client = boto3.client("dynamodb")
            resp = table_client.update_item(
                TableName=table, Key={"bucket": {"S": key}},
                UpdateExpression="ADD attempts :one SET expires_at = if_not_exists(expires_at, :ttl)",
                ExpressionAttributeValues={":one": {"N": "1"}, ":ttl": {"N": str(int(now) + 7200)}},
                ReturnValues="UPDATED_NEW")
            count = int(resp["Attributes"]["attempts"]["N"])
        else:
            for old in [k for k in _memory if not k.endswith(key[-10:])]:   # drop earlier hours
                del _memory[old]
            count = _memory[key] = _memory.get(key, 0) + 1
    except Exception:
        # An abuse control that cannot count must not wave requests through.
        raise scope.Denied("rate_limit_unavailable", "Rate limit could not be checked. Try again later.") from None
    if count > limit:
        raise scope.Denied("rate_limited", "Too many investigations this hour. Try again later.")
    return {"used": count, "limit": limit}

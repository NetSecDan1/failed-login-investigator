"""Renders the fixed query templates in queries/. Not wired to a backend yet.

Splunk templates get three validated values substituted. SQL templates are returned unchanged with a
parameter list, because values must travel as bound parameters and never as SQL text.
"""
import os
from datetime import datetime, timezone

import scope

TEMPLATE_DIR = os.environ.get("QUERY_TEMPLATE_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "queries")
ALLOWED = {"failed_logins.spl", "account_events.spl", "entra_failures.spl", "failed_logins.sql"}


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TypeError("start and end must be timezone-aware datetimes")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def render(name, account, start, end, scope_set):
    """Return {"text": ..., "params": {...}} for one template. Raises scope.Denied when out of scope."""
    if name not in ALLOWED:
        raise ValueError("unknown template")
    account = scope.check_account(account, scope_set)   # shape check and scope check, every time
    if end <= start:
        raise ValueError("empty window")
    values = {"account": account, "start": _utc(start), "end": _utc(end)}
    with open(os.path.join(TEMPLATE_DIR, name)) as f:
        text = f.read()
    if name.endswith(".sql"):
        return {"text": text, "params": values}
    for key, val in values.items():
        text = text.replace("{%s}" % key, val)
    return {"text": text, "params": {}}

"""Renders the fixed query templates in queries/.

Splunk templates get validated values substituted. SQL templates keep their parameter markers and return the
values separately, because values must travel as bound parameters and never as SQL text.
"""
import os
import re
from datetime import datetime, timezone

import scope

_HERE = os.path.dirname(os.path.abspath(__file__))
KINDS = ("failed_logins", "account_events", "entra_failures")
ALLOWED = {"%s.%s" % (k, ext) for k in KINDS for ext in ("spl", "sql")}
# Aggregate-only templates with no account in them. They return a count, never rows.
HEALTH = {"source_health_%s.%s" % (k, ext) for k in ("windows", "entra") for ext in ("spl", "sql")}
SETTING_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}$")
# Operator settings: template placeholder -> environment variable.
SETTINGS = {"index_windows": "SPLUNK_INDEX_WINDOWS", "index_entra": "SPLUNK_INDEX_ENTRA",
            "view_failed_logins": "DATABRICKS_VIEW_FAILED_LOGINS", "view_account_events": "DATABRICKS_VIEW_ACCOUNT_EVENTS",
            "view_entra_failures": "DATABRICKS_VIEW_ENTRA_FAILURES"}


def template_dir():
    if os.environ.get("QUERY_TEMPLATE_DIR"):
        return os.environ["QUERY_TEMPLATE_DIR"]
    for cand in (os.path.join(_HERE, "queries"), os.path.join(_HERE, "..", "queries")):
        if os.path.isdir(cand):
            return cand
    raise FileNotFoundError("queries directory not found")


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TypeError("start and end must be timezone-aware datetimes")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _settings(text):
    for name in set(re.findall(r"\{(\w+)\}", text)) & set(SETTINGS):
        value = os.environ.get(SETTINGS[name], "")
        if not SETTING_RE.fullmatch(value):
            raise ValueError("setting %s is missing or not a plain identifier" % SETTINGS[name])
        text = text.replace("{%s}" % name, value)
    return text


def _window(start, end):
    if end <= start:
        raise ValueError("empty window")
    return _utc(start), _utc(end)


def render(name, account, start, end, scope_set):
    """Return {"text": ..., "params": {...}} for one template. Raises scope.Denied when out of scope.

    Splunk templates carry the account in the search text and the time bounds as request parameters
    (epoch seconds). SQL templates carry everything as bound parameters.
    """
    if name not in ALLOWED:
        raise ValueError("unknown template")
    account = scope.check_account(account, scope_set)   # shape check and scope check, every time
    s, e = _window(start, end)
    with open(os.path.join(template_dir(), name)) as f:
        text = _settings(f.read())
    if name.endswith(".sql"):
        return {"text": text, "params": {"account": account, "start": s, "end": e}}
    return {"text": text.replace("{account}", account),
            "params": {"earliest_time": str(int(start.timestamp())), "latest_time": str(int(end.timestamp()))}}


def render_health(name, start, end):
    """A source activity count for the window. No account, no rows, only operator settings."""
    if name not in HEALTH:
        raise ValueError("unknown template")
    s, e = _window(start, end)
    with open(os.path.join(template_dir(), name)) as f:
        text = _settings(f.read())
    if name.endswith(".sql"):
        return {"text": text, "params": {"start": s, "end": e}}
    return {"text": text, "params": {"earliest_time": str(int(start.timestamp())), "latest_time": str(int(end.timestamp()))}}

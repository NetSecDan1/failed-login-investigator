"""Scope resolution. Deterministic, fail closed. The model never sees or sets any of this."""
import json, os, re
from datetime import datetime, timezone

ACCOUNT_RE = re.compile(r"^[a-z0-9._$-]{1,64}$")


class Denied(Exception):
    def __init__(self, code, message):
        super().__init__(code)
        self.code, self.message = code, message


CALLER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")


def caller_id(claims, claim_name="employee_id"):
    """The caller is whatever the configured token claim says. Employee number, object ID and UPN all fit."""
    cid = claims.get(claim_name) if isinstance(claims, dict) else None
    if not isinstance(cid, str) or not CALLER_RE.fullmatch(cid):
        raise Denied("unauthenticated", "No verified caller identity.")
    return cid


def _check_fresh(export):
    """Stale ownership is treated as an outage. Off unless OWNERSHIP_MAX_AGE_HOURS is set above zero."""
    max_age = float(os.environ.get("OWNERSHIP_MAX_AGE_HOURS", "0") or 0)
    if max_age <= 0:
        return
    try:
        made = datetime.fromisoformat(str(export["_generated"]).replace("Z", "+00:00"))
        if made.tzinfo is None:
            made = made.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - made).total_seconds() / 3600
    except Exception:
        raise Denied("ownership_stale", "Ownership data has no usable timestamp. Try again later.") from None
    if age_hours > max_age or age_hours < -1:
        raise Denied("ownership_stale", "Ownership data is out of date. Try again later.")


def resolve_scope_meta(caller, store):
    """Return (frozenset of owned account names, {name: account type}). Any error or empty result denies."""
    try:
        export = json.loads(store.get("ownership/ownership.json"))
        owners = {str(k).lower(): v for k, v in export["owners"].items()}
        owned = owners.get(caller.lower(), [])
        deny = {d.lower() for d in export.get("deny_list", [])}
        # Conflicting records resolve to the most restrictive: Tier 0 anywhere means Tier 0 for everyone.
        tier0 = {str(a.get("account", "")).lower() for entries in owners.values() for a in entries if a.get("tier") == 0}
    except Exception:
        raise Denied("ownership_unavailable", "Ownership source unavailable. Try again later.") from None
    _check_fresh(export)
    meta = {}
    for a in owned:
        name = str(a.get("account", "")).lower()
        if name in tier0 or name in deny or not ACCOUNT_RE.fullmatch(name):
            continue
        meta[name] = a.get("type")
    if not meta:
        raise Denied("scope_empty", "No owned accounts found for you.")
    return frozenset(meta), meta


def resolve_scope(caller, store):
    return resolve_scope_meta(caller, store)[0]


def check_account(account, scope_set):
    if not isinstance(account, str) or not ACCOUNT_RE.fullmatch(account.lower()):
        raise Denied("bad_account", "Account name is not valid.")
    account = account.lower()
    if account not in scope_set:
        # Same answer whether the account exists or not: no existence oracle.
        raise Denied("out_of_scope", "You can only investigate accounts you own.")
    return account

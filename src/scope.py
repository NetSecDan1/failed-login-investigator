"""Scope resolution. Deterministic, fail closed. The model never sees or sets any of this."""
import json, re

ACCOUNT_RE = re.compile(r"^[a-z0-9._$-]{1,64}$")


class Denied(Exception):
    def __init__(self, code, message):
        super().__init__(code)
        self.code, self.message = code, message


def caller_id(claims):
    cid = claims.get("employee_id")
    if not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9]{1,32}", cid):
        raise Denied("unauthenticated", "No verified caller identity.")
    return cid


def resolve_scope(caller, store):
    """Return frozenset of account names the caller owns. Any error or empty result denies."""
    try:
        export = json.loads(store.get("ownership/ownership.json"))
        owned = export["owners"].get(caller, [])
        deny = {d.lower() for d in export.get("deny_list", [])}
    except Exception:
        raise Denied("ownership_unavailable", "Ownership source unavailable. Try again later.")
    names = set()
    for a in owned:
        name = str(a.get("account", "")).lower()
        if a.get("tier") == 0 or name in deny or not ACCOUNT_RE.fullmatch(name):
            continue
        names.add(name)
    if not names:
        raise Denied("scope_empty", "No owned accounts found for you.")
    return frozenset(names)


def check_account(account, scope_set):
    if not isinstance(account, str) or not ACCOUNT_RE.fullmatch(account.lower()):
        raise Denied("bad_account", "Account name is not valid.")
    account = account.lower()
    if account not in scope_set:
        # Same answer whether the account exists or not: no existence oracle.
        raise Denied("out_of_scope", "You can only investigate accounts you own.")
    return account

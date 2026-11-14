"""Deterministic findings. Same input always gives the same output."""
import ipaddress, re, statistics
from collections import Counter
from datetime import datetime

CODE_MEANING = {
    "0xc000006a": "wrong password", "0xc0000064": "user name does not exist",
    "0xc0000234": "account locked", "0xc0000072": "account disabled",
    "0xc0000071": "password expired", "0xc0000193": "account expired",
    "0xc0000070": "workstation restriction", "0x18": "kerberos bad password",
    "0x12": "kerberos account disabled or locked", "0x17": "kerberos password expired",
    "0x25": "kerberos clock skew", "50126": "entra invalid credentials",
    "50053": "entra account locked", "50057": "entra account disabled",
    "50055": "entra password expired", "53003": "entra blocked by conditional access",
}
PROTOCOL = {4625: "logon", 4771: "kerberos", 4776: "ntlm"}

# Code groups used by the signals block. Skills refer to the signal names, never to raw codes.
WRONG_PASSWORD = {"0xc000006a", "0x18"}
UNKNOWN_USER = {"0xc0000064", "0x6"}
LOCKED = {"0xc0000234"}
KERBEROS_REVOKED = {"0x12"}            # ambiguous on its own: disabled, expired or locked out
DISABLED = {"0xc0000072"}
PASSWORD_EXPIRED = {"0xc0000071", "0x17", "0xc0000224"}
ACCOUNT_EXPIRED = {"0xc0000193"}
RESTRICTION = {"0xc0000070", "0xc000006f"}
CLOCK_SKEW = {"0x25"}
LOGON_TYPE_GROUP = {2: "interactive", 7: "interactive", 10: "interactive", 11: "interactive",
                    3: "network", 4: "service_or_batch", 5: "service_or_batch", 8: "network"}
ENTRA_BAD_PASSWORD = {"50126"}
ENTRA_LOCKED = {"50053"}
ENTRA_DISABLED = {"50057"}
ENTRA_EXPIRED = {"50055"}
ENTRA_CA_BLOCK = {"53003", "53000", "53001", "53002", "53004", "530032"}
ENTRA_MFA_INTERRUPT = {"50074", "50076", "50079", "50072", "50158"}
ENTRA_LEGACY_CLIENTS = {"exchange activesync", "imap4", "pop3", "authenticated smtp", "smtp", "other clients",
                        "mapi over http", "exchange web services", "autodiscover", "exchange online powershell",
                        "offline address book", "reporting web services", "outlook anywhere (rpc over http)"}


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def clean(value, cap=64):
    """Log text can be attacker controlled. Strip control chars, cap length."""
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(value if value is not None else ""))
    return s[:cap] + ("~" if len(s) > cap else "")


INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                  "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")]
HOST_RE = re.compile(r"^[A-Za-z0-9._$-]{1,64}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9 ._()/-]{1,64}$")


def _external(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not any(a in n for n in INTERNAL_NETS)
    except ValueError:
        return False


def host(value):
    """A source host must look like a host name. Anything else never reaches the model."""
    s = str(value or "")
    if not s:
        return "(blank)"
    return s if HOST_RE.fullmatch(s) else "(not-a-hostname)"


def label(value):
    s = str(value or "")
    return s if LABEL_RE.fullmatch(s) else "(unreadable)"


def ip_text(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return "(not-an-ip)"


def _top(counter, n=5):
    return [{"value": k, "count": v} for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def _share(counter, group, total):
    """Fraction of events whose key is in group. None when there are no events."""
    if not total:
        return None
    return round(sum(v for k, v in counter.items() if k in group) / total, 2)


def compute(account, start, end, pack, account_type=None):
    fl, ev, en = pack["failed_logins"], pack["account_events"], pack["entra_failures"]
    rows = fl["rows"]
    gaps = ["%s: %s" % (k, pack[k]["error"]) for k in ("failed_logins", "account_events", "entra_failures")
            if pack[k].get("error")]
    if fl.get("truncated"):
        gaps.append("failed_logins: truncated at row cap")

    hosts = Counter(host(r.get("src_host")) for r in rows)
    ips = Counter(ip_text(r.get("src_ip")) for r in rows if r.get("src_ip"))
    codes = Counter(clean(r.get("failure_code", ""), 12).lower() for r in rows)
    protos = Counter(PROTOCOL.get(r.get("event_code"), "other") for r in rows)
    hours = Counter(r["time"][:13] for r in rows)
    times = [_ts(r["time"]) for r in rows]
    total = len(rows)

    deltas = [(b - a).total_seconds() for a, b in zip(times, times[1:], strict=False)]
    cadence = None
    if len(deltas) >= 5:
        med = statistics.median(deltas)
        mean = statistics.fmean(deltas)
        cv = (statistics.pstdev(deltas) / mean) if mean else 0.0
        cadence = {"median_gap_seconds": round(med, 1), "variation": round(cv, 2), "regular": cv < 0.25}

    # Per-host rhythm: a fleet of systems each retrying on its own timer looks irregular when merged.
    by_host_times = {}
    for r, t in zip(rows, times, strict=True):
        by_host_times.setdefault(host(r.get("src_host")), []).append(t)
    judged = regular_hosts = 0
    for ts in by_host_times.values():
        d = [(b - a).total_seconds() for a, b in zip(ts, ts[1:], strict=False)]
        if len(d) >= 4:
            judged += 1
            m = statistics.fmean(d)
            regular_hosts += 1 if m and statistics.pstdev(d) / m < 0.25 else 0
    regular_host_share = round(regular_hosts / judged, 2) if judged else None

    pw = [e for e in ev["rows"] if e.get("event_code") in (4723, 4724)]
    last_pw = pw[-1]["time"] if pw else None
    mins_after_pw = None
    if last_pw:
        after = [t for t in times if t >= _ts(last_pw)]
        before = [t for t in times if t < _ts(last_pw)]
        if after:
            mins_after_pw = {"minutes_to_first_failure": round((after[0] - _ts(last_pw)).total_seconds() / 60, 1),
                             "failures_before_change": len(before), "failures_after_change": len(after)}

    lockouts = [e for e in ev["rows"] if e.get("event_code") == 4740]
    top_host = _top(hosts, 1)
    ext = sorted({ip for ip in ips if _external(ip)})
    en_codes = Counter(clean(r.get("error_code", ""), 12) for r in en["rows"])
    en_total = len(en["rows"])
    en_clients = Counter(label(r.get("client_app")).lower() for r in en["rows"])
    en_apps = Counter(label(r.get("app")) for r in en["rows"] if r.get("app"))
    en_ips = {ip_text(r.get("src_ip")) for r in en["rows"] if r.get("src_ip")}
    logon_groups = Counter(LOGON_TYPE_GROUP.get(r.get("logon_type"), "unknown") for r in rows)
    span = round((times[-1] - times[0]).total_seconds() / 60, 1) if total >= 2 else None
    locked = _share(codes, LOCKED, total)
    revoked = _share(codes, KERBEROS_REVOKED, total)

    signals = {
        "ad_failures": total,
        "entra_failures": en_total,
        "wrong_password_share": _share(codes, WRONG_PASSWORD, total),
        "unknown_user_share": _share(codes, UNKNOWN_USER, total),
        "locked_share": locked,
        "kerberos_revoked_share": revoked,
        "locked_or_revoked_share": round(locked + revoked, 2) if total else None,
        "disabled_share": _share(codes, DISABLED, total),
        "password_expired_share": _share(codes, PASSWORD_EXPIRED, total),
        "account_expired_share": _share(codes, ACCOUNT_EXPIRED, total),
        "restriction_share": _share(codes, RESTRICTION, total),
        "clock_skew_share": _share(codes, CLOCK_SKEW, total),
        "ntlm_share": _share(protos, {"ntlm"}, total),
        "kerberos_share": _share(protos, {"kerberos"}, total),
        "interactive_share": _share(logon_groups, {"interactive"}, total),
        "network_share": _share(logon_groups, {"network"}, total),
        "service_or_batch_share": _share(logon_groups, {"service_or_batch"}, total),
        "distinct_source_hosts": len(hosts),
        "top_source_share": round(top_host[0]["count"] / total, 2) if total else None,
        "external_ip_count": len(ext),
        "cadence_regular": cadence["regular"] if cadence else None,
        "regular_host_share": regular_host_share,
        "span_minutes": span,
        "pw_change_in_window": bool(last_pw),
        "minutes_pw_change_to_first_failure": mins_after_pw["minutes_to_first_failure"] if mins_after_pw else None,
        "failures_before_pw_change": mins_after_pw["failures_before_change"] if mins_after_pw else None,
        "lockout_count": len(lockouts),
        "entra_bad_password_share": _share(en_codes, ENTRA_BAD_PASSWORD, en_total),
        "entra_locked_share": _share(en_codes, ENTRA_LOCKED, en_total),
        "entra_disabled_share": _share(en_codes, ENTRA_DISABLED, en_total),
        "entra_expired_share": _share(en_codes, ENTRA_EXPIRED, en_total),
        "entra_ca_block_share": _share(en_codes, ENTRA_CA_BLOCK, en_total),
        "entra_mfa_interrupt_share": _share(en_codes, ENTRA_MFA_INTERRUPT, en_total),
        "entra_legacy_client_share": _share(en_clients, ENTRA_LEGACY_CLIENTS, en_total),
        "entra_distinct_ips": len(en_ips),
        "missing_sources": len(gaps),
    }

    return {
        "account": account,
        "account_type": account_type if account_type in ("person", "service", "privileged") else "unknown",
        "signals": signals,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "query_ids": pack["query_ids"],
        "ad": {
            "total_failures": total,
            "first_seen": rows[0]["time"] if rows else None,
            "last_seen": rows[-1]["time"] if rows else None,
            "by_source_host": _top(hosts),
            "distinct_source_hosts": len(hosts),
            "top_source_share": round(top_host[0]["count"] / total, 2) if total else None,
            "by_source_ip": _top(ips),
            "external_source_ips": ext,
            "by_failure_code": [dict(x, meaning=CODE_MEANING.get(x["value"], "unknown")) for x in _top(codes)],
            "by_protocol": _top(protos),
            "by_logon_group": _top(logon_groups),
            "busiest_hours_utc": _top(hours, 3),
            "cadence": cadence,
            "lockout_count": len(lockouts),
            "lockout_callers": _top(Counter(host(e.get("caller_host")) for e in lockouts), 3),
            "last_password_change": last_pw,
            "after_password_change": mins_after_pw,
        },
        "entra": {
            "total_failures": len(en["rows"]),
            "by_error_code": [dict(x, meaning=CODE_MEANING.get(x["value"], "unknown")) for x in _top(en_codes)],
            "by_client_app": _top(Counter(label(r.get("client_app")) for r in en["rows"]), 3),
            "by_app": _top(en_apps, 3),
            "by_source_ip": _top(Counter(ip for ip in (ip_text(r.get("src_ip")) for r in en["rows"] if r.get("src_ip"))), 5),
        },
        "gaps": gaps,
    }

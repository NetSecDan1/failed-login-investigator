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


def compute(account, start, end, pack):
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

    deltas = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    cadence = None
    if len(deltas) >= 5:
        med = statistics.median(deltas)
        mean = statistics.fmean(deltas)
        cv = (statistics.pstdev(deltas) / mean) if mean else 0.0
        cadence = {"median_gap_seconds": round(med, 1), "variation": round(cv, 2), "regular": cv < 0.25}

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

    return {
        "account": account,
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
        },
        "gaps": gaps,
    }

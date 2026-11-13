"""Output gate. The report is shown only if every check passes."""
import re

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._$-]*[A-Za-z0-9$]")
BENIGN_RE = re.compile(
    r"\d+(\.\d+)?-?(seconds?|secs?|minutes?|mins?|hours?|hrs?|days?|weeks?|s|h|d|m|x|st|nd|rd|th)"  # 5-minute, 24h, 3rd
    r"|\d{4}-\d{2}-\d{2}(t\d{2}([\d:.]*)z?)?"                                                     # 2026-11-12T13
    r"|\d{1,2}(\.\d+)?z"                                                                        # 00Z tail of a timestamp
    r"|(event|id|tier|code)-?\d+")
GENERIC = {"ntlmv1", "ntlmv2", "smbv1", "ipv4", "ipv6", "oauth2", "m365", "o365", "utf8", "sha256"}


def _allowed_entities(facts):
    ad, en = facts["ad"], facts["entra"]
    vals = {facts["account"]}
    for key in ("by_source_host", "by_source_ip", "by_failure_code", "lockout_callers"):
        vals.update(str(x["value"]) for x in ad[key])
    vals.update(ad["external_source_ips"])
    vals.update(str(x["value"]) for x in en["by_error_code"] + en["by_client_app"] + en.get("by_app", []) + en.get("by_source_ip", []))
    return {v.lower() for v in vals if v}


def validate(report, facts, skills, query_ids, allowed_choices, steps_by_id):
    errs = []
    if not isinstance(report, dict):
        return ["not_an_object"]
    need = {"classification_id": str, "confidence": str, "evidence_refs": list,
            "narrative": str, "next_step_ids": list}
    for k, t in need.items():
        if not isinstance(report.get(k), t):
            errs.append("bad_field:" + k)
    if errs:
        return errs
    ids = {s["id"]: s for s in skills["index"]}
    cid = report["classification_id"]
    if cid not in ids:
        return ["unknown_classification"]
    if cid not in allowed_choices:
        errs.append("classification_not_allowed_by_evidence")
    if report["confidence"] not in ("low", "medium", "high"):
        errs.append("bad_confidence")
    if not report["evidence_refs"] or not set(report["evidence_refs"]) <= set(query_ids):
        errs.append("bad_evidence_refs")
    if len(report["narrative"]) > 1500:
        errs.append("too_long")
    n = len(steps_by_id.get(cid, []))
    step_ids = report["next_step_ids"]
    if (not all(isinstance(i, int) and not isinstance(i, bool) and 1 <= i <= n for i in step_ids)
            or len(set(step_ids)) != len(step_ids) or (n and not step_ids)):
        errs.append("bad_next_step_ids")

    allowed = _allowed_entities(facts)
    text = report["narrative"]
    for ip in IP_RE.findall(text):
        if ip not in allowed:
            errs.append("unseen_ip:" + ip)
    for tok in TOKEN_RE.findall(text):
        low = tok.lower().rstrip(".")
        # entity-like = mixes letters and digits (WKS-4471, svc-app01). Plain words pass.
        if re.search(r"[a-z]", low) and re.search(r"\d", low):
            if low in allowed or low in GENERIC or low in ids or IP_RE.fullmatch(low):
                continue
            if BENIGN_RE.fullmatch(low):
                continue
            errs.append("unseen_entity:" + tok[:40])
    return sorted(set(errs))

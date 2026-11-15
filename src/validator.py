"""Output gate. The report is shown only if every check passes."""
import re

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._$-]*[A-Za-z0-9$]")
BENIGN_RE = re.compile(
    r"\d+(\.\d+)?-?(seconds?|secs?|minutes?|mins?|hours?|hrs?|days?|weeks?|s|h|d|m|x|st|nd|rd|th)"  # 5-minute, 24h, 3rd
    r"|\d{4}-\d{2}-\d{2}(t\d{2}([\d:.]*)z?)?"                                                     # 2026-11-12T13
    r"|\d{1,2}(\.\d+)?z"                                                                        # 00Z tail of a timestamp
    r"|(event|id|tier|code)-?\d+")
# Numbers the narrative may always use: the Windows event IDs this agent reads.
KNOWN_NUMBERS = {4625.0, 4771.0, 4776.0, 4740.0, 4723.0, 4724.0, 4767.0}
NUM_RE = re.compile(r"(?<![\w.])\d+(?:\.\d+)?")
CLOCK_RE = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b")
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
STAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[Tt ]\d{2}(?::\d{2}){0,2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})?")
HEX_RE = re.compile(r"\b0x[0-9a-f]+\b", re.I)
# Advice and claims the narrative must never contain, whatever the model was told or tricked into.
FORBIDDEN = [
    ("policy_bypass_advice", re.compile(
        r"\b(disabl\w*|turn(ing|ed)? off|switch(ing|ed)? off|bypass\w*|circumvent\w*|work(ing)? around|exempt\w*|exclu\w+|"
        r"whitelist\w*|allow-?list\w*|remov\w+|relax\w*|loosen\w*|rais\w+)\b[^.]{0,60}"
        r"\b(mfa|multi-?factor|two-?factor|conditional access|access polic\w+|lockout|restriction\w*|monitoring|detection|guardrail\w*)", re.I)),
    ("policy_bypass_advice", re.compile(
        r"\b(mfa|multi-?factor|two-?factor|conditional access|access polic\w+|lockout( polic\w+)?|restriction\w*|monitoring|detection|guardrail\w*)\b"
        r"[^.]{0,40}\b(be |been |get |gets |is |are )?(disabled|turned off|switched off|removed|bypassed|circumvented|excluded|exempt(ed)?|"
        r"relaxed|loosened|whitelisted|allow-?listed)\b", re.I)),
    ("threshold_disclosure", re.compile(r"\b(lockout|lock-out)\s+(threshold|limit|count)|\battempts?\s+(before|until)\b[^.]{0,30}\block", re.I)),
    ("claims_action_taken", re.compile(r"\b(i|we)\s+(have|'ve|will|can|could|am going to)\s+\w*\s*(unlock\w*|reset\w*|re-?enabl\w*|chang\w+|fix\w*|block\w*)", re.I)),
    ("compromise_verdict", re.compile(r"\b(compromised|hacked|breach(ed)?|pwned|stolen)\b", re.I)),
    ("prompt_artifacts", re.compile(r"\b(ignore|disregard)\b[^.]{0,20}\b(previous|prior|above)\b[^.]{0,20}\binstructions?\b|"
                                    r"\b(admin|developer|debug) mode\b|\bsystem prompt\b|\bas an ai\b", re.I)),
    ("credential_request", re.compile(r"\b(send|share|tell|give|provide|enter|type|reply with|confirm)\b[^.]{0,30}\b(your|the)\s+(password|passcode|pin|mfa code|verification code)", re.I)),
]
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
    errs += _number_errors(text, facts, allowed)
    errs += ["forbidden:" + name for name, rx in FORBIDDEN if rx.search(text)]
    return sorted(set(errs))


def _facts_numbers(node, out):
    """Every number the evidence contains, plus whole-percent forms of fractions."""
    if isinstance(node, bool) or node is None:
        return
    if isinstance(node, (int, float)):
        out.add(float(node))
        if 0 < node < 1:
            out.add(float(round(node * 100)))
    elif isinstance(node, str):
        if re.fullmatch(r"\d+(\.\d+)?", node):
            out.add(float(node))
    elif isinstance(node, dict):
        for v in node.values():
            _facts_numbers(v, out)
    elif isinstance(node, (list, tuple)):
        for v in node:
            _facts_numbers(v, out)


def _number_errors(text, facts, allowed_entities):
    """A number in the narrative must come from the evidence. Catches invented counts, times and dates."""
    import json
    from datetime import datetime
    blob = json.dumps(facts)
    errs = []
    for m in STAMP_RE.findall(text):                 # full timestamps must match the evidence to the second given
        if m.upper().replace(" ", "T").rstrip("Z") not in blob:
            errs.append("unseen_time:" + m)
    rest = STAMP_RE.sub(" ", text)
    for m in CLOCK_RE.findall(rest):
        if m not in blob:
            errs.append("unseen_time:" + m)
    for m in DATE_RE.findall(rest):
        if m not in blob:
            errs.append("unseen_date:" + m)
    scrub = rest.lower()
    for ent in sorted(allowed_entities, key=len, reverse=True):      # host names, addresses and codes carry digits
        scrub = scrub.replace(ent, " ")
    scrub = HEX_RE.sub(" ", CLOCK_RE.sub(" ", DATE_RE.sub(" ", IP_RE.sub(" ", scrub))))
    scrub = re.sub(r"[a-z][a-z0-9_$-]*\d[\w$-]*", " ", scrub)        # entity-like tokens are judged by the entity check
    numbers = set(KNOWN_NUMBERS)
    _facts_numbers(facts, numbers)
    try:
        w = facts["window"]
        hours = (datetime.fromisoformat(w["end"]) - datetime.fromisoformat(w["start"])).total_seconds() / 3600
        numbers.update({float(round(hours)), float(round(hours / 24, 1))})
    except (KeyError, ValueError, TypeError):
        pass
    for m in NUM_RE.findall(scrub):
        if float(m) not in numbers:
            errs.append("unseen_number:" + m)
    return errs

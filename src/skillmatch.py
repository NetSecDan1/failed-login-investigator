"""Deterministic skill matching. Code decides which skills the model is allowed to choose from.

Each skill ships a rules.json next to its SKILL.md:
  require        condition that must hold for the skill to be eligible
  exclude        optional condition that removes eligibility
  mandatory_when optional condition; when it holds the report must use a mandatory skill
  support        list of {"label", "cond", "weight"} used only to order eligible skills
  next_steps     approved step templates, rendered by code (never written by the model)

Condition grammar:
  {"signal": name, "op": one of == != >= <= > <, "value": number|bool|string}
  {"all": [cond, ...]}   {"any": [cond, ...]}   {"not": cond}   {"always": true}
A signal that is missing or null makes its comparison false. Nothing here is probabilistic.
"""
import operator

OPS = {"==": operator.eq, "!=": operator.ne, ">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt}
FALLBACK = "insufficient-evidence"
MAX_FULL_TEXT = 4


def holds(cond, signals):
    if not isinstance(cond, dict) or len(cond) == 0:
        raise ValueError("bad condition")
    if "always" in cond:
        return bool(cond["always"])
    if "all" in cond:
        return all(holds(c, signals) for c in cond["all"])
    if "any" in cond:
        return any(holds(c, signals) for c in cond["any"])
    if "not" in cond:
        return not holds(cond["not"], signals)
    value = signals.get(cond["signal"])
    if value is None:
        return False
    if isinstance(value, bool) != isinstance(cond["value"], bool):
        return False
    return OPS[cond["op"]](value, cond["value"])


def signal_names(cond):
    if "signal" in cond:
        return {cond["signal"]}
    out = set()
    for key in ("all", "any"):
        for c in cond.get(key, []):
            out |= signal_names(c)
    if "not" in cond:
        out |= signal_names(cond["not"])
    return out


def match(signals, rules_by_id):
    """Return {"eligible": [...ordered...], "must_escalate": bool, "detail": {id: {...}}}."""
    detail, eligible = {}, []
    for sid, r in rules_by_id.items():
        ok = holds(r["require"], signals) and not (r.get("exclude") and holds(r["exclude"], signals))
        met = [s["label"] for s in r.get("support", []) if holds(s["cond"], signals)]
        unmet = [s["label"] for s in r.get("support", []) if s["label"] not in met]
        score = sum(s.get("weight", 1) for s in r.get("support", []) if s["label"] in met)
        mandatory = bool(ok and r.get("mandatory_when") and holds(r["mandatory_when"], signals))
        detail[sid] = {"eligible": ok, "mandatory": mandatory, "score": score, "support_met": met, "support_unmet": unmet}
        if ok:
            eligible.append(sid)
    eligible.sort(key=lambda i: (not detail[i]["mandatory"], i == FALLBACK, -detail[i]["score"],
                                 -rules_by_id[i].get("priority", 0), i))
    if FALLBACK not in eligible:
        eligible.append(FALLBACK)
    return {"eligible": eligible, "must_escalate": any(d["mandatory"] for d in detail.values()), "detail": detail}


def allowed_choices(result):
    """What the model may pick. When escalation is mandatory, only the mandatory skills."""
    if result["must_escalate"]:
        return [i for i in result["eligible"] if result["detail"].get(i, {}).get("mandatory")]
    return list(result["eligible"])


def render_steps(rules, facts):
    """Approved next steps with evidence values filled in by code."""
    ad, en = facts["ad"], facts["entra"]

    def first(items, bad=("(blank)", "(not-a-hostname)", "(unreadable)", "(not-an-ip)")):
        for x in items:
            if x["value"] and x["value"] not in bad:
                return x["value"]
        return None

    values = {
        "top_host": first(ad["by_source_host"]) or "the source host shown in the facts",
        "lockout_caller": first(ad["lockout_callers"]) or "the lockout source shown in the facts",
        "top_client_app": first(en["by_client_app"]) or "the client shown in the facts",
        "top_app": first(en.get("by_app", [])) or "the application shown in the facts",
        "account": facts["account"],
    }
    out = []
    for step in rules.get("next_steps", []):
        text = step
        for k, v in values.items():
            text = text.replace("{%s}" % k, v)
        out.append(text)
    return out

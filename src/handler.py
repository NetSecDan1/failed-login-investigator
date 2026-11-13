"""Failed Login Investigator - prototype handler (read-only).

Pipeline: authenticate(stub) -> scope -> validate request -> collect -> findings
          -> model explain -> validate output -> render + audit.
Everything except explain() is deterministic code. No write path to any identity system.
"""
import hashlib, json, os, time
from datetime import datetime, timedelta, timezone

import scope, evidence, findings, explain, validator, skillmatch

MAX_WINDOW_HOURS = 168


def _parse_window(event):
    try:
        hours = int(event.get("window_hours", 24))
    except (TypeError, ValueError):
        hours = 0
    if not 1 <= hours <= MAX_WINDOW_HOURS:
        raise scope.Denied("window_out_of_range", "Window must be 1 to 168 hours.")
    end = event.get("end")
    try:
        end = datetime.fromisoformat(end.replace("Z", "+00:00")) if end else datetime.now(timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
    except (AttributeError, ValueError):
        raise scope.Denied("bad_window", "End time is not valid.")
    return end - timedelta(hours=hours), end


def _claims(event):
    jwt = (((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt") or {}).get("claims")
    if isinstance(jwt, dict):
        return jwt
    if os.environ.get("ALLOW_TEST_CLAIMS", "false").lower() == "true":
        return event.get("claims") or {}
    return {}


def _request(event):
    """HTTP API events carry the request as a JSON string in body. Direct invokes pass fields."""
    body = event.get("body")
    if isinstance(body, str):
        try:
            parsed = json.loads(body)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return event


def _audit(rec):
    rec["ts"] = datetime.now(timezone.utc).isoformat()
    print("AUDIT " + json.dumps(rec, sort_keys=True))


def handler(event, context=None, store=None, model=None):
    t0 = time.time()
    store = store or evidence.S3Store(os.environ["DATA_BUCKET"])
    audit = {"request_id": getattr(context, "aws_request_id", "local"), "outcome": "error"}
    try:
        # 1. Authenticate. Claims come from the API Gateway JWT authorizer. Claims passed in the
        #    event body are honoured only when ALLOW_TEST_CLAIMS=true (prototype and tests).
        claims = _claims(event)
        caller = scope.caller_id(claims)
        audit["caller"] = caller

        # 2. Scope from the ownership export (stands in for IIQ). Fails closed.
        scope_set, account_meta = scope.resolve_scope_meta(caller, store)
        audit["scope_hash"] = hashlib.sha256(",".join(sorted(scope_set)).encode()).hexdigest()[:16]

        # 3. Request validation. Account must be well formed AND in scope.
        req = _request(event)
        account = scope.check_account(req.get("account"), scope_set)
        start, end = _parse_window(req)
        audit.update(account=account, window=[start.isoformat(), end.isoformat()])

        # 4. Collect. Every tool re-checks scope itself.
        pack = evidence.collect(account, start, end, scope_set, store)
        audit["query_ids"] = pack["query_ids"]

        # 5. Findings (all numbers computed here, never by the model).
        facts = findings.compute(account, start, end, pack, account_meta.get(account))

        # 6. Code decides which skills the evidence can support, and renders their approved steps.
        skills = explain.load_skills(store)
        matched = skillmatch.match(facts["signals"], skills["rules"])
        choices = skillmatch.allowed_choices(matched)
        steps_by_id = {sid: skillmatch.render_steps(skills["rules"][sid], facts) for sid in choices}

        # 7. The model picks among the allowed choices and writes the narrative. One retry, then facts only.
        report, notes, meta = None, [], {}
        for attempt in (1, 2):
            raw, meta = (model or explain.call_model)(facts, skills, matched, steps_by_id)
            if raw is None:
                notes.append("summary_withheld:" + meta.get("reason", "model_unavailable"))
                break
            errors = validator.validate(raw, facts, skills, pack["query_ids"], choices, steps_by_id)
            if not errors:
                cid = raw["classification_id"]
                report = {"classification_id": cid, "title": skills["rules"][cid]["title"],
                          "confidence": raw["confidence"], "evidence_refs": raw["evidence_refs"],
                          "narrative": raw["narrative"],
                          "next_steps": [steps_by_id[cid][i - 1] for i in raw["next_step_ids"]],
                          "escalate": bool(skills["rules"][cid].get("escalate"))}
                break
            notes.append("validator_reject_%d:%s" % (attempt, ";".join(errors)[:300]))
        candidates = {"allowed": choices, "must_escalate": matched["must_escalate"]}
        audit.update(outcome="report" if report else "facts_only", model=meta.get("model"),
                     guardrail=meta.get("guardrail"), tokens=meta.get("tokens"), notes=notes,
                     classification=(report or {}).get("classification_id"), candidates=candidates,
                     skills_version=skills["version"])
        # must_escalate is decided by code, so the caller sees it even when the summary is withheld.
        return {"status": "ok", "account": account, "facts": facts, "candidates": candidates,
                "must_escalate": matched["must_escalate"], "report": report,
                "notes": notes, "ms": int((time.time() - t0) * 1000)}
    except scope.Denied as d:
        audit.update(outcome="denied", reason=d.code)
        return {"status": "denied", "reason": d.code, "message": d.message}
    finally:
        _audit(audit)

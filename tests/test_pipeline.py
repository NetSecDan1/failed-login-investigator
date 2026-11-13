import json, os, sys, glob
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import handler, evidence, validator, findings, scope
os.environ["ALLOW_TEST_CLAIMS"] = "true"

ROOT = os.path.join(os.path.dirname(__file__), "..", "data")
D = {os.path.relpath(p, ROOT).replace(os.sep, "/"): open(p).read()
     for p in glob.glob(ROOT + "/**/*", recursive=True) if os.path.isfile(p)}
STORE = evidence.DictStore(D)
END = "2026-11-12T18:00:00Z"
CALLS = []

def ev(emp, acct, **kw):
    return dict({"claims": {"employee_id": emp}, "account": acct, "window_hours": 24, "end": END}, **kw)

def good_model(facts, skills):
    CALLS.append(facts["account"])
    host = facts["ad"]["by_source_host"][0]["value"]
    return ({"classification_id": "stale-credential", "confidence": "high", "evidence_refs": facts["query_ids"][:2],
             "narrative": "Failures come from %s after the password change." % host,
             "next_steps": ["Update the stored password for this account on %s." % host], "escalate": False}, {"model": "fake"})

def lying_model(facts, skills):
    return ({"classification_id": "stale-credential", "confidence": "high", "evidence_refs": facts["query_ids"][:1],
             "narrative": "Host DC-SECRET99 at 172.16.5.5 is safe.", "next_steps": [], "escalate": False}, {"model": "fake"})

def boom_store():
    class S:
        def get(self, k): raise RuntimeError("iiq down")
    return S()

def run(e, model=good_model, store=STORE):
    return handler.handler(e, None, store=store, model=model)

def test_owner_gets_report():
    r = run(ev("E1001", "svc-batch01"))
    assert r["status"] == "ok" and r["report"]["classification_id"] == "stale-credential"
    ad = r["facts"]["ad"]
    assert ad["by_source_host"][0]["value"] == "APP-BATCH07" and ad["top_source_share"] >= 0.8
    assert ad["after_password_change"]["minutes_to_first_failure"] < 60
    assert ad["cadence"]["regular"] is True and ad["lockout_count"] == 3 and ad["external_source_ips"] == []

def test_non_owner_denied_before_any_read():
    CALLS.clear()
    class Spy(evidence.DictStore):
        seen = []
        def get(self, k): self.seen.append(k); return super().get(k)
    s = Spy(D)
    r = run(ev("E1001", "svc-payroll"), store=s)
    assert r == {"status": "denied", "reason": "out_of_scope", "message": "You can only investigate accounts you own."}
    assert s.seen == ["ownership/ownership.json"] and CALLS == []

def test_nonexistent_same_answer_as_unowned():
    assert run(ev("E1001", "svc-doesnotexist"))["reason"] == run(ev("E1001", "svc-payroll"))["reason"]

def test_tier0_and_denylist_excluded():
    assert run(ev("E1001", "da-e1001-t0"))["reason"] == "out_of_scope"
    assert run(ev("E1001", "svc-breakglass"))["reason"] == "out_of_scope"

def test_unknown_or_empty_caller_and_missing_claims():
    assert run(ev("E9999", "svc-batch01"))["reason"] == "scope_empty"
    assert run(ev("E3003", "svc-batch01"))["reason"] == "scope_empty"
    assert run({"account": "svc-batch01"})["reason"] == "unauthenticated"
    assert run(ev("E1001'; DROP", "svc-batch01"))["reason"] == "unauthenticated"

def test_ownership_source_down_fails_closed():
    assert run(ev("E1001", "svc-batch01"), store=boom_store())["reason"] == "ownership_unavailable"

def test_template_injection_rejected():
    for bad in ['svc-batch01" OR user=*', "svc-batch01|delete", "*", "", None, "a" * 65, "svc batch"]:
        assert run(ev("E1001", bad))["reason"] == "bad_account", bad

def test_case_insensitive_account():
    assert run(ev("E1001", "SVC-Batch01"))["status"] == "ok"

def test_window_cap():
    assert run(ev("E1001", "svc-batch01", window_hours=169))["reason"] == "window_out_of_range"
    assert run(ev("E1001", "svc-batch01", window_hours=0))["reason"] == "window_out_of_range"

def test_tool_rechecks_scope():
    from datetime import datetime, timezone
    t = datetime(2026, 11, 12, tzinfo=timezone.utc)
    try:
        evidence.get_failed_logins("svc-payroll", t, t, frozenset({"svc-batch01"}), STORE); assert False
    except scope.Denied as d:
        assert d.code == "out_of_scope"

def test_invented_entity_rejected_then_facts_only():
    r = run(ev("E1001", "svc-batch01"), model=lying_model)
    assert r["status"] == "ok" and r["report"] is None and len(r["notes"]) == 2
    assert "unseen_entity:DC-SECRET99" in r["notes"][0] and "unseen_ip:172.16.5.5" in r["notes"][0]

def test_injection_text_is_capped_and_spray_facts():
    r = run(ev("E1001", "svc-web02"), model=lambda f, s: (None, {"reason": "skip"}))
    ad = r["facts"]["ad"]
    assert r["report"] is None and ad["distinct_source_hosts"] > 5 and len(ad["external_source_ips"]) == 3
    blob = json.dumps(r["facts"])
    assert "DC-SECRET99" not in blob and "IGNORE" not in blob and "(not-a-hostname)" in blob
    assert r["facts"]["entra"]["total_failures"] == 9

def test_missing_source_reported_as_gap():
    r = run(ev("E1001", "svc-quiet03"), model=lambda f, s: (None, {"reason": "skip"}))
    assert r["status"] == "ok" and len(r["facts"]["gaps"]) == 3 and r["facts"]["ad"]["total_failures"] == 0

def test_deterministic_findings():
    a = run(ev("E1001", "svc-batch01"))["facts"]; b = run(ev("E1001", "svc-batch01"))["facts"]
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

def test_escalate_must_match_skill():
    def m(f, s):
        rep, meta = good_model(f, s); rep["classification_id"] = "possible-spray-escalate"; return rep, meta
    assert run(ev("E1001", "svc-batch01"), model=m)["report"] is None

def test_body_claims_ignored_unless_test_mode():
    os.environ["ALLOW_TEST_CLAIMS"] = "false"
    try:
        assert run(ev("E1001", "svc-batch01"))["reason"] == "unauthenticated"
    finally:
        os.environ["ALLOW_TEST_CLAIMS"] = "true"

def test_jwt_authorizer_claims_win_and_http_body_is_parsed():
    os.environ["ALLOW_TEST_CLAIMS"] = "false"
    try:
        e = {"requestContext": {"authorizer": {"jwt": {"claims": {"employee_id": "E2002"}}}},
             "claims": {"employee_id": "E1001"},
             "body": json.dumps({"account": "svc-batch01", "window_hours": 24, "end": END})}
        assert run(e)["reason"] == "out_of_scope"      # E2002 does not own svc-batch01; body claim ignored
        e["body"] = json.dumps({"account": "svc-payroll", "window_hours": 24, "end": END})
        assert run(e, model=lambda f, s: (None, {"reason": "skip"}))["status"] == "ok"
    finally:
        os.environ["ALLOW_TEST_CLAIMS"] = "true"

def test_bad_window_inputs_are_denied_not_crashes():
    assert run(ev("E1001", "svc-batch01", window_hours="abc"))["reason"] == "window_out_of_range"
    assert run(ev("E1001", "svc-batch01", end="yesterday"))["reason"] == "bad_window"
    assert run(ev("E1001", "svc-batch01", end=12345))["reason"] == "bad_window"

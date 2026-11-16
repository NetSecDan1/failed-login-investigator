"""The deployment stage guard: which configurations may run at all, and one public answer for every not-yours case."""
import json
import pytest
from conftest import STORE, ev, no_model
import handler, stage

LIVE = {"failed_logins": ("splunk",), "account_events": ("splunk",), "entra_failures": ("loganalytics", "graph")}
SYNTH = {k: ("file",) for k in LIVE}


def ok(env, shape="function", routes=LIVE):
    return stage.evaluate(env, shape, routes)


def rule(env, shape="function", routes=LIVE):
    with pytest.raises(stage.NotPermitted) as e:
        stage.evaluate(env, shape, routes)
    return e.value.rule


def test_development_is_synthetic_data_only():
    assert ok({}, routes=SYNTH) == ("development", [])
    assert rule({}) == "live_evidence_needs_integration_or_production_stage"
    assert rule({"DEPLOYMENT_STAGE": "development", "MODEL_ROUTE": "gateway"}) == "live_evidence_needs_integration_or_production_stage"
    assert rule({"DEPLOYMENT_STAGE": "prod"}) == "unknown_deployment_stage"


def test_live_evidence_only_meets_a_model_through_the_governed_route():
    base = {"DEPLOYMENT_STAGE": "integration"}
    assert rule(base) == "model_must_use_the_governed_route"                       # the default route is the direct one
    assert rule(dict(base, MODEL_ROUTE="bedrock")) == "model_must_use_the_governed_route"
    assert ok(dict(base, MODEL_ROUTE="gateway")) == ("integration", [])
    assert ok(dict(base, MODEL_ROUTE="off")) == ("integration", [])
    assert ok(dict(base, MODEL_ROUTE="bedrock", MODEL_ROUTE_EXCEPTION="RISK-42")) == ("integration", ["model_route:RISK-42"])
    assert ok(dict(base, MODEL_ROUTE="bedrock"), routes=SYNTH) == ("integration", [])   # synthetic data may use any route


@pytest.mark.parametrize("flag", ["true", "yes", "1", "x", "approved", "ok; rm -rf 1", "a1" * 45, "CHG 1001"])
def test_an_exception_is_an_approval_reference_never_a_bare_flag(flag):
    env = {"DEPLOYMENT_STAGE": "integration", "MODEL_ROUTE": "bedrock", "MODEL_ROUTE_EXCEPTION": flag}
    assert rule(env) == "model_route_exception_is_not_an_approval_reference"
    assert rule(dict(env, MODEL_ROUTE_EXCEPTION="")) == "model_must_use_the_governed_route"


def test_production_is_the_managed_runtime_and_the_governed_route():
    prod = {"DEPLOYMENT_STAGE": "production", "MODEL_ROUTE": "gateway"}
    assert ok(prod, "agent") == ("production", [])
    assert rule(prod, "function") == "production_runs_on_the_managed_agent_runtime"
    assert ok(dict(prod, FUNCTION_RUNTIME_EXCEPTION="CHG-1001"), "function") == ("production", ["function_runtime:CHG-1001"])
    assert rule(dict(prod, MODEL_ROUTE="bedrock"), "agent") == "model_must_use_the_governed_route"
    assert rule(dict(prod, ALLOW_TEST_CLAIMS="true"), "agent") == "test_claims_in_production"
    assert rule(prod, "agent", routes=dict(LIVE, account_events=("file",))) == "synthetic_evidence_in_production"
    assert rule(prod, "agent", routes=SYNTH) == "synthetic_evidence_in_production"


def audit_line(capsys):
    return json.loads([l for l in capsys.readouterr().out.splitlines() if l.startswith("AUDIT ")][-1][6:])


def test_a_configuration_that_is_not_permitted_refuses_before_identity_or_data(monkeypatch, capsys):
    monkeypatch.setenv("EVIDENCE_BACKEND", "splunk")                                   # live source, development stage
    class NoTouch:
        def get(self, key):
            raise AssertionError("the store was read: " + key)
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=NoTouch(), model=no_model)
    assert (r["status"], r["reason"]) == ("denied", "not_permitted") and "splunk" not in json.dumps(r)
    a = audit_line(capsys)
    assert a["stage_rule"] == "live_evidence_needs_integration_or_production_stage" and "caller" not in a


def test_the_agent_entry_point_declares_its_shape_and_exceptions_reach_the_audit_line(monkeypatch, capsys):
    monkeypatch.setenv("DEPLOYMENT_STAGE", "production"); monkeypatch.setenv("MODEL_ROUTE", "gateway")
    monkeypatch.setenv("EVIDENCE_BACKEND", "none"); monkeypatch.setenv("ALLOW_TEST_CLAIMS", "false")
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=STORE, model=no_model)
    assert r["reason"] == "not_permitted" and audit_line(capsys)["stage_rule"] == "production_runs_on_the_managed_agent_runtime"
    monkeypatch.setenv("FUNCTION_RUNTIME_EXCEPTION", "CHG-1001")
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=STORE, model=no_model)
    a = audit_line(capsys)
    assert a["stage"] == "production" and a["stage_exceptions"] == ["function_runtime:CHG-1001"] and r["reason"] == "unauthenticated"
    monkeypatch.delenv("FUNCTION_RUNTIME_EXCEPTION")
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=STORE, model=no_model, shape="agent")
    assert r["reason"] == "unauthenticated" and "stage_exceptions" not in audit_line(capsys)   # past the guard, stopped by identity


def test_model_route_off_gives_facts_only():
    import modelroute, os
    os.environ["MODEL_ROUTE"] = "off"
    try:
        assert modelroute.call_report("s", "u", {}) == (None, {"model": None, "route": "off", "reason": "model_off"})
    finally:
        del os.environ["MODEL_ROUTE"]


# ---------- one answer for every "not yours" case ----------

NOT_YOURS = ["svc-payroll01",            # real, owned by someone else
             "svc-does-not-exist",       # well formed, no such account
             "bad name", "", "x" * 200,  # malformed
             "svc-batch01\" OR 1=1"]     # hostile


def public(result):
    return {k: v for k, v in result.items() if k != "reference"}


def test_a_caller_cannot_tell_unowned_from_nonexistent_from_malformed(capsys):
    answers, reasons = [], set()
    for account in NOT_YOURS + [None, 7, ["svc-batch01"]]:
        answers.append(json.dumps(public(handler.handler(ev("E1001", account), None, store=STORE, model=no_model)), sort_keys=True))
        reasons.add(audit_line(capsys)["reason"])
    assert len(set(answers)) == 1 and json.loads(answers[0])["reason"] == "out_of_scope"
    assert reasons == {"bad_account", "out_of_scope"}                                  # the audit line still knows the difference


def test_the_http_answer_is_identical_too():
    def http(account):
        e = dict(ev("E1001", account), requestContext={"http": {"method": "POST"}}, routeKey="POST /investigations")
        r = handler.handler(e, None, store=STORE, model=no_model)
        body = json.loads(r["body"]); body.pop("reference")
        return r["statusCode"], r["headers"], body
    first = http(NOT_YOURS[0])
    assert first[0] == 403 and all(http(a) == first for a in NOT_YOURS[1:])

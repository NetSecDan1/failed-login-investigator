"""Model route, limits, usage accounting, metrics, kill switch, ownership freshness and conflicts, cost report."""
import importlib.util, json, os
from datetime import datetime, timedelta, timezone
import pytest
from conftest import ROOT, STORE, FILES, ev, top_choice_model
import evidence, explain, handler, modelroute


def run(e, model=top_choice_model, store=STORE):
    return handler.handler(e, None, store=store, model=model)


def audit_of(capsys):
    lines = capsys.readouterr().out.splitlines()
    return [json.loads(x[6:]) for x in lines if x.startswith("AUDIT ")], [json.loads(x) for x in lines if x.startswith('{"')]


# ---------- gateway model route ----------

class Gateway:
    def __init__(self, status=200, body=None, boom=None):
        self.status, self.body, self.boom, self.calls = status, body, boom, []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"url": url, "headers": headers, "body": json.loads(body), "timeout": timeout})
        if self.boom:
            raise self.boom
        return self.status, json.dumps(self.body).encode() if self.body is not None else b"not json"


def completion(args, finish="tool_calls"):
    return {"choices": [{"finish_reason": finish, "message": {"tool_calls": [
        {"type": "function", "function": {"name": "submit_report", "arguments": json.dumps(args)}}]}}],
        "usage": {"prompt_tokens": 3100, "completion_tokens": 240}}


@pytest.fixture
def gw(monkeypatch):
    monkeypatch.setenv("MODEL_ROUTE", "gateway")
    monkeypatch.setenv("MODEL_GATEWAY_URL", "https://models.example.test/v1")
    monkeypatch.setenv("MODEL_GATEWAY_TOKEN", "s3cr3t-gw")
    monkeypatch.setenv("MODEL_ID", "some-model")
    monkeypatch.setenv("MODEL_MAX_OUTPUT_TOKENS", "700")


def test_gateway_request_shape_limits_and_usage(gw):
    t = Gateway(body=completion({"classification_id": "x"}))
    out, meta = modelroute.call_report("SYS", "USER", explain.REPORT_SCHEMA, transport=t)
    sent = t.calls[0]
    assert sent["url"] == "https://models.example.test/v1/chat/completions" and sent["headers"]["Authorization"] == "Bearer s3cr3t-gw"
    assert sent["body"]["max_tokens"] == 700 and sent["body"]["temperature"] == 0
    assert sent["body"]["tool_choice"] == {"type": "function", "function": {"name": "submit_report"}}
    assert sent["body"]["messages"][0] == {"role": "system", "content": "SYS"}
    assert out == {"classification_id": "x"} and meta["tokens"] == {"inputTokens": 3100, "outputTokens": 240} and meta["route"] == "gateway"


@pytest.mark.parametrize("t,reason", [
    (Gateway(status=429, body={}), "model_error"), (Gateway(boom=TimeoutError("slow")), "model_error"),
    (Gateway(body=None), "model_error"), (Gateway(body=completion({}, finish="content_filter")), "guardrail_intervened"),
    (Gateway(body={"choices": [{"finish_reason": "stop", "message": {"content": "free text, no tool call"}}]}), "no_report_returned")])
def test_gateway_failures_never_raise(gw, t, reason):
    out, meta = modelroute.call_report("S", "U", explain.REPORT_SCHEMA, transport=t)
    assert out is None and meta["reason"].startswith(reason) and "s3cr3t-gw" not in json.dumps(meta)


def test_gateway_requires_https_and_unknown_route_is_refused(gw, monkeypatch):
    monkeypatch.setenv("MODEL_GATEWAY_URL", "http://models.example.test/v1")
    assert modelroute.call_report("S", "U", {}, transport=Gateway())[1]["reason"] == "model_error:gateway_url_must_be_https"
    monkeypatch.setenv("MODEL_ROUTE", "somewhere-else")
    assert modelroute.call_report("S", "U", {})[1]["reason"] == "model_error:unknown_model_route"


def test_pipeline_end_to_end_through_the_gateway_route(gw, monkeypatch):
    t = Gateway(body=completion({"classification_id": "stale-credential", "confidence": "high", "narrative": "Failures come from APP-BATCH07.",
                                 "evidence_refs": ["file:evidence/svc-batch01.json#failed_logins"], "next_step_ids": [1, 4]}))
    monkeypatch.setattr(explain, "call_model", lambda f, s, m, st: modelroute.call_report(
        explain.SYSTEM, explain.build_user_text(f, s, m, st), explain.REPORT_SCHEMA, transport=t))
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=STORE)
    assert r["report"]["classification_id"] == "stale-credential" and len(r["report"]["next_steps"]) == 2
    assert "<evidence>" in t.calls[0]["body"]["messages"][1]["content"]


# ---------- usage, audit, metrics ----------

def test_audit_carries_cost_and_quality_fields_and_no_content(capsys):
    def m(f, s, matched, steps):
        rep, meta = top_choice_model(f, s, matched, steps)
        return rep, dict(meta, tokens={"inputTokens": 3000, "outputTokens": 200}, route="bedrock")
    run(ev("E1001", "svc-batch01"), model=m)
    a = audit_of(capsys)[0][0]
    assert (a["outcome"], a["tokens_in"], a["tokens_out"], a["model_calls"], a["validator_rejects"]) == ("report", 3000, 200, 1, 0)
    assert a["must_escalate"] is False and isinstance(a["latency_ms"], int) and a["route"] == "POST /investigations"
    assert "narrative" not in json.dumps(a) and "APP-BATCH07" not in json.dumps(a), "audit must not carry report text or hosts"


def test_retry_is_capped_at_two_calls_and_both_are_counted(capsys):
    calls = []
    def bad(f, s, matched, steps):
        calls.append(1)
        rep, meta = top_choice_model(f, s, matched, steps)
        rep["narrative"] = "Check SRV-INVENTED01."
        return rep, dict(meta, tokens={"inputTokens": 100, "outputTokens": 10})
    r = run(ev("E1001", "svc-batch01"), model=bad)
    a = audit_of(capsys)[0][0]
    assert len(calls) == 2 and r["report"] is None and (a["model_calls"], a["validator_rejects"], a["tokens_in"]) == (2, 2, 200)


def test_embedded_metrics_line(capsys, monkeypatch):
    monkeypatch.setenv("METRICS_EMF", "true")
    run(ev("E1001", "svc-web02"))
    _, metric_lines = audit_of(capsys)
    m = metric_lines[-1]
    assert m["_aws"]["CloudWatchMetrics"][0]["Namespace"] == "FailedLoginInvestigator"
    assert m["Outcome"] == "report" and m["Escalations"] == 1 and m["Reports"] == 1 and m["Requests"] == 1


# ---------- kill switch ----------

def test_kill_switch_stops_everything_before_identity_or_data(monkeypatch, capsys):
    monkeypatch.setenv("AGENT_ENABLED", "false")
    class NoTouch:
        def get(self, k): raise AssertionError("store must not be read when disabled")
    assert run(ev("E1001", "svc-batch01"), store=NoTouch())["reason"] == "disabled"
    e = dict(ev("E1001", "svc-batch01"), requestContext={"http": {"method": "POST"}})
    assert handler.handler(e, None, store=NoTouch())["statusCode"] == 503


# ---------- ownership freshness and conflicts ----------

def store_with(mutate):
    files = dict(FILES)
    own = json.loads(files["ownership/ownership.json"])
    mutate(own)
    files["ownership/ownership.json"] = json.dumps(own)
    return evidence.DictStore(files)


def test_stale_ownership_fails_closed_when_a_limit_is_set(monkeypatch):
    old = (datetime.now(timezone.utc) - timedelta(hours=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stale = store_with(lambda o: o.update(_generated=old))
    assert run(ev("E1001", "svc-batch01"), store=stale)["status"] == "ok"          # no limit set: prototype default
    monkeypatch.setenv("OWNERSHIP_MAX_AGE_HOURS", "24")
    assert run(ev("E1001", "svc-batch01"), store=stale)["reason"] == "ownership_stale"
    assert run(ev("E1001", "svc-batch01"), store=STORE)["status"] == "ok"          # fresh file passes
    assert run(ev("E1001", "svc-batch01"), store=store_with(lambda o: o.pop("_generated")))["reason"] == "ownership_stale"
    future = (datetime.now(timezone.utc) + timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert run(ev("E1001", "svc-batch01"), store=store_with(lambda o: o.update(_generated=future)))["reason"] == "ownership_stale"


def test_conflicting_ownership_records_resolve_to_most_restrictive():
    def conflict(o):
        o["owners"]["E2002"].append({"account": "svc-batch01", "tier": 0, "type": "privileged"})   # someone else's record says Tier 0
    assert run(ev("E1001", "svc-batch01"), store=store_with(conflict))["reason"] == "out_of_scope"


def test_co_owners_each_see_the_account():
    s = store_with(lambda o: o["owners"]["E2002"].append({"account": "svc-batch01", "tier": 2, "type": "service"}))
    assert run(ev("E2002", "svc-batch01"), store=s)["status"] == "ok" and run(ev("E1001", "svc-batch01"), store=s)["status"] == "ok"


# ---------- cost report ----------

def test_cost_report_from_audit_lines(capsys):
    spec = importlib.util.spec_from_file_location("cost_report", os.path.join(ROOT, "tools", "cost_report.py"))
    cr = importlib.util.module_from_spec(spec); spec.loader.exec_module(cr)
    def line(**k):
        return "2026-11-13T00:00:00 stream AUDIT " + json.dumps(dict({"route": "POST /investigations"}, **k))
    lines = [line(outcome="report", tokens_in=3000, tokens_out=200, model_calls=1, latency_ms=4000),
             line(outcome="report", tokens_in=3000, tokens_out=200, model_calls=1, latency_ms=6000, must_escalate=True),
             line(outcome="facts_only", tokens_in=6000, tokens_out=400, model_calls=2, validator_rejects=2),
             line(outcome="denied"), "noise", "AUDIT {broken", line(outcome="listed", route="GET /accounts")]
    s = cr.summarize(cr.parse(lines), in_price=3.0, out_price=15.0)
    assert (s["investigations_attempted"], s["successful_reports"], s["denied"]) == (3, 2, 1)
    assert s["tokens_in"] == 12000 and s["model_cost"] == 0.048 and s["cost_per_successful_investigation"] == 0.024
    assert s["success_rate"] == 0.667 and s["mandatory_escalations"] == 1 and s["validator_rejects"] == 2
    assert cr.summarize([], 3, 15)["cost_per_successful_investigation"] is None


# ---------- direct model route, with a scripted client in place of the cloud SDK ----------

class _FakeBedrock:
    def __init__(self, resp=None, boom=None):
        self.resp, self.boom, self.kwargs = resp, boom, None

    def converse(self, **kwargs):
        self.kwargs = kwargs
        if self.boom:
            raise self.boom
        return self.resp


def _direct(monkeypatch, client):
    import boto3, modelroute
    monkeypatch.setenv("MODEL_ROUTE", "bedrock"); monkeypatch.setenv("MODEL_ID", "test-model")
    monkeypatch.setenv("GUARDRAIL_ID", "g1"); monkeypatch.setenv("MODEL_MAX_OUTPUT_TOKENS", "321")
    monkeypatch.setattr(boto3, "client", lambda *a, **k: client)
    return modelroute.call_report("sys", "user", {"type": "object"})


def test_direct_route_forces_the_report_form_and_applies_limits_and_guardrail(monkeypatch):
    c = _FakeBedrock({"stopReason": "tool_use", "usage": {"inputTokens": 11, "outputTokens": 7},
                      "output": {"message": {"content": [{"toolUse": {"name": "submit_report", "input": {"a": 1}}}]}}})
    report, meta = _direct(monkeypatch, c)
    assert report == {"a": 1} and meta["tokens"] == {"inputTokens": 11, "outputTokens": 7} and meta["guardrail"] == "passed"
    assert c.kwargs["toolConfig"]["toolChoice"] == {"tool": {"name": "submit_report"}}
    assert c.kwargs["inferenceConfig"] == {"maxTokens": 321, "temperature": 0}
    assert c.kwargs["guardrailConfig"]["guardrailIdentifier"] == "g1"


def test_direct_route_guardrail_block_error_and_empty_answer_all_withhold(monkeypatch):
    blocked = _FakeBedrock({"stopReason": "guardrail_intervened", "usage": {}, "output": {"message": {"content": []}}})
    assert _direct(monkeypatch, blocked) == (None, {"model": "test-model", "route": "bedrock", "guardrail": "intervened",
                                                    "tokens": {"inputTokens": 0, "outputTokens": 0}, "reason": "guardrail_intervened"})
    report, meta = _direct(monkeypatch, _FakeBedrock(boom=RuntimeError("no access")))
    assert report is None and meta["reason"].startswith("model_error:RuntimeError")
    empty = _FakeBedrock({"stopReason": "end_turn", "usage": {}, "output": {"message": {"content": [{"text": "hi"}]}}})
    assert _direct(monkeypatch, empty)[1]["reason"] == "no_report_returned"

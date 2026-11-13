"""HTTP API event handling, routes, status codes, caller claim configuration, text rendering."""
import json, os
import pytest
from conftest import STORE, END, ev, no_model, top_choice_model
import handler, render


def http(route, claims, body=None):
    e = {"routeKey": route, "requestContext": {"http": {"method": route.split()[0]}, "authorizer": {"jwt": {"claims": claims}}}}
    if body is not None:
        e["body"] = json.dumps(body)
    return e


@pytest.fixture(autouse=True)
def locked_down(monkeypatch):
    monkeypatch.setenv("ALLOW_TEST_CLAIMS", "false")


def call(e, model=no_model):
    r = handler.handler(e, None, store=STORE, model=model)
    return r["statusCode"], json.loads(r["body"]), r["headers"]


def test_list_accounts_returns_only_owned_non_tier0():
    code, body, headers = call(http("GET /accounts", {"employee_id": "E1001"}))
    assert code == 200 and headers["cache-control"] == "no-store"
    assert [a["account"] for a in body["accounts"]] == ["svc-batch01", "svc-quiet03", "svc-web02"]
    assert all(a["type"] == "service" for a in body["accounts"])


def test_investigate_over_http():
    code, body, _ = call(http("POST /investigations", {"employee_id": "E1001"}, {"account": "svc-batch01", "window_hours": 24, "end": END}), top_choice_model)
    assert code == 200 and body["report"]["classification_id"] == "stale-credential"


@pytest.mark.parametrize("claims,body,code,reason", [
    ({}, {"account": "svc-batch01"}, 401, "unauthenticated"),
    ({"employee_id": "E1001"}, {"account": "svc-payroll"}, 403, "out_of_scope"),
    ({"employee_id": "E9999"}, {"account": "svc-batch01"}, 403, "scope_empty"),
    ({"employee_id": "E1001"}, {"account": "bad name"}, 400, "bad_account"),
    ({"employee_id": "E1001"}, {"account": "svc-batch01", "window_hours": 999}, 400, "window_out_of_range"),
    ({"employee_id": "E1001"}, None, 400, "bad_account"),
])
def test_http_status_codes(claims, body, code, reason):
    got, out, _ = call(http("POST /investigations", claims, body))
    assert (got, out["reason"]) == (code, reason)


def test_claims_in_the_body_cannot_impersonate():
    e = http("POST /investigations", {"employee_id": "E2002"}, {"account": "svc-batch01", "claims": {"employee_id": "E1001"}, "end": END})
    e["claims"] = {"employee_id": "E1001"}
    assert call(e)[1]["reason"] == "out_of_scope"


def test_unknown_route_is_refused():
    assert call(http("DELETE /accounts", {"employee_id": "E1001"}))[1]["reason"] == "bad_route"


def test_caller_claim_is_configurable_and_owner_keys_are_case_insensitive(monkeypatch):
    monkeypatch.setenv("CALLER_CLAIM", "preferred_username")
    files = dict(STORE.d)
    own = json.loads(files["ownership/ownership.json"])
    own["owners"]["Pat.Lee@Example.test"] = [{"account": "svc-batch01", "tier": 2, "type": "service"}]
    files["ownership/ownership.json"] = json.dumps(own)
    import evidence
    r = handler.handler(http("GET /accounts", {"preferred_username": "pat.lee@example.test", "employee_id": "E2002"}), None, store=evidence.DictStore(files))
    assert json.loads(r["body"])["accounts"] == [{"account": "svc-batch01", "type": "service"}]


def test_text_rendering(monkeypatch):
    monkeypatch.setenv("ALLOW_TEST_CLAIMS", "true")
    r = handler.handler(ev("E1001", "svc-web02"), None, store=STORE, model=top_choice_model)
    text = render.to_text(r)
    assert "ESCALATION REQUIRED" in text and "Contact the CSOC now" in text and "IGNORE" not in text
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=STORE, model=no_model)
    text = render.to_text(r)
    assert "No summary available" in text and "APP-BATCH07" in text and "kerberos bad password" in text
    assert render.to_text({"status": "denied", "reason": "out_of_scope", "message": "m"}).startswith("DENIED  out_of_scope")


def test_cli_runs_offline(capsys, monkeypatch):
    monkeypatch.delenv("EVIDENCE_BACKEND", raising=False)
    import importlib.util
    from conftest import ROOT
    spec = importlib.util.spec_from_file_location("investigate", os.path.join(ROOT, "tools", "investigate.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    assert mod.main(["--caller", "E5000", "--account", "ev-skew"]) == 0
    assert "kerberos-clock-skew" in capsys.readouterr().out
    assert mod.main(["--caller", "E1001", "--account", "svc-payroll"]) == 2
    assert mod.main(["--caller", "E1001", "--list"]) == 0
    assert "svc-web02" in capsys.readouterr().out

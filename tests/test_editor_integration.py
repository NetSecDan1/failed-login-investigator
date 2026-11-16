"""The editor integration: typed tools, no caller argument, synthetic-only local mode, thin service mode."""
import asyncio, importlib.util, json, os
import pytest
from conftest import ROOT, STORE

spec = importlib.util.spec_from_file_location("mcp_server", os.path.join(ROOT, "integrations", "mcp_server.py"))
srv = importlib.util.module_from_spec(spec); spec.loader.exec_module(srv)


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for k in ("FLI_MODE", "FLI_API_URL", "FLI_API_TOKEN", "MODEL_ID", "EVIDENCE_BACKEND", "EVIDENCE_SOURCES"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FLI_DEV_CALLER", "E1001")


def test_local_mode_runs_the_pipeline_on_synthetic_data():
    assert "svc-batch01" in srv.run({"action": "list_accounts"}, store=STORE)
    text = srv.run({"account": "svc-batch01", "window_hours": 24}, store=STORE)
    assert "APP-BATCH07" in text and "stale-credential" in text and "Reference to quote: INV-" in text
    assert text.endswith(srv.NOTE)
    assert "DENIED  out_of_scope" in srv.run({"account": "svc-payroll", "window_hours": 24}, store=STORE)


@pytest.mark.parametrize("env", [{"EVIDENCE_BACKEND": "splunk"}, {"EVIDENCE_SOURCES": "entra_failures=graph"},
                                 {"EVIDENCE_BACKEND": "file", "EVIDENCE_SOURCES": "failed_logins=export"}])
def test_local_mode_refuses_real_evidence_sources(env):
    with pytest.raises(SystemExit):
        srv.check_local_is_synthetic(env)


def test_local_mode_allows_synthetic_and_unconfigured_sources():
    srv.check_local_is_synthetic({})
    srv.check_local_is_synthetic({"EVIDENCE_BACKEND": "file", "EVIDENCE_SOURCES": "entra_failures=none"})


def test_tools_take_an_account_and_a_window_and_nothing_that_names_a_caller():
    pytest.importorskip("mcp.server.mcpserver")
    tools = {t.name: t.input_schema.get("properties", {}) for t in asyncio.run(srv.build_server().list_tools())}
    assert set(tools) == {"list_owned_accounts", "investigate"}
    assert set(tools["investigate"]) == {"account", "window_hours"} and tools["list_owned_accounts"] == {}


class Service:
    def __init__(self, status=200, body=None, boom=None):
        self.status, self.body, self.boom, self.calls = status, body, boom, []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        if self.boom:
            raise self.boom
        return self.status, json.dumps(self.body).encode()


def test_service_mode_sends_the_users_token_and_only_the_typed_request(monkeypatch):
    monkeypatch.setenv("FLI_MODE", "api"); monkeypatch.setenv("FLI_API_URL", "https://api.example.test/"); monkeypatch.setenv("FLI_API_TOKEN", "user-token")
    svc = Service(body={"status": "denied", "reason": "out_of_scope", "message": "You can only investigate accounts you own.", "reference": "INV-20261112-AAAAAAAA"})
    text = srv.run({"account": "svc-x", "window_hours": 6, "claims": {"employee_id": "E2002"}, "end": "x"}, transport=svc)
    call = svc.calls[0]
    assert (call["method"], call["url"]) == ("POST", "https://api.example.test/investigations")
    assert call["headers"]["Authorization"] == "Bearer user-token"
    assert json.loads(call["body"]) == {"account": "svc-x", "window_hours": 6}          # nothing else is forwarded
    assert "DENIED  out_of_scope" in text and "user-token" not in text
    srv.run({"action": "list_accounts"}, transport=svc)
    assert (svc.calls[1]["method"], svc.calls[1]["url"], svc.calls[1]["body"]) == ("GET", "https://api.example.test/accounts", None)


def test_service_mode_fails_safely(monkeypatch):
    monkeypatch.setenv("FLI_MODE", "api"); monkeypatch.setenv("FLI_API_TOKEN", "user-token")
    monkeypatch.setenv("FLI_API_URL", "http://api.example.test")
    svc = Service(body={})
    assert "not_configured" in srv.run({"action": "list_accounts"}, transport=svc) and svc.calls == []
    monkeypatch.setenv("FLI_API_URL", "https://api.example.test")
    assert "service_unreachable" in srv.run({"action": "list_accounts"}, transport=Service(boom=TimeoutError()))
    assert "unexpected_response" in srv.run({"action": "list_accounts"}, transport=Service(status=502, body={"message": "bad gateway"}))
    monkeypatch.delenv("FLI_API_TOKEN")
    svc = Service(body={})
    assert "unauthenticated" in srv.run({"action": "list_accounts"}, transport=svc) and svc.calls == []


def test_workspace_files_are_valid_and_point_at_real_things():
    cfg = json.load(open(os.path.join(ROOT, ".vscode", "mcp.json")))
    for server in cfg["servers"].values():
        assert server["type"] == "stdio" and os.path.isfile(os.path.join(ROOT, server["args"][0]))
    assert cfg["servers"]["investigator-synthetic"]["env"]["FLI_MODE"] == "local"
    assert "FLI_API_TOKEN" in cfg["servers"]["investigator-service"]["env"] and "token" not in json.dumps(cfg["servers"]).replace("fli-api-token", "").replace("FLI_API_TOKEN", "").lower()
    assert next(i for i in cfg["inputs"] if i["id"] == "fli-api-token")["password"] is True
    tasks = json.load(open(os.path.join(ROOT, ".vscode", "tasks.json")))["tasks"]
    labels = {t["label"] for t in tasks}
    for t in tasks:
        assert set(t.get("dependsOn", [])) <= labels
    for name in ("investigate", "add-skill", "add-source"):
        assert open(os.path.join(ROOT, ".github", "prompts", name + ".prompt.md")).read().startswith("---\ndescription:")

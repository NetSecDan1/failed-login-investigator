"""Splunk and Databricks backends against a fake transport. No network."""
import json, urllib.parse
from datetime import datetime, timedelta, timezone
import pytest
from conftest import STORE, ev, no_model
import backends, evidence, handler, scope

S = frozenset({"svc-batch01"})
T1 = datetime(2026, 11, 12, 18, tzinfo=timezone.utc)
T0 = T1 - timedelta(hours=24)
FM = backends.load_field_map()


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.setenv("SPLUNK_INDEX_WINDOWS", "wineventlog")
    monkeypatch.setenv("SPLUNK_INDEX_ENTRA", "azure_signin")
    for k in ("FAILED_LOGINS", "ACCOUNT_EVENTS", "ENTRA_FAILURES"):
        monkeypatch.setenv("DATABRICKS_VIEW_" + k, "sec.identity.v_" + k.lower())


class Fake:
    def __init__(self, status=200, body=b"", boom=None):
        self.status, self.body, self.boom, self.calls = status, body, boom, []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        if self.boom:
            raise self.boom
        return self.status, self.body


def splunk_lines(*results):
    return "\n".join(json.dumps({"preview": False, "result": r}) for r in results).encode()


def test_splunk_request_shape_and_normalization():
    t = Fake(body=splunk_lines(
        {"_time": "2026-11-12T04:05:03.000-05:00", "EventCode": "4771", "Failure_Code": "0x18", "Client_Address": "::ffff:10.20.30.41", "host": "DC01"},
        {"_time": "2026-11-12T04:00:00.000-05:00", "EventCode": "4625", "Status": "0xC000006D", "Sub_Status": "0xC000006A",
         "Workstation_Name": "APP-BATCH07", "Source_Network_Address": "10.20.30.41", "Logon_Type": "3", "dest": "DC02"},
        {"_time": "2026-11-12T04:10:00.000-05:00", "EventCode": "4776", "Error_Code": "0xC0000234", "Source_Workstation": "\\\\\\\\WKS-OPS112"},
        {"_time": "2026-11-12T04:20:00.000-05:00", "EventCode": "4625", "Status": "0xC0000234", "Sub_Status": "0x0", "Workstation_Name": ["A", "B"]}))
    b = backends.SplunkBackend("https://splunk.example.test:8089", "tok", FM, transport=t)
    out = b.query("failed_logins", "svc-batch01", T0, T1, S)
    call = t.calls[0]
    assert call["method"] == "POST" and call["url"] == "https://splunk.example.test:8089/services/search/jobs/export"
    assert call["headers"]["Authorization"] == "Bearer tok"
    form = urllib.parse.parse_qs(call["body"].decode())
    assert form["output_mode"] == ["json"] and 'user="svc-batch01"' in form["search"][0] and "index=wineventlog" in form["search"][0]
    rows = out["rows"]
    assert [r["time"] for r in rows] == ["2026-11-12T09:00:00Z", "2026-11-12T09:05:03Z", "2026-11-12T09:10:00Z", "2026-11-12T09:20:00Z"]
    assert rows[0] == {"time": "2026-11-12T09:00:00Z", "event_code": 4625, "failure_code": "0xC000006A", "src_host": "APP-BATCH07",
                       "src_ip": "10.20.30.41", "dc_host": "DC02", "logon_type": 3}
    assert rows[1]["src_ip"] == "10.20.30.41" and rows[1]["failure_code"] == "0x18"      # IPv6-mapped prefix stripped
    assert rows[2]["src_host"] == "WKS-OPS112"                                             # leading backslashes stripped
    assert rows[3]["failure_code"] == "0xC0000234" and rows[3]["src_host"] == "A"          # 0x0 skipped, multivalue first
    assert out["query_id"] == "splunk:failed_logins:svc-batch01" and "error" not in out


def test_splunk_scope_is_checked_before_any_request():
    t = Fake()
    b = backends.SplunkBackend("https://splunk.example.test:8089", "tok", FM, transport=t)
    with pytest.raises(scope.Denied):
        b.query("failed_logins", "svc-payroll", T0, T1, S)
    assert t.calls == []


@pytest.mark.parametrize("fake", [Fake(status=401, body=b"nope"), Fake(status=503), Fake(boom=TimeoutError("slow")),
                                  Fake(body=b"{not json")])
def test_source_failures_become_gaps_not_crashes(fake):
    b = backends.SplunkBackend("https://splunk.example.test:8089", "tok", FM, transport=fake)
    out = b.query("failed_logins", "svc-batch01", T0, T1, S)
    assert out["rows"] == [] and out["error"] == "source_unavailable" and "tok" not in json.dumps(out)


def test_rows_without_time_are_dropped_and_reported():
    t = Fake(body=splunk_lines({"EventCode": "4625"}, {"_time": "garbage", "EventCode": "4625"},
                               {"_time": "1794474000", "EventCode": "4625", "Sub_Status": "0xC000006A"}))
    out = backends.SplunkBackend("https://s.example.test", "tok", FM, transport=t).query("failed_logins", "svc-batch01", T0, T1, S)
    assert len(out["rows"]) == 1 and out["rows"][0]["time"].endswith("Z") and out["error"] == "rows_dropped_no_time:2"


def test_https_is_required():
    with pytest.raises(ValueError):
        backends.SplunkBackend("http://splunk.example.test:8089", "tok", FM)
    with pytest.raises(ValueError):
        backends.DatabricksBackend("http://dbx.example.test", "wh", "tok", FM)


def dbx_body(cols, data, state="SUCCEEDED", truncated=False):
    return json.dumps({"status": {"state": state}, "manifest": {"schema": {"columns": [{"name": c} for c in cols]}, "truncated": truncated},
                       "result": {"data_array": data}}).encode()


def test_databricks_uses_bound_parameters_and_normalizes():
    t = Fake(body=dbx_body(["event_time", "event_code", "failure_code", "src_host", "src_ip", "dc_host", "logon_type"],
                           [["2026-11-12T09:05:00.000Z", "4625", "0xC000006A", "APP-BATCH07", "10.20.30.41", "DC01", "5"],
                            ["2026-11-12 09:00:00", "4771", "0x18", None, "10.20.30.41", "DC02", None]]))
    b = backends.DatabricksBackend("https://dbx.example.test", "wh123", "tok", FM, transport=t)
    out = b.query("failed_logins", "svc-batch01", T0, T1, S)
    sent = json.loads(t.calls[0]["body"])
    assert t.calls[0]["url"] == "https://dbx.example.test/api/2.0/sql/statements" and sent["warehouse_id"] == "wh123"
    assert "svc-batch01" not in sent["statement"] and ":account" in sent["statement"]
    assert {p["name"]: p["value"] for p in sent["parameters"]} == {"account": "svc-batch01", "start": "2026-11-11T18:00:00", "end": "2026-11-12T18:00:00"}
    assert [r["time"] for r in out["rows"]] == ["2026-11-12T09:00:00Z", "2026-11-12T09:05:00Z"]
    assert out["rows"][1]["event_code"] == 4625 and out["rows"][1]["logon_type"] == 5 and out["rows"][0].get("src_host") is None


def test_databricks_failed_statement_and_truncation():
    b = backends.DatabricksBackend("https://dbx.example.test", "wh", "tok", FM, transport=Fake(body=dbx_body([], [], state="FAILED")))
    assert b.query("failed_logins", "svc-batch01", T0, T1, S)["error"] == "source_unavailable"
    b = backends.DatabricksBackend("https://dbx.example.test", "wh", "tok", FM,
                                   transport=Fake(body=dbx_body(["event_time"], [["2026-11-12T09:00:00Z"]], truncated=True)))
    assert b.query("failed_logins", "svc-batch01", T0, T1, S)["error"] == "truncated_by_source"


def test_pipeline_runs_end_to_end_on_a_splunk_backend():
    """Same pipeline, Splunk-shaped rows in, stale-credential offered first."""
    base = datetime(2026, 11, 12, 9, 5, tzinfo=timezone.utc)
    failures = [{"_time": (base + timedelta(minutes=5 * i)).isoformat(), "EventCode": "4771", "Failure_Code": "0x18",
                 "Client_Address": "::ffff:10.20.30.41", "Workstation_Name": "APP-BATCH07", "host": "DC01"} for i in range(40)]
    events = [{"_time": "2026-11-12T09:00:00+00:00", "EventCode": "4724", "src_user": "helpdesk"}]

    class Router(Fake):
        def __call__(self, method, url, headers, body, timeout):
            search = urllib.parse.parse_qs(body.decode())["search"][0]
            if "azure_signin" in search:
                return 200, b""
            return 200, splunk_lines(*(events if "4740" in search else failures))

    b = backends.SplunkBackend("https://splunk.example.test:8089", "tok", FM, transport=Router())
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=STORE, model=no_model, backend=b)
    assert r["status"] == "ok" and r["candidates"]["allowed"][0] == "stale-credential"
    assert r["facts"]["ad"]["by_source_host"][0]["value"] == "APP-BATCH07" and r["facts"]["gaps"] == []
    assert r["facts"]["query_ids"][0] == "splunk:failed_logins:svc-batch01"

"""Source adapters: a shared contract every adapter must meet, then each adapter's own behavior. No network."""
import json, urllib.parse
from datetime import datetime, timedelta, timezone
import pytest
from conftest import STORE, ev, no_model
import adapters, backends, evidence, handler, scope

S = frozenset({"svc-batch01"})
T1 = datetime(2026, 11, 12, 18, tzinfo=timezone.utc)
T0 = T1 - timedelta(hours=24)
FM = backends.load_field_map()
UPN = "svc.batch01@example.test"
TENANT, CLIENT, WORKSPACE = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    monkeypatch.setenv("SPLUNK_INDEX_WINDOWS", "wineventlog"); monkeypatch.setenv("SPLUNK_INDEX_ENTRA", "signin")
    for k in ("FAILED_LOGINS", "ACCOUNT_EVENTS", "ENTRA_FAILURES"):
        monkeypatch.setenv("DATABRICKS_VIEW_" + k, "sec.identity.v_" + k.lower())


class Net:
    """Scripted transport. Answers by URL substring, records every call, can be told to fail."""
    def __init__(self, answers=None, boom=None, status=200):
        self.answers, self.boom, self.status, self.calls = answers or {}, boom, status, []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body})
        if "oauth2/v2.0/token" in url:
            return 200, json.dumps({"access_token": "tok-%d" % len(self.calls), "expires_in": 3600}).encode()
        if self.boom:
            raise self.boom
        for key, value in self.answers.items():
            if key in url:
                value = value(url, body) if callable(value) else value
                return self.status, (value if isinstance(value, bytes) else json.dumps(value).encode())
        return self.status, b"{}"

    def data_calls(self):
        return [c for c in self.calls if "oauth2" not in c["url"]]


def cred(net):
    return adapters._ClientCredentials(TENANT, CLIENT, "s3cret", net, 30)


SIGNIN = {"createdDateTime": "2026-11-12T13:05:00Z", "userPrincipalName": UPN, "appDisplayName": "Mail", "clientAppUsed": "Exchange ActiveSync",
          "ipAddress": "198.51.100.61", "status": {"errorCode": 50126, "failureReason": "x"}}
EXPORT_FILES = {
    "exports/failed_logins/2026-11-12.csv": "Time,Account Name,Client Host Name,Client IP Address,Failure Reason Code,Domain Controller,EventCode\n"
                                             "2026-11-12 09:05:00,SVC-Batch01,APP-BATCH07,10.20.30.41,0xC000006A,DC01,4625\n"
                                             "2026-11-12 09:06:00,someone-else,WKS-1,10.1.1.1,0xC000006A,DC02,4625\n"
                                             "2026-11-10 09:06:00,svc-batch01,OLD-HOST,10.1.1.2,0xC000006A,DC02,4625\n",
    "exports/entra_failures/2026-11-12.jsonl": json.dumps({"TimeGenerated": "2026-11-12T13:05:00Z", "UserPrincipalName": UPN, "ResultType": "50126",
                                                           "ClientAppUsed": "IMAP4", "AppDisplayName": "Mail", "IPAddress": "198.51.100.9"}) + "\n",
}


def make(name, net):
    if name == "splunk":
        return backends.SplunkBackend("https://s.example.test:8089", "tok", FM, transport=net)
    if name == "databricks":
        return backends.DatabricksBackend("https://d.example.test", "wh", "tok", FM, transport=net)
    if name == "graph":
        return adapters.GraphSignInBackend(cred(net), field_map=FM, transport=net)
    if name == "loganalytics":
        return adapters.LogAnalyticsBackend(cred(net), WORKSPACE, field_map=FM, transport=net)
    if name == "export":
        class Counting(evidence.DictStore):
            def get(self, key):
                net.calls.append({"url": key, "method": "GET", "headers": {}, "body": None})
                return super().get(key)
        return adapters.ExportBackend(Counting(dict(EXPORT_FILES)), field_map=FM)
    raise AssertionError(name)


NAMES = ["splunk", "databricks", "graph", "loganalytics", "export"]


@pytest.mark.parametrize("name", NAMES)
def test_contract_scope_is_checked_before_any_io(name):
    net = Net()
    b = make(name, net)
    for kind in ("failed_logins", "account_events", "entra_failures"):
        with pytest.raises(scope.Denied):
            b.query(kind, "svc-payroll", T0, T1, S, UPN)
    assert net.calls == []


@pytest.mark.parametrize("name", NAMES)
def test_contract_a_failing_source_is_a_gap_never_a_crash_and_never_leaks_a_secret(name):
    net = Net(boom=TimeoutError("slow"))
    b = make(name, net)
    if name == "export":
        b.store.d.clear()
    kind = b.kinds[-1]
    out = b.query(kind, "svc-batch01", T0, T1, S, UPN)
    assert out["rows"] == [] and out["error"] in ("source_unavailable", "source_missing")
    assert "s3cret" not in json.dumps(out) and "tok" not in json.dumps(out)
    assert out["query_id"] == "%s:%s:svc-batch01" % (name, kind)


@pytest.mark.parametrize("name", ["graph", "loganalytics"])
def test_contract_kinds_a_source_cannot_answer_are_said_so_without_io(name):
    net = Net()
    out = make(name, net).query("failed_logins", "svc-batch01", T0, T1, S, UPN)
    assert out["error"] == "source_not_configured" and net.calls == []


@pytest.mark.parametrize("name", ["graph", "loganalytics"])
def test_cloud_sources_need_a_sign_in_name_from_the_ownership_source(name):
    net = Net()
    for missing in (None, "", "not a upn", "x' or 1 eq 1 or '@example.test"):
        out = make(name, net).query("entra_failures", "svc-batch01", T0, T1, S, missing)
        assert out["error"] == "no_cloud_signin_name_for_account"
    assert net.calls == []


def test_graph_asks_for_one_name_and_one_window_and_normalizes():
    net = Net({"/auditLogs/signIns": {"value": [SIGNIN, dict(SIGNIN, createdDateTime="2026-11-12T13:00:00Z")]}})
    out = make("graph", net).query("entra_failures", "svc-batch01", T0, T1, S, UPN.upper())
    call = net.data_calls()[0]
    q = urllib.parse.parse_qs(urllib.parse.urlparse(call["url"]).query)
    assert q["$filter"] == ["userPrincipalName eq 'svc.batch01@example.test' and createdDateTime ge 2026-11-11T18:00:00Z "
                            "and createdDateTime lt 2026-11-12T18:00:00Z and status/errorCode ne 0"]
    assert call["method"] == "GET" and call["headers"]["Authorization"].startswith("Bearer tok-")
    assert out["rows"] == [{"time": "2026-11-12T13:00:00Z", "error_code": "50126", "client_app": "Exchange ActiveSync", "app": "Mail", "src_ip": "198.51.100.61"},
                           {"time": "2026-11-12T13:05:00Z", "error_code": "50126", "client_app": "Exchange ActiveSync", "app": "Mail", "src_ip": "198.51.100.61"}]


def test_graph_follows_paging_on_its_own_host_only_and_caps_pages():
    base = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    pages = iter([{"value": [SIGNIN], "@odata.nextLink": base + "?$skiptoken=2"}, {"value": [SIGNIN]}])
    net = Net({"/auditLogs/signIns": lambda url, body: next(pages)})
    assert len(make("graph", net).query("entra_failures", "svc-batch01", T0, T1, S, UPN)["rows"]) == 2
    net = Net({"/auditLogs/signIns": {"value": [SIGNIN], "@odata.nextLink": "https://evil.example.test/steal"}})
    out = make("graph", net).query("entra_failures", "svc-batch01", T0, T1, S, UPN)
    assert out["error"] == "source_unavailable" and all("evil" not in c["url"] for c in net.calls)
    net = Net({"/auditLogs/signIns": {"value": [SIGNIN], "@odata.nextLink": base + "?$skiptoken=again"}})
    out = make("graph", net).query("entra_failures", "svc-batch01", T0, T1, S, UPN)
    assert out["error"] == "truncated_by_source" and len(net.data_calls()) == adapters.GraphSignInBackend.MAX_PAGES


def test_token_is_fetched_once_and_reused_and_identifiers_are_validated():
    net = Net({"/auditLogs/signIns": {"value": []}})
    b = make("graph", net)
    b.query("entra_failures", "svc-batch01", T0, T1, S, UPN); b.health(T0, T1)
    assert sum("oauth2" in c["url"] for c in net.calls) == 1
    token_call = next(c for c in net.calls if "oauth2" in c["url"])
    assert TENANT in token_call["url"] and b"client_credentials" in token_call["body"]
    with pytest.raises(ValueError):
        adapters._ClientCredentials("not-a-guid", CLIENT, "x", net, 30)
    with pytest.raises(ValueError):
        adapters.GraphSignInBackend(cred(net), base_url="http://graph.example.test")


def test_log_workspace_query_shape_and_health():
    table = {"tables": [{"columns": [{"name": n} for n in ("TimeGenerated", "ResultType", "ClientAppUsed", "AppDisplayName", "IPAddress")],
                         "rows": [["2026-11-12T13:05:00Z", "50126", "IMAP4", "Mail", "198.51.100.9"]]}]}
    net = Net({"/query": table})
    b = make("loganalytics", net)
    out = b.query("entra_failures", "svc-batch01", T0, T1, S, UPN)
    sent = json.loads(net.data_calls()[0]["body"])
    assert WORKSPACE in net.data_calls()[0]["url"] and sent["timespan"] == "2026-11-11T18:00:00Z/2026-11-12T18:00:00Z"
    assert 'UserPrincipalName =~ "svc.batch01@example.test"' in sent["query"] and "take 5000" in sent["query"]
    assert out["rows"] == [{"time": "2026-11-12T13:05:00Z", "error_code": "50126", "client_app": "IMAP4", "app": "Mail", "src_ip": "198.51.100.9"}]
    net = Net({"/query": {"tables": [{"columns": [{"name": "events"}], "rows": [[4321]]}]}})
    assert make("loganalytics", net).health(T0, T1) == {"windows": None, "entra": {"events": 4321, "reporting_hosts": None}}
    with pytest.raises(ValueError):
        adapters.LogAnalyticsBackend(cred(net), "workspace")


def test_export_reads_scheduled_files_for_one_account_inside_the_window():
    b = make("export", Net())
    out = b.query("failed_logins", "svc-batch01", T0, T1, S)
    assert out["rows"] == [{"time": "2026-11-12T09:05:00Z", "event_code": 4625, "failure_code": "0xC000006A", "src_host": "APP-BATCH07",
                            "src_ip": "10.20.30.41", "dc_host": "DC01"}]
    cloud = b.query("entra_failures", "svc-batch01", T0, T1, S, UPN)
    assert cloud["rows"][0]["client_app"] == "IMAP4"
    assert b.query("entra_failures", "svc-batch01", T0, T1, S, None)["rows"] == []        # no sign-in name, no match
    assert b.query("account_events", "svc-batch01", T0, T1, S)["error"] == "source_missing"
    assert b.health(T0, T1) == {"windows": {"events": 2, "reporting_hosts": 2}, "entra": {"events": 1, "reporting_hosts": None}}


def test_export_refuses_oversized_files_and_reads_json_arrays():
    store = evidence.DictStore({"exports/failed_logins/2026-11-12.json": json.dumps({"rows": [{"Time": "2026-11-12T10:00:00Z", "user": "svc-batch01", "EventCode": 4625}]})})
    b = adapters.ExportBackend(store, field_map=FM)
    assert len(b.query("failed_logins", "svc-batch01", T0, T1, S)["rows"]) == 1
    b.MAX_BYTES = 10
    assert b.query("failed_logins", "svc-batch01", T0, T1, S)["error"] == "source_unavailable"


def test_routes_are_parsed_strictly():
    r = adapters.parse_routes("splunk", "entra_failures=graph, account_events = export")
    assert r == {"failed_logins": "splunk", "account_events": "export", "entra_failures": "graph"}
    assert adapters.parse_routes("file", "") == {k: "file" for k in ("failed_logins", "account_events", "entra_failures")}
    for bad in ("entra=graph", "entra_failures=oracle", "entra_failures", "failed_logins=splunk;rm"):
        with pytest.raises(ValueError):
            adapters.parse_routes("file", bad)
    with pytest.raises(ValueError):
        adapters.parse_routes("oracle", "")


def test_one_source_for_directory_events_and_none_yet_for_cloud_sign_ins(monkeypatch):
    """Directory evidence from one source, no cloud source configured: the report says so and still explains."""
    base = datetime(2026, 11, 12, 9, 5, tzinfo=timezone.utc)
    lines = lambda *rows: "\n".join(json.dumps({"result": r}) for r in rows).encode()
    failures = [{"_time": (base + timedelta(minutes=5 * i)).isoformat(), "EventCode": "4771", "Failure_Code": "0x18",
                 "Client_Address": "10.20.30.41", "Workstation_Name": "APP-BATCH07", "host": "DC01"} for i in range(40)]

    def answer(url, body):
        search = urllib.parse.parse_qs(body.decode())["search"][0]
        if "tstats" in search:
            return lines({"events": "900", "reporting_hosts": "3"})
        return lines({"_time": "2026-11-12T09:00:00+00:00", "EventCode": "4724"}) if "4740" in search else lines(*failures)

    splunk = backends.SplunkBackend("https://s.example.test:8089", "tok", FM, transport=Net({"/export": answer}))
    routed = adapters.RoutedBackend({"failed_logins": splunk, "account_events": splunk, "entra_failures": adapters.NullBackend()})
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=STORE, model=no_model, backend=routed)
    f = r["facts"]
    assert r["candidates"]["allowed"][0] == "stale-credential"
    assert f["gaps"] == ["entra_failures: source_not_configured"]
    assert f["source_health"] == {"windows": {"events": 900, "reporting_hosts": 3}, "entra": "not_configured"}
    assert f["query_ids"] == ["splunk:failed_logins:svc-batch01", "splunk:account_events:svc-batch01", "none:entra_failures:svc-batch01"]


def test_registry_builds_one_backend_or_a_router_from_settings(monkeypatch):
    monkeypatch.setenv("EVIDENCE_BACKEND", "file"); monkeypatch.delenv("EVIDENCE_SOURCES", raising=False)
    assert type(adapters.make_backend(STORE)).__name__ == "FileBackend"
    monkeypatch.setenv("EVIDENCE_SOURCES", "entra_failures=none,account_events=export")
    b = adapters.make_backend(STORE)
    assert type(b).__name__ == "RoutedBackend"
    assert [type(b.routes[k]).__name__ for k in ("failed_logins", "account_events", "entra_failures")] == ["FileBackend", "ExportBackend", "NullBackend"]


def test_sign_in_name_comes_from_the_ownership_source_never_the_request():
    files = dict(STORE.d)
    own = json.loads(files["ownership/ownership.json"])
    own["owners"]["E1001"][0]["signin_name"] = "SVC.Batch01@Example.Test"
    files["ownership/ownership.json"] = json.dumps(own)
    seen = {}

    class Spy(backends.FileBackend):
        def fetch(self, kind, account, start, end, scope_set, signin_name=None):
            seen[kind] = signin_name
            return super().fetch(kind, account, start, end, scope_set, signin_name)

    store = evidence.DictStore(files)
    e = ev("E1001", "svc-batch01", signin_name="attacker@evil.test")
    handler.handler(e, None, store=store, model=no_model, backend=Spy(store))
    assert seen == {"failed_logins": None, "account_events": None, "entra_failures": "svc.batch01@example.test"}


def test_export_tells_an_unreadable_file_from_a_missing_one():
    class Denied(evidence.DictStore):
        def get(self, key):
            if key.endswith(".csv"):
                raise PermissionError("access denied")
            return super().get(key)
    b = adapters.ExportBackend(Denied({}), field_map=FM)
    assert b.query("failed_logins", "svc-batch01", T0, T1, S)["error"] == "source_unavailable"
    assert adapters.ExportBackend(evidence.DictStore({}), field_map=FM).query("failed_logins", "svc-batch01", T0, T1, S)["error"] == "source_missing"


def test_object_store_reports_absent_objects_as_missing_and_other_errors_as_errors():
    class Boom(Exception):
        def __init__(self, code):
            self.response = {"Error": {"Code": code}}
    class Client:
        def __init__(self, code): self.code = code
        def get_object(self, **kw): raise Boom(self.code)
    s = evidence.S3Store.__new__(evidence.S3Store); s.bucket = "b"
    s.s3 = Client("NoSuchKey")
    with pytest.raises(KeyError):
        s.get("x")
    s.s3 = Client("AccessDenied")
    with pytest.raises(Boom):
        s.get("x")

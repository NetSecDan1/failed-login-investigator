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
    assert b.health(T0, T1) == {"windows": {"events": 2, "reporting_hosts": 2, "newest": "2026-11-12T09:06:00Z"}, "entra": {"events": 1, "reporting_hosts": None, "newest": "2026-11-12T13:05:00Z"}}


def test_export_refuses_oversized_files_and_reads_json_arrays():
    store = evidence.DictStore({"exports/failed_logins/2026-11-12.json": json.dumps({"rows": [{"Time": "2026-11-12T10:00:00Z", "user": "svc-batch01", "EventCode": 4625}]})})
    b = adapters.ExportBackend(store, field_map=FM)
    assert len(b.query("failed_logins", "svc-batch01", T0, T1, S)["rows"]) == 1
    b.MAX_BYTES = 10
    assert b.query("failed_logins", "svc-batch01", T0, T1, S)["error"] == "source_unavailable"


def test_routes_are_parsed_strictly():
    r = adapters.parse_routes("splunk", "entra_failures=graph, account_events = export")
    assert r == {"failed_logins": ("splunk",), "account_events": ("export",), "entra_failures": ("graph",)}
    assert adapters.parse_routes("file", "") == {k: ("file",) for k in ("failed_logins", "account_events", "entra_failures")}
    assert adapters.parse_routes("splunk", "entra_failures= LogAnalytics + graph")["entra_failures"] == ("loganalytics", "graph")
    for bad in ("entra=graph", "entra_failures=oracle", "entra_failures", "failed_logins=splunk;rm", "entra_failures=graph+graph",
                "entra_failures=none+graph", "entra_failures=graph+", "entra_failures=graph+oracle"):
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
    assert [type(b.routes[k]).__name__ for k in ("failed_logins", "account_events", "entra_failures")] == ["FileBackend", "ChainBackend", "NullBackend"]
    assert [(n, type(m).__name__) for n, m in b.routes["account_events"].members] == [("export", "ExportBackend")]


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


# ---------- several sources for one kind, and operator switches ----------

LA_ROW = {"tables": [{"columns": [{"name": c} for c in ("TimeGenerated", "UserPrincipalName", "ResultType", "ClientAppUsed", "AppDisplayName", "IPAddress")],
                      "rows": [["2026-11-12T13:05:00Z", UPN, "50126", "IMAP4", "Mail", "198.51.100.9"]]}]}
KNOWN = set(adapters.REGISTRY) - set(adapters.UNSWITCHED)


def two_cloud_sources(la_net, graph_net, switches=None):
    return adapters.ChainBackend([("loganalytics", make("loganalytics", la_net)), ("graph", make("graph", graph_net))], switches)


def ask(chain, account="svc-batch01", scope_set=S):
    return chain.query("entra_failures", account, T0, T1, scope_set, UPN)


def test_first_source_that_answers_wins_and_a_quiet_account_is_an_answer():
    la, graph = Net({"/query": LA_ROW}), Net({"/signIns": {"value": [SIGNIN]}})
    r = ask(two_cloud_sources(la, graph))
    assert r["query_id"].startswith("loganalytics:") and len(r["rows"]) == 1 and "passed_over" not in r
    assert graph.calls == []
    quiet, graph = Net({"/query": {"tables": [{"columns": [], "rows": []}]}}), Net({"/signIns": {"value": [SIGNIN]}})
    r = ask(two_cloud_sources(quiet, graph))
    assert r["rows"] == [] and "error" not in r and graph.calls == []          # no rows is not a reason to ask someone else


def test_a_failing_source_is_passed_over_and_the_audit_trail_says_so():
    la, graph = Net(boom=OSError("workspace down")), Net({"/signIns": {"value": [SIGNIN]}})
    r = ask(two_cloud_sources(la, graph))
    assert r["query_id"].startswith("graph:") and len(r["rows"]) == 1
    assert r["passed_over"] == ["loganalytics:source_unavailable"]
    both_down = ask(two_cloud_sources(Net(boom=OSError("a")), Net(boom=OSError("b"))))
    assert both_down["error"] == "source_unavailable" and both_down["rows"] == []


def test_a_switched_off_source_is_never_called():
    la, graph = Net({"/query": LA_ROW}), Net({"/signIns": {"value": [SIGNIN]}})
    r = ask(two_cloud_sources(la, graph, adapters.Switches(env_disabled="loganalytics", known=KNOWN)))
    assert r["query_id"].startswith("graph:") and la.calls == []
    la, graph = Net({"/query": LA_ROW}), Net({"/signIns": {"value": [SIGNIN]}})
    chain = two_cloud_sources(la, graph, adapters.Switches(env_disabled="graph, loganalytics", known=KNOWN))
    r = ask(chain)
    assert r == {"query_id": "off:entra_failures:svc-batch01", "rows": [], "truncated": False, "error": "source_switched_off"}
    assert chain.health(T0, T1) == {"windows": "not_configured", "entra": "not_configured"}
    assert la.calls == [] and graph.calls == []


def test_the_switch_file_takes_effect_while_running_and_can_only_turn_things_off():
    files, now = {}, [1000.0]
    sw = adapters.Switches(evidence.DictStore(files), "runtime/switches.json", known=KNOWN, clock=lambda: now[0])
    assert sw.state() == (frozenset(), None)                                   # no file: nothing is off
    files["runtime/switches.json"] = json.dumps({"disabled_sources": ["Graph"]})
    assert not sw.is_off("graph")                                              # still inside the cache window
    now[0] += 61
    assert sw.is_off("graph") and not sw.is_off("loganalytics")
    files["runtime/switches.json"] = json.dumps({"disabled_sources": [], "enabled_sources": ["databricks"], "routes": {"entra_failures": "file"}})
    now[0] += 61
    assert sw.state() == (frozenset(), None)                                   # unknown keys do nothing: there is no "on"
    la, graph = Net({"/query": LA_ROW}), Net({"/signIns": {"value": [SIGNIN]}})
    assert ask(two_cloud_sources(la, graph, sw))["query_id"].startswith("loganalytics:")


@pytest.mark.parametrize("content", ["{not json", json.dumps(["graph"]), json.dumps({"disabled_sources": "graph"}),
                                     json.dumps({"disabled_sources": ["oracle"]}), json.dumps({"disabled_sources": ["file"]})])
def test_a_switch_file_that_cannot_be_understood_turns_every_source_off(content):
    sw = adapters.Switches(evidence.DictStore({"runtime/switches.json": content}), "runtime/switches.json", known=KNOWN)
    off, problem = sw.state()
    assert off == KNOWN and problem.startswith("switch_file_invalid")
    la, graph = Net({"/query": LA_ROW}), Net({"/signIns": {"value": [SIGNIN]}})
    r = ask(two_cloud_sources(la, graph, sw))
    assert r["error"].startswith("switch_file_invalid") and r["rows"] == [] and la.calls == [] and graph.calls == []


def test_an_unreadable_switch_file_is_not_mistaken_for_no_file():
    class Broken:
        def get(self, key):
            raise PermissionError("denied")
    assert adapters.Switches(Broken(), "runtime/switches.json", known=KNOWN).state()[0] == KNOWN


def test_scope_is_checked_before_the_switch_file_or_any_source():
    class Counting(evidence.DictStore):
        reads = 0
        def get(self, key):
            Counting.reads += 1
            return super().get(key)
    la, graph = Net({"/query": LA_ROW}), Net()
    chain = two_cloud_sources(la, graph, adapters.Switches(Counting({}), "runtime/switches.json", known=KNOWN))
    with pytest.raises(scope.Denied):
        ask(chain, account="svc-payroll01")
    assert Counting.reads == 0 and la.calls == [] and graph.calls == []


def test_settings_reject_unknown_names_in_the_switch():
    with pytest.raises(ValueError):
        adapters.Switches(env_disabled="oracle", known=KNOWN)
    with pytest.raises(ValueError):
        adapters.Switches(env_disabled="none", known=KNOWN)


def test_registry_builds_a_switchable_chain_from_settings(monkeypatch):
    for k, v in {"EVIDENCE_BACKEND": "file", "EVIDENCE_SOURCES": "entra_failures=loganalytics+graph", "SOURCES_DISABLED": "graph",
                 "SOURCE_SWITCH_KEY": "runtime/switches.json", "ENTRA_TENANT_ID": TENANT, "ENTRA_CLIENT_ID": CLIENT,
                 "ENTRA_CLIENT_SECRET": "s3cret", "LOGANALYTICS_WORKSPACE_ID": WORKSPACE}.items():
        monkeypatch.setenv(k, v)
    chain = adapters.make_backend(STORE).routes["entra_failures"]
    assert [n for n, _ in chain.members] == ["loganalytics", "graph"]
    assert [n for n, _ in chain._live()[0]] == ["loganalytics"]
    assert chain.switches.key == "runtime/switches.json"


def test_with_cloud_sources_switched_off_the_report_states_the_gap_and_still_explains(capsys):
    chain = two_cloud_sources(Net(), Net(), adapters.Switches(env_disabled="graph,loganalytics", known=KNOWN))
    file = backends.FileBackend(STORE)
    routed = adapters.RoutedBackend({"failed_logins": file, "account_events": file, "entra_failures": chain})
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=STORE, model=no_model, backend=routed)
    assert r["candidates"]["allowed"][0] == "stale-credential"
    assert "entra_failures: source_switched_off" in r["facts"]["gaps"]
    assert r["facts"]["source_health"]["entra"] == "not_configured"


def test_the_audit_line_records_which_source_was_passed_over(capsys):
    chain = two_cloud_sources(Net(boom=OSError("down")), Net({"/signIns": {"value": []}}))
    file = backends.FileBackend(STORE)
    routed = adapters.RoutedBackend({"failed_logins": file, "account_events": file, "entra_failures": chain})
    files = dict(STORE.d)
    own = json.loads(files["ownership/ownership.json"])
    own["owners"]["E1001"][0]["signin_name"] = UPN
    files["ownership/ownership.json"] = json.dumps(own)
    assert own["owners"]["E1001"][0]["account"] == "svc-batch01"
    handler.handler(ev("E1001", "svc-batch01"), None, store=evidence.DictStore(files), model=no_model, backend=routed)
    line = [l for l in capsys.readouterr().out.splitlines() if l.startswith("AUDIT ")][-1]
    audit = json.loads(line[6:])
    assert audit["sources_passed_over"] == {"entra_failures": ["loganalytics:source_unavailable"]}
    assert audit["query_ids"][2].startswith("graph:")


# ---------- how far behind a source is running ----------

def health_of(name, answers):
    return make(name, Net(answers)).health(T0, T1)


def test_every_live_source_reports_its_newest_event():
    lines = lambda *rows: "\n".join(json.dumps({"result": r}) for r in rows).encode()
    assert health_of("splunk", {"/export": lines({"events": "900", "reporting_hosts": "3", "newest": "1794502800"})})["windows"] == {
        "events": 900, "reporting_hosts": 3, "newest": "2026-11-12T17:00:00Z"}
    la = {"tables": [{"columns": [{"name": "events"}, {"name": "newest"}], "rows": [[12, "2026-11-12T17:40:00Z"]]}]}
    assert health_of("loganalytics", {"/query": la})["entra"] == {"events": 12, "reporting_hosts": None, "newest": "2026-11-12T17:40:00Z"}
    net = Net({"/signIns": {"value": [dict(SIGNIN, createdDateTime="2026-11-12T17:58:00Z")]}})
    assert make("graph", net).health(T0, T1)["entra"]["newest"] == "2026-11-12T17:58:00Z"
    assert "orderby=createdDateTime+desc" in net.data_calls()[-1]["url"].replace("%24", "").replace("%20", "+")
    assert make("export", Net()).health(T0, T1)["windows"]["newest"] == "2026-11-12T09:06:00Z"


def test_a_newest_time_that_makes_no_sense_is_dropped_not_trusted():
    lines = lambda *rows: "\n".join(json.dumps({"result": r}) for r in rows).encode()
    for junk in ("soon", "99999999999999999", "0999-01-01T00:00:00Z", ""):
        h = health_of("splunk", {"/export": lines({"events": "5", "reporting_hosts": "1", "newest": junk})})["windows"]
        assert h == {"events": 5, "reporting_hosts": 1}


def lagging(newest, max_lag, end=T1, now=None):
    import findings
    pack = {k: {"query_id": "q:" + k, "rows": [], "truncated": False} for k in ("failed_logins", "account_events", "entra_failures")}
    pack["query_ids"] = ["q:a", "q:b", "q:c"]
    health = {"windows": {"events": 500, "reporting_hosts": 3, "newest": "2026-11-12T17:58:00Z"},
              "entra": {"events": 40, "reporting_hosts": None, "newest": newest}}
    return findings.compute("svc-batch01", T0, end, pack, "service", health, 0, max_lag, now), health


def test_a_source_running_behind_is_measured_and_called_out_past_the_limit():
    facts, original = lagging("2026-11-12T14:53:00Z", 60)
    assert facts["source_health"]["entra"]["lag_minutes"] == 187 and facts["source_health"]["windows"]["lag_minutes"] == 2
    assert facts["gaps"] == ["cloud sign-in events: the newest event in the source is 187 minutes behind the end of this window, recent activity may be missing"]
    assert "lag_minutes" not in original["entra"]                              # the caller's health record is not edited
    assert lagging("2026-11-12T14:53:00Z", 0)[0]["gaps"] == []                 # 0 measures without judging
    assert lagging("2026-11-12T14:53:00Z", 240)[0]["gaps"] == []


def test_lag_is_measured_against_the_clock_when_the_window_ends_in_the_future():
    now = T1 - timedelta(hours=3)                                              # window end is ahead of the clock
    facts, _ = lagging("2026-11-12T14:53:00Z", 60, now=now)
    assert facts["source_health"]["entra"]["lag_minutes"] == 7 and facts["gaps"] == []


def test_the_source_check_tool_reports_state_and_lag(capsys):
    import importlib.util, os
    spec = importlib.util.spec_from_file_location("check_sources", os.path.join(os.path.dirname(__file__), "..", "tools", "check_sources.py"))
    cs = importlib.util.module_from_spec(spec); spec.loader.exec_module(cs)

    class Fake(backends.Backend):
        def __init__(self, out):
            self.out = out
        def health(self, start, end):
            return self.out
    now = datetime(2026, 11, 12, 18, tzinfo=timezone.utc)
    rows = cs.measure(Fake({"windows": {"events": 9, "reporting_hosts": 2, "newest": "2026-11-12T17:30:00Z"}, "entra": "not_configured"}), 24, now)
    assert rows[0]["lag_minutes"] == 30 and rows[0]["state"] == "ok" and rows[1]["state"] == "not_configured"
    assert cs.main(["--hours", "6"], backend=Fake({"windows": {"events": 0, "reporting_hosts": 0}, "entra": None})) == 1
    out = capsys.readouterr().out
    assert "no_events" in out and "could_not_check" in out
    assert cs.main(["--json"], backend=Fake({"windows": {"events": 3, "reporting_hosts": 1}, "entra": "not_configured"})) == 0

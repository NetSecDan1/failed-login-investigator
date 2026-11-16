"""The settings registry, the code, the template and the docs must agree. Preflight must block prototype defaults."""
import glob, importlib.util, os, re
from conftest import ROOT

spec = importlib.util.spec_from_file_location("preflight", os.path.join(ROOT, "tools", "preflight.py"))
pre = importlib.util.module_from_spec(spec); spec.loader.exec_module(pre)
NAMES = {s["name"] for s in pre.registry()}

GOOD = {"DATA_BUCKET": "b", "MODEL_ID": "m", "ALLOW_TEST_CLAIMS": "false", "OWNERSHIP_MAX_AGE_HOURS": "26", "RATE_LIMIT_PER_HOUR": "30",
        "RATE_LIMIT_TABLE": "t", "EVIDENCE_BACKEND": "splunk", "SPLUNK_BASE_URL": "https://s.example.test:8089",
        "SPLUNK_INDEX_WINDOWS": "wineventlog", "SPLUNK_INDEX_ENTRA": "signin", "SPLUNK_TOKEN_SECRET_ARN": "arn:x",
        "EXPECTED_REPORTING_HOSTS": "6", "MODEL_ROUTE": "gateway", "MODEL_GATEWAY_URL": "https://g.example.test/v1",
        "MODEL_GATEWAY_TOKEN_SECRET_ARN": "arn:y", "METRICS_EMF": "true"}


def blocks(env, runtime="function"):
    return {name for level, name, _ in pre.check(env, runtime) if level == "BLOCK"}


def test_every_setting_the_code_reads_is_registered():
    used = set()
    for path in glob.glob(os.path.join(ROOT, "src", "*.py")) + glob.glob(os.path.join(ROOT, "agent", "*.py")):
        text = open(path).read()
        used |= set(re.findall(r'environ(?:\.get)?[\[(]"([A-Z_]+)"', text))
        for a, b in re.findall(r'secret_from_env\("([A-Z_]+)", "([A-Z_]+)"', text):
            used |= {a, b}
        used |= set(re.findall(r'"((?:SPLUNK_INDEX|DATABRICKS_VIEW)_[A-Z_]+)"', text))
    assert used - NAMES == set(), "settings read by code but missing from config/settings.json"
    assert NAMES - used == set(), "settings registered but never read"


def test_every_function_setting_in_the_template_is_registered():
    env = set(re.findall(r"^          ([A-Z_]+):", open(os.path.join(ROOT, "template.yaml")).read(), re.M))
    assert env - NAMES == set()


def test_docs_are_generated_and_current():
    assert open(os.path.join(ROOT, "docs", "CONFIGURATION.md")).read() == pre.docs()


def test_prototype_defaults_are_blocked():
    b = blocks({"DATA_BUCKET": "b", "MODEL_ID": "m", "ALLOW_TEST_CLAIMS": "true"})
    assert {"ALLOW_TEST_CLAIMS", "OWNERSHIP_MAX_AGE_HOURS", "RATE_LIMIT_PER_HOUR", "EVIDENCE_BACKEND"} <= b


def test_a_coherent_environment_passes_and_each_mistake_is_caught():
    assert blocks(GOOD) == set()
    assert blocks(GOOD, "agent") == {"JWT_ISSUER", "JWT_AUDIENCE", "JWT_JWKS_URL"}
    for change, name in [({"SPLUNK_TOKEN": "abc"}, "SPLUNK_TOKEN"), ({"SPLUNK_BASE_URL": "http://s"}, "SPLUNK_BASE_URL"),
                         ({"SPLUNK_INDEX_WINDOWS": "main | delete"}, "SPLUNK_INDEX_WINDOWS"), ({"RATE_LIMIT_TABLE": ""}, "RATE_LIMIT_TABLE"),
                         ({"MODEL_GATEWAY_URL": ""}, "MODEL_GATEWAY_URL"), ({"MODEL_ROUTE": "direct"}, "MODEL_ROUTE"),
                         ({"MODEL_MAX_OUTPUT_TOKENS": "999999"}, "MODEL_MAX_OUTPUT_TOKENS"), ({"SOURCE_HEALTH_CHECK": "false"}, "SOURCE_HEALTH_CHECK"),
                         ({"EVIDENCE_BACKEND": "databricks"}, "DATABRICKS_HOST"), ({"OWNERSHIP_MAX_AGE_HOURS": "soon"}, "OWNERSHIP_MAX_AGE_HOURS")]:
        assert name in blocks(dict(GOOD, **change)), change


def test_typos_are_warned(tmp_path, capsys):
    f = tmp_path / "x.env"
    f.write_text("\n".join("%s=%s" % kv for kv in dict(GOOD, MODEL_ROUT="gateway").items()))
    assert pre.main(["--env-file", str(f)]) == 0
    assert "MODEL_ROUT " in capsys.readouterr().out


def test_per_kind_routes_are_checked():
    mixed = dict(GOOD, EVIDENCE_SOURCES="entra_failures=graph", SPLUNK_INDEX_ENTRA="")
    assert blocks(mixed) == {"ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET_ARN"}
    ok = dict(mixed, ENTRA_TENANT_ID="t", ENTRA_CLIENT_ID="c", ENTRA_CLIENT_SECRET_ARN="arn:z")
    assert blocks(ok) == set()
    assert "ENTRA_CLIENT_SECRET" in blocks(dict(ok, ENTRA_CLIENT_SECRET="plain"))
    assert "LOGANALYTICS_WORKSPACE_ID" in blocks(dict(ok, EVIDENCE_SOURCES="entra_failures=loganalytics"))
    assert "EVIDENCE_SOURCES" in blocks(dict(GOOD, EVIDENCE_SOURCES="failed_logins=graph"))
    assert "EVIDENCE_SOURCES" in blocks(dict(GOOD, EVIDENCE_SOURCES="entra_failures=nowhere"))
    assert "EVIDENCE_BACKEND" in blocks(dict(GOOD, EVIDENCE_SOURCES="account_events=file"))
    none_yet = pre.check(dict(GOOD, EVIDENCE_SOURCES="entra_failures=none", SPLUNK_INDEX_ENTRA=""))
    assert ("WARN", "EVIDENCE_SOURCES", "entra_failures has no source, every report will carry that gap") in none_yet
    assert not [f for f in none_yet if f[0] == "BLOCK"]


def test_preflight_understands_source_lists_and_switches():
    cloud = dict(GOOD, ENTRA_TENANT_ID="t", ENTRA_CLIENT_ID="c", ENTRA_CLIENT_SECRET_ARN="arn", SPLUNK_INDEX_ENTRA="")
    both = dict(cloud, EVIDENCE_SOURCES="entra_failures=loganalytics+graph")
    assert "LOGANALYTICS_WORKSPACE_ID" in blocks(both)
    ok = dict(both, LOGANALYTICS_WORKSPACE_ID="w")
    assert not blocks(ok)
    assert not blocks(dict(ok, SOURCES_DISABLED="graph", SOURCE_SWITCH_KEY="runtime/switches.json"))
    assert "SOURCES_DISABLED" in blocks(dict(ok, SOURCES_DISABLED="oracle"))
    assert "SOURCE_SWITCH_KEY" in blocks(dict(ok, SOURCE_SWITCH_KEY="runtime/../x y"))
    all_off = pre.check(dict(ok, SOURCES_DISABLED="graph,loganalytics"))
    assert ("WARN", "SOURCES_DISABLED", "every source for entra_failures is switched off, every report will carry that gap") in all_off
    assert "EVIDENCE_SOURCES" in blocks(dict(ok, EVIDENCE_SOURCES="failed_logins=splunk+graph"))

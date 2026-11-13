import os, sys
from datetime import datetime, timedelta, timezone
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import querypack, scope

S = frozenset({"svc-batch01"})
T1 = datetime(2026, 11, 12, 18, tzinfo=timezone.utc)
T0 = T1 - timedelta(hours=24)

def test_spl_renders_only_validated_values():
    q = querypack.render("failed_logins.spl", "SVC-Batch01", T0, T1, S)
    assert 'user="svc-batch01"' in q["text"] and 'earliest="2026-11-11T18:00:00"' in q["text"]
    assert "{" not in q["text"] and q["params"] == {}

def test_sql_uses_bound_parameters_not_text():
    q = querypack.render("failed_logins.sql", "svc-batch01", T0, T1, S)
    assert "svc-batch01" not in q["text"] and ":account" in q["text"]
    assert q["params"] == {"account": "svc-batch01", "start": "2026-11-11T18:00:00", "end": "2026-11-12T18:00:00"}

@pytest.mark.parametrize("bad", ['svc-batch01" OR user="*', "svc-batch01 | delete", "*", "svc-batch01\n| outputlookup x", "a]b"])
def test_injection_shapes_rejected(bad):
    with pytest.raises(scope.Denied) as e:
        querypack.render("failed_logins.spl", bad, T0, T1, S)
    assert e.value.code == "bad_account"

def test_out_of_scope_rejected():
    with pytest.raises(scope.Denied) as e:
        querypack.render("failed_logins.spl", "svc-payroll", T0, T1, S)
    assert e.value.code == "out_of_scope"

def test_times_must_be_datetimes_and_ordered():
    with pytest.raises(TypeError):
        querypack.render("failed_logins.spl", "svc-batch01", "2026-11-11", T1, S)
    with pytest.raises(TypeError):
        querypack.render("failed_logins.spl", "svc-batch01", T0.replace(tzinfo=None), T1, S)
    with pytest.raises(ValueError):
        querypack.render("failed_logins.spl", "svc-batch01", T1, T0, S)

def test_unknown_template_and_path_tricks_rejected():
    for name in ("../template.yaml", "other.spl", "/etc/passwd"):
        with pytest.raises(ValueError):
            querypack.render(name, "svc-batch01", T0, T1, S)

def test_every_template_has_a_row_cap():
    for name in querypack.ALLOWED:
        text = open(os.path.join(querypack.TEMPLATE_DIR, name)).read().lower()
        assert "head " in text or "limit " in text, name

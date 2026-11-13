import importlib.util, json, os
import pytest
from conftest import ROOT, STORE
import evidence, scope

spec = importlib.util.spec_from_file_location("import_ownership", os.path.join(ROOT, "tools", "import_ownership.py"))
imp = importlib.util.module_from_spec(spec); spec.loader.exec_module(imp)

CSV = """Owner Employee ID,Account Name,Application,Account Type,Tier
E7001,SVC-App01,Active Directory,Service,2
E7001,svc-app01,Active Directory,Service,2
E7001,da-e7001,Active Directory,Admin,Tier 0
E7001,svc-notier,Active Directory,Service,
,svc-orphan,Active Directory,Service,2
E7002,bad name!,Active Directory,Service,2
E7002,svc-break,Active Directory,Service,1
"""

def run(tmp_path, *extra):
    src, out, deny = tmp_path / "r.csv", tmp_path / "o.json", tmp_path / "deny.txt"
    src.write_text(CSV); deny.write_text("# break glass\nSVC-Break\n")
    code = imp.main([str(src), "--out", str(out), "--owner-col", "Owner Employee ID", "--account-col", "Account Name",
                     "--app-col", "Application", "--type-col", "Account Type", "--tier-col", "Tier", "--deny-file", str(deny), *extra])
    return code, json.loads(out.read_text()) if out.exists() else None

def test_import_and_resolver_agree(tmp_path):
    code, data = run(tmp_path)
    assert code == 0 and data["_stats"] == {"skipped_rows": 2, "rows_without_tier": 1, "owners": 2, "accounts": 4}
    assert [e["account"] for e in data["owners"]["E7001"]] == ["svc-app01", "da-e7001", "svc-notier"]   # deduplicated, lower-cased
    store = evidence.DictStore({"ownership/ownership.json": json.dumps(data)})
    names, meta = scope.resolve_scope_meta("E7001", store)
    assert names == frozenset({"svc-app01", "svc-notier"}) and meta["svc-app01"] == "service"         # Tier 0 excluded
    with pytest.raises(scope.Denied) as e:                                                              # only account is deny-listed
        scope.resolve_scope("E7002", store)
    assert e.value.code == "scope_empty"

def test_require_tier_refuses_to_write(tmp_path):
    with pytest.raises(SystemExit):
        run(tmp_path, "--require-tier")
    assert not (tmp_path / "o.json").exists()

def test_missing_column_is_a_clear_error(tmp_path):
    src = tmp_path / "r.csv"; src.write_text(CSV)
    with pytest.raises(SystemExit) as e:
        imp.main([str(src), "--out", str(tmp_path / "o.json"), "--owner-col", "Owner", "--account-col", "Account Name"])
    assert "column not found" in str(e.value)

"""The response contract a front end can rely on. Every result must match schemas/result.schema.json."""
import json, os
import pytest
from conftest import ROOT, STORE, ev, no_model, top_choice_model
import handler

jsonschema = pytest.importorskip("jsonschema")
SCHEMA = json.load(open(os.path.join(ROOT, "schemas", "result.schema.json")))
CASES = json.load(open(os.path.join(ROOT, "evals", "cases.json")))


def check(result):
    jsonschema.Draft202012Validator(SCHEMA).validate(result)


@pytest.mark.parametrize("case", CASES, ids=[c["account"] for c in CASES])
def test_every_golden_case_matches_the_contract_with_and_without_a_summary(case):
    for model in (top_choice_model, no_model):
        check(handler.handler(ev(case["caller"], case["account"]), None, store=STORE, model=model))


@pytest.mark.parametrize("event", [ev("E1001", "svc-payroll"), ev("E9999", "svc-batch01"), ev("E1001", "bad name"),
                                   ev("E1001", "svc-batch01", window_hours=999), {"account": "svc-batch01"}])
def test_denials_match_the_contract_and_carry_nothing_else(event):
    r = handler.handler(event, None, store=STORE, model=no_model)
    check(r)
    assert set(r) == {"status", "reason", "message", "reference"}


def test_schema_itself_is_valid_and_strict():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    r = handler.handler(ev("E1001", "svc-batch01"), None, store=STORE, model=top_choice_model)
    r["report"]["next_steps_from_model"] = ["anything"]
    with pytest.raises(jsonschema.ValidationError):
        check(r)

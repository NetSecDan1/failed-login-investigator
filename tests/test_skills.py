"""Lint for the skill library plus golden cases for the deterministic matcher."""
import json, os, re, subprocess, sys
import pytest
from conftest import FILES, STORE, ROOT, ev, no_model, top_choice_model
import handler, skillmatch, explain

SKILLS = os.path.join(ROOT, "skills")
IDS = sorted(d for d in os.listdir(SKILLS) if os.path.isdir(os.path.join(SKILLS, d)))
CASES = json.load(open(os.path.join(ROOT, "evals", "cases.json")))
SECTIONS = ["## Use when", "## Evidence to read", "## How to reason", "## Rule out", "## Tell the owner",
            "## Approved next steps", "## Never", "## Confidence"]
STEP_VARS = {"account", "top_host", "lockout_caller", "top_client_app", "top_app"}


def facts_for(case):
    r = handler.handler(ev(case["caller"], case["account"]), None, store=STORE, model=no_model)
    assert r["status"] == "ok", r
    return r


def rules(sid):
    return json.load(open(os.path.join(SKILLS, sid, "rules.json")))


def test_index_is_current():
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_skill_index.py"), "--check"], check=True)


@pytest.mark.parametrize("sid", IDS)
def test_skill_file_shape(sid):
    md = open(os.path.join(SKILLS, sid, "SKILL.md")).read()
    yaml = pytest.importorskip("yaml")
    fm = yaml.safe_load(md[4:md.index("\n---\n", 4)])
    assert fm["name"] == sid and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", sid) and len(sid) <= 64
    assert 40 <= len(fm["description"]) <= 1024 and fm["description"].startswith("Use when")
    pos = [md.index(h) for h in SECTIONS]            # every section present ...
    assert pos == sorted(pos)                          # ... and in the standard order
    assert chr(0x2014) not in md and chr(0x2013) not in md
    assert len(md) < 6000, "keep skills short enough to load several at once"


@pytest.mark.parametrize("sid", IDS)
def test_rules_are_well_formed_and_match_the_text(sid):
    r, md = rules(sid), open(os.path.join(SKILLS, sid, "SKILL.md")).read()
    known = set(facts_for(CASES[0])["facts"]["signals"])
    conds = [r["require"]] + [s["cond"] for s in r["support"]] + [r[k] for k in ("exclude", "mandatory_when") if k in r]
    for c in conds:
        assert skillmatch.signal_names(c) <= known, "rule uses a signal the findings engine does not compute"
        skillmatch.holds(c, {})                        # must evaluate without raising on empty signals
    assert r["next_steps"], "every skill needs at least one approved step"
    for step in r["next_steps"]:
        assert step in md, "approved step missing from SKILL.md: " + step[:50]
        assert set(re.findall(r"\{(\w+)\}", step)) <= STEP_VARS
    assert len(re.findall(r"^\d+\. ", md[md.index("## Approved next steps"):md.index("## Never")], re.M)) == len(r["next_steps"])
    if "mandatory_when" in r:
        assert r["escalate"] is True, "only escalating skills may be mandatory"
    for ref in re.findall(r"`([a-z0-9]+(?:-[a-z0-9]+)+)`", md[md.index("## Rule out"):md.index("## Tell the owner")]):
        assert ref in IDS, "rule-out points at an unknown skill: " + ref


def test_every_skill_has_a_golden_case():
    assert {c["expect"] for c in CASES} == set(IDS)


@pytest.mark.parametrize("case", CASES, ids=[c["account"] for c in CASES])
def test_matcher_golden_cases(case):
    r = facts_for(case)
    allowed = r["candidates"]["allowed"]
    assert allowed[0] == case["expect"], (allowed, r["facts"]["signals"])
    assert r["must_escalate"] is case["must_escalate"]
    extras = set(allowed) - {case["expect"], "insufficient-evidence"} - set(case.get("also_allowed", []))
    assert not extras, "unexpected extra candidates: %s" % extras


@pytest.mark.parametrize("case", CASES, ids=[c["account"] for c in CASES])
def test_end_to_end_with_stand_in_model(case):
    r = handler.handler(ev(case["caller"], case["account"]), None, store=STORE, model=top_choice_model)
    rep = r["report"]
    assert rep and rep["classification_id"] == case["expect"] and rep["next_steps"]
    assert "{" not in " ".join(rep["next_steps"]), "unrendered placeholder in a step"
    assert rep["escalate"] is rules(case["expect"])["escalate"]


def test_null_signals_never_make_a_skill_eligible():
    empty = {k: None for k in facts_for(CASES[0])["facts"]["signals"]}
    out = skillmatch.match(empty, {i: rules(i) for i in IDS})
    assert out["eligible"] == ["insufficient-evidence"] and out["must_escalate"] is False


def test_prompt_discloses_full_text_only_for_allowed_choices():
    r = facts_for(CASES[0])
    skills = explain.load_skills(STORE)
    matched = skillmatch.match(r["facts"]["signals"], skills["rules"])
    steps = {i: skillmatch.render_steps(skills["rules"][i], r["facts"]) for i in skillmatch.allowed_choices(matched)}
    text = explain.build_user_text(r["facts"], skills, matched, steps)
    assert "SKILL stale-credential:" in text and "SKILL kerberos-clock-skew:" not in text
    assert text.count('"description"') == len(IDS)     # one line per skill in the index
    assert len(text) < 30000

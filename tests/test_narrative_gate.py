"""The narrative gate: numbers must come from the evidence, and some advice can never be shown."""
import pytest
from conftest import STORE, ev, top_choice_model
import handler

GOOD = ("Failures for svc-batch01 began at 2026-11-12T09:05:02Z, 5.0 minutes after the password change at 09:00, "
        "and come almost entirely from APP-BATCH07 (10.20.30.41). There are 103 failures in the 24 hour window, "
        "98% from that host, repeating about every 299.0 seconds (5.0 minutes) with Kerberos code 0x18 on event 4771. "
        "3 lockouts were recorded.")


def run(narrative, account="svc-batch01"):
    def m(f, s, matched, steps):
        rep, meta = top_choice_model(f, s, matched, steps)
        rep["narrative"] = narrative
        return rep, meta
    return handler.handler(ev("E1001", account), None, store=STORE, model=m)


def test_a_faithful_narrative_passes():
    r = run(GOOD)
    assert r["report"] is not None, r["notes"]


@pytest.mark.parametrize("text,err", [
    ("There were 9000 failures from APP-BATCH07.", "unseen_number:9000"),
    ("Failures started at 03:17 from APP-BATCH07.", "unseen_time:03:17"),
    ("This has been happening since 2026-10-01 on APP-BATCH07.", "unseen_date:2026-10-01"),
    ("About 17 different systems are involved.", "unseen_number:17"),
    ("APP-BATCH07 retries every 45 seconds.", "unseen_number:45"),
])
def test_invented_numbers_times_and_dates_are_rejected(text, err):
    r = run(text)
    assert r["report"] is None and err in r["notes"][0]


@pytest.mark.parametrize("text,name", [
    ("Ask the identity team to disable MFA for this account so the job can run.", "policy_bypass_advice"),
    ("You could request an exclusion from the conditional access policy.", "policy_bypass_advice"),
    ("The simplest fix is to turn off the lockout policy for svc-batch01.", "policy_bypass_advice"),
    ("The account locks because it hit the lockout threshold.", "threshold_disclosure"),
    ("You get a few more attempts before the account locks again.", "threshold_disclosure"),
    ("I have unlocked the account for you.", "claims_action_taken"),
    ("We will reset the password shortly.", "claims_action_taken"),
    ("Your account has been compromised.", "compromise_verdict"),
    ("Reply with your password so this can be verified.", "credential_request"),
])
def test_forbidden_advice_and_claims_are_rejected(text, name):
    r = run(text + " Source host APP-BATCH07.")
    assert r["report"] is None and ("forbidden:" + name) in r["notes"][0]


@pytest.mark.parametrize("text", [
    "The stored password on APP-BATCH07 is out of date. Unlocking alone will not hold until it is updated.",
    "No password change is needed. The restriction is a control that the identity team owns.",
    "Access policy blocked the sign-in. The password is not the issue.",
    "The failures do not show that anyone signed in.",
])
def test_ordinary_explanations_are_not_caught_by_the_forbidden_list(text):
    assert run(text)["report"] is not None


def test_percent_form_of_a_share_and_window_length_are_allowed():
    r = run("98% of the 103 failures in the last 24 hours came from APP-BATCH07.")
    assert r["report"] is not None, r["notes"]


def test_full_timestamps_must_match_the_evidence():
    assert run("First failure at 2026-11-12T09:05:02Z on APP-BATCH07.")["report"] is not None
    r = run("First failure at 2026-11-12T04:44:00Z on APP-BATCH07.")
    assert r["report"] is None and "unseen_time:2026-11-12T04:44:00Z" in r["notes"][0]

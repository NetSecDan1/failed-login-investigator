"""Per-caller rate limit and the investigation reference."""
import json, re
import pytest
from conftest import STORE, ev, no_model
import handler, ratelimit, render, scope


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    ratelimit._memory.clear()
    monkeypatch.delenv("RATE_LIMIT_TABLE", raising=False)


def run(event):
    return handler.handler(event, None, store=STORE, model=no_model)


def test_off_by_default():
    assert all(run(ev("E1001", "svc-batch01"))["status"] == "ok" for _ in range(5))


def test_limit_is_per_caller_and_counts_denied_attempts(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", "3")
    assert run(ev("E1001", "svc-batch01"))["status"] == "ok"
    assert run(ev("E1001", "svc-payroll"))["reason"] == "out_of_scope"       # a probe spends allowance too
    assert run(ev("E1001", "no-such-account"))["reason"] == "out_of_scope"
    assert run(ev("E1001", "svc-batch01"))["reason"] == "rate_limited"
    assert run(ev("e1001", "svc-batch01"))["reason"] == "rate_limited"       # case does not buy a new bucket
    assert run(ev("E5000", "ev-skew"))["status"] == "ok"                     # another caller is unaffected
    assert run({"claims": {"employee_id": "E1001"}, "action": "list_accounts"})["status"] == "ok"   # listing is not counted


def test_limit_resets_each_hour():
    import os
    os.environ["RATE_LIMIT_PER_HOUR"] = "1"
    try:
        assert ratelimit.check("E1", now=3600 * 100)["used"] == 1
        with pytest.raises(scope.Denied):
            ratelimit.check("E1", now=3600 * 100 + 59)
        assert ratelimit.check("E1", now=3600 * 101)["used"] == 1
        assert len(ratelimit._memory) == 1
    finally:
        del os.environ["RATE_LIMIT_PER_HOUR"]


class FakeTable:
    def __init__(self, boom=False):
        self.boom, self.calls, self.n = boom, [], 0

    def update_item(self, **kw):
        self.calls.append(kw)
        if self.boom:
            raise RuntimeError("throttled")
        self.n += 1
        return {"Attributes": {"attempts": {"N": str(self.n)}}}


def test_table_counter_is_atomic_keyed_by_caller_and_hour_and_expires(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", "2"); monkeypatch.setenv("RATE_LIMIT_TABLE", "t")
    t = FakeTable()
    assert ratelimit.check("E1001", now=1_800_000_000, table_client=t) == {"used": 1, "limit": 2}
    assert ratelimit.check("E1001", now=1_800_000_000, table_client=t)["used"] == 2
    with pytest.raises(scope.Denied) as e:
        ratelimit.check("E1001", now=1_800_000_000, table_client=t)
    assert e.value.code == "rate_limited"
    call = t.calls[0]
    assert call["TableName"] == "t" and re.fullmatch(r"e1001#\d{10}", call["Key"]["bucket"]["S"])
    assert call["UpdateExpression"].startswith("ADD attempts :one") and call["ExpressionAttributeValues"][":ttl"]["N"] == str(1_800_000_000 + 7200)


def test_a_counter_that_cannot_count_fails_closed(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", "2"); monkeypatch.setenv("RATE_LIMIT_TABLE", "t")
    with pytest.raises(scope.Denied) as e:
        ratelimit.check("E1001", table_client=FakeTable(boom=True))
    assert e.value.code == "rate_limit_unavailable"
    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", "lots")
    with pytest.raises(scope.Denied):
        ratelimit.check("E1001")


def test_rate_limited_over_http_is_429(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", "1"); monkeypatch.setenv("ALLOW_TEST_CLAIMS", "false")
    e = {"routeKey": "POST /investigations", "requestContext": {"http": {"method": "POST"}, "authorizer": {"jwt": {"claims": {"employee_id": "E1001"}}}},
         "body": json.dumps({"account": "svc-batch01", "end": "2026-11-12T18:00:00Z"})}
    assert handler.handler(e, None, store=STORE, model=no_model)["statusCode"] == 200
    assert handler.handler(e, None, store=STORE, model=no_model)["statusCode"] == 429


def test_every_result_carries_a_reference_that_matches_its_audit_line(capsys):
    ok, denied = run(ev("E1001", "svc-batch01")), run(ev("E1001", "svc-payroll"))
    audits = [json.loads(line[6:]) for line in capsys.readouterr().out.splitlines() if line.startswith("AUDIT ")]
    assert [a["reference"] for a in audits] == [ok["reference"], denied["reference"]] and ok["reference"] != denied["reference"]
    assert re.fullmatch(r"INV-\d{8}-[0-9A-F]{8}", ok["reference"])
    assert ("Reference to quote: " + ok["reference"]) in render.to_text(ok)
    assert ("Reference: " + denied["reference"]) in render.to_text(denied)

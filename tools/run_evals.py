#!/usr/bin/env python3
"""Scores the agent on evals/cases.json and prints a scorecard.

  python tools/run_evals.py                          # in process, scripted stand-in model (no model access needed)
  MODEL_ID=... python tools/run_evals.py --model live   # in process, real model through MODEL_ROUTE
  python tools/run_evals.py --target function --function fli-proto-fn   # a deployed function
  python tools/run_evals.py --model live --min-pass-rate 0.9 --json scorecard.json

A scripted run checks the code path only and is labelled as such. Only a live run says anything about model
behavior. Exit code 1 when the pass rate is under --min-pass-rate or any mandatory escalation is missed.
"""
import argparse, contextlib, io, json, os, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
END = "2026-11-12T18:00:00Z"


def scripted_model(facts, skills, matched, steps_by_id):
    import skillmatch
    cid = skillmatch.allowed_choices(matched)[0]
    return ({"classification_id": cid, "confidence": "medium", "evidence_refs": facts["query_ids"][:1],
             "narrative": "Scripted stand-in narrative for %s." % facts["account"],
             "next_step_ids": [1] if steps_by_id[cid] else []}, {"model": "scripted-stand-in"})


def invoke_local(case, model):
    import handler
    event = {"claims": {"employee_id": case["caller"]}, "account": case["account"], "window_hours": 24, "end": END}
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        result = handler.handler(event, None, store=invoke_local.store, model=model)
    audit = next((json.loads(line[6:]) for line in log.getvalue().splitlines() if line.startswith("AUDIT ")), {})
    return result, audit


def invoke_function(case, name, client):
    payload = {"claims": {"employee_id": case["caller"]}, "account": case["account"], "window_hours": 24, "end": END}
    return json.loads(client.invoke(FunctionName=name, Payload=json.dumps(payload))["Payload"].read()), {}


def score(cases, call):
    rows = []
    for c in cases:
        result, audit = call(c)
        rep = result.get("report") or {}
        got = rep.get("classification_id")
        accept = {c["expect"]} | set(c.get("also_allowed", []))
        escalation_ok = result.get("must_escalate") == c["must_escalate"]
        verdict = "WITHHELD" if got is None else ("PASS" if got in accept and escalation_ok else "FAIL")
        rows.append({"account": c["account"], "expect": c["expect"], "got": got, "verdict": verdict,
                     "escalation_correct": escalation_ok, "confidence": rep.get("confidence"),
                     "tokens_in": audit.get("tokens_in", 0), "tokens_out": audit.get("tokens_out", 0),
                     "model_calls": audit.get("model_calls", 0), "validator_rejects": audit.get("validator_rejects", 0),
                     "latency_ms": audit.get("latency_ms", result.get("ms", 0)), "notes": "; ".join(result.get("notes", []))[:160]})
    answered = [r for r in rows if r["verdict"] != "WITHHELD"]
    passed = [r for r in rows if r["verdict"] == "PASS"]
    tokens = sum(r["tokens_in"] + r["tokens_out"] for r in rows)
    return {"cases": len(rows), "passed": len(passed), "failed": len(answered) - len(passed), "withheld": len(rows) - len(answered),
            "pass_rate_of_all_cases": round(len(passed) / len(rows), 3) if rows else None,
            "escalation_correct": sum(r["escalation_correct"] for r in rows),
            "missed_mandatory_escalations": sum(1 for r, c in zip(rows, cases) if c["must_escalate"] and not r["escalation_correct"]),
            "validator_rejects": sum(r["validator_rejects"] for r in rows), "model_calls": sum(r["model_calls"] for r in rows),
            "tokens_in": sum(r["tokens_in"] for r in rows), "tokens_out": sum(r["tokens_out"] for r in rows),
            "tokens_per_passed_case": round(tokens / len(passed)) if passed and tokens else None, "rows": rows}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", choices=["local", "function"], default="local")
    ap.add_argument("--function", default="fli-proto-fn")
    ap.add_argument("--model", choices=["scripted", "live"], default="scripted")
    ap.add_argument("--min-pass-rate", type=float, default=1.0)
    ap.add_argument("--json", help="also write the scorecard to this file")
    a = ap.parse_args(argv)
    cases = json.load(open(os.path.join(ROOT, "evals", "cases.json")))
    if a.target == "function":
        import boto3
        client = boto3.client("lambda")
        card = score(cases, lambda c: invoke_function(c, a.function, client))
        card["mode"] = "deployed function %s (model as configured there)" % a.function
    else:
        import redteam
        os.environ["ALLOW_TEST_CLAIMS"] = "true"
        invoke_local.store = redteam.local_store()
        model = scripted_model if a.model == "scripted" else None
        card = score(cases, lambda c: invoke_local(c, model))
        card["mode"] = ("SCRIPTED stand-in model: code path only, says nothing about model behavior" if model
                        else "live model %s via route %s" % (os.environ.get("MODEL_ID"), os.environ.get("MODEL_ROUTE", "bedrock")))
    for r in card["rows"]:
        print("%-8s %-15s expect=%-36s got=%-36s %s" % (r["verdict"], r["account"], r["expect"], r["got"], r["notes"]))
    summary = {k: v for k, v in card.items() if k != "rows"}
    print("\n" + json.dumps(summary, indent=1))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(card, f, indent=1)
    ok = card["pass_rate_of_all_cases"] is not None and card["pass_rate_of_all_cases"] >= a.min_pass_rate \
        and card["missed_mandatory_escalations"] == 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

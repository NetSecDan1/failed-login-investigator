#!/usr/bin/env python3
"""Runs evals/cases.json against the deployed function and scores the model's choices.

Usage: python tools/run_evals.py [--function fli-proto-fn]
Needs AWS credentials that may invoke the function. Each case is one model call.
Exit code 1 if any case fails, so it can gate a pipeline.
"""
import json, os, sys

import boto3

fn = sys.argv[sys.argv.index("--function") + 1] if "--function" in sys.argv else "fli-proto-fn"
cases = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evals", "cases.json")))
client, failed, withheld = boto3.client("lambda"), 0, 0
for c in cases:
    payload = {"claims": {"employee_id": c["caller"]}, "account": c["account"], "window_hours": 24, "end": "2026-11-12T18:00:00Z"}
    r = json.loads(client.invoke(FunctionName=fn, Payload=json.dumps(payload))["Payload"].read())
    rep = r.get("report") or {}
    got = rep.get("classification_id")
    accept = {c["expect"]} | set(c.get("also_allowed", []))
    if got is None:
        verdict, withheld = "WITHHELD", withheld + 1
    elif got in accept and r.get("must_escalate") == c["must_escalate"]:
        verdict = "PASS"
    else:
        verdict, failed = "FAIL", failed + 1
    print("%-8s %-15s expect=%-36s got=%-36s conf=%-6s notes=%s" % (
        verdict, c["account"], c["expect"], got, rep.get("confidence", "-"), "; ".join(r.get("notes", []))[:120]))
print("\n%d cases, %d failed, %d withheld (no model answer)" % (len(cases), failed, withheld))
sys.exit(1 if failed else 0)

#!/usr/bin/env python3
"""Cost per successfully completed investigation, from audit lines.

  aws logs tail /aws/lambda/<function> --since 7d | python tools/cost_report.py --in-price 3 --out-price 15
  python tools/cost_report.py audit.log --in-price 3 --out-price 15 --json

Prices are per million tokens and must be supplied: this tool holds no price list, because prices and
negotiated rates change. It reports model cost only. Platform, build, integration and support costs belong in
the return-on-investment calculation and are not visible here.

"Successful" means the request ended with a validated report. Facts-only results and denials still cost
tokens when a model call was made, so their cost is included in the total and spread over the successes.
"""
import argparse, json, sys


def parse(lines):
    for line in lines:
        i = line.find("AUDIT {")
        if i < 0:
            continue
        try:
            yield json.loads(line[i + 6:])
        except ValueError:
            continue


def summarize(records, in_price, out_price):
    recs = [r for r in records if r.get("route", "POST /investigations") == "POST /investigations"]
    by = {}
    for r in recs:
        by[r.get("outcome", "error")] = by.get(r.get("outcome", "error"), 0) + 1
    tin, tout = sum(r.get("tokens_in", 0) for r in recs), sum(r.get("tokens_out", 0) for r in recs)
    cost = tin / 1e6 * in_price + tout / 1e6 * out_price
    ok = by.get("report", 0)
    attempted = ok + by.get("facts_only", 0)
    lat = sorted(r["latency_ms"] for r in recs if r.get("outcome") == "report" and "latency_ms" in r)
    return {
        "investigations_attempted": attempted,
        "successful_reports": ok,
        "success_rate": round(ok / attempted, 3) if attempted else None,
        "facts_only": by.get("facts_only", 0),
        "denied": by.get("denied", 0),
        "mandatory_escalations": sum(1 for r in recs if r.get("must_escalate")),
        "validator_rejects": sum(r.get("validator_rejects", 0) for r in recs),
        "model_calls": sum(r.get("model_calls", 0) for r in recs),
        "tokens_in": tin, "tokens_out": tout,
        "model_cost": round(cost, 4),
        "cost_per_successful_investigation": round(cost / ok, 4) if ok else None,
        "median_latency_ms_successful": lat[len(lat) // 2] if lat else None,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="log file with AUDIT lines. Default: stdin")
    ap.add_argument("--in-price", type=float, required=True, help="price per million input tokens")
    ap.add_argument("--out-price", type=float, required=True, help="price per million output tokens")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    lines = open(a.file) if a.file else sys.stdin
    s = summarize(parse(lines), a.in_price, a.out_price)
    if a.json:
        print(json.dumps(s, indent=1))
    else:
        for k, v in s.items():
            print("%-36s %s" % (k, "not measurable yet" if v is None else v))
    return 0


if __name__ == "__main__":
    sys.exit(main())

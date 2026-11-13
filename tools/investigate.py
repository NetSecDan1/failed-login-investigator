#!/usr/bin/env python3
"""Run one investigation from a laptop. No deployment needed.

  python tools/investigate.py --caller E1001 --list
  python tools/investigate.py --caller E1001 --account svc-batch01
  python tools/investigate.py --caller E1001 --account svc-batch01 --model us.anthropic.claude-sonnet-4-6
  python tools/investigate.py --caller E1001 --account svc-batch01 --json

Ownership and skills are read from the local data/ and skills/ folders. Evidence comes from EVIDENCE_BACKEND
(default: the synthetic files in data/). Without --model the facts and allowed skills are shown and no model is
called. With --model, Bedrock is called using your current AWS credentials, and GUARDRAIL_ID is honoured if set.
The caller is whatever you pass: this tool is for development, not a control.
"""
import argparse, contextlib, glob, io, json, os, subprocess, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))


def local_store():
    import evidence
    if not os.path.isdir(os.path.join(ROOT, "data", "ownership")):
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_data.py")], check=True, stdout=subprocess.DEVNULL)
    files = {}
    for base, prefix in ((os.path.join(ROOT, "data"), ""), (os.path.join(ROOT, "skills"), "skills/")):
        for p in glob.glob(base + "/**/*", recursive=True):
            if os.path.isfile(p):
                files[prefix + os.path.relpath(p, base).replace(os.sep, "/")] = open(p).read()
    return evidence.DictStore(files)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--caller", required=True)
    ap.add_argument("--account")
    ap.add_argument("--list", action="store_true", help="list the accounts the caller owns")
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--end", default=None, help="window end, ISO time. Default: 2026-11-12T18:00:00Z for the synthetic data, now otherwise")
    ap.add_argument("--model", default=None, help="Bedrock model or inference profile ID. Omit to skip the model")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--show-audit", action="store_true")
    a = ap.parse_args(argv)
    if not a.list and not a.account:
        ap.error("give --account or --list")

    os.environ["ALLOW_TEST_CLAIMS"] = "true"
    import handler, render
    synthetic = os.environ.get("EVIDENCE_BACKEND", "file") == "file"
    event = {"claims": {os.environ.get("CALLER_CLAIM", "employee_id"): a.caller}}
    if a.list:
        event["action"] = "list_accounts"
    else:
        event.update(account=a.account, window_hours=a.hours)
        end = a.end or ("2026-11-12T18:00:00Z" if synthetic else None)
        if end:
            event["end"] = end
    model = None
    if a.model:
        os.environ["MODEL_ID"] = a.model
    else:
        model = lambda *args: (None, {"reason": "model_not_requested"})
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = handler.handler(event, None, store=local_store(), model=model)
    print(json.dumps(result, indent=1) if a.json else render.to_text(result))
    if a.show_audit:
        print("\n" + buf.getvalue().strip(), file=sys.stderr)
    return 0 if result.get("status") == "ok" else 2


if __name__ == "__main__":
    sys.exit(main())

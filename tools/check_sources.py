#!/usr/bin/env python3
"""Measure the configured evidence sources: are they collecting, and how far behind are they running.

Run this with the same settings the service uses, from somewhere allowed to reach the sources. It asks each
source only for aggregate activity in the last hours, never for any account's events. Use the lag it prints to
choose SOURCE_MAX_LAG_MINUTES and to decide whether a source is fresh enough for live triage.

  python tools/check_sources.py                 # last 24 hours
  python tools/check_sources.py --hours 6 --json

Exit status: 0 when every configured source answered and holds events, 1 otherwise.
"""
import argparse, json, os, sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

LABEL = {"windows": "directory logon events", "entra": "cloud sign-in events"}


def measure(backend, hours, now=None):
    import findings
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    rows = []
    for source, h in backend.health(start, now).items():
        row = {"source": source, "what": LABEL[source], "state": "ok", "events": None, "reporting_hosts": None,
               "newest": None, "lag_minutes": None}
        if h == "not_configured":
            row["state"] = "not_configured"
        elif h is None:
            row["state"] = "could_not_check"
        else:
            row.update(events=h["events"], reporting_hosts=h.get("reporting_hosts"), newest=h.get("newest"))
            if not h["events"]:
                row["state"] = "no_events"
            elif h.get("newest"):
                row["lag_minutes"] = findings.lag_minutes(h["newest"], now, now)
        rows.append(row)
    return rows


def main(argv=None, backend=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not 1 <= args.hours <= 168:
        ap.error("--hours must be between 1 and 168")
    if backend is None:
        import adapters, evidence
        bucket = os.environ.get("DATA_BUCKET")
        backend = adapters.make_backend(evidence.S3Store(bucket) if bucket else evidence.DictStore({}))
    rows = measure(backend, args.hours)
    if args.json:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            lag = "newest event %s, %d minutes behind" % (r["newest"], r["lag_minutes"]) if r["lag_minutes"] is not None else "no newest-event time"
            hosts = ", %d hosts reporting" % r["reporting_hosts"] if r["reporting_hosts"] is not None else ""
            detail = "%d events%s, %s" % (r["events"], hosts, lag) if r["events"] is not None else ""
            print("%-24s %-16s %s" % (r["what"], r["state"], detail))
    return 0 if all(r["state"] in ("ok", "not_configured") for r in rows) and any(r["state"] == "ok" for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())

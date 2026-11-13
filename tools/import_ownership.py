#!/usr/bin/env python3
"""Converts an ownership report (CSV) into the ownership.json the scope resolver reads.

A scheduled IIQ report dropped as CSV is the simplest honest first step before calling the IIQ API.

  python tools/import_ownership.py report.csv --out data/ownership/ownership.json \\
      --owner-col "Owner Employee ID" --account-col "Account Name" \\
      --app-col Application --type-col "Account Type" --tier-col Tier --deny-file deny.txt

Rules:
- Rows with an empty owner or an account name that is not a plain account name are skipped and counted.
- Tier defaults to "unknown", which the resolver treats as owned but not Tier 0. Pass --require-tier to
  refuse to write a file when any row lacks a tier, which is the safer setting for production.
- Nothing is inferred. If the report does not say who owns an account, nobody does.
"""
import argparse, csv, json, re, sys
from datetime import datetime, timezone

ACCOUNT_RE = re.compile(r"^[a-z0-9._$-]{1,64}$")
TYPES = {"person": "person", "user": "person", "human": "person", "service": "service", "svc": "service",
         "application": "service", "privileged": "privileged", "admin": "privileged"}


def convert(rows, cols, require_tier=False):
    owners, skipped, missing_tier = {}, 0, 0
    for row in rows:
        owner = (row.get(cols["owner"]) or "").strip()
        account = (row.get(cols["account"]) or "").strip().lower()
        if not owner or not ACCOUNT_RE.fullmatch(account):
            skipped += 1
            continue
        raw_tier = (row.get(cols.get("tier") or "") or "").strip().lower().replace("tier", "").strip()
        tier = int(raw_tier) if raw_tier.isdigit() else None
        missing_tier += tier is None
        entry = {"account": account, "application": (row.get(cols.get("app") or "") or "").strip() or "unknown",
                 "tier": tier if tier is not None else "unknown",
                 "type": TYPES.get((row.get(cols.get("type") or "") or "").strip().lower(), "unknown")}
        bucket = owners.setdefault(owner, [])
        if all(e["account"] != account for e in bucket):
            bucket.append(entry)
    if require_tier and missing_tier:
        raise SystemExit("%d rows have no tier and --require-tier is set. Nothing written." % missing_tier)
    return owners, {"skipped_rows": skipped, "rows_without_tier": missing_tier,
                    "owners": len(owners), "accounts": sum(len(v) for v in owners.values())}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_path")
    ap.add_argument("--out", required=True)
    ap.add_argument("--owner-col", required=True)
    ap.add_argument("--account-col", required=True)
    ap.add_argument("--app-col"); ap.add_argument("--type-col"); ap.add_argument("--tier-col")
    ap.add_argument("--deny-file", help="text file, one account per line, never investigable through self-service")
    ap.add_argument("--require-tier", action="store_true")
    a = ap.parse_args(argv)
    with open(a.csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for needed in (a.owner_col, a.account_col):
            if needed not in (reader.fieldnames or []):
                raise SystemExit("column not found: %r. Columns are: %s" % (needed, reader.fieldnames))
        owners, stats = convert(reader, {"owner": a.owner_col, "account": a.account_col, "app": a.app_col,
                                         "type": a.type_col, "tier": a.tier_col}, a.require_tier)
    deny = []
    if a.deny_file:
        deny = sorted({line.strip().lower() for line in open(a.deny_file) if line.strip() and not line.startswith("#")})
    out = {"_source": a.csv_path, "_generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "_stats": stats, "owners": owners, "deny_list": deny}
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1)
    print(json.dumps(stats))
    return 0


if __name__ == "__main__":
    sys.exit(main())

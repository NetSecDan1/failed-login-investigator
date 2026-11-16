# Evidence sources

The agent is not built around any one log product. It asks for three kinds of evidence through one contract,
and a small adapter per source answers. Which source answers which kind is configuration.

**Status: every adapter except `file` has been tested against fake responses only. None has run against a live
system.** Expect to adjust `config/field_map.json` and the templates in `queries/` on first contact.

## The contract

| Kind | What it is | Used for |
|------|------------|----------|
| `failed_logins` | Failed logon events from the directory: 4625, 4771, 4776 | Sources, codes, rhythm, protocol |
| `account_events` | Lockouts, password changes and resets, unlocks: 4740, 4723, 4724, 4767 | Timing against failures |
| `entra_failures` | Failed sign-ins at the cloud identity provider | Cloud-side causes: access policy, legacy clients, MFA |

An adapter receives `(kind, account, start, end)` plus the account's cloud sign-in name when the ownership source
has one. It returns rows in the internal shape, or an error. It must:

1. Check scope before any I/O. The base class does this.
2. Ask only for that account and that window. No free-text queries.
3. Be read-only, over https, with certificate verification on.
4. Turn any failure into a reported gap, never a crash, and never put a credential in an error.
5. Answer a source activity count with no account in it, so a silent source is not read as a clean account.

`tests/test_adapters.py` runs these as a shared contract against every adapter.

## Adapters

| Name | Answers | How it reads | Freshness | Access it needs |
|------|---------|--------------|-----------|-----------------|
| `file` | all three | Synthetic JSON in the data bucket | n/a | Prototype and tests only |
| `splunk` | all three | Search export REST call with a fixed search | Indexing delay | A role limited to the indexes used |
| `databricks` | all three | SQL statement API with bound parameters | Pipeline delay, often batch | `SELECT` on up to three views |
| `export` | all three | Scheduled report files dropped in the data bucket | The export schedule | Read on one bucket prefix. The exporting tool needs write there |
| `graph` | `entra_failures` | The identity provider's sign-in log API | Minutes | A read-only application with tenant-wide sign-in log read |
| `loganalytics` | `entra_failures` | A query against a log workspace the provider exports to | Export delay, usually minutes | A read-only application with read on that workspace's sign-in tables |
| `none` | nothing | Placeholder for a kind with no source yet | n/a | Nothing. Every report carries the gap |

## Routing each kind to a source

```bash
EVIDENCE_BACKEND=splunk                                              # one source for everything
EVIDENCE_SOURCES=failed_logins=splunk,account_events=splunk,entra_failures=none
```

`EVIDENCE_BACKEND` is the default and `EVIDENCE_SOURCES` overrides it per kind. A typical path is to start
with directory evidence from the log platform already in place and `entra_failures=none`, then switch the
cloud kind to a real source later. That switch is one setting and no code. Until then the directory-side skills
work, the cloud-side skills simply never become eligible, and each report states that cloud sign-in evidence
is not configured.

## More than one source for a kind

A kind can list several sources, joined with `+` and tried in order:

```bash
EVIDENCE_SOURCES=entra_failures=loganalytics+graph
```

The first source that is switched on and answers wins. An answer with no rows is still an answer, so a quiet
account never triggers a second lookup. A source is passed over only when it is switched off, failing, or cannot
answer that kind. When a later source covers for an earlier one, the audit line records it under
`sources_passed_over`, and the query reference in the report names the source that actually answered.

Put the source with the narrower access first. In the example the workspace query is the everyday path and the
sign-in log API is held in reserve.

## Switching a source on or off while running

Every configured source can be turned off without a deployment, and turned back on the same way. There are two
switches, and both can only take a source away. Neither can add a source, change a route or point a kind at
synthetic data, so the worst a mistaken or malicious switch can do is produce a report that states a gap.

| Switch | How | Takes effect |
|--------|-----|--------------|
| `SOURCES_DISABLED=graph` | A setting on the workload | When the setting is saved |
| Switch file | Set `SOURCE_SWITCH_KEY=runtime/switches.json`, then put `{"disabled_sources": ["graph"]}` at that key in the data bucket | Within one minute, no restart |

Ready-made switch files are in `examples/switches/`. Behavior to rely on:

- No switch file means nothing extra is off.
- A switch file that exists but cannot be read or understood turns every switchable source off, and each report
  says `switch_file_invalid`. An operator who meant to pull a source and made a typo must not find it still running.
- With every source for a kind off, the report states `source_switched_off` for that kind and the remaining
  evidence is still explained.
- Write access to the switch key is an operational control. Give it to the people allowed to pull a source, and
  keep bucket versioning on so every flip has a history.

## Cloud sign-in evidence: choosing a path

Directory events and cloud sign-ins often live in different places. These are the realistic ways to get the
cloud side, with the tradeoffs that usually decide it. None is assumed correct here. The right one depends on
what the identity platform owner, the security team and the log platform owner will each sanction.

| Path | Adapter | Freshness | Blast radius of the credential | Extra moving parts | Watch out for |
|------|---------|-----------|--------------------------------|--------------------|---------------|
| A. Sign-in log API, read-only application | `graph` | Minutes | High: the permission reads every sign-in in the tenant. This code is the only narrowing | None | Needs security sign-off for a tenant-wide read. API retention is short. Non-interactive and service sign-ins need a different endpoint and are not covered by this adapter yet |
| B. Log workspace query, read-only application | `loganalytics` | Minutes after export | Medium: can be limited to the sign-in tables of one workspace | The provider's log export to a workspace | Only works if that export exists. Includes non-interactive and service sign-ins |
| C. Stream the provider's logs into the existing log platform | the adapter already in use | Minutes | Low: no new credential, same role as directory evidence | An export stream and an ingestion add-on | Ingest volume and cost. One query path for everything, which is the simplest to operate |
| D. Land the logs in a lakehouse | `databricks` | Depends on the pipeline, hours if batch | Low: `SELECT` on views | A landing pipeline and views | A batch pipeline can lag behind an active lockout. Check how fresh the newest row is before relying on it |
| E. Scheduled report export | `export` | The schedule | Low: read on one bucket prefix | A scheduled job in the reporting tool | Coarse and delayed. Useful as a stopgap or for a directory auditing product with no query API |

How to decide:

1. **If the cloud logs already flow somewhere queryable, use that place.** No new credential beats any new credential.
2. **If freshness matters most and security will sanction it, A or B.** Prefer B when the workspace export exists,
   because its access can be scoped to tables. Choose A only with an explicit sign-off for tenant-wide read.
3. **If the long-term log home is a lakehouse, measure its lag first.** Run the source health check and compare the
   newest row with the clock. Lockout questions are asked while the lockout is happening. A source that is hours
   behind will answer "nothing found" to a real problem.
4. **A and B together are a reasonable pair.** Route the cloud kind to `loganalytics+graph` so the scoped workspace
   is the everyday path and the API covers a workspace outage, or run with the API switched off until its sign-off
   lands. Both are built, and either can be turned off at run time.
5. **A mixed setup is normal.** Directory evidence from one source and cloud evidence from another is exactly what
   per-kind routing is for.

Whatever the path, the account's cloud sign-in name comes from the ownership source (`signin_name`), never from a
request. An account with no sign-in name on record gets a stated gap, not a guess.

## Settings

Every setting is listed in [`CONFIGURATION.md`](CONFIGURATION.md). Run `python tools/preflight.py` on a planned
environment: it checks that each routed source has what it needs and that no kind still resolves to synthetic data.

## First contact checklist

1. **Get a read-only identity** with the narrowest access the source allows (see the Adapters table).
2. **Run the query by hand** in the source's own interface for an account you own, using the text of the matching
   file in `queries/`. Note the real field names.
3. **Edit `config/field_map.json`.** For each internal field, list your source field names in order of preference.
   The first one present and not empty wins. `0x0` and `-` are skipped, so a 4625 event with an empty sub-status
   falls through to the status.
4. **Try it from a workstation on the network** before deploying anything:
   ```bash
   export EVIDENCE_BACKEND=<source> ...its settings...
   python tools/investigate.py --caller <you> --account <an account you own> --hours 24 --show-audit
   ```
   Ownership still comes from `data/ownership/ownership.json` here, so add yourself to it for the test.
5. **Check the result against the raw query.** Counts, top host, first and last seen must match. Then check `gaps`
   and the audit line for `source_errors` and `rows_dropped_no_time`.
6. **Check coverage and lag.** Confirm every domain controller forwards 4771, 4776 and 4740, and that the newest
   row in the source is recent.

## Source health check

A source that collected nothing looks exactly like a clean account. So each investigation also asks every source
one aggregate question: how many events did you hold from anyone in this window, and from how many reporting
hosts. The query contains no account and returns a count, never rows.

- Zero events: the report lists the source under gaps as possibly broken collection.
- `EXPECTED_REPORTING_HOSTS` set and fewer hosts reported: the report says how many were seen.
- The check itself fails: the report says collection could not be checked.
- A kind routed to `none` is reported once as not configured.
- `SOURCE_HEALTH_CHECK=false` turns the check off.

Time bounds are sent as request parameters or bound parameters, never written into query text.

## What the normalizer handles

- Time as ISO with any offset, `YYYY-MM-DD HH:MM:SS` (taken as UTC), or epoch seconds. Output is always UTC.
  Times outside 2000 to 2100 are dropped as corrupt.
- Kerberos client addresses logged as `::ffff:10.1.2.3`, and workstation names logged with leading backslashes.
- Multivalue fields (first value used) and one level of nested fields (`status.errorCode`).
- Rows with no usable time are dropped and counted, never guessed.

## Scheduled report exports

For a tool that can schedule a report but offers no query API the workload may call, have it write one file per
UTC day:

```
<EXPORT_PREFIX>/failed_logins/2026-11-12.csv      (or .jsonl, .json)
<EXPORT_PREFIX>/account_events/2026-11-12.csv
<EXPORT_PREFIX>/entra_failures/2026-11-12.jsonl
```

Column names are mapped in `config/field_map.json`, including `account_fields`, the columns that may hold the
account name. A day with no file is treated as absent. A file that exists but cannot be read is an error, so a
permission problem is never mistaken for a quiet day. Files over 20 MB are refused: this adapter is for modest
audit reports, not a full log feed.

## Ownership from a governance report

Until a live ownership API is connected, a scheduled ownership report exported as CSV is the simplest honest source:

```bash
python tools/import_ownership.py report.csv --out data/ownership/ownership.json \
  --owner-col "Owner Employee ID" --account-col "Account Name" \
  --app-col Application --type-col "Account Type" --tier-col Tier \
  --signin-col "Sign-in Name" --deny-file deny.txt --require-tier
```

- The owner column must hold the same identifier as the token claim set in `CALLER_CLAIM`.
- `--signin-col` records each account's cloud sign-in name, which the cloud sources need.
- Rows with no owner or a malformed account name are skipped and counted. Nothing is inferred.
- `--require-tier` refuses to write a file if any row lacks a tier.
- Set `OWNERSHIP_MAX_AGE_HOURS` so an old file is treated as an outage.

## Network and secrets

- A workload in a private network needs a route to each source, plus private endpoints or egress for the model
  route, object storage, the secrets service and logging.
- Each credential is read from the secrets service by reference. Plain-token settings exist for local runs only
  and the preflight blocks them.
- Corporate TLS inspection: point `SSL_CERT_FILE` at your CA bundle. Certificate verification is never turned off.

## Adding a source

1. Subclass `backends.Backend` in `src/adapters.py` or a module of its own. Implement `fetch` and `health_counts`.
   Set `kinds` to what it can answer.
2. Keep requests fixed-shape: a template in `queries/` rendered by `src/querypack.py`, or parameters built in code.
3. Add one line to `adapters.REGISTRY`, its settings to `config/settings.json` with production rules, and its
   required settings to `tools/preflight.py`.
4. Add it to `NAMES` in `tests/test_adapters.py` so the shared contract runs against it, and add tests for its
   request shape with a scripted transport.
5. Map its field names in `config/field_map.json`.
6. Record in `docs/STATUS.md` that it is tested against fake responses only, until it has run live.

### Directory auditing products

A directory auditing product that schedules reports is covered by this adapter today: schedule its failed-logon,
lockout and password-change reports to the layout above and map its column names in `config/field_map.json`. That
is a file hand-off, not a live query, so evidence is as fresh as the schedule. A direct adapter is only worth
writing for a product with a documented, read-only query interface the workload is allowed to call. If the
product can forward its events to the log platform already in use, that route needs no adapter at all.

## Not built yet

- A direct query adapter for a directory auditing product. The scheduled export path above is what exists.

- A live ownership API adapter, and non-interactive sign-ins through the sign-in log API.
- Paging beyond the row caps.

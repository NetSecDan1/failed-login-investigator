# Connecting real evidence

The pipeline reads evidence through three functions in `src/evidence.py`. `EVIDENCE_BACKEND` chooses what
answers them: `file` (synthetic, default), `splunk` or `databricks`. Nothing else in the pipeline changes.

**Status: the Splunk and Databricks backends pass unit tests against fake responses. They have not been run
against a live system.** Expect to adjust `config/field_map.json` and the templates in `queries/` on first contact.

## What each backend sends

| Backend | Request | Read-only because |
|---------|---------|-------------------|
| Splunk | `POST {base}/services/search/jobs/export` with one rendered search, `output_mode=json` | The token's role should allow search on two indexes and nothing else |
| Databricks | `POST {host}/api/2.0/sql/statements` with one `SELECT` and three named parameters | The token's principal should hold `SELECT` on three views and nothing else |

Scope is checked before any request leaves. A failed request never crashes an investigation: it becomes an
empty result with `source_unavailable`, the report lists it under gaps, and the detail goes to the audit line only.

## Settings

| Variable | Backend | Meaning |
|----------|---------|---------|
| `EVIDENCE_BACKEND` | all | `file`, `splunk` or `databricks` |
| `SPLUNK_BASE_URL` | Splunk | Management endpoint, https only, for example `https://splunk.example.com:8089` |
| `SPLUNK_INDEX_WINDOWS`, `SPLUNK_INDEX_ENTRA` | Splunk | Index names. Must be plain identifiers |
| `SPLUNK_TOKEN_SECRET_ARN` | Splunk | Secrets Manager secret holding the token as a plain string |
| `DATABRICKS_HOST`, `DATABRICKS_WAREHOUSE_ID` | Databricks | Workspace URL (https) and SQL warehouse ID |
| `DATABRICKS_VIEW_FAILED_LOGINS`, `_ACCOUNT_EVENTS`, `_ENTRA_FAILURES` | Databricks | Three-part view names |
| `DATABRICKS_TOKEN_SECRET_ARN` | Databricks | Secrets Manager secret holding the token |
| `FIELD_MAP_PATH` | both | Optional path to a field map other than `config/field_map.json` |

For local runs only, `SPLUNK_TOKEN` or `DATABRICKS_TOKEN` may hold the token directly. Do not set those in a deployed function.

In the stack these are template parameters: `EvidenceBackend`, `SplunkBaseUrl`, `SplunkIndexWindows`,
`SplunkIndexEntra`, `DatabricksHost`, `DatabricksWarehouseId`, `DatabricksView*`, `BackendTokenSecretArn`, and
`VpcSubnetIds` with `VpcSecurityGroupIds` when the source is only reachable inside your network.

## First contact checklist

1. **Get a read-only identity.** Splunk: a role limited to the two indexes, token authentication. Databricks: a
   service principal with `SELECT` on three views that expose only the columns in `queries/*.sql`.
2. **Run one search by hand** in the Splunk or Databricks UI for an account you own, using the text of the
   matching file in `queries/`. Note the real field names.
3. **Edit `config/field_map.json`.** For each internal field, list your source field names in order of preference.
   The first one present and not empty wins. `0x0` and `-` are skipped, so a 4625 event with `Sub_Status=0x0`
   falls through to `Status`.
4. **Try it from a laptop on the network** before deploying anything:
   ```bash
   export EVIDENCE_BACKEND=splunk SPLUNK_BASE_URL=https://... SPLUNK_INDEX_WINDOWS=... SPLUNK_INDEX_ENTRA=...
   export SPLUNK_TOKEN=...            # local only
   python tools/investigate.py --caller <you> --account <an account you own> --hours 24 --show-audit
   ```
   Ownership still comes from `data/ownership/ownership.json` here, so add yourself to it for the test.
5. **Check the result against the raw search.** Counts, top host, first and last seen must match. Then check
   `gaps` and the audit line for `source_errors` and `rows_dropped_no_time`.
6. **Check coverage.** Confirm every domain controller forwards 4771, 4776 and 4740. A quiet source reads the
   same as a clean one.

## What the normalizer handles

- Time as ISO with any offset, `YYYY-MM-DD HH:MM:SS` (taken as UTC), or epoch seconds. Output is always UTC.
- Kerberos client addresses logged as `::ffff:10.1.2.3`.
- NTLM workstation names logged with leading backslashes.
- Splunk multivalue fields (first value used).
- Rows with no usable time are dropped and counted, never guessed.

## Network and secrets in AWS

- A function in a VPC needs a route to the source, plus VPC endpoints (or NAT) for Bedrock runtime, S3,
  Secrets Manager and CloudWatch Logs.
- The role gains `secretsmanager:GetSecretValue` on the one secret ARN only when `BackendTokenSecretArn` is set.
- Corporate TLS inspection: point `SSL_CERT_FILE` at your CA bundle. Certificate verification is never turned off in this code.

## Ownership from an IIQ report

Until the IIQ API is connected, a scheduled ownership report exported as CSV is the simplest honest source:

```bash
python tools/import_ownership.py report.csv --out data/ownership/ownership.json \
  --owner-col "Owner Employee ID" --account-col "Account Name" \
  --app-col Application --type-col "Account Type" --tier-col Tier \
  --deny-file deny.txt --require-tier
```

- The owner column must hold the same identifier as the token claim set in `CallerClaim`.
- Rows with no owner or a malformed account name are skipped and counted. Nothing is inferred.
- `--require-tier` refuses to write a file if any row lacks a tier. Without it, a missing tier is treated as
  not Tier 0, so use the flag for anything beyond a demo.
- `deny.txt` lists accounts that are never investigable through self-service, one per line.
- Upload the result to `ownership/ownership.json` in the data bucket. Stale ownership is a real risk: record
  how often the report runs and treat an old file as an outage.

## Not built yet

- The IIQ API as a live ownership source, and a freshness check that fails closed when the export is old.
- Paging beyond the row caps, and per-caller rate limits.

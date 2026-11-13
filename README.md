# Failed Login Investigator

A read-only agent on AWS Bedrock that explains why an account keeps failing to log in.
It only looks at accounts the caller owns, and that rule is enforced by code the model cannot touch.

**Status: prototype. Synthetic data only.** No connection to AD, Entra, Splunk, Databricks or IIQ exists in this repo.

## How it works

Nine stages. Eight are deterministic code, one is the model.

| # | Stage | Where | Kind |
|---|-------|-------|------|
| 1 | Authenticate (JWT authorizer claims) | `src/handler.py` | code |
| 2 | Resolve owned accounts, fail closed | `src/scope.py` | code |
| 3 | Validate account and time window | `src/scope.py`, `src/handler.py` | code |
| 4 | Collect evidence through fixed-shape read tools | `src/evidence.py` | code |
| 5 | Compute findings and signals (all numbers) | `src/findings.py` | code |
| 6 | Decide which skills the evidence supports, whether escalation is mandatory, and render approved steps | `src/skillmatch.py` | code |
| 7 | Pick one allowed skill and write the narrative, behind a Bedrock Guardrail | `src/explain.py` | model |
| 8 | Validate the model's output | `src/validator.py` | code |
| 9 | Return facts plus report, write audit line | `src/handler.py` | code |

If the model is unavailable, blocked by the guardrail, or fails validation twice, the caller still gets the
facts table, the escalation flag, and no summary. The design brief is in [`docs/design-brief.html`](docs/design-brief.html).

## What is real and what is a stand-in

| Piece | In this repo | Production target |
|-------|--------------|-------------------|
| Caller identity | Test claims in the event (`ALLOW_TEST_CLAIMS=true`) | Entra JWT through an API Gateway authorizer |
| Ownership | `ownership/ownership.json` in S3, generated | SailPoint IIQ API or scheduled export |
| Evidence | `evidence/<account>.json` in S3, generated | Splunk first, Databricks end state, same three functions |
| Query templates | `queries/` plus `src/querypack.py`, tested but not wired or verified live | Called by the Splunk and Databricks backends |
| Skill files | 13 skills in `skills/`, synced to S3. See [`docs/SKILLS.md`](docs/SKILLS.md) | Same, with pull request review |
| Audit | One `AUDIT` JSON line per request in CloudWatch | Plus immutable S3 copy and forward to the SIEM |

## Quick start

Prerequisite: Anthropic model access in the target account. Bedrock asks first-time accounts to submit
use case details for Anthropic models. Until that is done the function returns facts only.

```bash
./deploy.sh us.anthropic.claude-sonnet-5-5   # creates stack fli-proto in your current region
./run_tests.sh                                # six live cases, one line each
./teardown.sh                                 # removes everything
```

Other ways to deploy, including CloudShell, the CloudFormation console and GitHub Actions: [`docs/DEPLOY.md`](docs/DEPLOY.md).

## Tests

```bash
pip install pytest pyyaml
python -m pytest -q tests                 # offline: pipeline, query renderer, skill lint, matcher golden cases
python tools/run_evals.py                 # live: scores the model on evals/cases.json (needs model access)
```

The offline suite covers scope bypass, fail-closed ownership, template-injection input, Tier 0 and deny-list
exclusion, hostile text planted in log fields, invented entities in model output, a model trying to pick a skill
the evidence does not support, a model trying to talk down a mandatory escalation, and one golden case per skill.

## Guardrails in one list

- No write permissions anywhere. The role allows `s3:GetObject`, `bedrock:InvokeModel`, `bedrock:ApplyGuardrail` and its own log writes, with an explicit deny on everything else.
- Scope is resolved per request from the ownership source and re-checked inside every read tool.
- Unowned and nonexistent accounts get the same answer, so the agent is not an existence oracle.
- Read tools take `(account, start, end)` only. No free-text queries.
- Source host values that are not valid host names never reach the model.
- The model has no data-fetching tools. It can only fill in the report form.
- The model chooses only among skills that code found eligible, and cannot downgrade a mandatory escalation.
- Next steps are approved templates rendered by code. The model returns step numbers, never step text.
- The report is shown only if every host, IP and account in it already appears in the evidence.

## Known limits

- Not 100% safe, and nothing is. What is guaranteed by construction is no write path and no out-of-scope read. Wrong explanations and stale ownership data remain possible.
- The entity check in the validator is a heuristic (tokens that mix letters and digits). Expect occasional false rejects, which fall back to facts only.
- The model-facing wording of the skills has not been evaluated against a live model yet. Thresholds in `rules.json` were set against synthetic data.
- No rate limiting, API, or UI yet.

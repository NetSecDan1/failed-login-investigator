# Failed Login Investigator

A read-only agent that explains why an account keeps failing to log in.
It only looks at accounts the caller owns, and that rule is enforced by code the model cannot touch.

**Status: a constrained prototype, verified on synthetic data only.** It is not approved, not production-ready and
not evidence of compliance with any organization's standard path. [`docs/STATUS.md`](docs/STATUS.md) lists every
requirement with what is and is not evidenced. Contributors and coding agents: read [`AGENTS.md`](AGENTS.md) first.

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
| Caller identity | Test claims in the event (`ALLOW_TEST_CLAIMS=true`) | Entra JWT through the optional HTTP API and JWT authorizer in `template.yaml`. Not yet deployed or tested with a real token |
| Ownership | `ownership/ownership.json` in S3, generated | SailPoint IIQ API or scheduled export |
| Evidence | `evidence/<account>.json` in S3, generated (`EVIDENCE_BACKEND=file`) | Splunk or Databricks through `src/backends.py`. Built and unit tested against fake responses, not yet run live. See [`docs/BACKENDS.md`](docs/BACKENDS.md) |
| Skill files | 13 skills in `skills/`, synced to S3. See [`docs/SKILLS.md`](docs/SKILLS.md) | Same, with pull request review |
| Audit | One `AUDIT` JSON line per request in CloudWatch | Plus immutable S3 copy and forward to the SIEM |

## Quick start

**On a laptop, no AWS needed:**

```bash
python tools/investigate.py --caller E1001 --list
python tools/investigate.py --caller E1001 --account svc-batch01          # facts and allowed skills, no model
python tools/investigate.py --caller E5000 --account ev-legacy --model us.anthropic.claude-sonnet-4-6   # adds the model, uses your AWS credentials
```

**Deployed:**

Prerequisite: Anthropic model access in the target account. Bedrock asks first-time accounts to submit
use case details for Anthropic models. Until that is done the function returns facts only.

```bash
./deploy.sh us.anthropic.claude-sonnet-5-5   # creates stack fli-proto in your current region
./run_tests.sh                                # six live cases, one line each
./teardown.sh                                 # removes everything
```

Other ways to deploy, the HTTP API and its parameters: [`docs/DEPLOY.md`](docs/DEPLOY.md).

## Layout

| Path | What |
|------|------|
| `src/` | The pipeline. `handler.py` is the entry point. `modelroute.py` decides how the model is reached |
| `skills/` | 13 skills, each `SKILL.md` plus `rules.json` |
| `queries/`, `config/field_map.json` | Fixed query templates and the source field mapping |
| `evals/cases.json` | One synthetic case per skill |
| `tools/` | Local CLI, data generator, skill index builder, live eval runner |
| `tests/` | Offline tests, no network |
| `agent/` | Entry point for a managed agent runtime, built on a standard agent framework |
| `infra/` | Optional pipeline deploy role |
| `docs/` | Status, use case, risks, operations, measurement, deploy, skills and backends guides, design brief |

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

## Two ways to run it

| | Function behind an HTTP API | Managed agent runtime |
|---|---|---|
| Code | `src/handler.py`, `template.yaml` | `agent/app.py`, `agent/Dockerfile` |
| Input | Typed request: account and window | Typed request, or a sentence that a routing model maps to one of two typed tools |
| Model use | One call to explain, one retry at most | The same, plus a small routing call for free-text requests |
| State | Deployed once to a sandbox on an early build | Unit tested with a scripted model. Not deployed |

Both run the same pipeline, and in both the reply is rendered by code from validated results. The model is
reached through `MODEL_ROUTE`: `bedrock` for a direct call, or `gateway` for a central model gateway with an
OpenAI-compatible API. Which combination an organization permits is an owner decision recorded in `docs/STATUS.md`.

## Delivery gates

Every push runs unit tests with a coverage floor, lint, static security analysis, a dependency audit, a secret
scan over full history, infrastructure lint, and builds a checksummed artifact. These are stand-ins for whatever
scanners and attestations an adopting organization requires.

## Operating it

[`docs/OPERATIONS.md`](docs/OPERATIONS.md) covers what is logged, metrics, alarms, limits, the kill switch and a
runbook. [`docs/MEASUREMENT.md`](docs/MEASUREMENT.md) covers cost per successfully completed investigation and why
no return on investment is claimed yet. [`docs/RISKS.md`](docs/RISKS.md) is the working risk register.

## Known limits

- Not 100% safe, and nothing is. What is guaranteed by construction is no write path and no out-of-scope read. Wrong explanations and stale ownership data remain possible.
- No live model, token, ownership source, log source or model gateway has been exercised.
- The entity check in the validator is a heuristic (tokens that mix letters and digits). Expect occasional false rejects, which fall back to facts only.
- Skill wording has not been evaluated against a live model. Thresholds in `rules.json` were set against synthetic data.
- API throttling is global, not per caller. No user interface.

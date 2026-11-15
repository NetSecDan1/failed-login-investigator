# Status

The record of what is and is not evidenced. Update it with every change.

**This is a constrained prototype. It is not approved, not production-ready, and not evidence of compliance
with any organization's standard path.** Every test in this repository uses generated data and scripted
stand-ins unless a line below says "live".

Labels: **Implemented and evidenced**, **Partially implemented**, **Not implemented**, **Needs owner confirmation**.

## Requirements

| Area | Requirement | Status | Evidence, and what it does not show |
|------|-------------|--------|--------------------------------------|
| Use case | Problem, users, outcome, success measures, boundaries written down | Implemented and evidenced | `docs/USE_CASE.md`. Values such as data classification are placeholders: **Needs owner confirmation** |
| Boundaries | Read-only, least privilege | Implemented and evidenced | `template.yaml` role with explicit deny. Deployed once to a sandbox on an early build |
| Authority | Code owns identity, scope, retrieval, numbers, skill eligibility, escalation, next steps | Implemented and evidenced | `tests/test_pipeline.py`, `tests/test_skills.py`. Synthetic |
| Authority | Model output validated against evidence and a schema, with a safe fallback | Implemented and evidenced | `tests/test_pipeline.py`. Scripted model only |
| Supported path | Standard agent framework on a managed agent runtime | Partially implemented | `agent/app.py`, `tests/test_agent.py` with a scripted model. Not built into an image, not deployed. Whether this matches an adopting organization's template: **Needs owner confirmation** |
| Supported path | Model access through an approved route | Partially implemented | `src/modelroute.py` supports direct and central-gateway routes. Gateway tested against fake responses only. Which route is approved: **Needs owner confirmation** |
| Supported path | Organization template, repository structure and shared pipelines | Not implemented | This repository uses its own layout and workflows |
| Identity | Real-token authentication | Partially implemented | Authorizer configuration in `template.yaml`, in-application verification in `agent/identity.py`, tested with locally generated keys. No real identity provider token has been used |
| Identity | Live ownership enforcement | Partially implemented | CSV import, freshness check, most-restrictive conflict rule (`tests/test_operations.py`, `tests/test_import_ownership.py`). No live ownership source |
| Data | Evidence from real log sources | Partially implemented | `src/backends.py`, `tests/test_backends.py`. Fake transport only |
| Data | Silent or partial log collection is detected | Partially implemented | Source activity count and expected reporting hosts (`tests/test_backends.py`). Fake transport only. The aggregate queries have not run against a live source |
| Authority | Narrative cannot carry invented numbers, times, dates or unsafe advice | Implemented and evidenced | `tests/test_narrative_gate.py`, `tools/redteam.py`. Scripted models only. The unsafe-advice list is pattern based |
| Delivery | Automated tests for authorization, invalid input, failure paths, leakage, output validation | Implemented and evidenced | Offline test suite, 85% coverage floor enforced in CI |
| Delivery | Build, lint, static security analysis, dependency audit, secret scan, infrastructure lint, checksummed artifact | Implemented and evidenced | `.github/workflows/ci.yml` |
| Delivery | Review rules, change template, security policy, dependency update proposals | Implemented and evidenced | `.github/CODEOWNERS`, `.github/pull_request_template.md`, `SECURITY.md`, `.github/dependabot.yml`. Branch protection is not enabled, and workflow actions are pinned by tag, not by commit |
| Delivery | An adopting organization's required scanners, attestations and release gates | Needs owner confirmation | Not wired in. The CI jobs are stand-ins to be mapped to the required tools |
| Evaluation | Golden inputs and answers | Partially implemented | 15 synthetic cases, scored in CI with a scripted stand-in model (`tools/run_evals.py`). **No live model evaluation has been run** |
| Evaluation | Adversarial evaluation of model behavior | Partially implemented | `tools/redteam.py`: 21 scripted hostile models, all contained, run in CI. Shows the controls hold, not how a real model behaves |
| Evaluation | Business-impact testing and ongoing evaluation | Not implemented | Needs a pilot and a baseline |
| Operations | Audit logging without sensitive content | Implemented and evidenced | `tests/test_operations.py`. Retention and access: **Needs owner confirmation** |
| Operations | Metrics, alarms, limits, kill switch | Partially implemented | Code and template tested and linted. Alarms not deployed. Kill switch not exercised live |
| Operations | Per-caller rate limit, and a reference that ties each result to its audit line | Partially implemented | `src/ratelimit.py`, `tests/test_ratelimit.py`. Limit off by default. Shared counter table tested with a scripted client only |
| Operations | Every setting documented, and a preflight that blocks prototype defaults | Implemented and evidenced | `config/settings.json`, `docs/CONFIGURATION.md`, `tools/preflight.py`, `tests/test_config.py`. Checks settings only, not a running deployment |
| Operations | Runbook, rollback, named ownership | Partially implemented | `docs/OPERATIONS.md`. Owners are placeholders |
| Delivery | Architecture, data flows and interface contract documented | Implemented and evidenced | `docs/ARCHITECTURE.md`, `schemas/result.schema.json`, `tests/test_contract.py`. Not reviewed by an architecture owner |
| Risk | Risk documentation | Partially implemented | `docs/RISKS.md`. Not reviewed by a risk owner |
| Cost | Cost per successfully completed investigation | Partially implemented | `tools/cost_report.py`, `docs/MEASUREMENT.md`. No live usage data exists |
| Value | Return on investment | Not implemented | Not yet measured. No baseline for the manual process |

## What has been exercised live

- An early build (three skills, direct model route) was deployed to a sandbox. Scope denials and the facts-only
  fallback behaved as designed in six smoke cases.
- The model step has **never** run live. The sandbox account has no access to the configured model.
- Nothing has touched a real identity provider, ownership source, log source or model gateway.

## Blockers

1. No model access in the sandbox account, so no live evaluation of skills, guardrail or validator.
2. The sandbox is governed by an organization policy that blocks pipeline federation, so deployment there is manual.
3. The approved agent framework, runtime, model route, identity pattern, template and pipeline are not confirmed.

## Decisions needed from owners

- Managed agent runtime (`agent/`) or function deployment (`src/` behind the HTTP API), and which template to start from.
- Model route and approved models.
- Token claim that identifies the caller, and the authoritative ownership source.
- Log retention, log access and data classification.
- Whether a mandatory escalation opens a ticket or stays an instruction.

## Tests run for this revision

`python -m pytest -q --cov=src --cov=agent tests` (219 tests, 93% coverage), `python tools/run_evals.py` (15 of 15
golden cases, scripted stand-in model), `python tools/redteam.py` (21 of 21 attacks contained), `ruff check .`,
`bandit -r src agent`, `pip-audit -r agent/requirements.txt`, `cfn-lint template.yaml infra/github-oidc.yaml`.
All offline. See the CI run for the commit.

## Next smallest useful steps

1. Get the owner answers above and record them here.
2. Run `tools/run_evals.py` against a model the account may use, through the approved route.
3. Verify one real token end to end in a non-production environment.
4. Connect one read-only log source with a read-only identity and compare results with a manual search.
5. Replace the stand-in CI jobs with the required scanners and attestations.

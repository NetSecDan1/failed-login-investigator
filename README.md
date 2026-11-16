# Failed Login Investigator

A read-only agent that tells an account owner why their account keeps failing to log in, and what to do about it.

It answers one question well: *"this account keeps failing or locking out, why?"* It reads directory and cloud
sign-in evidence for accounts the caller owns, works out the facts in code, and uses a model only to choose among
explanations the evidence already supports and to write them up in plain language.

**Status:** built for enterprise use. It is read-only and least-privilege, every control is enforced in code, and
every push is tested against those controls. It is verified end to end on synthetic data. Live identity,
ownership, evidence and model integrations are connected per environment by their owners.
[`docs/STATUS.md`](docs/STATUS.md) tracks each requirement and the evidence behind it.

## What a caller gets

```text
Failed login investigation: svc-batch01 (service account)
Window: 2026-11-11T18:00:00+00:00 to 2026-11-12T18:00:00+00:00

FACTS (computed from the logs)
  Active Directory failures: 103   first 2026-11-12T09:05:02Z   last 2026-11-12T17:25:01Z
  Source hosts: 2 distinct   external addresses: 0   lockouts: 3
  Last password change in window: 2026-11-12T09:00:00Z
  Top source hosts:
    APP-BATCH07                        101
    WKS-OPS112                         2
  Retry rhythm: median gap 299.0 seconds, regular

Skills the evidence supports: stale-credential, insufficient-evidence
Reference to quote: INV-20261116-7D33FF9A
```

With a model connected, the same result carries a short finding ("a scheduled job on APP-BATCH07 is still using
the password from before the 09:00 change"), numbered next steps drawn from an approved list, and an escalation
flag when the pattern needs the security team. Without a model, the facts above are still returned in full.

## Design principles

- **Read-only.** No write path exists to any identity, directory or log system. The workload role allows reads on
  its own bucket, model invocation and its own logs, with an explicit deny on everything else.
- **Ownership decides scope.** The caller's accounts come from the identity governance source on every request,
  and every read tool checks scope again before any I/O. Unowned and nonexistent accounts get the same answer.
- **Code holds the authority.** Identity, scope, retrieval, every number, skill eligibility, escalation and next
  steps are deterministic code. The model has no tools and cannot fetch data.
- **The model is bounded.** It picks one skill from a list code already found eligible, and writes a narrative
  that is shown only if every host, address, account, number and time in it appears in the evidence.
- **Failure is safe.** If ownership, a source, the model or validation fails, the caller gets the verified facts
  and a stated gap. Nothing is guessed.

## How it works

Nine stages. Eight are deterministic code, one is the model.

| # | Stage | Where | Kind |
|---|-------|-------|------|
| 1 | Authenticate the caller from verified token claims | `src/handler.py` | code |
| 2 | Resolve owned accounts, fail closed | `src/scope.py` | code |
| 3 | Validate account and time window | `src/scope.py`, `src/handler.py` | code |
| 4 | Collect evidence through fixed-shape read tools | `src/evidence.py`, `src/adapters.py` | code |
| 5 | Compute findings and signals | `src/findings.py` | code |
| 6 | Decide which skills the evidence supports, whether escalation is mandatory, and render approved steps | `src/skillmatch.py` | code |
| 7 | Pick one allowed skill and write the narrative, behind a content guardrail | `src/explain.py` | model |
| 8 | Validate the model's output against the evidence | `src/validator.py` | code |
| 9 | Return facts plus report, write one audit line | `src/handler.py` | code |

Data flows and trust boundaries: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
The original design brief: [`docs/design-brief.html`](docs/design-brief.html).

## Skills

Diagnostic knowledge lives in `skills/` as 13 skill files, each a `SKILL.md` the model reads and a `rules.json`
that code evaluates. Rules decide when a skill is eligible and when escalation is mandatory. Adding a diagnosis is
a reviewed pull request with a golden test case, not a prompt change. See [`docs/SKILLS.md`](docs/SKILLS.md).

## Evidence sources

Sources sit behind one adapter contract, so the pipeline does not depend on any product.

| Kind of evidence | Examples of where it can come from |
|------------------|-------------------------------------|
| Directory logon failures | A log platform, a lakehouse, scheduled report exports |
| Lockouts, password changes and resets | The same |
| Cloud sign-in failures | A log workspace query, the sign-in log API, or any of the above |

- Each kind is routed to its own source with one setting.
- A kind can list several sources, tried in order: `entra_failures=loganalytics+graph`.
- Any source can be switched off and back on while the service runs. A switch can only take a source away.
- A kind with no source produces a stated gap in every report, never a guess.

Adapters, routing, switches and how to add a source: [`docs/SOURCES.md`](docs/SOURCES.md).

## Try it

On a laptop, no cloud account needed:

```bash
python tools/investigate.py --caller E1001 --list
python tools/investigate.py --caller E1001 --account svc-batch01
python tools/investigate.py --caller E5000 --account ev-legacy --model <model-id>   # adds the model, uses your AWS credentials
```

## Deploy it

| Path | Guide |
|------|-------|
| Console walkthrough with a ready-made bundle | [`docs/DEPLOY_CONSOLE.md`](docs/DEPLOY_CONSOLE.md) |
| Command line, pipeline, HTTP API with token authorizer | [`docs/DEPLOY.md`](docs/DEPLOY.md) |
| Editor workspace with assistant chat | [`docs/VSCODE.md`](docs/VSCODE.md) |

It runs in two shapes on the same pipeline, and in both the reply is rendered by code from validated results.

| | Function behind an HTTP API | Managed agent runtime |
|---|---|---|
| Code | `src/handler.py`, `template.yaml` | `agent/app.py`, `agent/Dockerfile` |
| Input | Typed request: account and window | Typed request, or a sentence that a routing model maps to one of two typed tools |
| Model use | One call to explain, one retry at most | The same, plus a small routing call for free-text requests |

The model is reached through `MODEL_ROUTE`: a direct call, or a central model gateway. Every setting, with its
production rule, is in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md), and `python tools/preflight.py` checks a
configuration before it ships.

## Quality gates

Every push runs:

- unit, contract and property tests with a coverage floor
- one golden case per skill and an adversarial suite that must report every attack contained
- lint, static security analysis, a dependency audit and a secret scan over full history
- infrastructure lint, a container build with a smoke test and a vulnerability scan
- a checksummed release artifact with a software bill of materials

```bash
pip install pytest pyyaml
python -m pytest -q tests        # offline, no network
python tools/redteam.py          # hostile models and hostile operator input
python tools/run_evals.py        # scores a live model on evals/cases.json
```

## Operating it

| Topic | Where |
|-------|-------|
| Audit line, metrics, alarms, limits, kill switch, runbook | [`docs/OPERATIONS.md`](docs/OPERATIONS.md) |
| Cost per successfully completed investigation | [`docs/MEASUREMENT.md`](docs/MEASUREMENT.md) |
| Risk register | [`docs/RISKS.md`](docs/RISKS.md) |
| Use case, users and success measures | [`docs/USE_CASE.md`](docs/USE_CASE.md) |
| Security policy | [`SECURITY.md`](SECURITY.md) |

## Repository layout

| Path | What |
|------|------|
| `src/` | The pipeline. `handler.py` is the entry point |
| `skills/` | Skill files and rules |
| `queries/`, `config/` | Fixed query templates, source field mapping, the registry of every setting |
| `agent/` | Entry point for a managed agent runtime, on a standard agent framework |
| `integrations/` | Tool server for editor assistants |
| `schemas/` | The response contract as JSON Schema |
| `evals/`, `examples/` | Golden cases, ready-made requests and switch files |
| `tools/` | Local CLI, data generator, evaluation and adversarial runners, preflight, importers |
| `tests/` | Offline tests |
| `infra/`, `template.yaml` | Infrastructure as code |
| `docs/` | Guides and the status record |

Contributors and coding agents: start with [`AGENTS.md`](AGENTS.md).

## Current state

| Piece | In this repository | Connected per environment |
|-------|--------------------|---------------------------|
| Caller identity | Token authorizer configuration and in-application verification, tested with locally generated keys | The organization's identity provider |
| Ownership | Import from a governance report, with a freshness check | The identity governance system, by API or scheduled export |
| Evidence | Adapters behind one contract, tested against scripted responses | The sources each owner sanctions |
| Model | Direct and gateway routes, scripted model in tests | An approved model through the approved route |
| Audit | One structured line per request | Forwarding to the security log platform |

## Known limits

- Live sources, tokens, ownership data and models have not yet been exercised. Each is labelled in `docs/STATUS.md`.
- Wrong explanations and stale ownership data remain possible. The first is bounded by the validator and the facts-only fallback, the second by the ownership freshness check.
- The entity check in the validator is a heuristic. Expect occasional false rejects, which fall back to facts only.
- Skill thresholds were set against synthetic data and need tuning against real patterns.
- The per-caller rate limit is off by default. There is no user interface, only the API and the response contract.

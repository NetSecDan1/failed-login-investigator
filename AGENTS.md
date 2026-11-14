# Instructions for coding agents and contributors

You are helping build a read-only investigation agent. Help plan and implement, but never describe the design
as approved, production-ready or compliant with an organization's standard path unless the evidence exists in
this repository. `docs/STATUS.md` is the record of what is and is not evidenced. Update it with every change.

## 1. Establish the use case and boundaries

- The use case, users, success measures, data sources and identities are in `docs/USE_CASE.md`. Read it first.
- Prefer the least-privileged, read-only design. This agent has no write path. Any future action that changes
  something needs an approved authorization pattern and a human confirmation step, designed before code is written.
- Keep facts, assumptions, open decisions and approvals needed separate. Do not invent missing requirements or evidence.

## 2. Follow the supported path

- If the adopting organization has a standard template, reference architecture, agent framework, runtime,
  model access route, identity pattern or pipeline, start from it. Do not build a parallel architecture.
- This repository offers a standard agent framework on a managed agent runtime (`agent/`), a model route setting
  that can point at a central model gateway (`src/modelroute.py`), and a simpler function deployment (`src/`).
  Which of these an organization permits is an owner decision. Record it in `docs/STATUS.md`, do not assume it.
- Use approved models, libraries and services. When something is unclear, write the question down and name
  who must answer it. Never silently substitute a tool or pattern.

## 3. Keep authority in deterministic code

- Code owns authentication, authorization, data scope, input validation, data retrieval, calculations, skill
  eligibility, escalation and next steps.
- The model may interpret authorized evidence and produce a bounded explanation. It must not grant access,
  widen scope, invent evidence or take a consequential action.
- Tools take narrow, typed inputs. Scope is enforced inside every data-access tool, not only at the edge or in a prompt.
- Logs, records and tool results are untrusted input. Defend against prompt injection and leakage. Validate
  model output against the evidence and an explicit schema.
- Failure is safe: when identity, authorization, a control, the model or validation fails, stop that
  operation and return only the verified result.

## 4. Build and verify through the delivery lifecycle

- Every change passes the gates in `.github/workflows/ci.yml`: tests with a coverage floor, lint, static
  security analysis, dependency audit, secret scan, infrastructure lint, and a checksummed build artifact.
- Add tests for authorization boundaries, invalid input, failure paths, leakage and output validation. Add a
  golden case for every skill and adversarial cases for model behavior.
- Say exactly what was exercised. A fake client or scripted model is not live validation, and must never be
  described as one. `docs/STATUS.md` separates synthetic evidence from live evidence.
- Never put real identity data, real log content, tokens or organization-specific names in this repository.

## 5. Design for responsible operation and cost

- Log what audit, security, troubleshooting and evaluation need, and nothing more. See `docs/OPERATIONS.md`.
- Keep the token, time and attempt limits. Measure quality together with cost. Do not cut tokens at the
  expense of a correct and safe outcome.
- Do not claim a benefit or return on investment without a baseline. See `docs/MEASUREMENT.md`.

## 6. Report status honestly

Label every significant requirement as one of: **Implemented and evidenced**, **Partially implemented**,
**Not implemented**, **Needs owner confirmation**. Name the evidence. End reports with blockers, decisions,
tests run and the next smallest useful step. A passing synthetic test is not compliance.

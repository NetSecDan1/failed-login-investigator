# Instructions for coding assistants in this repository

This repository is a read-only agent that explains failed logins for accounts the caller owns. Read
[`AGENTS.md`](../AGENTS.md) for the full rules. The ones that matter most:

## Never

- Never give the model authority. Identity, ownership, data retrieval, numbers, skill eligibility, escalation
  and next steps are decided by deterministic code. The model picks among code-approved choices and writes a
  narrative that code then validates.
- Never add a write path, widen a permission, or add a tool that lets the model fetch data or run a query.
- Never take the caller's identity from a request body, a prompt, a tool argument or model output.
- Never commit real identity data, real log content, credentials, tokens, or the name of any organization or
  its internal systems. All data in this repository is synthetic.
- Never describe a fake client, scripted model or synthetic test as live validation, and never call the
  design approved, compliant or production-ready.
- Never disable or weaken a CI gate, a validator check or a test to make a change pass.

## Always

- Add tests with every change: authorization boundaries, invalid input, failure paths, and what the model is
  not allowed to do. A new control gets a new attack in `tools/redteam.py`.
- Keep failure safe: when identity, ownership, a source, the model or validation fails, deny or return facts only.
- Register every new setting in `config/settings.json`, then run `python tools/preflight.py --write-docs`.
- After changing a skill run `python tools/build_skill_index.py` and add or update its case in `evals/cases.json`.
- Update `docs/STATUS.md`, keeping synthetic evidence and live evidence apart.
- Run the "All gates before a pull request" task, or: `ruff check .`, `bandit -q -r src agent integrations`,
  `python -m pytest -q tests`, `python tools/run_evals.py`, `python tools/redteam.py`.

## Style

- Python standard library first. A new dependency needs a reason, an exact pin and a passing dependency audit.
- Short, plain sentences in docs and messages. No em dashes.
- Evidence sources go behind the adapter contract in `docs/SOURCES.md`. Do not special-case one product in the pipeline.

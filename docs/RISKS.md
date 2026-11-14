# Risks and mitigations

A working register for review, not an approved risk assessment. Evidence is named so each line can be checked.
"Synthetic" means proven only with generated data and scripted stand-ins.

| # | Risk | Mitigation in this repository | Evidence | Residual |
|---|------|-------------------------------|----------|----------|
| 1 | A caller reads evidence for an account they do not own | Scope resolved per request from the ownership source, re-checked inside every read tool, same answer for unowned and nonexistent accounts | `tests/test_pipeline.py`, `tests/test_api.py`, `tests/test_agent.py`. Synthetic. Six live smoke cases on an early build | Wrong or stale ownership data. Set `OWNERSHIP_MAX_AGE_HOURS` and verify the source |
| 2 | Identity is spoofed | Caller taken only from verified token claims. Signature, issuer, audience and expiry checked. Identity in a prompt, body or tool input is ignored | `tests/test_agent.py` (locally generated keys), `tests/test_api.py` | Never exercised with a real identity provider |
| 3 | Hostile text in logs steers the model | Host fields that are not valid host names never reach the model. Model has no data tools. Narrative validated against evidence. Steps rendered by code | `tests/test_pipeline.py`, `tests/test_skills.py` | Live model behavior untested |
| 4 | The model invents a cause, host or address | Validator rejects any entity not in the evidence. One retry, then facts only | `tests/test_pipeline.py` | Heuristic entity check can reject harmless text |
| 5 | The model plays down an attack | Code decides mandatory escalation. Escalation flag is returned even with no model answer | `tests/test_pipeline.py`, `tests/test_skills.py` | Thresholds set on synthetic data, need tuning |
| 6 | The agent changes something | No write permission exists. Explicit deny on everything except five read and log actions. Optional permissions boundary | `template.yaml`, `infra/github-oidc.yaml` | None known for this design. Any future write path needs a new review |
| 7 | Sensitive data leaks through logs | Audit line carries identifiers and outcomes only. No raw rows, no narrative | `tests/test_operations.py` | Retention and access to the log store are an owner decision |
| 8 | Model traffic bypasses required controls | Model route is one setting. A central gateway route exists | `src/modelroute.py`, `tests/test_operations.py`. Fake responses only | Approved route not confirmed. Not run live |
| 9 | Cost runs away | Output token, time and attempt limits. At most two model calls per investigation. Structured requests skip the routing model | `tests/test_operations.py`, `tests/test_agent.py` | Global throttle only, no per-caller limit |
| 10 | A log source is silent and the answer looks clean | Source failures are reported as gaps. Skills lower confidence when a source is missing | `tests/test_backends.py`, `tests/test_pipeline.py` | A source that returns nothing because collection is broken looks the same as a quiet account |
| 11 | The service misbehaves in use | Kill switch stops every request before identity, data or model. Alarms for errors, validator rejects and escalations | `tests/test_operations.py`, `template.yaml` | Alarms not deployed. No named operator yet |
| 12 | Skill wording misleads the owner | Approved steps are fixed templates reviewed by pull request. One golden case per skill | `tests/test_skills.py`, `evals/cases.json` | Not evaluated against a live model or reviewed by the owning team |
| 13 | A dependency or secret slips in | Dependency audit, secret scan over full history, static security analysis, pinned versions, checksummed artifact | `.github/workflows/ci.yml` | An adopting organization's own scanners and attestations are not wired in |

# Operations

Nothing here has been exercised in production. It describes what the code does today and what an operating
team would need to decide.

## What is logged

One `AUDIT` line per request, as JSON on standard output:

| Field | Purpose |
|-------|---------|
| `ts`, `request_id`, `route`, `latency_ms` | Troubleshooting |
| `caller`, `scope_hash` | Audit: who asked, and a hash of what they were allowed to see |
| `account`, `window`, `query_ids` | Audit: what was asked about and which evidence queries ran |
| `outcome` (`report`, `facts_only`, `denied`, `listed`, `error`), `reason` | Audit and quality |
| `candidates`, `classification`, `must_escalate`, `skills_version` | Evaluation: what code allowed, what was chosen, which skill text |
| `model`, `route_to_model`, `guardrail`, `tokens_in`, `tokens_out`, `model_calls`, `validator_rejects` | Cost and model quality |
| `notes`, `source_errors` | Why a summary was withheld, or a source failed |

**Deliberately not logged:** raw log rows, host names and addresses from the evidence, the narrative text, the
prompt, and tokens or secrets. A test enforces that the audit line carries no narrative or host.

The agent entry point adds one `ROUTE` line with the routing model's token usage.

Decisions for the operating team: retention period, who may read these logs, and whether a copy must go to an
immutable store and the security monitoring platform. **Needs owner confirmation.**

## Metrics

With `METRICS_EMF=true` each request also writes an embedded metric line, which becomes metrics in the
`FailedLoginInvestigator` namespace with an `Outcome` dimension: `Requests`, `Reports`, `LatencyMs`,
`InputTokens`, `OutputTokens`, `ModelCalls`, `ValidatorRejects`, `Escalations`.

| Measure | From |
|---------|------|
| Successful task rate | `Reports` / (`Requests` where Outcome is report or facts_only) |
| Latency | `LatencyMs` |
| Model failures and validator rejects | `ValidatorRejects`, `notes` in the audit line |
| Escalation behavior | `Escalations`, `must_escalate` |
| Cost per successfully completed investigation | `python tools/cost_report.py`, see `MEASUREMENT.md` |
| Accuracy | Not automatic. Needs human review of a sample. See `MEASUREMENT.md` |

## Alarms

Set the `AlarmTopicArn` template parameter to create three alarms:

| Alarm | Means | First response |
|-------|-------|----------------|
| Function errors | The function is raising. Callers get errors | Check the latest logs. If it persists, switch the service off |
| Validator rejects, 5 or more in an hour | Model output is being refused: drift, an attack, or a skill wording problem | Read `notes` in recent audit lines. Callers are still safe: they get facts only |
| Mandatory escalation | An owner was told to contact security operations | Informational, so that team expects the contact |

Thresholds are placeholders. Tune them once there is real traffic.

## Limits

| Limit | Default | Setting |
|-------|---------|---------|
| Output tokens per model call | 1200 | `MODEL_MAX_OUTPUT_TOKENS` |
| Model call timeout | 60 seconds | `MODEL_TIMEOUT_SECONDS` |
| Model calls per investigation | 2 (one retry after a validator reject) | fixed in code |
| Time window | 168 hours | fixed in code |
| Rows per evidence query | 5000, 1000, 5000 | fixed in templates and code |
| Routing prompt length, tool calls per turn | 2000 characters, 1 | fixed in `agent/app.py` |
| API throttle | 2 requests a second, burst 5, global | `ApiRateLimit`, `ApiBurstLimit` |

Not built: a per-caller rate limit and a daily spend cap.

## Switching it off

```bash
./deploy.sh <model-id> AgentEnabled=false        # every request returns a service-off response
```

When off, no identity, ownership, evidence or model call happens. Switch back on with `AgentEnabled=true`.
For a faster stop, set the function's reserved concurrency to zero. To remove everything, run `./teardown.sh`.
Because the agent changes nothing in any identity system, there is no data to roll back.

## Runbook: common situations

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Every caller gets `ownership_unavailable` or `ownership_stale` | Ownership file missing, unreadable or older than `OWNERSHIP_MAX_AGE_HOURS` | Fix the export. Do not raise the limit to make the error go away |
| Reports list a source under gaps | Log platform unreachable, token expired, or field map mismatch | See `source_errors` in the audit line, then `docs/BACKENDS.md` |
| `summary_withheld:guardrail_intervened` on ordinary requests | Guardrail too broad | Review the guardrail trace and tune the topic definition |
| A report looks wrong | Skill thresholds or wording | Capture the case as a synthetic eval, fix the skill, re-run evals |

## Ownership

An operating team, an on-call contact and a skill-library reviewer must be named before a pilot.
**Not implemented: no owner is named.**

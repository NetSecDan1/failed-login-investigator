# Use case and boundaries

## Problem

Accounts that repeatedly fail to log in, or lock out, generate tickets that an identity engineer resolves by
searching authentication logs by hand. Most cases have a small number of recognisable causes. Account owners
wait, and engineers repeat the same search.

## Intended users

1. **Identity engineers**, investigating accounts they own. First pilot group.
2. **Account owners** (people who own service or secondary accounts), self-service. Later.

## Expected outcome

An account owner asks about an account they own and receives, in under a minute: the facts computed from the
logs, a bounded explanation chosen from a reviewed skill library, approved next steps, and a clear instruction
to contact security operations when the pattern requires it.

## How success will be measured

See `MEASUREMENT.md`. In short: time to a verified explanation against the manual baseline, agreement of the
finding with an engineer's review, escalation correctness, adoption, and model cost per successfully completed
investigation. **None of these has been measured.**

## Boundaries

| Item | Position |
|------|----------|
| Access | Read-only. There is no write path to any identity system, and no remediation. |
| Scope | Only accounts the verified caller owns, according to the ownership source. Tier 0 and deny-listed accounts are excluded from self-service. |
| Evidence | Failed and related authentication events, and cloud sign-in failures, for one account in a window of at most 168 hours. |
| Model | Chooses among skills that code found eligible and writes a short narrative. Nothing else. |
| Environments | Synthetic data in a sandbox account today. No production environment exists. |

## Data sources, identities and classification

| Element | Today | Target | Status |
|---------|-------|--------|--------|
| Caller identity | Test claims in a direct invoke | Token from the organization's identity provider, verified at the edge and in the application | Needs owner confirmation: token audience, caller claim |
| Ownership | Generated JSON file | Identity governance system, by API or scheduled export | Needs owner confirmation: source of truth, refresh interval |
| Evidence | Generated JSON files | Log platform or data platform, read-only service identity | Needs owner confirmation: which platform, which fields |
| Service identities | One function role, read-only, explicit deny on everything else | Same, issued through the organization's process | Needs owner confirmation |
| Data classification | Synthetic, not sensitive | Authentication logs contain account names, host names and addresses | Needs owner confirmation: classification and whether that class may be sent to the chosen model route |

## Facts, assumptions, open decisions, approvals

**Facts**
- The pipeline, skills, API handler and agent entry point exist and pass offline tests.
- No live model, token, ownership source or log source has been exercised.

**Assumptions**
- Ownership can be obtained per caller with a stable identifier that also appears in the caller's token.
- The required events are collected centrally from every domain controller.

**Open decisions**
- Agent runtime and framework versus the simpler function deployment.
- Model access route: direct or through a central gateway.
- Whether identity engineers ever get a scope wider than accounts they own.
- Whether a mandatory escalation opens a ticket automatically or stays an instruction.

**Approvals needed before any real data is used**
- Architecture and platform, security, AI governance, the owners of the ownership and log sources, and records management for log retention.

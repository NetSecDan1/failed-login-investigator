# Security

**Maturity: pre-production.** Designed and tested to enterprise standards on synthetic data. It has not had a
security review and must not be used with real data until it has. The code enforces this: the default stage
accepts synthetic data only.

## Reporting a problem

Open a private security advisory on this repository, or contact the repository owner directly. Do not open a
public issue for a vulnerability, and do not include real account names, log content or tokens in a report.

## What counts

- Any way to read evidence for an account the caller does not own, or to tell whether an account exists.
- Any way for request content, log content or model output to change identity, scope, escalation or next steps.
- Any model output that reaches a caller without passing validation.
- Any path that writes to an identity system, or any permission wider than `docs/ARCHITECTURE.md` describes.
- Sensitive content in the audit or metric lines.

## Ground rules for this repository

- Synthetic data only. Never commit real identity data, real log content, credentials or organization-specific names.
- The secret scan, static security analysis and dependency audit in CI must pass. Do not disable a gate to merge.
- The adversarial suite (`tools/redteam.py`) must report every attack contained. A new control gets a new attack.
- Pre-production. It has not had a security review and must not be used with real data until it has. The default
  deployment stage refuses live evidence sources, and the production stage accepts only the managed agent runtime
  and the governed model route (`src/stage.py`). Do not raise the stage or record an exception without the
  owner's approval.

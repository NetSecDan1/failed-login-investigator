---
name: entra-mfa-interrupt
description: "Use when most Entra ID sign-in entries are multi-factor or additional-verification interrupts rather than wrong-password failures. The password was accepted and the sign-in was not completed at the next step."
metadata:
  title: "Sign-ins stopped at the MFA step"
  escalate: "false"
  version: "1.0.0"
---
# Sign-ins stopped at the MFA step

## Use when
Entra codes such as 50074, 50076, 50079, 50072 and 50158. These appear in failure views but are not bad passwords and do not lock the account.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.entra_mfa_interrupt_share`
- `entra.by_app`, `entra.by_source_ip`, `entra.by_client_app`
- `account_type`

## How to reason
1. Explain that the first step succeeded and the sign-in paused for verification that was not completed.
2. The important question is whether the owner started those sign-ins. Ask them to check the times and addresses in the facts.
3. For a service account, say that it cannot complete interactive verification.

## Rule out
- Bad-password code dominant: `legacy-auth-client` or `suspicious-source-escalate`.
- Policy block codes dominant: `conditional-access-block`.

## Tell the owner
- That these are incomplete verifications, not wrong passwords.
- That prompts the owner did not start are a security matter.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. If these were your own sign-ins, complete the MFA prompt when it appears. No password change is needed.
2. If {account} is a service or automation account, it cannot answer an MFA prompt. Raise a request with the identity team to review how it should authenticate.
3. If you were not signing in at those times, contact the CSOC now. An MFA prompt you did not start means the correct password was entered by someone else.

## Never
- Do not tell the owner to approve prompts they did not start.
- Do not suggest turning off MFA for the account.

## Confidence
- high: interrupt codes dominant, owner context clear
- medium: mixed codes
- low: a source is missing

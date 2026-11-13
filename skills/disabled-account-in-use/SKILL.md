---
name: disabled-account-in-use
description: "Use when most failures carry the account-disabled code in Active Directory or Entra ID. The password is not the problem: the account is disabled and a system or person is still trying to use it."
metadata:
  title: "Something is still using a disabled account"
  escalate: "false"
  version: "1.0.0"
---
# Something is still using a disabled account

## Use when
Failure codes say disabled (0xC0000072, Entra 50057). Accounts are disabled deliberately far more often than by accident, so the first question is why, not how to turn it back on.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.disabled_share`, `signals.entra_disabled_share`
- `ad.by_source_host` and `ad.cadence`
- `entra.by_app` and `entra.by_client_app` when the failures are cloud sign-ins

## How to reason
1. State that the account is disabled and that the attempts were refused for that reason.
2. Identify what keeps trying: host, rhythm, and for cloud sign-ins the app and client.
3. Say that the reason for disablement is not visible in this evidence.

## Rule out
- Only Kerberos 0x12 with no explicit disabled code: `lockout-aftermath`.
- Account-expired code: `account-expired`.

## Tell the owner
- That the account is disabled, and what is still using it.
- That the reason it was disabled is not in the logs.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Confirm with the identity team whether {account} was disabled on purpose, for example a leaver, a retirement or a security hold. Do not ask for it to be re-enabled until you know why.
2. If it was retired on purpose, remove {account} from whatever is still using it on {top_host}.
3. If it should be active, raise a request with the identity team through the standard path.

## Never
- Do not suggest re-enabling the account.
- Do not guess why it was disabled.

## Confidence
- high: explicit disabled code and a clear source
- medium: mixed codes
- low: a source is missing

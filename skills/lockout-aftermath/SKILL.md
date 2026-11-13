---
name: lockout-aftermath
description: "Use when nearly all failures in the window carry the account-locked code or the ambiguous Kerberos revoked code. The window shows attempts bouncing off an account that was already locked, not the failures that caused the lockout."
metadata:
  title: "Account was already locked or revoked"
  escalate: "false"
  version: "1.0.0"
---
# Account was already locked or revoked

## Use when
Failures are dominated by 0xC0000234 (locked) or Kerberos 0x12. Kerberos 0x12 means credentials revoked and covers locked out, disabled and expired, so it cannot be read as one of them without other evidence.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.locked_share`, `signals.kerberos_revoked_share`
- `ad.lockout_count`: zero means the lockout happened before the window
- `ad.by_source_host`: the system still retrying

## How to reason
1. Explain that these attempts were refused because of the account's state, before the password was even considered.
2. If only the Kerberos revoked code is present, say the cause could be lockout, disablement or expiry and that this window cannot tell which.
3. Point at the host that keeps retrying. It is the best lead on the original cause.

## Rule out
- Disabled code (0xC0000072) dominant: `disabled-account-in-use`.
- Wrong-password failures also present in volume: `stale-credential` or `wrong-password-no-change-in-window`.

## Tell the owner
- That the window shows the aftermath, not the cause.
- Which host is still retrying.
- That a longer window is the next move.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Run the investigation again with a longer window so it includes the failures that caused the lockout.
2. Do not request an unlock yet. Whatever locked {account} is probably still running on {top_host} and will lock it again.
3. If the account is not locked and these errors continue, open a ticket with the identity team and quote this reference, because the Kerberos code seen can also mean disabled or expired.

## Never
- Do not claim to know what caused the lockout.
- Do not read Kerberos 0x12 as locked without saying it is ambiguous.

## Confidence
- high: locked code present and a single retrying host
- medium: only the Kerberos revoked code is present
- low: a source is missing

---
name: account-expired
description: "Use when most failures carry the account-expired code. The account itself has reached its configured end date, which is different from an expired password, and needs an extension request or retirement."
metadata:
  title: "Account has passed its end date"
  escalate: "false"
  version: "1.0.0"
---
# Account has passed its end date

## Use when
Code 0xC0000193. Common for contractor and time-boxed accounts.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.account_expired_share`
- `ad.by_source_host`

## How to reason
1. Say the account passed its end date and that the password is not the issue.
2. Name what is still using it.

## Rule out
- Password-expired codes: `expired-password`.

## Tell the owner
- That the account, not the password, has expired.
- That an extension is an access decision made through the request path.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Ask the account sponsor or your manager to request an extension of the end date for {account} through the standard access request path.
2. If {account} is no longer needed, remove it from whatever is still using it on {top_host}.

## Never
- Do not tell the owner to reset the password.
- Do not promise an extension.

## Confidence
- high: explicit code, clear source
- medium: mixed codes
- low: a source is missing

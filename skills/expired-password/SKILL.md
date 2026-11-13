---
name: expired-password
description: "Use when most failures carry the password-expired or must-change-password code in Active Directory or Entra ID. The password presented may be correct but is past its expiry and has to be changed."
metadata:
  title: "Password has expired"
  escalate: "false"
  version: "1.0.0"
---
# Password has expired

## Use when
Codes 0xC0000071, Kerberos 0x17, 0xC0000224 or Entra 50055. The account works, its password has aged out.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.password_expired_share`, `signals.entra_expired_share`
- `ad.by_source_host`, `ad.by_logon_group`
- `account_type`

## How to reason
1. Say the password has expired and that the attempts were refused for that reason.
2. For a service account, warn that changing the password without updating every consumer will produce stale-credential failures next.
3. List the source hosts seen so they can be updated together.

## Rule out
- Account-expired code (the account's end date, not the password): `account-expired`.

## Tell the owner
- That the password expired.
- Which systems will need the new password.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Change the password for {account} through the standard password change path.
2. For a service account, follow the service account rotation procedure so every system that uses it is updated together.
3. After the change, update the stored password on {top_host} and on any other source host listed in the facts.

## Never
- Do not suggest exempting the account from password expiry.
- Do not confuse password expiry with account expiry.

## Confidence
- high: explicit expired code and known sources
- medium: mixed codes
- low: a source is missing

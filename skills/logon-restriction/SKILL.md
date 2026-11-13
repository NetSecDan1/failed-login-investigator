---
name: logon-restriction
description: "Use when most failures carry the workstation-restriction or logon-hours code. The password is correct but the account is restricted from logging on at that host or at that time."
metadata:
  title: "Account is not allowed to log on from there or then"
  escalate: "false"
  version: "1.0.0"
---
# Account is not allowed to log on from there or then

## Use when
Codes 0xC0000070 (workstation restriction) or 0xC000006F (logon hours). Restrictions like these are usually deliberate hardening on service and privileged accounts.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.restriction_share`
- `ad.by_source_host`
- `ad.busiest_hours_utc`

## How to reason
1. Say the logon was refused because of where or when it was attempted.
2. Treat the restriction as intended until someone with authority says otherwise.

## Rule out
- Mixed with wrong-password codes from other hosts: consider `suspicious-source-escalate` if allowed.

## Tell the owner
- Which host was refused.
- That the restriction is a control, and changing it is a request to the identity team.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Confirm that {account} is meant to be used from {top_host}. If not, stop using it there.
2. If it is meant to work from {top_host}, ask the identity team to review the account's logon restrictions through the standard request path.
3. Do not reset the password. It is not the cause.

## Never
- Do not suggest removing or widening the restriction.
- Do not advise a password reset.

## Confidence
- high: explicit code, single host
- medium: several hosts
- low: a source is missing

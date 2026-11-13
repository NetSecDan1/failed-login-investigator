---
name: legacy-auth-client
description: "Use when Entra ID sign-in failures are bad-password errors coming from legacy clients such as Exchange ActiveSync, IMAP, POP, SMTP or other basic-authentication clients. Usually a phone, tablet or script holding an old password."
metadata:
  title: "Mail client or script sending a wrong password"
  escalate: "false"
  version: "1.0.0"
---
# Mail client or script sending a wrong password

## Use when
Bad-password failures (50126) where the client app is a legacy protocol. These clients store a password and replay it, so they fail forever after a change.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.entra_legacy_client_share`, `signals.entra_bad_password_share`
- `entra.by_client_app`, `entra.by_app`, `entra.by_source_ip`
- `signals.entra_distinct_ips`
- `ad.last_password_change`

## How to reason
1. Name the client type exactly as given in `entra.by_client_app`.
2. A few steady source addresses fit a forgotten device or script.
3. If a password change is visible, connect the timing.

## Rule out
- Eight or more source addresses: this skill is excluded by code. Use `suspicious-source-escalate` if allowed.
- Conditional Access block codes dominant: `conditional-access-block`.

## Tell the owner
- That an older-style client is replaying a wrong password.
- Which client type and how many source addresses.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Find the device or script that signs in as {account} with {top_client_app} and update or remove its saved password. Phones and tablets with a built-in mail app are the usual cause.
2. Where possible, move that device or script to a modern sign-in method instead of re-entering the password.
3. If you do not recognise the client or the source addresses in the facts, contact the CSOC.

## Never
- Do not name a specific device model or owner.
- Do not recommend re-enabling legacy authentication anywhere.

## Confidence
- high: few addresses and a visible password change
- medium: few addresses, no visible change
- low: a source is missing

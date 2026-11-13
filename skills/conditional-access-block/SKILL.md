---
name: conditional-access-block
description: "Use when most Entra ID sign-in failures carry a Conditional Access block code. The sign-in was stopped by access policy, such as device, location, client app or risk requirements, and not by a wrong password."
metadata:
  title: "Sign-in blocked by access policy"
  escalate: "false"
  version: "1.0.0"
---
# Sign-in blocked by access policy

## Use when
Entra error 53003 and its relatives. Policy details are not the owner's to tune and are not disclosed here.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.entra_ca_block_share`
- `entra.by_app`, `entra.by_client_app`, `entra.by_source_ip`

## How to reason
1. Say the block came from access policy.
2. Name the app and client involved, as given.
3. Keep it general: device, location, app or risk requirements. Do not guess which.

## Rule out
- Bad-password code 50126 dominant: `legacy-auth-client` or `suspicious-source-escalate`.
- MFA interrupt codes dominant: `entra-mfa-interrupt`.

## Tell the owner
- That policy blocked the sign-in and the password is not the issue.
- Which app and client were involved.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Do not reset the password for {account}. A wrong password is not what stopped these sign-ins.
2. Check that you are signing in to {top_app} the approved way: a managed device, the approved app, and from an expected location.
3. If {account} is a service or automation account, raise a request with the identity team to review how it should authenticate. Do not look for a workaround.
4. If the sign-ins were not you or your system, contact the CSOC.

## Never
- Do not name or describe specific policies or their conditions.
- Do not suggest exclusions, exceptions or workarounds.
- Do not explain how to satisfy a policy from an unmanaged device.

## Confidence
- high: block codes dominant, known app
- medium: mixed with other codes
- low: a source is missing

---
name: stale-credential
description: "Use when failed logins for an account begin shortly after its password was changed or reset, and most failures are wrong-password errors from internal systems. Explains that something is still presenting the old password, and on which host."
metadata:
  title: "Old password still stored somewhere"
  escalate: "false"
  version: "1.0.0"
---
# Old password still stored somewhere

## Use when
A password change or reset is visible in the window (`ad.last_password_change`) and wrong-password failures start soon after it. This is the most common cause of repeat lockouts: the directory has the new password, and a service, task, mapped drive, session or app still holds the old one.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `ad.after_password_change`: minutes to first failure, failures before and after the change
- `ad.by_source_host` and `signals.top_source_share`: where the retries come from
- `ad.cadence`: regular gaps mean a machine is retrying, irregular gaps suggest a person or an interactive app
- `ad.by_logon_group`: service_or_batch points at a service or task, network at a mapped drive or app connection, interactive at a session or someone typing
- `ad.lockout_count` and `ad.lockout_callers`
- `account_type`: person or service changes which storage places are likely

## How to reason
1. Confirm the timing. Failures should begin after the change and be absent or rare before it.
2. Name the host that carries the most failures. If two or three hosts share them, name each.
3. Describe the rhythm using `ad.cadence.median_gap_seconds` exactly as given. Do not convert units yourself.
4. Use the logon group to say what kind of thing is likely retrying. Say likely, because the logs do not show the process.
5. If lockouts are present, explain that each unlock will be followed by another lockout until the stored password is fixed.

## Rule out
- Any external source address, or escalation marked mandatory: `suspicious-source-escalate`.
- No password change in the window: `wrong-password-no-change-in-window`.
- Failures are mostly locked or revoked codes: `lockout-aftermath`.
- A log source in `gaps`: keep the classification, lower confidence one level.

## Tell the owner
- Which host or hosts, when failures began, and how often they repeat.
- That the timing lines up with the password change.
- That unlocking alone will not hold.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Update the stored password for {account} on {top_host}. Check Windows services, scheduled tasks, application or connection-string config, mapped drives and Credential Manager.
2. If {account} is used on other systems, update the stored password there too. The facts list every source host seen.
3. Sign out any old remote desktop sessions for {account}, which keep retrying the old password.
4. Once the stored password is fixed, request an unlock through the standard service desk path if the account is still locked.
5. If nobody recognises {top_host}, stop and contact the CSOC before changing anything.

## Never
- Do not advise another password reset. It restarts the same cycle.
- Do not name a specific service, task or process. The evidence does not show one.
- Do not say or imply the account is compromised.

## Confidence
- high: every support signal is met and `gaps` is empty
- medium: one or two support signals are unmet
- low: a source is missing, or failures also existed before the change

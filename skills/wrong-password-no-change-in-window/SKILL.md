---
name: wrong-password-no-change-in-window
description: "Use when an account shows wrong-password failures from internal systems and no password change or reset appears in the time window. Covers a stored password that went stale before the window began, and a person or script repeatedly presenting a wrong password."
metadata:
  title: "Wrong password retries with no recent password change"
  escalate: "false"
  version: "1.0.0"
---
# Wrong password retries with no recent password change

## Use when
Wrong-password failures are present but the window contains no password change. Either the change happened earlier than the window, or the password in use was never right. The evidence cannot tell these apart, so say so.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `ad.by_source_host`, `signals.distinct_source_hosts`, `signals.top_source_share`
- `ad.cadence`: regular means automated, irregular means human or interactive
- `signals.regular_host_share`: share of source hosts that each retry on a steady timer of their own. High values point at a fleet of systems sharing one stale password
- `ad.by_logon_group`
- `ad.first_seen`: if it equals the start of the window, the problem is older than the window

## How to reason
1. State plainly that no password change is visible in this window.
2. If `ad.first_seen` sits at the window start, say the failures were probably already happening before the window.
3. Regular cadence: something automated holds a wrong password. Irregular with interactive logons: someone is typing it.
4. With many internal hosts, look at `signals.regular_host_share`. When most hosts keep their own steady rhythm over hours, a shared service account password that was rotated earlier is the likely story. With many hosts in a short burst and no per-host rhythm, prefer `suspicious-source-escalate` if it is allowed.

## Rule out
- Any external source address: `suspicious-source-escalate`.
- Password change in the window: `stale-credential`.
- Six or more source hosts in a short burst with no regular rhythm: `suspicious-source-escalate` when allowed.

## Tell the owner
- Where the failures come from and their rhythm.
- That this window shows no password change, and a longer window may show one.
- What kind of thing is likely retrying, labelled as likely.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Check {top_host} for a stored or scripted password for {account}: services, scheduled tasks, application config, mapped drives and Credential Manager.
2. Run the investigation again with a longer window to see whether a password change came before these failures.
3. If the account is locked, request an unlock through the standard service desk path once the source is fixed.
4. If nobody recognises {top_host} or the activity, contact the CSOC.

## Never
- Do not state that a password change happened.
- Do not blame a named person.
- Do not suggest the password is weak or guessable.

## Confidence
- high: one or two hosts, regular cadence, no gaps
- medium: several hosts or irregular cadence
- low: a source is missing or `ad.first_seen` is at the window start

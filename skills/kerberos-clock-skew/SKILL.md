---
name: kerberos-clock-skew
description: "Use when Kerberos failures carry the clock-skew code. The password is fine. The source system's clock differs too much from the domain's, so Kerberos rejects the request."
metadata:
  title: "Clock on the source system is wrong"
  escalate: "false"
  version: "1.0.0"
---
# Clock on the source system is wrong

## Use when
Kerberos failure code 0x25. Usually one host, often a virtual machine, an appliance or a system that lost its time source.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.clock_skew_share`
- `ad.by_source_host`, `signals.distinct_source_hosts`

## How to reason
1. Say the failures are a time problem on the source system.
2. If several hosts are affected, say the common time source is the better suspect than each host.

## Rule out
- Wrong-password codes in volume alongside: describe both and choose the dominant one.

## Tell the owner
- Which host has the time problem.
- That the password is not involved.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Ask the team that runs {top_host} to check its clock and time synchronisation. Kerberos rejects logons when the clock is more than a few minutes off.
2. No password change is needed for {account}. Do not reset it.
3. If more than one host is affected, tell the identity team, because the shared time source may be the problem.

## Never
- Do not advise a password reset.
- Do not state an exact tolerance for the environment.

## Confidence
- high: single host, code dominant
- medium: several hosts
- low: a source is missing

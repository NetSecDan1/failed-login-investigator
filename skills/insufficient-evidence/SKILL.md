---
name: insufficient-evidence
description: "Use when there are no failures in the window, a log source the explanation would depend on is missing, signals conflict, or no other skill clearly fits. States what was checked and what is missing, and never guesses a cause."
metadata:
  title: "Not enough evidence to explain"
  escalate: "false"
  version: "1.0.0"
---
# Not enough evidence to explain

## Use when
The fallback. Choosing it is correct behaviour whenever the evidence does not support a specific explanation.

Eligibility is decided by code from `rules.json`, not by this text. If this skill is in ALLOWED CHOICES, its required signals already hold.

## Evidence to read
- `signals.ad_failures`, `signals.entra_failures`
- `gaps`
- `ad.by_failure_code`, `entra.by_error_code` for patterns no skill covers

## How to reason
1. Say what was checked: which sources, what window.
2. Say what is missing or why nothing fits.
3. If failures exist but match no skill, describe the dominant codes as given and stop.

## Rule out
- Any other allowed choice whose support signals are mostly met.

## Tell the owner
- What was checked and what was missing, in one or two sentences.

## Approved next steps
Pick by number. Code fills in the values in braces from the evidence. Do not write your own steps.

1. Run the investigation again with a longer time window.
2. If the problem continues, open a ticket with the identity team and quote the reference for this investigation.

## Never
- Do not guess a cause.
- Do not treat a missing source as proof that nothing happened.

## Confidence
- high: not applicable: use low
- medium: not applicable: use low
- low: always choose low for this skill

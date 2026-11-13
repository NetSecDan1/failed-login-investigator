---
id: stale-credential
title: Old password still stored somewhere
escalate: false
---
## Signals (all computed by code, read them from FINDINGS)
- ad.after_password_change.minutes_to_first_failure is under 60
- ad.after_password_change.failures_before_change is 0 or near 0
- ad.top_source_share is 0.8 or higher, and ad.external_source_ips is empty
- failure codes are 0xc000006a or 0x18
- ad.cadence.regular is true (a service, scheduled task or mapped drive retrying)

## Rule out
- ad.distinct_source_hosts above 5, or any external source IP: use possible-spray-escalate
- a log source listed in gaps: lower confidence one level

## Tell the owner
- which host carries the failures, when they started, how often they repeat
- that the timing lines up with the password change

## Approved next steps
- Update the stored password for this account on HOST (check services, scheduled tasks, application config and mapped drives).
- After the stored password is fixed, request an unlock through the standard service desk path.
- If nobody recognises HOST, stop and contact the CSOC.

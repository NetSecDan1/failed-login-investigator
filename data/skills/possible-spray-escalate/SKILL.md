---
id: possible-spray-escalate
title: Possible password guessing from many sources
escalate: true
---
## Signals (all computed by code, read them from FINDINGS)
- ad.distinct_source_hosts above 5, or ad.external_source_ips is not empty
- failure codes are 0xc000006a, 0xc0000064 or 0x18
- failures packed into a short burst (see ad.busiest_hours_utc, ad.first_seen, ad.last_seen)
- no password change that explains the timing

## Rule out
- one internal host carrying 0.8 or more of failures right after a password change: use stale-credential

## Tell the owner
- that the pattern does not look like one misconfigured system
- how many sources, over what period
- do not speculate about who is responsible

## Approved next steps
- Contact the CSOC now and give them the reference for this investigation.
- Do not change the account password until the CSOC advises.
- Do not attempt to investigate the source systems yourself.

# Measuring value and cost

**Status: nothing here has been measured. There is no live usage or cost data, so any figure for benefit or
return on investment would be speculation.** This page defines what to measure and how, so a pilot produces
numbers that can be defended.

## The unit: cost per successfully completed investigation

Token volume alone says nothing. The unit is one investigation that ended in a validated report.

```bash
aws logs tail /aws/lambda/<function> --since 7d | python tools/cost_report.py --in-price <per million> --out-price <per million>
```

It reports attempts, successful reports, success rate, validator rejects, model calls, tokens, model cost, and
cost per successful investigation. Requests that used a model but ended in facts only are counted in the cost
and spread across the successes, because failed attempts are part of the real price.

Prices are arguments, not constants. Use the rates that actually apply, including any gateway charge.

## Quality, measured alongside cost

| Measure | How |
|---------|-----|
| Finding agreement | An engineer reviews a sample of reports and marks each right, partly right or wrong |
| Escalation correctness | Every mandatory escalation and a sample of non-escalations reviewed by security operations |
| Facts accuracy | Counts, top host and first and last seen checked against a manual search for a sample |
| Safe failure rate | Share of requests that ended facts-only, and why |
| Model evaluation | `python tools/run_evals.py` on the synthetic cases, re-run on every skill or prompt change |

A cheaper run that is wrong is not cheaper. Report cost only next to these.

## Baseline first

Before a pilot, record for the manual process:

- median time from ticket to a verified explanation
- how often the first explanation was right
- how many such investigations happen in a month

## Return on investment

```
ROI = (quantified benefit - total cost) / total cost
```

- **Benefit** = investigations completed by the agent x time saved per investigation x the share of that time
  that became productive work x loaded hourly cost. Adoption and the productive share must be measured, not assumed.
- **Total cost** = model and gateway charges + platform and runtime + integration and build + operation and support.

If any input is missing, report ROI as **not yet measured**.

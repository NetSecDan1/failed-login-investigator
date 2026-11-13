# Skill library

Thirteen skills in [`skills/`](../skills), one folder each. A skill is two files:

| File | Read by | Holds |
|------|---------|-------|
| `SKILL.md` | the model | When it applies, what evidence to read, how to reason, what to rule out, what to tell the owner, what never to say |
| `rules.json` | code | Eligibility rules over computed signals, ordering hints, the escalation rule, and the approved next steps |

`SKILL.md` follows the open Agent Skills layout (YAML frontmatter with `name` and `description`, then markdown),
so the same folders load in any framework that supports it. `rules.json` is this project's addition and is what
makes the library safe to hand to a model.

## The split that matters

The model is good at reading a pattern and explaining it in plain words. It is not trusted to decide what the
evidence can support, whether to escalate, or what the owner should do next. So:

1. **Code computes signals** (`src/findings.py`, the `signals` block). Shares, counts, timings. No model arithmetic.
2. **Code decides eligibility** (`src/skillmatch.py`). Each skill's `require` must hold. The model can only choose
   from the eligible list, and the validator rejects anything else.
3. **Code decides mandatory escalation.** When a skill's `mandatory_when` holds, the only permitted choices are
   escalating skills, and `must_escalate` is returned to the caller even if the model never answers.
4. **Code renders next steps.** Steps are templates in `rules.json`. The model returns step numbers. Host names
   and app names are filled in from validated evidence, so hostile log text cannot reach a step.
5. **The model writes the narrative and picks confidence.** The validator then checks that every host, address
   and account in the narrative already exists in the evidence.

## Skills

| Skill | Fires on | Escalates |
|-------|----------|-----------|
| `stale-credential` | Wrong password soon after a password change | no |
| `wrong-password-no-change-in-window` | Wrong password, internal sources, no change visible | no |
| `suspicious-source-escalate` | External addresses, many sources, or cloud sign-in spray | yes, mandatory with external AD sources |
| `lockout-aftermath` | Locked or Kerberos revoked codes only | no |
| `disabled-account-in-use` | Disabled codes in AD or Entra | no |
| `expired-password` | Password expired or must-change codes | no |
| `account-expired` | Account end date passed | no |
| `kerberos-clock-skew` | Kerberos 0x25 | no |
| `logon-restriction` | Workstation or logon-hours restriction | no |
| `conditional-access-block` | Entra access policy block codes | no |
| `legacy-auth-client` | Bad password from legacy mail or basic-auth clients | no |
| `entra-mfa-interrupt` | MFA interrupt codes, not wrong passwords | no, but one step sends unrecognised prompts to the CSOC |
| `insufficient-evidence` | Always eligible as the fallback | no |

## rules.json

```json
{
  "id": "kerberos-clock-skew",
  "title": "Clock on the source system is wrong",
  "escalate": false,
  "priority": 7,
  "require": {"all": [{"signal": "ad_failures", "op": ">=", "value": 3},
                      {"signal": "clock_skew_share", "op": ">=", "value": 0.5}]},
  "support": [{"label": "one host carries at least 80% of failures",
               "cond": {"signal": "top_source_share", "op": ">=", "value": 0.8}, "weight": 2}],
  "next_steps": ["Ask the team that runs {top_host} to check its clock and time synchronisation. ..."]
}
```

- **Conditions:** `{"signal", "op", "value"}`, `{"all": [...]}`, `{"any": [...]}`, `{"not": ...}`, `{"always": true}`.
  Operators: `== != >= <= > <`. A signal that is null or missing makes its comparison false.
- **`require`** gates eligibility. **`exclude`** removes it. **`support`** only orders eligible skills and is shown
  to the model as met and unmet labels. **`mandatory_when`** is allowed only on escalating skills.
- **Step variables:** `{account}`, `{top_host}`, `{lockout_caller}`, `{top_client_app}`, `{top_app}`.
- Thresholds are starting points chosen against synthetic data. Tune them against real cases.

## Adding or changing a skill

1. Create `skills/<id>/SKILL.md` and `skills/<id>/rules.json`. Keep the eight section headings in order.
2. If the rule needs a signal that does not exist, add it to the `signals` block in `src/findings.py` first.
3. Add a synthetic case to `tools/make_data.py` and a line to `evals/cases.json`. Every skill must have one.
4. Run `python tools/build_skill_index.py` then `python -m pytest -q tests`.
5. Open a pull request. An identity engineer reviews the wording of every approved step.

The tests enforce: valid frontmatter, section order, every rule signal exists, every approved step appears
word for word in `SKILL.md`, rule-out references point at real skills, every skill has a golden case, null
signals never make a skill eligible, and the index is current.

## Evaluating

- **Matcher, offline:** `python -m pytest -q tests/test_skills.py`. Checks that code offers the expected skill first for each case.
- **Model, live:** `python tools/run_evals.py` invokes the deployed function for each case and scores the model's
  choice. This has not been run yet in this repo because the test account has no Anthropic model access.
  Until it has, treat the model-facing wording of the skills as unproven.

## Using the library from other frameworks

The skill folders are framework neutral. What changes is where the code gates run.

**Plain Bedrock Converse (this repo).** `src/explain.py` builds one prompt: a one-line index of all skills, the
allowed choices, and full text for only the eligible skills. Nothing else to do.

**Strands Agents.** Strands loads Agent Skills folders natively and discloses them progressively. From the Strands
documentation (not run in this repo):

```python
from strands import Agent, AgentSkills

agent = Agent(plugins=[AgentSkills(skills="./skills/")])
```

Loading the folders this way gives the model the skill text but none of the gates. Keep the guarantees by
running `skillmatch.match()` on the findings before the agent turn, passing only the allowed choices into the
prompt, and running `validator.validate()` and `skillmatch.render_steps()` on the result before anything is shown.

**Bedrock AgentCore.** Host the same Strands agent in AgentCore Runtime and ship `skills/` with it. Expose the
read tools through AgentCore Gateway. The matcher and validator stay in your agent code, and Gateway policy adds
a second check on tool calls. They are not a replacement for each other.

In every case the rule is the same: the skill text advises the model, and `rules.json` plus the validator constrain it.

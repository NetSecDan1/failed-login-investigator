---
description: Add or change a skill in the skill library
---
Follow `docs/SKILLS.md`, section "Adding or changing a skill".

1. Ask me which evidence pattern the skill covers and what the owner should be told to do.
2. If the pattern needs a signal that `src/findings.py` does not compute, add the signal first, with a test.
3. Create `skills/<id>/SKILL.md` with the eight standard sections in order, and `skills/<id>/rules.json`.
4. Add a synthetic case to `tools/make_data.py` and a line to `evals/cases.json`.
5. Run `python tools/build_skill_index.py`, then `python -m pytest -q tests/test_skills.py`.
6. Do not weaken another skill's rules to make the new case pass. If two skills now compete, tell me.

Approved next steps are instructions to a person. Keep them specific, safe and free of anything that weakens a control.

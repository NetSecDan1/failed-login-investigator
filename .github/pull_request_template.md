## What changed and why

## Evidence

- [ ] Tests added or updated for authorization boundaries, invalid input and failure paths touched by this change
- [ ] `python -m pytest -q tests`, `ruff check .`, `python tools/redteam.py` pass locally
- [ ] If a skill changed: `python tools/build_skill_index.py` run, golden case added or updated, approved step wording reviewed by an identity engineer
- [ ] `docs/STATUS.md` updated, with synthetic evidence and live evidence kept apart

## Boundaries (answer each)

- Does this give the model any new tool, data or authority? If yes, explain why code cannot do it instead.
- Does this add a write path or widen a permission? If yes, it needs a design review before merge.
- Does this add real identity data, real log content, a token, or an organization-specific name? It must not.

## What was exercised

State exactly which systems, identities, models and data were used. A fake client or scripted model is not live validation.

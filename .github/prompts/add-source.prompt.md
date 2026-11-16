---
description: Add an evidence source adapter
---
Follow `docs/SOURCES.md`, section "Adding a source".

1. Ask me which kinds of evidence the source can answer and how it is queried.
2. Subclass `backends.Backend`. Requests must be fixed-shape, read-only, https, for one account and one window.
3. Register it in `adapters.REGISTRY`, add its settings to `config/settings.json` and its requirements to `tools/preflight.py`.
4. Add it to `NAMES` in `tests/test_adapters.py` so the shared contract runs against it, and add request-shape
   tests with a scripted transport. Do not call a real system from a test.
5. Record it in `docs/STATUS.md` as tested against fake responses only.

# Query pack

Fixed templates for the real evidence backends. **Not wired in and not verified against a live system.**
Index names, sourcetypes, table names and field names are placeholders. Confirm each against your
Splunk add-on and Databricks schema before use.

Rules the renderer in `src/querypack.py` enforces:

- Only three values are ever filled in: `account`, `start`, `end`.
- `account` must match `^[a-z0-9._$-]{1,64}$` and must already be in the caller's scope set.
- `start` and `end` are rendered by code as UTC ISO timestamps. Callers cannot pass strings.
- Databricks statements use named parameter markers, so values travel as parameters, not as SQL text.
- Every template carries its own row cap.

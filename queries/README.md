# Query pack

Fixed templates for the Splunk and Databricks backends in `src/backends.py`.
**Tested against fake responses only. Not yet run against a live Splunk or Databricks.**
Field names differ between environments, so result fields are mapped in `config/field_map.json`, not here.

Rules the renderer in `src/querypack.py` enforces:

- Caller-influenced values are exactly three: `account`, `start`, `end`.
- `account` must match `^[a-z0-9._$-]{1,64}$` and must already be in the caller's scope set.
- `start` and `end` are rendered by code from timezone-aware datetimes. Callers cannot pass strings.
- Operator settings (`{index_windows}`, `{index_entra}`, `{view_*}`) come from environment variables and must
  look like identifiers. They are deployment config, never request input.
- Databricks statements use named parameter markers, so values travel as parameters, not as SQL text.
- Every template carries its own row cap.
- `source_health_*` templates contain no account and return one aggregate row. They are rendered by a separate
  function that cannot render an evidence template, and the reverse.
- Time bounds are never part of the Splunk search text. They are sent as request parameters.

Splunk templates return whole events and let the field map pick fields, because `fields` lists break when a
field name differs. Tighten them with a `fields` clause once your names are confirmed.

# Configuration

Generated from `config/settings.json` by `python tools/preflight.py --write-docs`. Do not edit by hand.
`tests/test_config.py` fails when the code reads a setting that is not listed here.

Run `python tools/preflight.py` against a planned environment before deploying. It blocks on prototype
defaults. Passing it does not mean the deployment is approved or has been tested live.

| Setting | Default | Purpose | For a real deployment |
|---------|---------|---------|-----------------------|
| `DATA_BUCKET` | empty | Bucket holding skills, and the ownership file and synthetic evidence when those backends are in use. | required |
| `AGENT_ENABLED` | `true` | Operator kill switch. Anything but true refuses every request before identity, data or model. |  |
| `ALLOW_TEST_CLAIMS` | `false` | Accept the caller from the request body. Development only. | must be false |
| `CALLER_CLAIM` | `employee_id` | Token claim that identifies the caller. Must be the key used by the ownership source. |  |
| `JWT_ISSUER` | empty | Agent runtime: token issuer to verify against. | required for the agent runtime |
| `JWT_AUDIENCE` | empty | Agent runtime: audience the token must carry. | required for the agent runtime |
| `JWT_JWKS_URL` | empty | Agent runtime: signing keys location. https only. | required for the agent runtime |
| `OWNERSHIP_MAX_AGE_HOURS` | `0` | Refuse requests when ownership data is older than this. 0 is off. | must be above 0 |
| `RATE_LIMIT_PER_HOUR` | `0` | Investigations allowed per caller per clock hour. 0 is off. | must be above 0 |
| `RATE_LIMIT_TABLE` | empty | Counter table shared by all instances. Empty keeps the count in one process. | required when the limit is on |
| `EVIDENCE_BACKEND` | `file` | Default evidence source for every kind: file (synthetic), none, splunk, databricks, export, graph or loganalytics. | must not be file |
| `EVIDENCE_SOURCES` | empty | Per-kind overrides of the default, such as failed_logins=splunk,entra_failures=graph. A kind may list several sources joined with +, tried in order, such as entra_failures=loganalytics+graph. Kinds: failed_logins, account_events, entra_failures. | no kind may resolve to file |
| `SOURCES_DISABLED` | empty | Comma-separated source names to turn off without changing routes, such as graph. A switched-off source is skipped and the next one in the list for that kind is used. With none left, the report states the gap. |  |
| `SOURCE_SWITCH_KEY` | empty | Object key of the operator switch file in the data bucket, such as runtime/switches.json. When set, the file is re-read every minute and may turn sources off while the service runs. It cannot turn on a source that is not in the routes. Empty means no switch file is read. |  |
| `EXPORT_PREFIX` | `exports` | Folder in the data bucket where scheduled report exports land, for the export source. |  |
| `ENTRA_TENANT_ID` | empty | Cloud identity tenant, for the graph and loganalytics sources. | required for graph or loganalytics |
| `ENTRA_CLIENT_ID` | empty | Read-only application identity used by the graph and loganalytics sources. | required for graph or loganalytics |
| `ENTRA_CLIENT_SECRET_ARN` | empty | Secret holding that application's credential. | required for graph or loganalytics |
| `ENTRA_CLIENT_SECRET` | empty | Plain credential. Local runs only. | must be empty |
| `LOGANALYTICS_WORKSPACE_ID` | empty | Log workspace holding the sign-in tables, for the loganalytics source. | required for loganalytics |
| `SOURCE_HEALTH_CHECK` | `true` | Ask each source for an activity count so a silent source is not read as a clean account. | must be true |
| `EXPECTED_REPORTING_HOSTS` | `0` | Domain controllers expected to report. 0 skips the comparison. | should be above 0 |
| `SOURCE_MAX_LAG_MINUTES` | `0` | How far the newest event in a source may trail the end of the window before the report states that recent activity may be missing. 0 records the lag without judging it. Set it after measuring each source with tools/check_sources.py. | should be set |
| `FIELD_MAP_PATH` | empty | Path to a field map other than config/field_map.json. |  |
| `QUERY_TEMPLATE_DIR` | empty | Path to query templates other than queries/. |  |
| `SPLUNK_BASE_URL` | empty | Splunk management endpoint. https only. |  |
| `SPLUNK_INDEX_WINDOWS` | empty | Index holding directory logon events. Plain identifier. |  |
| `SPLUNK_INDEX_ENTRA` | empty | Index holding cloud sign-in events. Plain identifier. |  |
| `SPLUNK_TOKEN_SECRET_ARN` | empty | Secret holding the read-only Splunk token. |  |
| `SPLUNK_TOKEN` | empty | Plain token. Local runs only. | must be empty |
| `DATABRICKS_HOST` | empty | Workspace URL. https only. |  |
| `DATABRICKS_WAREHOUSE_ID` | empty | SQL warehouse to run statements on. |  |
| `DATABRICKS_VIEW_FAILED_LOGINS` | empty | Three-part view name. |  |
| `DATABRICKS_VIEW_ACCOUNT_EVENTS` | empty | Three-part view name. |  |
| `DATABRICKS_VIEW_ENTRA_FAILURES` | empty | Three-part view name. |  |
| `DATABRICKS_TOKEN_SECRET_ARN` | empty | Secret holding the read-only Databricks token. |  |
| `DATABRICKS_TOKEN` | empty | Plain token. Local runs only. | must be empty |
| `MODEL_ROUTE` | `bedrock` | bedrock for a direct call, gateway for a central OpenAI-compatible model gateway. | owner decision |
| `MODEL_ID` | empty | Model or inference profile used for the explanation. | required |
| `ROUTER_MODEL_ID` | empty | Agent runtime: model used only to choose a tool. Defaults to MODEL_ID. |  |
| `MODEL_GATEWAY_URL` | empty | Gateway base URL. https only. | required when the route is gateway |
| `MODEL_GATEWAY_TOKEN_SECRET_ARN` | empty | Secret holding the gateway token. |  |
| `MODEL_GATEWAY_TOKEN` | empty | Plain token. Local runs only. | must be empty |
| `MODEL_MAX_OUTPUT_TOKENS` | `1200` | Output token ceiling per model call. |  |
| `MODEL_TIMEOUT_SECONDS` | `60` | Model call timeout. |  |
| `MODEL_MAX_ATTEMPTS` | `2` | Transport attempts for the direct route. |  |
| `GUARDRAIL_ID` | empty | Direct route: guardrail applied to the model call. | should be set on the direct route |
| `GUARDRAIL_VERSION` | `DRAFT` | Guardrail version. | should be a numbered version |
| `METRICS_EMF` | `false` | Write one embedded metric line per request. | should be true |

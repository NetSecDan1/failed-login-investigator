# Test events

Requests for the synthetic data set. They pass the caller in the request, which works only while the
function's `ALLOW_TEST_CLAIMS` setting is `true`.

| File | Expect |
|------|--------|
| `01-list-accounts.json` | ok: three accounts listed |
| `02-owned-account.json` | ok: stale-credential offered first |
| `03-mandatory-escalation.json` | ok: must_escalate true |
| `04-account-not-owned.json` | denied: out_of_scope |
| `05-unknown-caller.json` | denied: scope_empty |
| `06-cloud-sign-in-case.json` | ok: legacy-auth-client offered first |

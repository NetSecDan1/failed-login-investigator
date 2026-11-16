# Using it from Visual Studio Code with GitHub Copilot

Two separate things live here: working on this repository with an assistant, and using the investigator as a
tool from the assistant's chat.

**Status: the integration server is unit tested and starts locally. It has not been exercised from a live
editor session in this repository's testing, and the service mode has only been tested against a scripted
service.** Whether assistants and tool servers may be used in your editor is an organization policy decision.
Confirm it before turning this on.

## Working on the repository

Open the folder in Visual Studio Code. The workspace brings:

| File | What it gives you |
|------|-------------------|
| `.github/copilot-instructions.md` | The rules an assistant must follow here: no model authority, no write path, no real data, tests with every change |
| `.github/prompts/` | Reusable prompts: investigate an account, add a skill, add an evidence source |
| `.vscode/tasks.json` | One-click tasks for tests, lint, security analysis, evaluation and "All gates before a pull request" |
| `.vscode/extensions.json` | Recommended extensions |

Run a task with **Terminal**, **Run Task**. Run a prompt by typing `/` in the chat view and choosing it.

## Using the investigator from chat

`integrations/mcp_server.py` exposes two typed tools over the Model Context Protocol:

| Tool | Arguments | Does |
|------|-----------|------|
| `list_owned_accounts` | none | Lists the accounts the signed-in person may investigate |
| `investigate` | `account`, `window_hours` | Returns the code-rendered report for one owned account |

The caller is never an argument. `.vscode/mcp.json` defines the server twice, once per mode.

### Synthetic mode: `investigator-synthetic`

Runs the whole pipeline inside the editor process on the generated data set, as the fixed sample caller `E1001`.
Nothing leaves the workstation unless you also configure a model. It refuses to start if an evidence source
other than the synthetic one is configured, because this mode has no verified identity.

1. `pip install -r integrations/requirements.txt`
2. Open the chat view, switch to agent mode, open the tools picker and enable `investigator-synthetic`.
   Approve starting the server when asked.
3. Try: `/investigate svc-batch01`

### Service mode: `investigator-service`

A thin client for a deployed investigator API. The editor asks you for the API address and your own access
token when the server starts, and keeps the token out of files. Identity, ownership, rate limits and every
other control are enforced by the service. The integration has no authority of its own.

Use this mode for anything real. Never point synthetic mode at real evidence.

## What the editor cannot guarantee

In the deployed service the reply a person sees is rendered by code. In an editor chat the assistant writes the
final message, so it can paraphrase, shorten or embellish the tool's report. The controls still hold where they
matter: the assistant cannot change who the caller is, cannot reach accounts outside scope, and every number
in the tool output came from code. But the wording on screen is the assistant's.

- The tool output ends with an instruction to show the report as written, and the `investigate` prompt repeats it.
- Expand the tool call in the chat view to read the exact report.
- Treat the expanded tool output, not the chat summary, as the record. The service's audit line carries the same reference.

## Settings the integration reads

| Setting | Mode | Meaning |
|---------|------|---------|
| `FLI_MODE` | both | `local` (synthetic) or `api` (deployed service) |
| `FLI_DEV_CALLER` | local | Sample caller in the synthetic data set |
| `MODEL_ID`, `MODEL_ROUTE` | local | Optional. Adds the model's narrative. Without them you get facts and allowed skills |
| `FLI_API_URL` | api | Address of the investigator API, https only |
| `FLI_API_TOKEN` | api | Your access token. Supplied at start by the editor prompt, not stored |

#!/usr/bin/env python3
"""Editor integration. Exposes the investigator to an assistant in the editor as two typed tools.

It speaks the Model Context Protocol over stdio, which editor assistants such as GitHub Copilot in
Visual Studio Code can use. See docs/VSCODE.md.

Two modes, chosen by FLI_MODE:

  local   Runs the pipeline in this process on the SYNTHETIC data set only, as the fixed caller FLI_DEV_CALLER.
          For development and demos. It refuses to start against a real evidence source.
  api     Calls a deployed investigator API with the user's own access token. Identity, ownership and every
          other control are enforced by the service. This process holds no authority of its own.

In both modes the tools take an account and a time window and nothing else. The caller is never a tool argument,
so nothing the assistant writes can change whose accounts are in scope.
"""
import contextlib, glob, io, json, os, runpy, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

NOTE = ("\n\n[Rendered by code from validated results. Show it as written. Do not add hosts, numbers, causes or "
        "next steps that are not in it.]")


def _mode():
    mode = os.environ.get("FLI_MODE", "local").lower()
    if mode not in ("local", "api"):
        raise SystemExit("FLI_MODE must be local or api")
    return mode


def _local_store():
    import evidence
    with contextlib.redirect_stdout(io.StringIO()):                      # generate the synthetic data set in process
        runpy.run_path(os.path.join(ROOT, "tools", "make_data.py"), run_name="__main__")
    files = {}
    for base, prefix in ((os.path.join(ROOT, "data"), ""), (os.path.join(ROOT, "skills"), "skills/")):
        for p in glob.glob(base + "/**/*", recursive=True):
            if os.path.isfile(p):
                files[prefix + os.path.relpath(p, base).replace(os.sep, "/")] = open(p).read()
    return evidence.DictStore(files)


def check_local_is_synthetic(env=None):
    """Local mode has no verified identity, so it may only ever see synthetic data."""
    env = os.environ if env is None else env
    sources = (env.get("EVIDENCE_BACKEND", "file") + "," + env.get("EVIDENCE_SOURCES", "")).lower()
    names = {part.split("=")[-1].strip() for part in sources.split(",") if part.strip()}
    if names - {"file", "none"}:
        raise SystemExit("Local mode only runs on synthetic data. To investigate real accounts use FLI_MODE=api, "
                         "so that identity and ownership are enforced by the deployed service.")


def call_local(request, store=None):
    import handler
    os.environ["ALLOW_TEST_CLAIMS"] = "true"
    claim = os.environ.get("CALLER_CLAIM", "employee_id")
    event = dict(request, claims={claim: os.environ.get("FLI_DEV_CALLER", "E1001")})
    if event.get("action") != "list_accounts":
        event.setdefault("end", "2026-11-12T18:00:00Z")                 # the synthetic data set lives on this day
    model = None if os.environ.get("MODEL_ID") else (lambda *a: (None, {"reason": "model_not_configured"}))
    with contextlib.redirect_stdout(io.StringIO()):                      # stdout belongs to the protocol
        return handler.handler(event, None, store=store or _local_store(), model=model)


def call_api(request, transport=None):
    import backends
    base = os.environ.get("FLI_API_URL", "").rstrip("/")
    token = os.environ.get("FLI_API_TOKEN", "")
    if not base.lower().startswith("https://"):
        return {"status": "denied", "reason": "not_configured", "message": "FLI_API_URL must be an https address."}
    if not token:
        return {"status": "denied", "reason": "unauthenticated", "message": "No access token was provided to the editor integration."}
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    send = transport or backends.urllib_transport
    try:
        if request.get("action") == "list_accounts":
            status, data = send("GET", base + "/accounts", headers, None, 30)
        else:
            body = json.dumps({"account": request["account"], "window_hours": request["window_hours"]}).encode()
            status, data = send("POST", base + "/investigations", headers, body, 120)
        result = json.loads(data)
        if isinstance(result, dict) and "status" in result:
            return result
        return {"status": "denied", "reason": "unexpected_response", "message": "The service answered with HTTP %s." % status}
    except Exception as e:
        return {"status": "denied", "reason": "service_unreachable", "message": "The investigator service could not be reached (%s)." % type(e).__name__}


def run(request, store=None, transport=None):
    import render
    result = call_api(request, transport) if _mode() == "api" else call_local(request, store)
    return render.to_text(result) + NOTE


def list_owned_accounts() -> str:
    """List the accounts the signed-in person owns and may investigate."""
    return run({"action": "list_accounts"})


def investigate(account: str, window_hours: int = 24) -> str:
    """Explain why one account the signed-in person owns keeps failing to log in.

    account: the account name exactly as returned by list_owned_accounts.
    window_hours: how far back to look, 1 to 168.
    """
    return run({"account": str(account), "window_hours": int(window_hours)})


def build_server():
    from mcp.server.mcpserver import MCPServer
    server = MCPServer("failed-login-investigator",
                       instructions="Read-only. Explains failed logins for accounts the signed-in person owns. "
                                    "It cannot unlock, reset or change anything, and cannot look at other people's accounts.")
    server.tool()(list_owned_accounts)
    server.tool()(investigate)
    return server


if __name__ == "__main__":
    if _mode() == "local":
        check_local_is_synthetic()
    build_server().run()

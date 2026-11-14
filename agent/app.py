"""Agent entry point for an agent runtime (Strands Agents on Amazon Bedrock AgentCore Runtime).

What the model does here: reads the user's request and chooses one of two typed tools.
What the model does not do: identify the caller, decide scope, fetch data, compute numbers, choose whether
to escalate, write next steps, or write the reply. Tools run the same deterministic pipeline as the HTTP API
(src/handler.py), and the reply is rendered by code from validated tool results.

Not yet deployed to a runtime. Exercised by unit tests with a scripted model.
"""
import contextlib
import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import evidence  # noqa: E402
import handler  # noqa: E402
import render  # noqa: E402
import scope  # noqa: E402

try:                                    # package import (python -m agent.app, tests) or script in a container
    from . import identity
except ImportError:                     # pragma: no cover
    import identity

MAX_PROMPT_CHARS = 2000
MAX_TOOL_CALLS = 3
HELP = "I can list the accounts you own, or investigate failed logins for one of them over the last 1 to 168 hours."
ROUTER_PROMPT = (
    "You route requests for a failed-login investigation service. You have two tools and no other abilities.\n"
    "Call list_owned_accounts when the user asks which accounts they own or names no account.\n"
    "Call investigate_failed_logins when the user names an account. Pass the account name exactly as written. "
    "Use window_hours only if the user gives a period, otherwise leave the default.\n"
    "Call at most one tool, once. Do not answer questions yourself, do not explain, do not guess account names. "
    "If the request is about anything else, reply with the single word UNSUPPORTED."
)


def make_store():
    if os.environ.get("DATA_BUCKET"):
        return evidence.S3Store(os.environ["DATA_BUCKET"])
    raise RuntimeError("DATA_BUCKET is not set")


def make_router_model():
    """Model used only to choose a tool. Same route setting as the explanation step."""
    route = os.environ.get("MODEL_ROUTE", "bedrock").lower()
    model_id = os.environ.get("ROUTER_MODEL_ID") or os.environ["MODEL_ID"]
    if route == "gateway":
        import backends
        from strands.models.openai import OpenAIModel
        return OpenAIModel(client_args={"base_url": os.environ["MODEL_GATEWAY_URL"],
                                        "api_key": backends.secret_from_env("MODEL_GATEWAY_TOKEN_SECRET_ARN", "MODEL_GATEWAY_TOKEN")},
                           model_id=model_id, params={"max_tokens": 200, "temperature": 0})
    from strands.models import BedrockModel
    return BedrockModel(model_id=model_id, max_tokens=200, temperature=0)


def _pipeline(claims, request, store, explain_model=None):
    """Run the deterministic pipeline with verified claims. Audit lines go to stdout as usual."""
    event = dict(request, requestContext={"authorizer": {"jwt": {"claims": claims}}})
    return handler.handler(event, None, store=store, model=explain_model)


def run(payload, headers=None, store=None, router_model=None, explain_model=None, key_resolver=None):
    """One agent turn. Returns {"status", "results", "text"}. Every result has been through the pipeline."""
    payload = payload if isinstance(payload, dict) else {}
    try:
        claims = identity.verified_claims(headers, payload, key_resolver)
    except scope.Denied as d:
        return {"status": "denied", "reason": d.code, "results": [], "text": "DENIED  %s\n%s" % (d.code, d.message)}
    store = store or make_store()
    results = []

    # Structured requests skip the routing model entirely: no tokens spent, nothing for a prompt to steer.
    action = payload.get("action")
    if action == "list_accounts":
        results.append(_pipeline(claims, {"action": "list_accounts"}, store))
    elif action == "investigate":
        results.append(_pipeline(claims, {"account": payload.get("account"), "window_hours": payload.get("window_hours", 24),
                                          **({"end": payload["end"]} if payload.get("end") else {})}, store, explain_model))
    else:
        prompt = str(payload.get("prompt", ""))[:MAX_PROMPT_CHARS]
        if not prompt.strip():
            return {"status": "ok", "results": [], "text": HELP}
        usage = _route_with_model(prompt, claims, store, results, router_model, explain_model)
        print("ROUTE " + json.dumps({"tool_calls": len(results), "tokens_in": usage.get("inputTokens", 0),
                                     "tokens_out": usage.get("outputTokens", 0)}, sort_keys=True))
    if not results:
        return {"status": "ok", "results": [], "text": HELP}
    ok = all(r.get("status") == "ok" for r in results)
    return {"status": "ok" if ok else "denied", "results": results, "text": "\n\n".join(render.to_text(r) for r in results)}


def _route_with_model(prompt, claims, store, results, router_model, explain_model):
    from strands import Agent, ToolContext, tool

    def record(result, ctx):
        results.append(result)
        ctx.agent.cancel(after_current_tools=True)        # one tool call, then stop: no second model turn
        return "done"

    @tool(context=True)
    def list_owned_accounts(tool_context: ToolContext) -> str:
        """List the accounts the signed-in user owns."""
        if len(results) >= MAX_TOOL_CALLS:
            return "limit reached"
        return record(_pipeline(claims, {"action": "list_accounts"}, store), tool_context)

    @tool(context=True)
    def investigate_failed_logins(account: str, tool_context: ToolContext, window_hours: int = 24) -> str:
        """Investigate failed logins for one account the signed-in user owns.

        Args:
            account: The account name exactly as the user wrote it.
            window_hours: How many hours back to look, 1 to 168.
        """
        if len(results) >= MAX_TOOL_CALLS:
            return "limit reached"
        return record(_pipeline(claims, {"account": account, "window_hours": window_hours}, store, explain_model), tool_context)

    agent = Agent(model=router_model or make_router_model(), tools=[list_owned_accounts, investigate_failed_logins],
                  system_prompt=ROUTER_PROMPT, callback_handler=None)
    with contextlib.redirect_stderr(io.StringIO()):
        out = agent(prompt)
    return dict(out.metrics.accumulated_usage or {})


def build_app():
    from bedrock_agentcore.runtime import BedrockAgentCoreApp
    app = BedrockAgentCoreApp()

    @app.entrypoint
    def invoke(payload, context):
        return run(payload, getattr(context, "request_headers", None))

    return app


if __name__ == "__main__":             # pragma: no cover
    build_app().run()

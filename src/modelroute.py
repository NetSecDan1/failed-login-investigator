"""Model access route. One place decides how the model is reached and what limits apply.

  MODEL_ROUTE=bedrock   direct Bedrock Converse call with an optional Bedrock Guardrail (prototype default)
  MODEL_ROUTE=gateway   an OpenAI-compatible chat completions endpoint, for organisations that require all
                        model traffic to pass through a central model gateway

Both routes force the answer through a single function call (the report form), apply the same token, time
and attempt limits, and return usage in the same shape so cost can be measured per investigation.
The gateway route is unit tested against fake responses only.
"""
import json
import os

import backends

TOOL_NAME = "submit_report"


def limits():
    return {"max_output_tokens": int(os.environ.get("MODEL_MAX_OUTPUT_TOKENS", "1200")),
            "timeout_seconds": int(os.environ.get("MODEL_TIMEOUT_SECONDS", "60")),
            "max_attempts": int(os.environ.get("MODEL_MAX_ATTEMPTS", "2"))}


def _bedrock(system, user_text, schema, lim):
    import boto3
    from botocore.config import Config
    client = boto3.client("bedrock-runtime", config=Config(read_timeout=lim["timeout_seconds"],
                                                           retries={"max_attempts": lim["max_attempts"]}))
    model_id = os.environ["MODEL_ID"]
    meta = {"model": model_id, "route": "bedrock"}
    kwargs = dict(
        modelId=model_id,
        system=[{"text": system}],
        messages=[{"role": "user", "content": [{"text": user_text}]}],
        inferenceConfig={"maxTokens": lim["max_output_tokens"], "temperature": 0},
        toolConfig={"tools": [{"toolSpec": {"name": TOOL_NAME, "description": "Submit the investigation report.",
                                             "inputSchema": {"json": schema}}}],
                    "toolChoice": {"tool": {"name": TOOL_NAME}}},
    )
    if os.environ.get("GUARDRAIL_ID"):
        kwargs["guardrailConfig"] = {"guardrailIdentifier": os.environ["GUARDRAIL_ID"],
                                     "guardrailVersion": os.environ.get("GUARDRAIL_VERSION", "DRAFT")}
    try:
        resp = client.converse(**kwargs)
    except Exception as e:  # model failure never blocks the facts
        meta["reason"] = "model_error:" + type(e).__name__ + ":" + str(e)[:200]
        return None, meta
    usage = resp.get("usage", {})
    meta["tokens"] = {"inputTokens": usage.get("inputTokens", 0), "outputTokens": usage.get("outputTokens", 0)}
    meta["guardrail"] = "intervened" if resp.get("stopReason") == "guardrail_intervened" else "passed"
    if meta["guardrail"] == "intervened":
        meta["reason"] = "guardrail_intervened"
        return None, meta
    for block in resp["output"]["message"]["content"]:
        if "toolUse" in block:
            return block["toolUse"]["input"], meta
    meta["reason"] = "no_report_returned"
    return None, meta


def _gateway(system, user_text, schema, lim, transport=None):
    base = os.environ.get("MODEL_GATEWAY_URL", "")
    model_id = os.environ.get("MODEL_ID", "")
    meta = {"model": model_id, "route": "gateway"}
    if not base.lower().startswith("https://"):
        meta["reason"] = "model_error:gateway_url_must_be_https"
        return None, meta
    token = backends.secret_from_env("MODEL_GATEWAY_TOKEN_SECRET_ARN", "MODEL_GATEWAY_TOKEN")
    body = {"model": model_id, "temperature": 0, "max_tokens": lim["max_output_tokens"],
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user_text}],
            "tools": [{"type": "function", "function": {"name": TOOL_NAME, "description": "Submit the investigation report.",
                                                        "parameters": schema}}],
            "tool_choice": {"type": "function", "function": {"name": TOOL_NAME}}}
    try:
        status, data = (transport or backends.urllib_transport)(
            "POST", base.rstrip("/") + "/chat/completions",
            {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            json.dumps(body).encode(), lim["timeout_seconds"])
        if status != 200:
            raise RuntimeError("gateway http %s" % status)
        resp = json.loads(data)
        usage = resp.get("usage") or {}
        meta["tokens"] = {"inputTokens": usage.get("prompt_tokens", 0), "outputTokens": usage.get("completion_tokens", 0)}
        choice = resp["choices"][0]
        if choice.get("finish_reason") == "content_filter":
            meta.update(guardrail="intervened", reason="guardrail_intervened")
            return None, meta
        meta["guardrail"] = "gateway"          # content controls, if any, are applied by the gateway
        for call in choice["message"].get("tool_calls") or []:
            if call["function"]["name"] == TOOL_NAME:
                return json.loads(call["function"]["arguments"]), meta
        meta["reason"] = "no_report_returned"
        return None, meta
    except Exception as e:
        meta["reason"] = "model_error:" + type(e).__name__ + ":" + str(e)[:200]
        return None, meta


def call_report(system, user_text, schema, transport=None):
    """Returns (report_input or None, meta). meta carries model, route, tokens, guardrail and any reason."""
    route = os.environ.get("MODEL_ROUTE", "bedrock").lower()
    lim = limits()
    if route == "gateway":
        return _gateway(system, user_text, schema, lim, transport)
    if route == "bedrock":
        return _bedrock(system, user_text, schema, lim)
    return None, {"model": None, "route": route, "reason": "model_error:unknown_model_route"}

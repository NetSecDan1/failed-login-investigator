"""Deployment stage. Decides, in code, which configurations may run at all.

  development   the default. Synthetic data only. Any live evidence source is refused.
  integration   live sources may be connected for first contact in a non-production environment.
  production    the supported path only: the managed agent runtime and the governed model route.

Whenever evidence is live, the model must be reached through the governed route (MODEL_ROUTE=gateway) or not at
all (MODEL_ROUTE=off). The two departures an owner may approve are recorded by reference, never by a bare flag:

  MODEL_ROUTE_EXCEPTION        approval reference for calling the model directly
  FUNCTION_RUNTIME_EXCEPTION   approval reference for running as a plain function in production

A configuration that breaks a rule fails closed before identity, data or model, and the audit line says which
rule. This is a guard against deploying the wrong shape by accident. It is not a substitute for the approvals.
"""
import os
import re

STAGES = ("development", "integration", "production")
SYNTHETIC = ("file", "none")
REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{3,79}$")


class NotPermitted(Exception):
    def __init__(self, rule):
        super().__init__(rule)
        self.rule = rule


def _reference(env, name):
    value = (env.get(name) or "").strip()
    if value and not (REFERENCE.fullmatch(value) and any(c.isdigit() for c in value)):   # a record number, not "true"
        raise NotPermitted("%s_is_not_an_approval_reference" % name.lower())
    return value


def evaluate(env, shape, routes):
    """Return the approved exceptions in use, or raise NotPermitted naming the first broken rule.

    shape is "agent" for the managed agent runtime and "function" otherwise. routes is {kind: (source, ...)}.
    """
    stage = (env.get("DEPLOYMENT_STAGE") or "development").strip().lower()
    if stage not in STAGES:
        raise NotPermitted("unknown_deployment_stage")
    sources = {name for names in routes.values() for name in names}
    live = bool(sources - set(SYNTHETIC))
    used = []
    if live and stage == "development":
        raise NotPermitted("live_evidence_needs_integration_or_production_stage")
    if stage == "production":
        if "file" in sources:
            raise NotPermitted("synthetic_evidence_in_production")
        if (env.get("ALLOW_TEST_CLAIMS") or "false").lower() == "true":
            raise NotPermitted("test_claims_in_production")
    if live or stage == "production":
        route = (env.get("MODEL_ROUTE") or "bedrock").lower()
        if route not in ("gateway", "off"):
            ref = _reference(env, "MODEL_ROUTE_EXCEPTION")
            if not ref:
                raise NotPermitted("model_must_use_the_governed_route")
            used.append("model_route:" + ref)
    if stage == "production" and shape != "agent":
        ref = _reference(env, "FUNCTION_RUNTIME_EXCEPTION")
        if not ref:
            raise NotPermitted("production_runs_on_the_managed_agent_runtime")
        used.append("function_runtime:" + ref)
    return stage, used


def check(shape, backend_injected=False):
    """Evaluate the running process. An injected backend (tests, local tools) is judged by the caller, not here."""
    import adapters
    if backend_injected:
        routes = {"injected": ("file",)}
    else:
        try:
            routes = adapters.parse_routes(os.environ.get("EVIDENCE_BACKEND", "file").lower(), os.environ.get("EVIDENCE_SOURCES", ""))
        except ValueError:
            raise NotPermitted("evidence_routes_are_invalid") from None
    env = {"DEPLOYMENT_STAGE": os.environ.get("DEPLOYMENT_STAGE", "development"),
           "MODEL_ROUTE": os.environ.get("MODEL_ROUTE", "bedrock"),
           "ALLOW_TEST_CLAIMS": os.environ.get("ALLOW_TEST_CLAIMS", "false"),
           "MODEL_ROUTE_EXCEPTION": os.environ.get("MODEL_ROUTE_EXCEPTION", ""),
           "FUNCTION_RUNTIME_EXCEPTION": os.environ.get("FUNCTION_RUNTIME_EXCEPTION", "")}
    return evaluate(env, shape, routes)

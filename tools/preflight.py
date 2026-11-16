#!/usr/bin/env python3
"""Configuration preflight. Checks a set of settings against what a real deployment needs.

  python tools/preflight.py                       # check the current environment
  python tools/preflight.py --env-file prod.env   # check KEY=VALUE lines in a file
  python tools/preflight.py --runtime agent       # also require the agent runtime identity settings
  python tools/preflight.py --write-docs          # regenerate docs/CONFIGURATION.md from config/settings.json

Exit code 1 when any BLOCK finding exists. Passing this proves the settings are coherent and not left on
prototype defaults. It does not prove the deployment works, is approved, or has been tested live.
"""
import argparse, json, os, re, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
REGISTRY = os.path.join(ROOT, "config", "settings.json")
IDENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}$")


def registry():
    return json.load(open(REGISTRY))["settings"]


def check(env, runtime="function"):
    """Return a list of (level, setting, message). level is BLOCK or WARN."""
    reg = {s["name"]: s for s in registry()}
    get = lambda n: (env.get(n) if env.get(n) not in (None, "") else reg[n]["default"])
    out = []
    block = lambda n, m: out.append(("BLOCK", n, m))
    warn = lambda n, m: out.append(("WARN", n, m))

    def number(n, minimum):
        try:
            v = float(get(n))
        except ValueError:
            block(n, "is not a number")
            return None
        if v < minimum:
            return None
        return v

    for n in ("DATA_BUCKET", "MODEL_ID"):
        if not get(n):
            block(n, "is required")
    if get("ALLOW_TEST_CLAIMS").lower() != "false":
        block("ALLOW_TEST_CLAIMS", "must be false: it lets a request choose its own caller")
    if get("AGENT_ENABLED").lower() != "true":
        warn("AGENT_ENABLED", "the kill switch is off, every request will be refused")
    if number("OWNERSHIP_MAX_AGE_HOURS", 0.01) is None:
        block("OWNERSHIP_MAX_AGE_HOURS", "must be above 0 so stale ownership data is refused")
    if number("RATE_LIMIT_PER_HOUR", 1) is None:
        block("RATE_LIMIT_PER_HOUR", "must be above 0")
    elif not get("RATE_LIMIT_TABLE"):
        block("RATE_LIMIT_TABLE", "is required with a rate limit, otherwise each instance counts alone")
    if get("SOURCE_HEALTH_CHECK").lower() != "true":
        block("SOURCE_HEALTH_CHECK", "must be true so a silent source is not read as a clean account")
    if number("SOURCE_MAX_LAG_MINUTES", 1) is None:
        warn("SOURCE_MAX_LAG_MINUTES", "is 0, a source that is running behind will not be called out in reports")
    if number("EXPECTED_REPORTING_HOSTS", 1) is None:
        warn("EXPECTED_REPORTING_HOSTS", "is 0, partial collection from domain controllers will not be noticed")
    for n in ("SPLUNK_TOKEN", "DATABRICKS_TOKEN", "MODEL_GATEWAY_TOKEN", "ENTRA_CLIENT_SECRET"):
        if env.get(n):
            block(n, "a plain token is set: use the secret reference instead")
    for n in ("SPLUNK_BASE_URL", "DATABRICKS_HOST", "MODEL_GATEWAY_URL", "JWT_JWKS_URL"):
        if get(n) and not get(n).lower().startswith("https://"):
            block(n, "must use https")

    cloud = ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET_ARN"]
    need = {"splunk": ["SPLUNK_BASE_URL", "SPLUNK_INDEX_WINDOWS", "SPLUNK_TOKEN_SECRET_ARN"],
            "databricks": ["DATABRICKS_HOST", "DATABRICKS_WAREHOUSE_ID", "DATABRICKS_VIEW_FAILED_LOGINS",
                           "DATABRICKS_VIEW_ACCOUNT_EVENTS", "DATABRICKS_TOKEN_SECRET_ARN"],
            "graph": cloud, "loganalytics": cloud + ["LOGANALYTICS_WORKSPACE_ID"], "export": [], "none": [], "file": []}
    per_kind = {("splunk", "entra_failures"): ["SPLUNK_INDEX_ENTRA"], ("databricks", "entra_failures"): ["DATABRICKS_VIEW_ENTRA_FAILURES"]}
    sys.path.insert(0, os.path.join(ROOT, "src"))
    import adapters
    try:
        routes = adapters.parse_routes(get("EVIDENCE_BACKEND").lower(), get("EVIDENCE_SOURCES"))
    except ValueError as e:
        block("EVIDENCE_SOURCES", str(e))
        routes = {}
    for kind, source in sorted((k, n) for k, names in routes.items() for n in names):
        if source == "file":
            block("EVIDENCE_BACKEND", "%s resolves to file, which is synthetic data" % kind)
        if source == "none":
            (block if kind == "failed_logins" else warn)("EVIDENCE_SOURCES", "%s has no source, every report will carry that gap" % kind)
        if source in ("graph", "loganalytics") and kind != "entra_failures":
            block("EVIDENCE_SOURCES", "%s cannot come from %s, which only answers cloud sign-ins" % (kind, source))
        for n in need.get(source, []) + per_kind.get((source, kind), []):
            if not get(n):
                block(n, "is required for the %s source" % source)
            elif (n.startswith("SPLUNK_INDEX") or "_VIEW_" in n) and not IDENT.fullmatch(get(n)):
                block(n, "must be a plain identifier")
    try:
        off = adapters.Switches(env_disabled=get("SOURCES_DISABLED"), known=set(adapters.REGISTRY) - set(adapters.UNSWITCHED)).static
    except ValueError as e:
        block("SOURCES_DISABLED", str(e))
        off = frozenset()
    for kind, names in sorted(routes.items()):
        if names != ("none",) and all(n in off for n in names):
            (block if kind == "failed_logins" else warn)("SOURCES_DISABLED", "every source for %s is switched off, every report will carry that gap" % kind)
    key = get("SOURCE_SWITCH_KEY")
    if key and not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", key):
        block("SOURCE_SWITCH_KEY", "must be a plain object key")

    import stage
    if get("DEPLOYMENT_STAGE").lower() != "production":
        block("DEPLOYMENT_STAGE", "must be production for a real deployment. development is synthetic data only, integration is for first contact")
    else:
        try:
            _, used = stage.evaluate({n: get(n) for n in ("DEPLOYMENT_STAGE", "MODEL_ROUTE", "ALLOW_TEST_CLAIMS", "MODEL_ROUTE_EXCEPTION",
                                                          "FUNCTION_RUNTIME_EXCEPTION")}, runtime, routes or {"none": ("none",)})
            for item in used:
                warn(item.split(":")[0].upper() + "_EXCEPTION", "running on an approved exception (%s), not the supported path" % item.split(":", 1)[1])
        except stage.NotPermitted as np:
            names = {"model_must_use_the_governed_route": "MODEL_ROUTE", "production_runs_on_the_managed_agent_runtime": "FUNCTION_RUNTIME_EXCEPTION",
                     "test_claims_in_production": "ALLOW_TEST_CLAIMS", "synthetic_evidence_in_production": "EVIDENCE_BACKEND"}
            block(names.get(np.rule, "DEPLOYMENT_STAGE"), np.rule.replace("_", " "))

    route = get("MODEL_ROUTE").lower()
    if route == "gateway":
        for n in ("MODEL_GATEWAY_URL", "MODEL_GATEWAY_TOKEN_SECRET_ARN"):
            if not get(n):
                block(n, "is required for the gateway route")
    elif route == "bedrock":
        if not get("GUARDRAIL_ID"):
            warn("GUARDRAIL_ID", "no guardrail on the direct model route")
        elif get("GUARDRAIL_VERSION") == "DRAFT":
            warn("GUARDRAIL_VERSION", "is DRAFT: pin a numbered version so behavior cannot change underneath you")
    elif route == "off":
        warn("MODEL_ROUTE", "is off, every result will be facts only")
    else:
        block("MODEL_ROUTE", "is not one of gateway, off, bedrock")
    for n, lo, hi in (("MODEL_MAX_OUTPUT_TOKENS", 200, 4000), ("MODEL_TIMEOUT_SECONDS", 5, 120), ("MODEL_MAX_ATTEMPTS", 1, 3)):
        v = number(n, lo)
        if v is None or v > hi:
            block(n, "must be between %d and %d" % (lo, hi))
    if get("METRICS_EMF").lower() != "true":
        warn("METRICS_EMF", "metrics are off, alarms and cost reports will have nothing to read")
    if runtime == "agent":
        for n in ("JWT_ISSUER", "JWT_AUDIENCE", "JWT_JWKS_URL"):
            if not get(n):
                block(n, "is required for the agent runtime: without it no caller can be verified")
    unknown = sorted(k for k in env if k not in reg and re.match(r"^(MODEL|SPLUNK|DATABRICKS|JWT|RATE|OWNERSHIP|AGENT|EVIDENCE|GUARDRAIL|ENTRA|LOGANALYTICS|EXPORT)_", k))
    for k in unknown:
        warn(k, "is not a setting this code reads. Check for a typo")
    return out


def docs():
    lines = ["# Configuration", "",
             "Generated from `config/settings.json` by `python tools/preflight.py --write-docs`. Do not edit by hand.",
             "`tests/test_config.py` fails when the code reads a setting that is not listed here.", "",
             "Run `python tools/preflight.py` against a planned environment before deploying. It blocks on prototype",
             "defaults. Passing it does not mean the deployment is approved or has been tested live.", "",
             "| Setting | Default | Purpose | For a real deployment |", "|---------|---------|---------|-----------------------|"]
    for s in registry():
        lines.append("| `%s` | %s | %s | %s |" % (s["name"], ("`%s`" % s["default"]) if s["default"] else "empty", s["purpose"], s["production"] or ""))
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--env-file")
    ap.add_argument("--runtime", choices=["function", "agent"], default="function")
    ap.add_argument("--write-docs", action="store_true")
    a = ap.parse_args(argv)
    if a.write_docs:
        with open(os.path.join(ROOT, "docs", "CONFIGURATION.md"), "w") as f:
            f.write(docs())
        print("wrote docs/CONFIGURATION.md")
        return 0
    env = dict(os.environ)
    if a.env_file:
        env = {}
        for line in open(a.env_file):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"')
    findings = check(env, a.runtime)
    for level, name, msg in findings:
        print("%-5s %-32s %s" % (level, name, msg))
    blocks = sum(1 for f in findings if f[0] == "BLOCK")
    print("\n%d blocking, %d warnings" % (blocks, len(findings) - blocks))
    return 1 if blocks else 0


if __name__ == "__main__":
    sys.exit(main())

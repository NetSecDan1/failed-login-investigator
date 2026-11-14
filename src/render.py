"""Plain-text rendering of a result. Facts come from code. Only the narrative comes from the model."""


def _rows(items, label="value", n=5):
    return ["    %-34s %s" % (str(x[label])[:34], x["count"]) for x in items[:n]] or ["    (none)"]


def to_text(result):
    if result.get("status") != "ok":
        return "DENIED  %s\n%s" % (result.get("reason"), result.get("message", ""))
    if "accounts" in result:
        return "Accounts you own:\n" + "\n".join("  %-28s %s" % (a["account"], a["type"]) for a in result["accounts"])
    f, rep = result["facts"], result.get("report")
    ad, en = f["ad"], f["entra"]
    out = ["Failed login investigation: %s (%s account)" % (f["account"], f["account_type"]),
           "Window: %s to %s" % (f["window"]["start"], f["window"]["end"]), ""]
    if result.get("must_escalate"):
        out += ["!! ESCALATION REQUIRED. Contact the CSOC and quote this investigation. (decided by code)", ""]
    if rep:
        out += ["FINDING   %s  [confidence: %s]" % (rep["title"], rep["confidence"]), "", rep["narrative"], "", "NEXT STEPS"]
        out += ["  %d. %s" % (i + 1, s) for i, s in enumerate(rep["next_steps"])]
    else:
        out += ["FINDING   No summary available (%s). The facts below are complete." % "; ".join(result.get("notes", []))[:160]]
    out += ["", "FACTS (computed from the logs)",
            "  Active Directory failures: %s   first %s   last %s" % (ad["total_failures"], ad["first_seen"], ad["last_seen"]),
            "  Source hosts: %s distinct   external addresses: %s   lockouts: %s" % (
                ad["distinct_source_hosts"], len(ad["external_source_ips"]), ad["lockout_count"]),
            "  Last password change in window: %s" % (ad["last_password_change"] or "none seen"),
            "  Top source hosts:"] + _rows(ad["by_source_host"]) + ["  Failure codes:"]
    out += ["    %-12s %-38s %s" % (x["value"], x["meaning"], x["count"]) for x in ad["by_failure_code"]] or ["    (none)"]
    if ad["cadence"]:
        out += ["  Retry rhythm: median gap %s seconds, %s" % (ad["cadence"]["median_gap_seconds"],
                                                              "regular" if ad["cadence"]["regular"] else "irregular")]
    out += ["  Entra sign-in failures: %s" % en["total_failures"]]
    if en["total_failures"]:
        out += ["  Entra error codes:"] + ["    %-12s %-38s %s" % (x["value"], x["meaning"], x["count"]) for x in en["by_error_code"]]
        out += ["  Client apps:"] + _rows(en["by_client_app"])
    if f["gaps"]:
        out += ["", "GAPS (sources that could not be read)"] + ["  - " + g for g in f["gaps"]]
    out += ["", "Skills the evidence supports: " + ", ".join(result["candidates"]["allowed"]),
            "Evidence references: " + ", ".join(f["query_ids"])]
    return "\n".join(out)

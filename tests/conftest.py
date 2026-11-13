import glob, os, subprocess, sys
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ["ALLOW_TEST_CLAIMS"] = "true"
subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_data.py")], check=True, stdout=subprocess.DEVNULL)

import evidence  # noqa: E402


def load_store():
    d = {}
    for base, prefix in ((os.path.join(ROOT, "data"), ""), (os.path.join(ROOT, "skills"), "skills/")):
        for p in glob.glob(base + "/**/*", recursive=True):
            if os.path.isfile(p):
                d[prefix + os.path.relpath(p, base).replace(os.sep, "/")] = open(p).read()
    return d


FILES = load_store()
STORE = evidence.DictStore(FILES)
END = "2026-11-12T18:00:00Z"


def ev(emp, acct, **kw):
    return dict({"claims": {"employee_id": emp}, "account": acct, "window_hours": 24, "end": END}, **kw)


def no_model(*a):
    return None, {"reason": "skip"}


def top_choice_model(facts, skills, matched, steps_by_id):
    """Stands in for the model: picks the best supported allowed choice and names the top host."""
    import skillmatch
    cid = skillmatch.allowed_choices(matched)[0]
    host = facts["ad"]["by_source_host"][0]["value"] if facts["ad"]["by_source_host"] else "no host"
    return ({"classification_id": cid, "confidence": "high", "evidence_refs": facts["query_ids"][:1],
             "narrative": "Failures come from %s." % host,
             "next_step_ids": [1] if steps_by_id[cid] else []}, {"model": "fake"})

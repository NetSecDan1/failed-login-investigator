#!/usr/bin/env python3
"""Builds skills/index.json from each skill's SKILL.md frontmatter and rules.json.

Run after any change under skills/. CI fails if the committed index is stale.
The version is a content hash, so the audit log records exactly which skill text was used.
"""
import hashlib, json, os, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "skills")


def frontmatter(text):
    if not text.startswith("---\n"):
        raise ValueError("missing frontmatter")
    head = text[4:text.index("\n---\n", 4)]
    out = {}
    for line in head.splitlines():
        if line.startswith(("name:", "description:")):
            key, value = line.split(":", 1)
            value = value.strip()
            out[key] = json.loads(value) if value.startswith('"') else value
    return out


def build():
    digest, skills = hashlib.sha256(), []
    for sid in sorted(os.listdir(ROOT)):
        d = os.path.join(ROOT, sid)
        if not os.path.isdir(d):
            continue
        md = open(os.path.join(d, "SKILL.md")).read()
        raw_rules = open(os.path.join(d, "rules.json")).read()
        fm, rules = frontmatter(md), json.loads(raw_rules)
        if fm["name"] != sid or rules["id"] != sid:
            raise ValueError("%s: name or id does not match its folder" % sid)
        digest.update(md.encode()); digest.update(raw_rules.encode())
        skills.append({"id": sid, "title": rules["title"], "description": fm["description"], "escalate": bool(rules["escalate"])})
    return {"version": digest.hexdigest()[:12], "skills": skills}


if __name__ == "__main__":
    index = build()
    path = os.path.join(ROOT, "index.json")
    if "--check" in sys.argv:
        current = json.load(open(path)) if os.path.exists(path) else None
        if current != index:
            sys.exit("skills/index.json is stale. Run: python tools/build_skill_index.py")
        print("index ok", index["version"])
    else:
        with open(path, "w") as f:
            json.dump(index, f, indent=1); f.write("\n")
        print("wrote index", index["version"], len(index["skills"]), "skills")

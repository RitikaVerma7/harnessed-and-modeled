#!/usr/bin/env python3
"""
Harnessed & Modeled — automated threat model for an AI agent (model + harness).

Reads an agent's harness description (YAML), then:
  1. builds a pytm model (elements, trust boundaries, data flows) -> DFD
  2. runs pytm's STRIDE threat library on it               -> model/infra threats
  3. runs agent-specific rules on the harness               -> attack paths (Rule of Two, etc.)

Usage:
  python tm.py askbot/harness.yaml                  # threat summary
  python tm.py askbot/harness.yaml --dfd            # also write dfd.dot (+ dfd.png if Graphviz is installed)
  python tm.py askbot/harness.yaml --json out.json  # findings as JSON (paste into an LLM, see prompts/)
  python tm.py --diff askbot/harness.yaml askbot/harness_v2.yaml   # what changed in the threat model?

Exit code is 1 when a HIGH agent finding exists, so it can gate a PR in CI.
"""
import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter, defaultdict

import yaml
from pytm import (TM, Actor, Boundary, Classification, Data, Dataflow,
                  Datastore, ExternalEntity, Process)

RUNTIME = "Agent Runtime"


# ---------------------------------------------------------------- harness -> system model
def load(path):
    with open(path) as f:
        return yaml.safe_load(f)


def components(h):
    """Every tool and MCP server, with its Rule-of-Two tags."""
    out = []
    for t in h.get("tools", []):
        out.append({**t, "kind": "tool"})
    for m in h.get("mcp_servers", []):
        out.append({**m, "kind": "mcp", "backend": m["name"], "backend_type": "external"})
    return out


def flows(h):
    """Data flows implied by the harness, as (source, sink, label) tuples."""
    model, user = h["model"]["name"], h["user"]["name"]
    fl = [(user, model, "User prompt"), (model, user, "Answer")]
    if h.get("memory", {}).get("persistent"):
        fl += [(model, "Agent Memory", "Write memory"), ("Agent Memory", model, "Recall memory")]
    for c in components(h):
        fl += [(model, c["backend"], f"{c['name']} (call)"),
               (c["backend"], model, f"{c['name']} (result)")]
    return fl


def build_pytm(h):
    tm = TM(f"{h['agent']} threat model")
    tm.description = h.get("description", h["agent"])
    tm.isOrdered = True
    tm.mergeResponses = True       # draw call + result as one two-way arrow

    boundaries = {}

    def b(name):
        return boundaries.setdefault(name, Boundary(name))

    nodes = {}
    user = Actor(h["user"]["name"])
    user.inBoundary = b(h["user"].get("boundary", "Users"))
    nodes[user.name] = user

    model = Process(h["model"]["name"])
    model.inBoundary = b(RUNTIME)
    model.sanitizesInput = False          # an LLM does not reliably sanitize its input
    model.hasAccessControl = False
    nodes[model.name] = model

    if h.get("memory", {}).get("persistent"):
        mem = Datastore("Agent Memory")
        mem.inBoundary = b(RUNTIME)
        mem.storesSensitiveData = True
        mem.isEncryptedAtRest = False
        nodes[mem.name] = mem

    for c in components(h):
        if c["backend_type"] == "datastore":
            n = Datastore(c["backend"])
            n.storesPII = bool(c.get("sensitive_data"))
            n.storesSensitiveData = bool(c.get("sensitive_data"))
        else:
            n = ExternalEntity(c["backend"])
        n.inBoundary = b(c.get("boundary", "External"))
        nodes[c["backend"]] = n

    sensitive = Data("Sensitive data", classification=Classification.SENSITIVE)
    public = Data("Prompt / text", classification=Classification.PUBLIC)
    sens_names = {c["backend"] for c in components(h) if c.get("sensitive_data")}
    made = {}
    for src, dst, label in flows(h):
        df = Dataflow(nodes[src], nodes[dst], label)
        df.data = sensitive if src in sens_names else public
        df.isEncrypted = True
        back = made.get((dst, src))
        if back:                       # draw request + response as one two-way arrow
            df.isResponse, df.responseTo = True, back
        made[(src, dst)] = df
    return tm


# ---------------------------------------------------------------- agent-specific rules
def agent_findings(h):
    """Harness rules. Deterministic: same YAML in, same findings out."""
    cs = components(h)
    sources = [c for c in cs if c.get("untrusted_input")]
    sensitive = [c for c in cs if c.get("sensitive_data")]
    sinks = [c for c in cs if c.get("external_action")]
    model = h["model"]["name"]
    out = []

    # R1 Rule of Two: untrusted input + sensitive data + external action in ONE agent
    for s in sources:
        for d in sensitive:
            for k in sinks:
                gated = k.get("approval") == "human"
                out.append({
                    "id": f"PATH:{s['name']}>{d['name']}>{k['name']}",
                    "severity": "MEDIUM" if gated else "HIGH",
                    "rule": "Rule of Two violated (all three in one agent)",
                    "owasp": "ASI01 Goal Hijack, ASI02 Tool Misuse",
                    "path": f"{s['name']} -> {model} (injected) -> {d['name']} -> {k['name']}",
                    "why": f"Text from {s['backend']} can steer the model to read {d['backend']} "
                           f"and send it out via {k['name']}."
                           + ("" if gated else " No human approval on the outbound step."),
                    "mitigation": f"Require human approval on {k['name']}, or split the agent so no "
                                  "single agent holds all three capabilities.",
                })
    if sources and sensitive and not sinks:
        out.append({
            "id": "RULE2:two-of-three", "severity": "LOW",
            "rule": "Rule of Two: 2 of 3 present (no outbound channel yet)",
            "owasp": "ASI01 Goal Hijack",
            "path": f"{sources[0]['name']} -> {model} (injected) -> {sensitive[0]['name']}",
            "why": "Injected content can make the model read sensitive data. Adding any outbound tool "
                   "turns this into an exfiltration path.",
            "mitigation": "Watch for any PR that adds an external_action tool.",
        })

    # R2 sensitive tool with no approval, reachable while untrusted content is in context
    for d in sensitive:
        if sources and d.get("approval") != "human":
            out.append({
                "id": f"AUTHZ:{d['name']}", "severity": "MEDIUM",
                "rule": "Sensitive tool callable without approval or per-user scoping",
                "owasp": "ASI03 Identity & Privilege Abuse",
                "path": f"{model} -> {d['name']}",
                "why": f"{d['name']} runs with the agent's privileges, not the asking user's. "
                       "A rule in the system prompt is a request to the model, not access control.",
                "mitigation": f"Scope {d['name']} to the requesting user's identity; log every call.",
            })

    # R3 unpinned MCP server
    for m in (c for c in cs if c["kind"] == "mcp"):
        v = str(m.get("version", "")).strip()
        if not v or v == "latest" or v[0] in "^~*>":
            out.append({
                "id": f"SUPPLY:{m['name']}", "severity": "MEDIUM",
                "rule": "MCP server version not pinned",
                "owasp": "ASI04 Agentic Supply Chain",
                "path": f"{m['name']} -> {model}",
                "why": "A new upstream release can silently change tool descriptions or behavior (rug pull).",
                "mitigation": "Pin an exact version and review diffs of tool descriptions on upgrade.",
            })

    # R4 persistent memory written from untrusted context
    mem = h.get("memory", {})
    if mem.get("persistent") and mem.get("write_policy", "none") == "none" and sources:
        out.append({
            "id": "MEMORY:poisoning", "severity": "MEDIUM",
            "rule": "Persistent memory with no write policy",
            "owasp": "ASI06 Memory & Context Poisoning",
            "path": f"{sources[0]['name']} -> {model} -> Agent Memory -> (later sessions)",
            "why": "Injected 'facts' get saved and reused for other users and future sessions.",
            "mitigation": "Only write reviewed facts; tag memory with provenance; add expiry.",
        })

    # R5 sensitive data leaves through the model provider (every tool result goes into the prompt)
    m = h["model"]
    if m.get("hosting", "third-party") != "self-hosted":
        for d in sensitive:
            out.append({
                "id": f"EGRESS:{d['name']}", "severity": "LOW",
                "rule": "Sensitive data sent to a third-party model endpoint",
                "owasp": "LLM02 Sensitive Information Disclosure",
                "path": f"{d['name']} -> {model} -> {m.get('provider', 'model provider')}",
                "why": f"Whatever {d['name']} returns is put in the prompt and sent to the model provider. "
                       "Redaction helps but is not a guarantee.",
                "mitigation": "Use an approved endpoint with a data agreement and no retention, "
                              "return only the fields needed, or self-host the model.",
            })
    return out


# ---------------------------------------------------------------- output
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def print_report(h, tm, agent):
    print(f"\n=== {h['agent']}: automated threat model ===\n")
    print("SYSTEM MODEL (generated from harness)")
    bounds = defaultdict(list)
    for e in TM._elements:
        if not isinstance(e, (Dataflow, Boundary)):
            bounds[e.inBoundary.name if e.inBoundary else "-"].append(e.name)
    for bname, names in bounds.items():
        print(f"  [{bname}] {', '.join(names)}")
    print(f"  {len(TM._flows)} data flows\n")

    per = defaultdict(Counter)
    for f in tm.findings:
        per[f.target][f.severity] += 1
    print(f"STRIDE THREATS (pytm threat library): {len(tm.findings)} findings")
    for target, c in sorted(per.items(), key=lambda kv: -sum(kv[1].values()))[:8]:
        sev = ", ".join(f"{k} {v}" for k, v in c.most_common())
        print(f"  {target:<32} {sev}")
    print("  (run with --json to see every finding)\n")

    print("AGENT / HARNESS FINDINGS (attack paths)")
    for a in sorted(agent, key=lambda a: SEV_ORDER[a["severity"]]):
        print(f"  [{a['severity']:<6}] {a['rule']}")
        print(f"           path: {a['path']}")
        print(f"           why:  {a['why']}")
        print(f"           fix:  {a['mitigation']}   ({a['owasp']})")
    if not any(a["severity"] == "HIGH" for a in agent):
        print("  No HIGH attack path found. That is not proof of safety: the rules only check")
        print("  what they know about, and only as well as the tags are set.")
    print()


def write_dfd(tm):
    tm.check()
    dot = tm.dfd()
    with open("dfd.dot", "w") as f:
        f.write(dot)
    if shutil.which("dot"):
        subprocess.run(["dot", "-Tpng", "dfd.dot", "-o", "dfd.png"], check=True)
        print("DFD written to dfd.png")
    else:
        print("DFD written to dfd.dot (install Graphviz to render: brew install graphviz)")


def diff(old_path, new_path):
    old, new = load(old_path), load(new_path)
    of, nf = set(flows(old)), set(flows(new))
    oa = {a["id"]: a for a in agent_findings(old)}
    na = {a["id"]: a for a in agent_findings(new)}
    print(f"\n=== Threat model diff: {old_path} -> {new_path} ===\n")
    print("NEW DATA FLOWS")
    for s, d, label in sorted(nf - of):
        print(f"  + {s} -> {d}  [{label}]")
    print("\nNEW FINDINGS")
    for i in sorted(set(na) - set(oa), key=lambda i: (SEV_ORDER[na[i]["severity"]], i)):
        print(f"  + [{na[i]['severity']}] {na[i]['rule']}: {na[i]['path']}")
    print("\nCHANGED SEVERITY")
    changed = sorted(i for i in set(na) & set(oa) if na[i]["severity"] != oa[i]["severity"])
    for i in changed:
        print(f"  ~ [{oa[i]['severity']} -> {na[i]['severity']}] {na[i]['rule']}: {na[i]['path']}")
    print("\nRESOLVED FINDINGS")
    for i in sorted(set(oa) - set(na)):
        print(f"  - [{oa[i]['severity']}] {oa[i]['rule']}")
    print()
    # a finding is "new HIGH" if it didn't exist before, or wasn't HIGH before
    return any(na[i]["severity"] == "HIGH" and oa.get(i, {}).get("severity") != "HIGH" for i in na)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("harness", nargs="?", help="path to harness.yaml")
    p.add_argument("--dfd", action="store_true", help="write dfd.dot / dfd.png")
    p.add_argument("--json", metavar="FILE", help="write all findings as JSON")
    p.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), help="compare two harness files")
    args = p.parse_args()

    if args.diff:
        new_high = diff(*args.diff)
        if new_high:
            print("GATE FAILED: this change introduces a HIGH-risk attack path.\n")
        else:
            print("GATE PASSED: no new HIGH attack path (not proof of safety).\n")
        sys.exit(1 if new_high else 0)
    if not args.harness:
        p.error("give a harness.yaml or use --diff")

    h = load(args.harness)
    tm = build_pytm(h)
    if args.dfd:
        write_dfd(tm)
    else:
        tm.check()
    tm.resolve()
    agent = agent_findings(h)
    print_report(h, tm, agent)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "agent": h["agent"],
                "flows": [{"from": s, "to": d, "label": l} for s, d, l in flows(h)],
                "agent_findings": agent,
                "stride_findings": [{"target": f.target, "threat_id": f.threat_id,
                                     "severity": f.severity, "description": f.description}
                                    for f in tm.findings],
            }, f, indent=2)
        print(f"Findings written to {args.json}")

    sys.exit(1 if any(a["severity"] == "HIGH" for a in agent) else 0)


if __name__ == "__main__":
    main()

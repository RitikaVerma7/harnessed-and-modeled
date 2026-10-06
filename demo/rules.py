"""
The agent rules: the harness-specific part of the threat model.

pytm (in tm.py) builds the system model and runs its generic STRIDE library.
These rules look for dangerous *combinations* in an agent's harness, using only
the tags in harness.yaml. Deterministic: same YAML in, same findings out.

  R1  Rule of Two: untrusted input + sensitive data + external action   HIGH (MEDIUM with approval, LOW at 2 of 3)
  R2  Sensitive tool callable without approval or per-user scoping       MEDIUM
  R3  MCP server version not pinned                                      MEDIUM
  R4  Persistent memory with no write policy                             MEDIUM
  R5  Sensitive data sent to a third-party model endpoint                LOW

Add your own rule inside agent_findings(): append a dict with the same keys.
"""


def components(h):
    """Every tool and MCP server, with its Rule-of-Two tags."""
    out = []
    for t in h.get("tools", []):
        out.append({**t, "kind": "tool"})
    for m in h.get("mcp_servers", []):
        out.append({**m, "kind": "mcp", "backend": m["name"], "backend_type": "external"})
    return out


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

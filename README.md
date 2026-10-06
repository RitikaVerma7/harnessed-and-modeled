# Harnessed & Modeled: Automated Threat Modeling for AI Agents

Companion repo for the talk at **BSides NYC, AI Security Village** · Ritika Verma

Threat-model an AI agent, **model and harness**, with [OWASP pytm](https://github.com/OWASP/pytm), a few agent-specific rules and an LLM. Then re-run it on every change, so the threat model stays current as the agent grows.

> **Want to learn it properly?** Follow **[HANDS-ON.md](HANDS-ON.md)**: a step-by-step guide (about 60–90 minutes) where you run every part, change the agent, and watch the threat model change.

---

## The idea in 30 seconds

An AI agent is a **model plus a harness**: the tools, MCP servers, permissions and memory that let it act.

- The **model** is where things go wrong: prompt injection, hallucination, data leakage.
- The **harness** decides how bad it gets.

The harness is already written down in code and config. So the threat model can be **generated from it** and **re-run on every pull request**, and a PR that opens a new attack path fails the check.

The main rule is Meta's **Rule of Two**: one agent should not combine *untrusted input*, *sensitive data* and *external action* unless a human approves the risky step.

## How it works

```
agent code, mcp.json ──► ai.py draft ──► harness.yaml   (AI drafts it, a human reviews the flagged tags)
                                              │
harness.yaml  ──►  tm.py  ──►  1. System model + data flow diagram with trust boundaries   (pytm)
                               2. STRIDE threats per element and data flow                 (pytm)
                               3. Agent attack paths: Rule of Two and more                 (rules in tm.py)
                                         │
                                         ▼
                               findings.json ──► ai.py explain ──► abuse stories + mitigations
                                                 (checked: nothing dropped, invented or downgraded)
                                         │
                                         ▼
                               tm.py --diff on every PR ──► fail the check on a new HIGH path
```

**Design rule:** the rules decide what is risky; the LLM only explains it. The LLM can add ideas, but it can never remove or downgrade a finding.

## Setup (5 minutes)

You need Python 3.9 or newer. [Graphviz](https://graphviz.org/download/) is optional; it draws the diagram as a PNG.

```bash
git clone https://github.com/RitikaVerma7/harnessed-and-modeled.git
cd harnessed-and-modeled/demo
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
brew install graphviz        # optional (Linux: sudo apt install graphviz)
```

## Try it: the AskBot demo

AskBot is a made-up internal HR assistant agent. It reads a shared HR inbox, looks up payroll, reads Jira tickets through an MCP server, and remembers facts across chats.

**1. Threat-model the agent** (no API key needed)
```bash
python tm.py askbot/harness.yaml --dfd
```
Prints the system model, a STRIDE summary and the agent attack paths, and writes `dfd.png`. You'll see a **LOW**: an injected email can read payroll, but there's no way to send it out yet.

**2. A "3-line PR" adds an email tool**
```bash
python tm.py --diff askbot/harness.yaml askbot/harness_v2.yaml
```
`harness_v2.yaml` adds `send_email` and unpins the MCP server. The diff shows two new **HIGH** exfiltration paths (`read_email → model → payroll_lookup → send_email`) and exits with code 1, which fails a CI check.

**3. The fix: one line**
```bash
python tm.py --diff askbot/harness_v2.yaml askbot/harness_v3.yaml
```
`harness_v3.yaml` requires human approval on `send_email`. HIGH drops to MEDIUM and the check passes.

**4. Let the AI draft the harness from the agent's code**
```bash
python ai.py draft askbot/agent/ --against askbot/harness.yaml --runs 3
```
Claude reads `askbot/agent/agent.py` and `mcp.json`, labels every tool, and lists what a human should review.

**5. Let the AI write abuse stories, and check them**
```bash
python tm.py askbot/harness_v2.yaml --json findings.json
python ai.py explain findings.json --brief
python ai.py explain findings.json --inject --brief    # try to prompt-inject the threat modeler
```

Steps 4 and 5 need an API key: `export ANTHROPIC_API_KEY=...` (get one at console.anthropic.com). The model defaults to `claude-opus-5-5`; set `TM_MODEL` to use another.

**No API key?** Paste `demo/prompts/attack_paths.md` plus `findings.json` into any chatbot to get the abuse stories (HANDS-ON.md section 7c).

## Use it on your own agent

1. **Describe your agent.** Either copy `demo/askbot/harness.yaml` and edit it, or let the AI draft it from your code:
   ```bash
   python ai.py draft path/to/your/agent/ -o my_agent.yaml
   ```
2. **Review every tag.** For each tool and MCP server, the whole model rests on four answers:

   | Tag | Question |
   |---|---|
   | `untrusted_input` | Can an outsider control what this tool returns? (email, web, tickets, docs) |
   | `sensitive_data` | Does it read private data? (PII, payroll, secrets, source code) |
   | `external_action` | Does it change state or send data out? (email, HTTP, writes) |
   | `approval` | Does a human approve it before it runs? (`none` / `human`) |

3. **Run the threat model:** `python tm.py my_agent.yaml --dfd`
4. **Add the CI check** (below) so every change is re-checked.

## The agent rules

| Rule | Severity | STRIDE | OWASP |
|---|---|---|---|
| Rule of Two: untrusted input + sensitive data + external action, no approval | HIGH | I | ASI01, ASI02 |
| Same, but the outbound step needs human approval | MEDIUM | I | ASI01, ASI02 |
| Sensitive tool callable without approval or per-user scoping | MEDIUM | E | ASI03 |
| MCP server version not pinned | MEDIUM | S, T | ASI04 |
| Persistent memory with no write policy | MEDIUM | T | ASI06 |
| Rule of Two: 2 of 3 present (no outbound channel yet) | LOW | I | ASI01 |
| Sensitive data sent to a third-party model endpoint | LOW | I | LLM02 |

ASI = [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/). The rules are plain Python functions in `agent_findings()` in `demo/tm.py`; add your own (HANDS-ON.md section 8 shows how).

## Run it in CI

`.github/workflows/threat-model.yml` compares `demo/askbot/harness.yaml` on the base branch with the PR's version, and fails the check if the PR introduces a new HIGH attack path. Point it at your own harness file to use it on your agent.

## Limits (read this)

- **No finding is not the same as safe.** A clean run means no known pattern matched, not "secure".
- **The tags are the trust assumptions.** If a tool is mis-tagged, the output is wrong. One wrong tag can hide a HIGH.
- **A rule in the system prompt is not a control.** Count only what the harness enforces in code.
- **pytm's STRIDE library is generic.** Many of its findings are web-app style threats. The agent rules carry the harness-specific signal.
- **The AI draft can be wrong.** It assumes the worst when the code is silent. A human signs off on every tag.
- **LLMs hallucinate.** `ai.py explain` flags stories for findings that don't exist; "possible gaps" are ideas for a human, not findings.
- **The threat-modeling bot is an agent too.** It reads text attackers can write, so it can be prompt-injected. That's why the rules, not the LLM, decide severity.
- **Accuracy isn't measured.** This is a starting point, not a scanner.

## What's in here

```
harnessed-and-modeled/
├── README.md
├── HANDS-ON.md                   # step-by-step guide: run and learn every part
├── demo/
│   ├── tm.py                     # harness.yaml → pytm model → DFD, STRIDE, agent rules, PR diff gate
│   ├── ai.py                     # LLM: draft harness.yaml from code; write abuse stories; check the answers
│   ├── requirements.txt
│   ├── askbot/
│   │   ├── agent/                # AskBot's code and mcp.json (input for ai.py draft)
│   │   ├── harness.yaml          # AskBot v1 (reviewed)
│   │   ├── harness_v2.yaml       # v2: the "3-line PR" (+ send_email, unpinned MCP)
│   │   └── harness_v3.yaml       # v3: the fix (send_email needs human approval)
│   └── prompts/                  # the LLM prompts, and AskBot's system prompt
├── docs/references.md            # frameworks, tools, incidents, research
└── .github/workflows/threat-model.yml
```

## References

- OWASP pytm: https://github.com/OWASP/pytm
- OWASP Top 10 for Agentic Applications: https://genai.owasp.org/
- Meta, Agents Rule of Two: https://ai.meta.com/blog/practical-ai-agent-security/
- Previous workshop, DEF CON 33 *From Prompt to Protection*: https://github.com/RitikaVerma7/DEFCON33

More in [docs/references.md](docs/references.md).

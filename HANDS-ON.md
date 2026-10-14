# Hands-on guide

Run the whole demo on your own machine, then keep going with exercises that go further.

- **Sections 0–5** are the same demo as the [Colab notebook](hands-on.ipynb), run locally. If you already did the notebook, skip to section 6.
- **Sections 6–10** are new: more experiments, a look under the hood, breaking the AI, writing your own rule, CI, and your own agent. (The notebook has the same exercises at the end, if you'd rather stay in Colab.)

All expected outputs below come from real runs.

---

## 0. The idea (1 min)

An AI agent is a **model plus a harness**: the tools, MCP servers, permissions and memory that let it act. The model is where things go wrong (prompt injection); the harness decides how bad it gets.

The main rule is Meta's **Rule of Two**: one agent should not combine *untrusted input*, *sensitive data* and *external action* unless a human approves the risky step.

The harness is written down in code and config, so the threat model can be generated from it and re-run on every change:

```
askbot/agent/ (code) ──► ai.py draft ──► harness description  (AI drafts, you review)
harness.yaml ──► tm.py + rules.py ──► diagram + STRIDE threats + agent attack paths
findings     ──► ai.py explain ──► abuse stories, checked against the findings
tm.py --diff old new ──► exit code 1 on a new HIGH ──► a failed CI check
```

The rules decide what's risky. The AI only describes and explains.

---

## 1. Set up (10 min)

```bash
git clone https://github.com/RitikaVerma7/harnessed-and-modeled.git
cd harnessed-and-modeled/demo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Every time you open a new terminal later, run `cd harnessed-and-modeled/demo && source .venv/bin/activate` again.

**Optional:** install Graphviz to draw the diagram as an image (`brew install graphviz`, or `sudo apt install graphviz` on Linux). Without it you get `dfd.dot` instead of `dfd.png`.

**Optional:** for the AI steps, set an API key from [console.anthropic.com](https://console.anthropic.com): `export ANTHROPIC_API_KEY=...`

---

## 2. Meet AskBot (5 min)

AskBot is an internal HR assistant agent. Look at its code first, then at the short description the threat model reads.

```bash
open -e askbot/agent/agent.py askbot/agent/mcp.json askbot/harness.yaml
```

In the code, notice:
- `payroll_lookup`: *any employee_id is accepted; the tool runs with AskBot's service account*
- `read_email`: *anyone, including people outside the company, can email this address*
- `REQUIRE_CONFIRMATION = []`: no human approves anything

In `harness.yaml`, every tool has four tags. They're the only thing the rules look at:

| Tag | Question it answers |
|---|---|
| `untrusted_input` | Can an outsider control what this tool returns? |
| `sensitive_data` | Does it read private data? |
| `external_action` | Does it change state or send data out? |
| `approval` | Does a human approve it first? (`none` / `human`) |

No tool has `external_action: true` yet. Remember that.

---

## 3. Generate the threat model (5 min)

```bash
python tm.py askbot/harness.yaml --dfd
open dfd.png
```

**You should see** (trimmed):
```
STRIDE THREATS (pytm threat library): 130 findings
...
AGENT / HARNESS FINDINGS (attack paths)
  [MEDIUM] Sensitive tool callable without approval or per-user scoping
  [MEDIUM] Persistent memory with no write policy
  [LOW   ] Rule of Two: 2 of 3 present (no outbound channel yet)
           path: read_email -> AskBot LLM (injected) -> payroll_lookup
  [LOW   ] Sensitive data sent to a third-party model endpoint
  No HIGH attack path found. That is not proof of safety: ...
```

- **The diagram** came from the config. Nobody drew it. Red dashed boxes are trust boundaries.
- **The 130 STRIDE findings** come from pytm's generic library. Mostly noise for an agent (section 7 shows why).
- **The agent findings** come from the rules in `rules.py`. The LOW: an injected email can make AskBot read payroll, but it has no way to send it out.
- **No HIGH isn't safe.** It means no rule matched.

---

## 4. The 3-line PR, and the fix (10 min)

A PR adds a `send_email` tool and unpins the Jira MCP server. The model doesn't change.

```bash
diff askbot/harness.yaml askbot/harness_v2.yaml
python tm.py --diff askbot/harness.yaml askbot/harness_v2.yaml; echo "exit code: $?"
```

**You should see:** two new `[HIGH] Rule of Two violated` paths (for example `read_email -> AskBot LLM (injected) -> payroll_lookup -> send_email`), `[MEDIUM] MCP server version not pinned`, the LOW resolved, then `GATE FAILED` and `exit code: 1`. In CI, exit code 1 fails the PR check.

**The fix:** `harness_v3.yaml` changes one line, so `send_email` needs `approval: human`.
```bash
python tm.py --diff askbot/harness_v2.yaml askbot/harness_v3.yaml; echo "exit code: $?"
```
**You should see:** both paths under `CHANGED SEVERITY` as `[HIGH -> MEDIUM]`, then `GATE PASSED` and `exit code: 0`.

**One wrong tag hides a HIGH.** Pretend someone tagged the inbox and Jira as trusted:
```bash
sed 's/untrusted_input: true/untrusted_input: false/' askbot/harness_v2.yaml > my.yaml
python tm.py my.yaml
```
Both HIGHs disappear, but the agent didn't get any safer. The tags are the trust assumptions.

---

## 5. The AI steps (15 min, needs an API key)

**Draft the harness description from the code.** The AI reads the code three times, tags every tool with evidence, and flags anything for a human:
```bash
python ai.py draft askbot/agent/ --against askbot/harness.yaml --runs 3
```
Look at **NEEDS HUMAN REVIEW**: tags where the AI disagrees with the reviewed `harness.yaml`, and questions it couldn't answer from the code.

**Write abuse stories, and check them:**
```bash
python tm.py askbot/harness_v2.yaml --json findings.json
python ai.py explain findings.json --brief
```
Look at **CHECKING THE LLM'S ANSWER**: every finding explained, nothing invented or downgraded.

**Try to prompt-inject the threat modeler:**
```bash
python ai.py explain findings.json --inject --brief
```
A hidden note tells the AI to mark the top finding LOW. Whatever it does, the severities and the gate come from the rules.

**No key?** Copy everything below the `---` line in `prompts/attack_paths.md`, replace `PASTE findings.json HERE` with the contents of `findings.json`, and paste it into any chatbot.

---

> ## Continue here
> Sections 6–10 are new. If you came from the notebook, this is where you pick up.

## 6. More experiments (15 min)

Each experiment changes one thing in a copy of the v2 harness. Start each one from a fresh copy:
```bash
cp askbot/harness_v2.yaml my.yaml && open -e my.yaml
```
Edit `my.yaml`, save, then run `python tm.py my.yaml` and compare with the expected result.

| # | Change in `my.yaml` | What you should see | What it teaches |
|---|---|---|---|
| A | Under `jira-mcp`: `version: "1.4.2"` | `MCP server version not pinned` disappears | Pin MCP servers (supply chain) |
| B | Under `memory:`: `write_policy: reviewed` | `Persistent memory with no write policy` disappears | Gate what the agent remembers |
| C | Under `model:`: `hosting: self-hosted` | `Sensitive data sent to a third-party model endpoint` disappears | Every tool result goes to the model provider |
| D | Add a `web_fetch` tool (below) | A new `[HIGH]` path: `web_fetch -> ... -> payroll_lookup -> send_email` | New tools are checked automatically |

**Tool for experiment D** (paste under `tools:`, keep the indentation):
```yaml
  - name: web_fetch
    backend: Public Web
    backend_type: external
    boundary: Internet
    untrusted_input: true
    sensitive_data: false
    external_action: false
    approval: none
```

**Your own:** what's the smallest change that removes *both* HIGHs without human approval on `send_email`? (Hint: the Rule of Two needs all three properties.)

---

## 7. Look under the hood: pytm's STRIDE findings (10 min)

The report only summarizes the 130 STRIDE findings. Export them all:
```bash
python tm.py askbot/harness.yaml --json findings_v1.json
python -c "import json,collections; d=json.load(open('findings_v1.json')); c=collections.Counter(x['threat_id'] for x in d['stride_findings']); print(len(d['stride_findings']),'findings,',len(c),'kinds'); print(c.most_common(5))"
python -c "import json; print(json.load(open('findings_v1.json'))['stride_findings'][0])"
```

**You should see:** 130 findings of 43 kinds, and the first one is something like `'target': 'AskBot LLM', 'threat_id': 'INP02', 'description': 'Overflow Buffers'`.

"Overflow Buffers" on an LLM isn't a useful finding: pytm's library was built for traditional apps. It's a baseline, not the answer. The agent rules in `rules.py` carry the harness-specific signal.

---

## 8. Break the AI (15 min, needs an API key)

**What happens if the code doesn't say the inbox is public?** Make a copy of AskBot with that sentence removed, and let the AI draft it:
```bash
cp -r askbot/agent my_agent
sed -i.bak 's/Anyone, including "/"/; s/"people outside the company, can email this address\./"/' my_agent/agent.py && rm my_agent/agent.py.bak
grep -A1 '"read_email"' my_agent/agent.py
python ai.py draft my_agent/ --against askbot/harness.yaml -o weak_draft.yaml
```
Does the AI still tag `read_email` as `untrusted_input: true`? If not, does **NEEDS HUMAN REVIEW** still catch it (the keyword check, and the comparison with the reviewed harness)? This is exactly how a wrong tag gets in.

**What if nobody reviews the AI's draft?** Run the rules straight on it:
```bash
python tm.py harness.draft.yaml
```
The AI is cautious when the code is silent. In our runs it assumed the Jira MCP server can write, so the rules found HIGHs **before** the PR. A good question for a reviewer, but wrong to accept unreviewed.

---

## 9. Write your own rule (20 min)

The rules are plain Python in `rules.py`. Read the table at the top of the file, then the Rule of Two:
```python
sources   = [c for c in cs if c.get("untrusted_input")]
sensitive = [c for c in cs if c.get("sensitive_data")]
sinks     = [c for c in cs if c.get("external_action")]
# every source × sensitive × sink combination = one attack path
# HIGH unless the sink has approval: human
```

**Add a rule:** open `rules.py` and paste this just **above** the line `# R4 persistent memory written from untrusted context`:
```python
    # R6 (my rule) external action with no approval at all
    for k in sinks:
        if k.get("approval") != "human":
            out.append({
                "id": f"ACTION:{k['name']}", "severity": "MEDIUM",
                "rule": "External action runs without human approval",
                "owasp": "ASI02 Tool Misuse",
                "path": f"{model} -> {k['name']}",
                "why": f"The model can call {k['name']} on its own.",
                "mitigation": f"Add approval: human to {k['name']}.",
            })

```
Run `python tm.py askbot/harness_v2.yaml`. You should see:
```
[MEDIUM] External action runs without human approval
         path: AskBot LLM -> send_email
```

### 9b. Your turn: a rule for skills and plugins

Agents increasingly load **skills and plugins**: add-ons with their own instructions and code, often from a marketplace. They run with the agent's tools and permissions, and the current rules don't look at them.

**1. Give AskBot a skill.** Copy the v2 harness and add this at the bottom of `my.yaml` (no indentation before `skills:`):
```bash
cp askbot/harness_v2.yaml my.yaml && open -e my.yaml
```
```yaml
skills:
  - name: expense-report
    source: marketplace      # marketplace | internal
    version: latest
    reviewed: false
```

**2. Write rule R7** in `rules.py`, above `# R4 persistent memory written from untrusted context`. It should flag a skill whose `source` isn't `internal` **and** that is either unpinned (`latest`, empty, or a range like `^2.0`) or not reviewed. Use R3 (the MCP pinning rule) as a model. Start from:
```python
    # R7 (my rule) third-party skills and plugins
    for sk in h.get("skills", []):
        # TODO: if this is a third-party skill that is unpinned or not reviewed, append a finding
        pass

```

**3. Test it:** `python tm.py my.yaml` should show your new finding. Then pin the version **and** set `reviewed: true` (or `source: internal`), and it should disappear.

<details>
<summary>One solution</summary>

```python
    # R7 (my rule) third-party skills and plugins
    for sk in h.get("skills", []):
        version = str(sk.get("version", "")).strip()
        unpinned = not version or version == "latest" or version[0] in "^~*>"
        if sk.get("source") != "internal" and (unpinned or not sk.get("reviewed")):
            out.append({
                "id": f"SKILL:{sk['name']}", "severity": "MEDIUM",
                "rule": "Third-party skill not pinned or not reviewed",
                "owasp": "ASI04 Agentic Supply Chain",
                "path": f"{sk['name']} -> {model}",
                "why": "A skill's instructions and code run with the agent's tools and permissions. "
                       "If it's unpinned or unreviewed, it can change under you.",
                "mitigation": "Pin the version, review its instructions and code, and limit which tools it can call.",
            })

```
</details>

**More ideas:** a rule for a tool name containing `exec` or `shell` (code execution), or for a tool with `untrusted_input: true` whose output can be written to persistent memory.

---

## 10. Take it further (on your own)

**Run it in GitHub CI.**
1. Fork this repo, and enable Actions on your fork.
2. On a new branch, edit `demo/askbot/harness.yaml` (not v2) and add the `send_email` tool (copy it from `harness_v2.yaml`).
3. Open a PR. The workflow compares `harness.yaml` on `main` with the PR's version, and the **agent-threat-model** check should fail.

**Use it on your own agent.**
1. Let the AI draft a description from your agent's code: `python ai.py draft path/to/your/agent/ -o my_agent.yaml`
2. Read every tag and fix what's wrong. The four questions in section 2 are the whole input.
3. Run `python tm.py my_agent.yaml --dfd` and read the agent findings.
4. Copy `.github/workflows/threat-model.yml` into your agent's repo and point it at your harness file.

---

## Limits

- **No finding is not the same as safe.** A clean run means no known pattern matched.
- **The tags are the trust assumptions.** One wrong tag can hide a HIGH.
- **A rule in the system prompt is not a control.** Count only what the harness enforces in code.
- **pytm's STRIDE library is generic.** The agent rules carry the harness-specific signal.
- **The AI can be wrong, and can be attacked.** A human reviews the draft; the rules, not the AI, set severity.

## Troubleshooting

| Problem | Fix |
|---|---|
| `python: command not found` or `No module named 'pytm'` | Activate the environment: `source .venv/bin/activate` |
| `DFD written to dfd.dot` | Install Graphviz, then re-run |
| `exit code: 1` | **Expected** when there's a new HIGH. That's the gate working. |
| YAML error after editing | Usually indentation: tools are indented 2 spaces, their fields 4 |
| `ai.py`: "The API key was rejected" | Check `ANTHROPIC_API_KEY`: a key from console.anthropic.com, no spaces or quotes |
| You changed the demo files by accident | Restore them with `git checkout -- askbot/ rules.py` |

## Cheat sheet

```bash
cd harnessed-and-modeled/demo && source .venv/bin/activate

python tm.py askbot/harness.yaml --dfd                           # threat model + diagram
python tm.py --diff askbot/harness.yaml askbot/harness_v2.yaml   # the PR: gate fails
python tm.py --diff askbot/harness_v2.yaml askbot/harness_v3.yaml # the fix: gate passes
python tm.py askbot/harness_v2.yaml --json findings.json         # export findings

python ai.py draft askbot/agent/ --against askbot/harness.yaml --runs 3   # AI drafts the description
python ai.py explain findings.json --brief                       # abuse stories, checked
python ai.py explain findings.json --inject --brief              # try to prompt-inject it
```

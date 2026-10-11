# Commands

## 0. Setup
Turn on the Python environment and go to the demo folder. Do this once per Terminal window, before recording.
```bash
source ~/Desktop/BSidesNYC/.venv/bin/activate && cd ~/Desktop/BSidesNYC/harnessed-and-modeled/demo
export ANTHROPIC_API_KEY=your-key-here
clear
```

## 1. Read the agent's code
AskBot as engineers wrote it: tools, an MCP server, memory.
Nobody keeps a threat-model file for this.
```bash
open -e askbot/agent/agent.py askbot/agent/mcp.json
```

## 2. AI drafts the harness description
The AI reads the code three times and tags every tool.
Anything it's unsure of is flagged for a human to review.
```bash
clear && python ai.py draft askbot/agent/ --against askbot/harness.yaml --runs 3
```

## 3. Generate the threat model
pytm builds the model and diagram; the agent rules find the risks.
Today it's a LOW: injected email can read payroll, but can't send it out.
```bash
clear && python tm.py askbot/harness.yaml --dfd
open dfd.png
```

## 4. The 3-line PR
The PR adds a `send_email` tool and unpins the MCP server.
LOW becomes HIGH, and the check fails (exit code 1).
```bash
clear && diff askbot/harness.yaml askbot/harness_v2.yaml
```
```bash
clear && python tm.py --diff askbot/harness.yaml askbot/harness_v2.yaml; echo "exit code: $?"
```

## 5. AI explains, code checks
The AI writes an abuse story for each finding.
Code checks nothing was dropped, invented or downgraded.
```bash
clear && python tm.py askbot/harness_v2.yaml --json findings.json > /dev/null && python ai.py explain findings.json --brief
```

## 6. Try to prompt-inject the threat modeler
A hidden note tells the AI to mark the top finding LOW.
Whatever it does, the severities and the gate come from the rules.
```bash
clear && python ai.py explain findings.json --inject --brief
```

## 7. The fix
One line: `send_email` now needs human approval.
HIGH drops to MEDIUM, and the check passes (exit code 0).
```bash
clear && python tm.py --diff askbot/harness_v2.yaml askbot/harness_v3.yaml; echo "exit code: $?"
```

## Cleanup
Removes the files the demo created, so they don't get copied to GitHub.
```bash
rm -f dfd.png dfd.dot findings.json harness.draft.yaml
```

---

**No Wi-Fi?** Add one of these to steps 2, 5 or 6 to show the saved answer instead:
- Step 2: `--replay ~/Desktop/BSidesNYC/talk-backup/llm_draft.json`
- Step 5: `--replay ~/Desktop/BSidesNYC/talk-backup/llm_explain.json`
- Step 6: `--replay ~/Desktop/BSidesNYC/talk-backup/llm_explain_injected.json`

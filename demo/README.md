# demo/

The code you run. Run every command from this folder, with the virtual environment active.

**New here? Start with the [main README](../README.md)**, or the step-by-step [HANDS-ON.md](../HANDS-ON.md).

| File | What it is |
|---|---|
| `tm.py` | The threat model: `harness.yaml` → pytm model, data flow diagram, STRIDE, PR diff gate. No AI. |
| `rules.py` | **The agent rules** (Rule of Two and four more): the harness-specific findings. Add your own here. |
| `ai.py` | The AI steps: draft `harness.yaml` from an agent's code, write abuse stories, check the answers. Needs `ANTHROPIC_API_KEY`. |
| `requirements.txt` | `pip install -r requirements.txt` |
| `askbot/agent/` | The example agent's code and `mcp.json`: what `ai.py draft` reads |
| `askbot/harness.yaml` | AskBot v1, reviewed |
| `askbot/harness_v2.yaml` | v2, the "3-line PR": adds `send_email`, unpins the MCP server |
| `askbot/harness_v3.yaml` | v3, the fix: `send_email` needs human approval |
| `prompts/` | The LLM prompts, and AskBot's system prompt |

Files you create while running (`dfd.png`, `findings.json`, `harness.draft.yaml`) are ignored by git.

# Harnessed & Modeled: Automated Threat Modeling for AI Agents

Hands-on companion to the talk at **BSides NYC, AI Security Village** · Ritika Verma

## What you'll do

Using **AskBot**, an example HR assistant agent, you will:

1. Generate a threat model of the agent, **model and harness**, with OWASP pytm and agent-specific rules.
2. Watch a 3-line pull request turn a LOW risk into a HIGH one, and fail a CI check.
3. Fix it with one line, and see the risk drop.
4. Let an LLM draft the threat model from the agent's code and write abuse stories, then check its work, and try to prompt-inject it.
5. Point it at your own agent.

## Start here

Pick one:

- **No setup, in your browser:** [![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/RitikaVerma7/harnessed-and-modeled/blob/main/hands-on.ipynb) The demo (parts 1–5, about 15 minutes), then keep going with more exercises (parts 6–10).
- **On your own machine:** 👉 follow **[HANDS-ON.md](HANDS-ON.md)**. Sections 0–5 are the demo, sections 6–10 the same exercises as the notebook's parts 6–10, plus running it in GitHub CI.

## What you need

- For the Colab notebook: just a browser and a Google account
- For HANDS-ON.md: Python 3.9 or newer, and a terminal
  - plus [Graphviz](https://graphviz.org/download/) (optional), to draw the diagram as an image
- Either way, an [Anthropic API key](https://console.anthropic.com) is optional: it's only for the AI steps (notebook parts 5, 8 and 10; HANDS-ON sections 5 and 8). Without one, everything else works, and both show a copy-paste alternative.

## What's in here

| Path | What it is |
|---|---|
| [HANDS-ON.md](HANDS-ON.md) | The step-by-step guide. Start here. |
| [hands-on.ipynb](hands-on.ipynb) | The demo and the exercises as a Colab notebook, no setup |
| [demo/](demo/) | The code you run, and the AskBot example. Run every command from inside `demo/`. |
| [docs/references.md](docs/references.md) | Frameworks, tools and incidents from the talk |
| `.github/workflows/` | A GitHub Actions check that fails a PR when it adds a HIGH attack path (HANDS-ON section 9) |

## Learn more

- OWASP pytm: https://github.com/OWASP/pytm
- OWASP Top 10 for Agentic Applications: https://genai.owasp.org/
- Meta, Agents Rule of Two: https://ai.meta.com/blog/practical-ai-agent-security/
- Previous workshop, DEF CON 33 *From Prompt to Protection*: https://github.com/RitikaVerma7/DEFCON33

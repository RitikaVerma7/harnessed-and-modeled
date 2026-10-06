# References

Further reading from the talk. Some 2026 items are preprints.

## Frameworks
- OWASP Top 10 for Agentic Applications (Dec 9, 2025): https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/
- Meta, "Agents Rule of Two" (Oct 31, 2025): https://ai.meta.com/blog/practical-ai-agent-security/
- CSA MAESTRO, agentic threat-modeling framework: https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro
- OWASP Multi-Agentic System Threat Modeling Guide: https://genai.owasp.org/resource/multi-agentic-system-threat-modeling-guide-v1-0/

## Other tools
- OWASP pytm: https://github.com/OWASP/pytm (PyPI has 1.3.1; v1.4 on GitHub adds an `LLM` element)
- STRIDE-GPT, LLM threat modeling CLI with SARIF output: https://github.com/mrwadams/stride-gpt
- AWS Threat Designer, supports STRIDE + MAESTRO: https://github.com/awslabs/threat-designer
- CSA MAESTRO Threat Analyzer: https://github.com/CloudSecurityAlliance/MAESTRO
- Cisco MCP Scanner: https://github.com/cisco-ai-defense/mcp-scanner
- Snyk Agent Scan (formerly Invariant mcp-scan)

## Incidents
- Pillar Security, sandbox escapes in Cursor, Codex, Gemini CLI and Antigravity through config files that trusted tools run outside the sandbox (Jul 20, 2026): https://www.bleepingcomputer.com/news/security/cursor-codex-gemini-cli-antigravity-hit-by-sandbox-escapes/
- GitHub MCP prompt injection leaking private repos (May 2025): https://www.devclass.com/ai-ml/2025/05/27/researchers-warn-of-prompt-injection-vulnerability-in-github-mcp-with-no-obvious-fix/1623458
- postmark-mcp, first malicious MCP server, BCC'd all email (Sep 2025): https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html
- "Comment and Control": PR comments hijacked AI review agents in CI (Apr 2026). This is a good example for "the threat-modeling bot needs guardrails too": https://venturebeat.com/security/ai-agent-runtime-security-system-card-audit-comment-and-control-2026
- OWASP GenAI Exploit Round-up Q1 2026: https://genai.owasp.org/2026/04/14/owasp-genai-exploit-round-up-report-q1-2026/

## Research on LLM threat modeling
- ACSE-Eval, LLM threat models vs expert threat models on AWS scenarios: https://arxiv.org/abs/2505.11565
- "The Attacker Moves Second": adaptive attacks broke 12 prompt-injection defenses: https://arxiv.org/abs/2510.09023

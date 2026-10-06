# AskBot: the agent as engineers actually wrote it (trimmed).
# Nobody keeps a harness.yaml. This file plus mcp.json is the real harness.
# `python ai.py draft askbot/agent/` reads these files and drafts harness.yaml from them.

MODEL = "hosted-llm"                       # provider model id
SYSTEM_PROMPT_FILE = "prompts/askbot_system.md"

MEMORY = {
    "backend": "sqlite:///askbot_memory.db",
    "persist_across_sessions": True,       # facts are reused in later chats, for every user
    "writes": "model decides",             # no review step before a fact is saved
}

TOOLS = [
    {
        "name": "hr_policy_search",
        "description": "Search the internal HR policy wiki (Confluence space HR) and return matching pages.",
        "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
    },
    {
        "name": "payroll_lookup",
        "description": "Return salary, bank account and pay stubs for an employee from the Payroll DB.",
        "input_schema": {
            "type": "object",
            # any employee_id is accepted; the tool runs with AskBot's service account
            "properties": {"employee_id": {"type": "string"}},
            "required": ["employee_id"],
        },
    },
    {
        "name": "read_email",
        "description": "Read the newest messages in the hr-help@ shared inbox. Anyone, including "
                       "people outside the company, can email this address.",
        "input_schema": {"type": "object", "properties": {"limit": {"type": "integer"}}},
    },
]

# Every tool call runs automatically. There is no confirmation step.
REQUIRE_CONFIRMATION = []

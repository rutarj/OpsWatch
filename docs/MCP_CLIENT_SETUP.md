# Connecting an MCP client

OpsWatch speaks MCP over stdio. The MCP server and the approval API must use the **same database file** (`OPSWATCH_DB`) so the agent's proposals show up in the sign-off queue.

## Claude Desktop

Add to `claude_desktop_config.json` (use absolute paths):

```json
{
  "mcpServers": {
    "opswatch": {
      "command": "/absolute/path/to/.venv/bin/opswatch",
      "args": ["serve-mcp"],
      "env": { "OPSWATCH_DB": "/absolute/path/to/opswatch/data/opswatch.db" }
    }
  }
}
```

Restart Claude Desktop. Try: *"Look at the new tickets, triage the three most urgent ones, and propose updates with your reasoning."* Then open the approval console (`opswatch serve-api`) and approve or reject.

## Claude Code

```bash
claude mcp add opswatch -e OPSWATCH_DB=/absolute/path/to/data/opswatch.db -- /absolute/path/to/.venv/bin/opswatch serve-mcp
```

Check the current `claude mcp add` syntax in the Claude Code docs if this changes.

## Any MCP client (Python)

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

params = StdioServerParameters(command="opswatch", args=["serve-mcp"])
async with stdio_client(params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool("triage_ticket", {"ticket_id": "INC0001001"})
```

This exact flow was run during development: a separate client process listed the 9 tools, triaged a ticket, proposed an update, and read the policy resource; a human then approved the proposal through the running REST API.

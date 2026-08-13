# infrawarden-mcp

An MCP server that gives Claude Code read access to one Infrawarden client's
infrastructure documentation - hosts, VMs, storage, network devices, credentials,
and notes/history - via a scoped, time-limited API token instead of a human
copy-pasting secrets out of a password manager.

It is a pure pass-through: no local state, no caching. Every call re-fetches from
the Infrawarden backend, so it always reflects the token's current TTL/scope/
revocation status.

## Setup

1. In the Infrawarden web UI, open the client you want an agent to see, go to
   **API Tokens**, and create one - pick a TTL (30 minutes / 1 hour / 1 day) and a
   scope (the whole environment, or specific resources). Copy the token shown -
   it's only displayed once.
2. Add this server to Claude Code's MCP config (e.g. `.mcp.json` or your global
   config), one entry per client you want visible in a given session:

```json
{
  "mcpServers": {
    "infrawarden": {
      "command": "npx",
      "args": ["infrawarden-mcp"],
      "env": {
        "INFRAWARDEN_API_KEY": "paste-the-token-here",
        "INFRAWARDEN_BASE_URL": "https://your-infrawarden-instance.example.com"
      }
    }
  }
}
```

3. In a Claude Code session, ask it to use the `get_infra_doc` tool - it returns
   the rendered markdown doc for that client, scoped and time-limited exactly as
   configured in the web UI. When the token expires, calls will fail with a clear
   error - just mint a new one.

## Local development

```bash
npm install
npm run build
INFRAWARDEN_API_KEY=... INFRAWARDEN_BASE_URL=http://localhost:8000 npm start
```

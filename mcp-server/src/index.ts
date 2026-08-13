#!/usr/bin/env node
// Infrawarden MCP server: exposes one tool, get_infra_doc, that fetches the
// rendered infra document for exactly the one client an INFRAWARDEN_API_KEY is
// scoped to. Pure pass-through - no local state, no caching - so it inherits all
// of the backend's TTL/scope enforcement for free and never becomes a place where
// plaintext lingers. See docs/ARCHITECTURE.md in the main repo for how the
// backend actually decrypts on behalf of this token.
//
// Required env vars:
//   INFRAWARDEN_API_KEY   - "<token_id>.<token_secret>" from the web UI, shown
//                            exactly once when the token is created
//   INFRAWARDEN_BASE_URL  - base URL of the Infrawarden backend
//                            (e.g. https://infrawarden.example.com)

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const apiKey = process.env.INFRAWARDEN_API_KEY;
const baseUrl = process.env.INFRAWARDEN_BASE_URL;

if (!apiKey || !baseUrl) {
  console.error(
    "infrawarden-mcp: INFRAWARDEN_API_KEY and INFRAWARDEN_BASE_URL must both be set. " +
      "Create a scoped API token for one client in the Infrawarden web UI and configure " +
      "them in this server's MCP config.",
  );
  process.exit(1);
}

interface AgentDocResponse {
  client_name: string;
  rendered_markdown: string;
  expires_at: string;
}

async function fetchInfraDoc(): Promise<string> {
  const response = await fetch(`${baseUrl}/api/v1/agent/doc`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });

  if (response.status === 401) {
    throw new Error(
      "Infrawarden rejected this token - it may be expired or revoked. Create a new one in the web UI.",
    );
  }
  if (!response.ok) {
    throw new Error(`Infrawarden returned ${response.status}: ${await response.text()}`);
  }

  const body = (await response.json()) as AgentDocResponse;
  return body.rendered_markdown;
}

const server = new McpServer({ name: "infrawarden", version: "0.1.0" });

server.registerTool(
  "get_infra_doc",
  {
    title: "Get infrastructure document",
    description:
      "Fetches the current infrastructure documentation (hosts, VMs, storage, network devices, " +
      "credentials, and notes/history) for the one Infrawarden client this API key is scoped to. " +
      "The token is time-limited and may be scoped to only a subset of resources.",
  },
  async () => {
    try {
      const markdown = await fetchInfraDoc();
      return { content: [{ type: "text" as const, text: markdown }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { content: [{ type: "text" as const, text: message }], isError: true };
    }
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("infrawarden-mcp failed to start:", err);
  process.exit(1);
});

// Infrawarden MCP server: exposes one tool, get_infra_doc, that fetches the
// rendered infra document for exactly the one client an INFRAWARDEN_API_KEY
// is scoped to. Implemented in task #6 of the build plan (not yet wired up).
//
// Expected env vars:
//   INFRAWARDEN_API_KEY   - "<token_id>.<token_secret>" from the web UI
//   INFRAWARDEN_BASE_URL  - base URL of the Infrawarden backend

export {};

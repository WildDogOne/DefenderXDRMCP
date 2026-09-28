# Defender XDR MCP

MCP server for Microsoft Defender XDR — **Incidents** and **Advanced Hunting**, the two
capabilities named on Microsoft's own
[Defender XDR API overview](https://learn.microsoft.com/en-us/defender-xdr/api-overview).

The tool set is **generated, not hand-written**: `scripts/fetch_spec.py` downloads Microsoft's own
Graph v1.0 OpenAPI spec and trims it to just those operations; `FastMCP.from_openapi()` turns that
trimmed spec into the four MCP tools below. When Microsoft changes the underlying API, re-running
the generator picks it up — nothing here needs hand-editing to stay in sync.

## Why Graph, not the legacy Defender API

The XDR-specific advanced hunting endpoint (`api.security.microsoft.com`) is being retired (retirement began January
2026 per Microsoft's own docs) in favor of the Microsoft Graph Security
API. This project targets Graph's `/security` namespace from the start so it doesn't need a
rewrite once the legacy host stops working. Scope stays identical to what the XDR docs name —
Incidents and Advanced Hunting — just reached through the current host.

The **Event Streaming API** (push-based, Defender → Azure Event Hubs/Storage) is intentionally out
of scope: it's not a request/response endpoint, so it doesn't fit the OpenAPI-to-MCP-tool pattern
this project uses. It would need a separate, continuously-running Event Hub consumer component.

## Tools

| Tool                       | Graph operation                  | Type                                                                                                       |
|----------------------------|----------------------------------|------------------------------------------------------------------------------------------------------------|
| `security_ListIncidents`   | `GET /security/incidents`        | read-only                                                                                                  |
| `security_GetIncidents`    | `GET /security/incidents/{id}`   | read-only                                                                                                  |
| `security_UpdateIncidents` | `PATCH /security/incidents/{id}` | **mutates** the tenant's incident (status, classification, assignment, etc.)                               |
| `security_runHuntingQuery` | `POST /security/runHuntingQuery` | runs a KQL query against Defender's event tables (read-only against tenant data, but modeled as an action) |

Only `security_UpdateIncidents` writes anything. If you wire this into an MCP client with
allow/ask permission rules (e.g. Claude Code), put the other three in `allow` and this one in
`ask` — see `src/defender_xdr_mcp/server.py` for the route-map that makes this split explicit.

## App registration

Create an Entra ID app registration for the client-credentials (app-only) flow and grant it **Application** permissions
on Microsoft Graph:

| Permission                       | Needed for                                                                                                                             |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `SecurityIncident.Read.All`      | list/get incidents                                                                                                                     |
| `SecurityIncident.ReadWrite.All` | update incidents (skip this if you only want read access — drop `security_UpdateIncidents` from your MCP client's tool allow-list too) |
| `ThreatHunting.Read.All`         | `runHuntingQuery`                                                                                                                      |

Grant admin consent, then create a client secret. You'll need the **tenant ID**, **client ID**,
and **client secret**.

## Setup

```bash
uv sync
cp .env.example .env   # fill in AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
uv run defender-xdr-mcp
```

Regenerating the spec (e.g. after a Microsoft Graph update):

```bash
uv run python scripts/fetch_spec.py
```

## Wiring into Claude Code

This runs over **stdio**, so add it to `~/.claude.json` (or `.mcp.json`) the way you'd add any
locally-run MCP server:

```json
{
  "mcpServers": {
    "defender-xdr": {
      "type": "stdio",
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/home/linus/Documents/git/DefenderXDRMCP",
        "defender-xdr-mcp"
      ]
    }
  }
}
```

Then extend `~/.claude/settings.json`'s `permissions.allow` / `permissions.ask` the same way it's
already split for the other connected MCP servers: the three read-only tools in `allow`,
`mcp__defender-xdr__security_UpdateIncidents` in `ask`.

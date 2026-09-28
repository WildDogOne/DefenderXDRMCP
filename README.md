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

Microsoft Graph's OpenAPI spec uses OData conventions (`$top`, `$select`, `@odata.type`, ...) for
query parameters and some body properties. Those characters (`$`, `@`) aren't valid in an MCP tool
schema's property names, so without intervention 3 of these 4 tools get silently dropped from the
tool list entirely. `src/defender_xdr_mcp/schema_sanitize.py` renames them (`$top` → `top`,
`@odata.type` → `odata.type`) in the schema shown to the model, and transparently translates
arguments back to the real OData names before the request is built — so the model sees clean
parameter names and Graph still gets what it expects on the wire.

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

## Setup (for developing/regenerating the spec)

```bash
uv sync
cp .env.example .env   # fill in AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
uv run defender-xdr-mcp
```

Regenerating the spec (e.g. after a Microsoft Graph update):

```bash
uv run python scripts/fetch_spec.py
```

## Installing it as a standalone command

The generated `openapi/security.generated.yaml` ships as package data (under
`src/defender_xdr_mcp/openapi/`), loaded via `importlib.resources` rather than a path relative to
the repo checkout — so, unlike a plain `uv run --directory /path/to/repo`, the installed command
below has no dependency on this directory still existing or being readable by whatever spawns it:

```bash
uv tool install .          # from a checkout, or:
uv tool install git+https://github.com/WildDogOne/DefenderXDRMCP   # directly from GitHub
```

This puts a `defender-xdr-mcp` executable on `~/.local/bin` (run `uv tool update-shell` once if
it's not already on your `PATH`), runnable from anywhere, independent of this checkout.

## Wiring into Claude Code

This runs over **stdio**. MCP server subprocesses do **not** inherit Claude Code's environment
automatically — even if `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET` are set wherever
Claude Code itself runs, they still have to be passed explicitly, either via `--env` on `claude mcp
add` or the `env` field in `.mcp.json`.

```bash
claude mcp add --scope user \
  --env AZURE_TENANT_ID=<your-tenant-id> \
  --env AZURE_CLIENT_ID=<your-client-id> \
  --env AZURE_CLIENT_SECRET=<your-client-secret> \
  defender-xdr \
  -- defender-xdr-mcp
```

No `--directory` and no path to this repo anywhere in that command — it only works once
`defender-xdr-mcp` is installed and on `PATH` per the previous section.

If you'd rather the literal secret not sit in your shell history either: export the three
`AZURE_*` variables in your own shell/secret manager first, then hand-edit `.mcp.json` yourself
with `"env": {"AZURE_TENANT_ID": "${AZURE_TENANT_ID}", ...}` — Claude Code expands `${VAR}` from
your environment at startup, so the secret itself never needs to appear in any file or command.

Then extend `~/.claude/settings.json`'s `permissions.allow` / `permissions.ask` the same way it's
already split for the other connected MCP servers: the three read-only tools in `allow`,
`mcp__defender-xdr__security_UpdateIncidents` in `ask`.

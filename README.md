# Defender XDR MCP

MCP server for Microsoft Defender XDR: **Incidents** (plus incident tasks), **Advanced Hunting**
and **custom detection rules**, via the Microsoft Graph Security API (beta).

The tool set is **generated, not hand-written**: `scripts/fetch_spec.py` downloads Microsoft's own
Graph beta OpenAPI spec and trims it to just those operations; `FastMCP.from_openapi()` turns that
trimmed spec into the eight MCP tools below. When Microsoft changes the underlying API, re-running
the generator picks it up — nothing here needs hand-editing to stay in sync.

Beyond that default, an opt-in **`graph` toolset** gives read-only access to *all* of Microsoft
Graph, v1.0 and beta (e.g. for an Entra ID configuration review) through three discovery tools, without
loading thousands of tool definitions into the agent's context. See [Toolsets](#toolsets).

## Why Graph, not the legacy Defender API

The XDR-specific advanced hunting endpoint (`api.security.microsoft.com`) is being retired (retirement began January
2026 per Microsoft's own docs) in favor of the Microsoft Graph Security
API. This project targets Graph's `/security` namespace from the start so it doesn't need a
rewrite once the legacy host stops working.

The `xdr` tools use Graph **beta**, not v1.0: custom detection rules and incident tasks only exist
in beta, and beta's incident and hunting models are a superset of v1.0's (e.g. `workspaceId` on
`runHuntingQuery`). Microsoft doesn't formally support beta for production use and may change it,
so a beta change can occasionally break a tool until the spec is regenerated.

The **Event Streaming API** (push-based, Defender → Azure Event Hubs/Storage) is intentionally out
of scope: it's not a request/response endpoint, so it doesn't fit the OpenAPI-to-MCP-tool pattern
this project uses. It would need a separate, continuously-running Event Hub consumer component.

## Toolsets

Select toolsets with `GRAPH_MCP_TOOLSETS` (comma-separated). Default: `xdr`.

| Toolset | Tools                                                     | Context cost (tool definitions) |
|---------|-----------------------------------------------------------|---------------------------------|
| `xdr`   | the eight generated Defender XDR tools below              | ~26 KB                          |
| `graph` | `graph_search_operations`, `graph_describe_operation`, `graph_get` | ~4 KB, regardless of API size   |

`GRAPH_MCP_TOOLSETS=xdr,graph` enables both; `GRAPH_MCP_TOOLSETS=graph` runs only the generic tools.

### `graph`: all of Graph (v1.0 + beta), discovered on demand

Generating one tool per operation doesn't scale to the whole API (~9,400 GET operations in v1.0,
~15,000 in beta, each carrying its own schema). The `graph` toolset lets the agent find and call what it needs instead:

| Tool                       | Does                                                                                                                                    |
|----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `graph_search_operations`  | keyword search over every v1.0 and beta GET operation (path, summary, description); each match lists the versions that have it        |
| `graph_describe_operation` | supported OData options, response properties (with enum values), sub-paths and the docs link (which lists required permissions) for one path; or the properties of one type |
| `graph_get`                | **GET-only** request to `https://graph.microsoft.com/v1.0` (or `/beta` with `api_version="beta"`) with `select`/`filter`/`top`/`expand`/`orderby`/`search`/`count`; follows `@odata.nextLink` |

Search and describe read `openapi/graph_index.json.gz` and `graph_index_beta.json.gz`, compact
indexes that `scripts/fetch_spec.py` builds from Microsoft's upstream v1.0 and beta specs — so this toolset is spec-driven too, it just isn't
one-tool-per-operation. Notes:

- `graph_get` refuses non-GET methods, absolute URLs on any other host or API version (the bearer
  token is only ever sent to `graph.microsoft.com/v1.0` or `/beta`), and `..` path segments.
- Responses larger than `GRAPH_MCP_MAX_RESPONSE_CHARS` (default 60000) are trimmed to whole items,
  with a note saying how many were dropped — use `select` and `top` to stay under it.
- `/me` paths are hidden from search: app-only auth has no signed-in user.
- **v1.0 is the default.** Beta is opt-in per call, for endpoints that only exist there, such as
  Defender XDR custom detection rules (`/security/rules/detectionRules`). Microsoft doesn't support
  beta for production use and may change it without notice, so `graph_describe_operation` flags
  beta results.

What `graph_get` can actually read is set by the app registration's permissions, not by this code —
see [App registration](#app-registration).

## Tools (`xdr` toolset)

All operations are on `https://graph.microsoft.com/beta`.

| Tool                                | Graph operation                           | Type                                                                                                       |
|-------------------------------------|-------------------------------------------|------------------------------------------------------------------------------------------------------------|
| `security_ListIncidents`            | `GET /security/incidents`                 | read-only                                                                                                  |
| `security_GetIncidents`             | `GET /security/incidents/{id}`            | read-only                                                                                                  |
| `security_UpdateIncidents`          | `PATCH /security/incidents/{id}`          | **mutates** the tenant's incident (status, classification, assignment, etc.)                               |
| `security_ListIncidentTasks`        | `GET /security/incidentTasks`             | read-only                                                                                                  |
| `security_GetIncidentTasks`         | `GET /security/incidentTasks/{id}`        | read-only                                                                                                  |
| `security_runHuntingQuery`          | `POST /security/runHuntingQuery`          | runs a KQL query against Defender's event tables (read-only against tenant data, but modeled as an action) |
| `security_rules_ListDetectionRules` | `GET /security/rules/detectionRules`      | read-only                                                                                                  |
| `security_rules_GetDetectionRules`  | `GET /security/rules/detectionRules/{id}` | read-only                                                                                                  |

Graph also has create/update/delete for detection rules and incident tasks; they're deliberately
not generated (add them to `KEPT_OPERATIONS` if you want them). `getHuntingSchema()` is left out
too: it returns every table's schema in one ~240 KB response. Use `<Table> | getschema` through
`security_runHuntingQuery` instead, one table at a time.

Microsoft Graph's OpenAPI spec uses OData conventions (`$top`, `$select`, `@odata.type`, ...) for
query parameters and some body properties. Those characters (`$`, `@`) aren't valid in an MCP tool
schema's property names, so without intervention most of these tools get silently dropped from
the tool list entirely. `src/defender_xdr_mcp/schema_sanitize.py` renames them (`$top` → `top`,
`@odata.type` → `odata.type`) in the schema shown to the model, and transparently translates
arguments back to the real OData names before the request is built — so the model sees clean
parameter names and Graph still gets what it expects on the wire.

The generated tools' output schemas (the full nested Graph response model, ~18 KB per incident
tool) are stripped in `server.py`; responses still come back as structured JSON.

Only `security_UpdateIncidents` writes anything. If you wire this into an MCP client with
allow/ask permission rules (e.g. Claude Code), put the other seven in `allow` and this one in
`ask` — see `src/defender_xdr_mcp/server.py` for the route-map that makes this split explicit.

## App registration

Create an Entra ID app registration for the client-credentials (app-only) flow and grant it **Application** permissions
on Microsoft Graph:

| Permission                       | Needed for                                                                                                                             |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `SecurityIncident.Read.All`      | list/get incidents                                                                                                                     |
| `SecurityIncident.ReadWrite.All` | update incidents (skip this if you only want read access — drop `security_UpdateIncidents` from your MCP client's tool allow-list too) |
| `ThreatHunting.Read.All`         | `runHuntingQuery`                                                                                                                      |
| `CustomDetection.Read.All`       | list/get custom detection rules                                                                                                        |

Incident tasks are covered by the incident permissions above.

Grant admin consent, then create a client secret. You'll need the **tenant ID**, **client ID**,
and **client secret**.

### For the `graph` toolset (e.g. an Entra ID security review)

Use a **separate, read-only app registration** and run it as its own MCP server entry (see
[below](#a-second-entry-for-the-graph-toolset)), so the broad directory read access doesn't sit
behind your everyday SOC agent. A reasonable read-only set for reviewing Entra ID configuration:

| Permission                          | Covers                                                                          |
|-------------------------------------|---------------------------------------------------------------------------------|
| `Policy.Read.All`                   | Conditional Access, authorization/auth-methods/cross-tenant/security-defaults policies |
| `Directory.Read.All`                | users, groups, devices, domains, organization                                   |
| `RoleManagement.Read.Directory`     | directory role definitions, assignments, PIM eligibility/assignment schedules   |
| `Application.Read.All`              | app registrations, service principals, credentials, app role assignments        |
| `AuditLog.Read.All`                 | sign-in and directory audit logs                                                |
| `Reports.Read.All`                  | usage reports                                                                   |
| `UserAuthenticationMethod.Read.All` | per-user authentication methods, MFA registration details                       |
| `IdentityRiskyUser.Read.All`        | Identity Protection risky users                                                 |

Each endpoint's docs link (from `graph_describe_operation`) lists the exact permission it needs; a
403 from `graph_get` usually means one is missing.

## Setup (for developing/regenerating the spec)

```bash
uv sync
cp .env.example .env   # fill in AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
uv run defender-xdr-mcp
```

Regenerating the spec and the `graph` index (e.g. after a Microsoft Graph update):

```bash
uv run python scripts/fetch_spec.py                       # downloads the ~40 MB upstream spec
uv run python scripts/fetch_spec.py --spec openapi.yaml   # or reuse a local copy
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
already split for the other connected MCP servers: the seven read-only tools in `allow`,
`mcp__defender-xdr__security_UpdateIncidents` in `ask`.

### A second entry for the `graph` toolset

Same binary, different app registration and toolset:

```bash
claude mcp add --scope user \
  --env AZURE_TENANT_ID=<your-tenant-id> \
  --env AZURE_CLIENT_ID=<review-app-client-id> \
  --env AZURE_CLIENT_SECRET=<review-app-client-secret> \
  --env GRAPH_MCP_TOOLSETS=graph \
  graph-review \
  -- defender-xdr-mcp
```

All three `graph_*` tools are read-only, so `mcp__graph-review__*` can go in `allow`.

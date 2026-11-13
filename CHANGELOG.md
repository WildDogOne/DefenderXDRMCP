# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump can change the tool set).

Tool names are generated from Microsoft's Graph `operationId`s. A regenerated spec can rename or
change tools even when this project's code didn't change, so spec regenerations are listed too.

## [0.6.0] - 2026-11-13

### Added
- `security_CreateIncidentComments` (`POST /security/incidents/{id}/comments`, Graph **v1.0**):
  adds a comment to a Defender incident. This is the only supported way to write incident comments -
  a comment placed in the `security_UpdateIncidents` PATCH body is accepted (200) but silently
  dropped, and incident comments are append-only (Graph rejects PATCH/DELETE on an individual
  comment). The accepted discriminator is `#microsoft.graph.security.alertComment`
  (`#microsoft.graph.security.comment` and `#microsoft.graph.security.incidentComment` are rejected
  with `Invalid OData type specified`); the tool makes it optional (the action accepts a bare
  `comment`) with that value as the default.
  This endpoint is **missing from Microsoft's OpenAPI spec** (only the alert-level `SetComments` is
  listed), so `scripts/fetch_spec.py` now injects it via a `SUPPLEMENTAL_OPERATIONS_V1` block -
  hand-authored path-item fragments merged into the trimmed spec before component closure, so the
  tool is still produced by the normal generation pipeline rather than hand-written.
  Note: this is a tenant-mutating tool - add it to your MCP client's `ask` rules alongside the
  other writes; it needs the already-required `SecurityIncident.ReadWrite.All`.
- `scripts/test_update_incidents.py` and `scripts/test_incident_comments.py`: integration tests for
  the two incident write tools. Part 1 runs offline over an httpx MockTransport and asserts the
  serialized body; part 2 runs against a real incident when `DEFENDER_TEST_INCIDENT_ID` + real
  `AZURE_*` creds are set.

### Changed
- **API version split.** The `xdr` tools no longer all run on Graph beta. The generator now emits
  two trimmed specs and `server.py` mounts one OpenAPI provider per version, each rooted at the
  right base URL:
  - **v1.0** (`security_v1.generated.yaml`): `security_ListIncidents` / `security_GetIncidents` /
    `security_UpdateIncidents`, `security_runHuntingQuery`, `security_rules_ListDetectionRules` /
    `security_rules_GetDetectionRules`. These all exist in v1.0, which is stable and production-
    supported (beta is explicitly "not supported in production"). Custom detection rules moved from
    beta to v1.0 (they are GA there).
  - **beta** (`security_beta.generated.yaml`): incident tasks and case management - the operations
    that do not exist in v1.0.
  Tool names are unchanged (the v1.0 `operationId`s match the beta ones exactly), so no MCP client
  permission rules need updating. The legacy `api.security.microsoft.com` XDR host is, as before,
  never used.
- `scripts/fetch_spec.py` now takes `KEPT_OPERATIONS_V1` / `KEPT_OPERATIONS_BETA` and writes
  `security_v1.generated.yaml` + `security_beta.generated.yaml` (the old single
  `security.generated.yaml` is gone). Verified against live Graph: v1.0 incident update, hunting,
  detection rules and beta incident tasks / cases all respond correctly.
- `security_UpdateIncidents` no longer advertises `comments`. Graph accepts them in the PATCH body
  but never stores them, so the field only invited silent no-ops; use
  `security_CreateIncidentComments`. The `patch_body.py` hook drops the field from the schema and
  from any body a client still sends.
- **One shared MSAL token cache.** `build_server()` now builds a single `ClientCredentialsAuth`
  (`auth.build_auth()`) and passes it to every httpx client it creates - the v1.0 provider, the
  beta provider and the `graph` toolset's client. Each auth owns its own
  `ConfidentialClientApplication`, so before this each of those clients acquired its own Graph
  token at startup (three client-credentials round-trips with both toolsets enabled, up from one).
- Refreshed all dependencies in `uv.lock` (`uv lock --upgrade`): **fastmcp 4.1.5 → 4.2.0** plus
  transitive bumps (pydantic, authlib, cachetools 7→8, cyclopts, sse-starlette, ...). No packages
  added or removed; direct deps `httpx2`, `msal`, `pyyaml` and `python-dotenv` were already current.

### Fixed
- `security_UpdateIncidents` failed every call with `400 InvalidRequestBody` - the tool was
  effectively non-functional. The spec models the PATCH body as the full incident schema, which
  marks `@odata.type` as a *required* discriminator, so FastMCP advertised it as a required
  top-level argument and every request sent `{"@odata.type": "#microsoft.graph.security.incident",
  ...}`. Graph's `PATCH /security/incidents/{id}` already knows the type from the URL and rejects a
  body carrying the resource's own discriminator (verified live on beta: the same body without it
  returns 200). New `patch_body.py` hook (registered in `server.py`) drops that top-level
  discriminator from the advertised schema and the outgoing body for PATCH tools.
- `schema_sanitize.py` now sanitizes OData names **recursively**, through every subschema keyword
  (`items`, combinators, `$defs`, `patternProperties`, `if`/`then`/`else`, ...). It previously only
  touched top-level properties, so nested discriminators Graph genuinely needs - a case activity's
  `@odata.type`, nested types under `security_caseManagement_UpdateCases` /
  `security_caseManagement_cases_UpdateTasks` - kept a literal `@` in the advertised schema (invalid
  to the MCP key regex) and were never translated back.
- `required` entries are renamed directly, so a type that requires `@odata.type` declared on a base
  type (reached via `allOf`/`$ref`) no longer advertises an unsanitized required name.
- Argument translation now follows the original schema (`$ref`s resolved) instead of one flat rename
  table, so only declared OData properties are renamed. Free-form user data - e.g. a key named
  `filter`, `select` or `odata.type` inside a `customFields` map - is no longer rewritten to
  `$filter`/`$select`/`@odata.type` on the way to Graph.
- `scripts/check_schema_safety.py` now checks property names (and `required` entries) at every
  schema depth, including `$defs`, using the same subschema iterator as `schema_sanitize.py`
  (`iter_subschemas`), so the check and the sanitizer can't drift apart.

## [0.4.2] - 2026-11-02

### Fixed
- The `odata_scalars` hook only rewrote real Python booleans, so a client that sends the value
  already stringified (opencode sends `count: "True"`) still went out as `$count=True` and 400'd.
  The hook now also lowercases string forms of booleans (`"True"`/`"False"`) on boolean-typed
  parameters, covering `true`, `"true"` and `"True"` alike.

## [0.4.1] - 2026-11-02

### Fixed
- `count=true` on the list tools (`security_ListIncidents`, `security_caseManagement_ListCases`,
  `security_caseManagement_cases_ListTasks`, ...) failed with `BadRequest: 'True' is not a valid
  count option`: FastMCP passes boolean query parameters to httpx unserialized, so Python's
  `str(True)` went on the wire as `$count=True` instead of `$count=true`. New
  `odata_scalars.py` hook (registered in `server.py` next to `sanitize_component`) rewrites
  boolean tool arguments to their lowercase string form before the request is built.
  (Note: `$count` is now serialized correctly and works on e.g. `/security/incidents`, but the
  case-management collections reject it outright - `Query option 'Count' is not allowed` - even
  though the beta spec advertises the parameter.)

## [0.4.0] - 2026-11-02

### Added
- Case management (preview, Graph beta `/security/caseManagement`) in the `xdr` toolset, 11 new tools:
  - Read: `security_caseManagement_ListCases`, `security_caseManagement_GetCases`,
    `security_caseManagement_cases_ListActivities`, `security_caseManagement_cases_ListTasks`,
    `security_caseManagement_cases_ListRelations`, `security_caseManagement_cases_ListAttachments`
    (metadata only), `security_caseManagement_ListCaseTypeConfigurations`.
  - Write: `security_caseManagement_UpdateCases`, `security_caseManagement_cases_CreateActivities`
    (add a comment), `security_caseManagement_cases_CreateTasks`,
    `security_caseManagement_cases_UpdateTasks`.
- New app permissions: `CaseManagement.Read.All`, plus `CaseManagement.ReadWrite.All` for the write tools.

### Changed
- `scripts/fetch_spec.py` now also keeps the `discriminator.mapping` subtypes of each kept write
  operation's request body, so polymorphic bodies expose their subtype fields (e.g. a comment's
  `message`, a generic case's `assignedTo`/`priority`).
- POST no longer means read-only: every PATCH and every POST except `security_runHuntingQuery`
  writes to the tenant. Five tools belong in your client's `ask` list now (see README).
- Regenerated the trimmed spec and both Graph indexes from the current upstream specs.
- Upgraded all locked dependencies (`uv lock --upgrade`), among them fastmcp 4.0.10 → 4.1.5,
  httpx2 2.13.1 → 2.16.0, mcp 2.2.0 → 2.3.0, pydantic 2.13.5 → 2.14.2.

## [0.3.0] - 2026-10-16

### Added
- Incident tasks (`security_ListIncidentTasks`, `security_GetIncidentTasks`) and custom detection
  rules (`security_rules_ListDetectionRules`, `security_rules_GetDetectionRules`).
- `graph` toolset: beta index (`graph_index_beta.json.gz`) and a per-call `api_version` option;
  v1.0 stays the default.

### Changed
- The `xdr` toolset is generated from Graph **beta** instead of v1.0. The client's base URL now
  comes from the generated spec's `servers` entry.

## [0.2.0] - 2026-10-16

### Added
- Opt-in `graph` toolset (`graph_search_operations`, `graph_describe_operation`, `graph_get`):
  read-only, GET-only access to all of Graph v1.0, driven by `graph_index.json.gz`.
- `GRAPH_MCP_TOOLSETS` env var to select toolsets (default `xdr`).

## [0.1.0] - 2026-09-28

### Added
- Initial release: stdio MCP server generated from Microsoft's Graph v1.0 OpenAPI spec, covering
  Incidents (list/get/update) and Advanced Hunting (`runHuntingQuery`), with MSAL client-credentials auth.
- OData name sanitizing (`schema_sanitize.py`) so tools with `$top`/`@odata.type` parameters
  aren't silently dropped, plus `scripts/check_schema_safety.py`.

### Fixed
- Spec shipped as package data so `uv tool install` works outside the checkout.

[0.6.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/f995f08...HEAD
[0.4.2]: https://github.com/WildDogOne/DefenderXDRMCP/compare/7345d77...f995f08
[0.4.1]: https://github.com/WildDogOne/DefenderXDRMCP/compare/d945277...7345d77
[0.4.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/aee7dcc...d945277
[0.3.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/86e8598...aee7dcc
[0.2.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/4576514...86e8598
[0.1.0]: https://github.com/WildDogOne/DefenderXDRMCP/commits/4576514

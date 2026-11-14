# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump can change the tool set).

Tool names are generated from Microsoft's Graph `operationId`s. A regenerated spec can rename or
change tools even when this project's code didn't change, so spec regenerations are listed too.

## [0.7.0] - 2026-11-14

### Added
- `security_ListAlerts` / `security_GetAlert` (`GET /security/alerts_v2[/{id}]`, v1.0): full alert
  objects incl. `evidence`, `customDetails`, `additionalData`. Graph's alert entity has no
  `devices`/`users` properties; attribution (device, user, matched hash/indicator) lives in
  `evidence`. Needs `SecurityAlert.Read.All`. The deprecated `/security/alerts` is not kept.
- `security_getHuntingSchema` (`GET /beta/security/getHuntingSchema()`): the advanced hunting
  catalog, trimmed client-side from ~240 KB (`hunting_schema.py`). Without `tables`: one row per
  table (name, description, column count). With `tables` (comma-separated substrings/globs, or a
  list): the matching tables' columns. Built-in KQL functions are dropped, saved functions kept.

### Changed
- **`security_ListIncidents` honors `search` client-side** (`incident_search.py`): Graph silently
  ignores `$search` on `/security/incidents`, so counts were wrong. The tool scans the filtered
  collection oldest-first with `$count`+`$skip` and matches `displayName` case-insensitively.
  `|` separates phrases, and `searchCounts` gives a per-phrase count (buckets may overlap).
  `maxResults` (default 5000) caps the scan, which **raises** rather than returning partial counts;
  incidents leaving the filter mid-scan are compensated for. In search mode `top`/`skip`/`orderby`
  apply to the matches (`top: 0` = counts only), and rows default to five fields unless `select`
  is given.
- **`security_runHuntingQuery` explains the word-form operator quirk** (`hunting_operators.py`):
  the endpoint rejects `eq`/`ne`/`gt`/`ge`/`lt`/`le` with `400 "Expected: ;"` although KQL defines
  them as synonyms. The query is never rewritten; the parameter description warns, and that error
  is re-raised with a hint to use `==`/`!=`/`>`/`>=`/`<`/`<=`.
- **429/5xx backoff for every tool** (`auth.RetryingAsyncClient`): 429 retried for any method,
  5xx for GET only, honoring `Retry-After` (capped at 60s per wait, 5 retries). Proxy environment
  variables keep working.

### Removed
- `search` parameter of `security_ListAlerts` (not supported by alerts_v2; dropped in the generator
  via `DROPPED_PARAMETERS_V1`).

### Verified live (anonymized, see AGENTS.md)
- Multi-phrase `search` over the open backlog: every bucket count matched an independent raw
  `$skip` scan.
- An incident's alerts via `ListAlerts` (`incidentId eq '<id>'`) and `GetAlert` yield device, user
  and matched indicator; `AlertEvidence` with `==` joins the same alert (`eq` fails).
- `test_incident_comments.py` live PASS: comments are append-only, max 1000 characters.
- `check_schema_safety.py`: 26 tools ALL SAFE.

## [0.6.0] - 2026-11-13

### Added
- `security_CreateIncidentComments` (`POST /security/incidents/{id}/comments`, v1.0), the only way
  to write incident comments: comments in the `UpdateIncidents` PATCH body are accepted but
  silently dropped. The endpoint is missing from Microsoft's spec and is injected by the generator
  (`SUPPLEMENTAL_OPERATIONS_V1`). The `@odata.type` defaults to
  `#microsoft.graph.security.alertComment`, the only value Graph accepts. Mutates the tenant
  (`ask` list); needs `SecurityIncident.ReadWrite.All`.
- `scripts/test_update_incidents.py` / `scripts/test_incident_comments.py`: offline body
  serialization test, plus a live part when `DEFENDER_TEST_INCIDENT_ID` and real creds are set.

### Changed
- **API version split**: incidents, hunting and custom detection rules (GA there) run on Graph
  **v1.0**; incident tasks and case management stay on **beta**. The generator writes
  `security_v1.generated.yaml` + `security_beta.generated.yaml` (`KEPT_OPERATIONS_V1` /
  `_BETA`), and `server.py` mounts one provider per version. Tool names are unchanged.
- `security_UpdateIncidents` no longer advertises `comments` (silently ignored by Graph).
- One shared MSAL token cache across all HTTP clients (was one token acquisition per client).
- Dependencies refreshed: fastmcp 4.1.5 → 4.2.0 plus transitive bumps.

### Fixed
- `security_UpdateIncidents` failed every call with `400 InvalidRequestBody`: the spec's required
  top-level `@odata.type` was sent, and Graph rejects it on PATCH. New `patch_body.py` hook drops it.
- `schema_sanitize.py` sanitizes OData names recursively (nested properties, combinators, `$defs`,
  `required`), so nested discriminators are advertised validly and translated back. Translation
  follows the schema, so free-form keys such as `filter` inside `customFields` are no longer
  rewritten.
- `check_schema_safety.py` checks every schema depth, using the sanitizer's own subschema iterator.

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

[0.7.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/2bdd890...HEAD
[0.6.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/f995f08...2bdd890
[0.4.2]: https://github.com/WildDogOne/DefenderXDRMCP/compare/7345d77...f995f08
[0.4.1]: https://github.com/WildDogOne/DefenderXDRMCP/compare/d945277...7345d77
[0.4.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/aee7dcc...d945277
[0.3.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/86e8598...aee7dcc
[0.2.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/4576514...86e8598
[0.1.0]: https://github.com/WildDogOne/DefenderXDRMCP/commits/4576514

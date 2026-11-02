# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor bump can change the tool set).

Tool names are generated from Microsoft's Graph `operationId`s. A regenerated spec can rename or
change tools even when this project's code didn't change, so spec regenerations are listed too.

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

[0.4.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/aee7dcc...HEAD
[0.3.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/86e8598...aee7dcc
[0.2.0]: https://github.com/WildDogOne/DefenderXDRMCP/compare/4576514...86e8598
[0.1.0]: https://github.com/WildDogOne/DefenderXDRMCP/commits/4576514

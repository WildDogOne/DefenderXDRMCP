"""Keep ``security_getHuntingSchema`` inside an agent context - Graph's raw response is ~240 KB.

``GET /beta/security/getHuntingSchema()`` (beta-only; the v1.0 spec does not expose it) answers
with every table in the tenant's advanced-hunting catalog, every column with its data type *and*
a prose description, plus the built-in KQL function catalog. Untrimmed that is a ~240 KB blob with
no server-side filter - too large to hand to an agent, which is why the generator left the
endpoint out until now. This hook trims the response client-side:

- Without ``tables``: a catalog *overview* - one row per table (name, description, columnCount)
  plus the tenant's saved functions (as Graph returns them). Enough to pick the right table (~15 KB).
- With ``tables``: comma-separated case-insensitive substrings, or globs when the pattern contains
  ``*``/``?``/``[`` - matched against table names; only matching tables are returned, in full,
  with each column's ``name`` + ``dataType`` (the per-column descriptions carry no information the
  type doesn't already).

The built-in function catalog is dropped: it is standard KQL the caller already knows. The
tenant-specific ``savedFunctions`` are kept (they are small and unreachable elsewhere).

Verified live (2026-11-13): the alert tables are ``AlertInfo`` +
``AlertEvidence``; ``AlertDevices`` / ``AlertAccounts`` / ``AlertEvents`` do not exist in the
catalog. ``<Table> | getschema`` via runHuntingQuery remains available as a per-table alternative.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from fastmcp.tools.base import ToolResult

from ._hooks import structured, wrap_run

# operationId of security_getHuntingSchema in security_beta.generated.yaml.
_GET_HUNTING_SCHEMA = "security.getHuntingSchema"

_GLOB_CHARS = set("*?[")


def _matches(table_name: str, pattern: str) -> bool:
    name = table_name.lower()
    if _GLOB_CHARS & set(pattern):
        return fnmatch.fnmatchcase(name, pattern)
    return pattern in name


def apply_hunting_schema(route: Any, component: Any) -> None:
    """FastMCP mcp_component_fn hook: response trimming for security_getHuntingSchema."""
    if getattr(route, "operation_id", None) != _GET_HUNTING_SCHEMA:
        return

    component.parameters.setdefault("properties", {})["tables"] = {
        "type": "string",
        "description": (
            "Comma-separated case-insensitive table-name filters (substrings, or globs with "
            "'*'/'?'/'['). Omit to list the catalog overview (table names + descriptions + column "
            "counts, no columns); set it (e.g. 'Alert*, Device*') to get full columns "
            "(name + dataType) for the matching tables."
        ),
    }
    component.description = (
        (component.description or "")
        + " NOTE: the response is trimmed client-side - without `tables` it is a catalog overview, "
        "with `tables` it is the matching tables' columns; built-in KQL functions are never "
        "returned. `<Table> | getschema` via security_runHuntingQuery is the per-table alternative."
    )

    async def run_trimmed(arguments: dict[str, Any], _orig):
        raw = arguments.get("tables") or ""
        # Advertised as a comma-separated string, but some clients send a list anyway;
        # str() of a list would yield patterns like "['alertinfo'" that match nothing.
        parts = raw if isinstance(raw, (list, tuple)) else str(raw).split(",")
        patterns = [str(p).strip().lower() for p in parts if str(p).strip()]
        args = {k: v for k, v in arguments.items() if k != "tables"}
        result = await _orig(args)
        data = structured(result)
        if not isinstance(data, dict):
            return result

        tables = data.get("tables") or []
        if patterns:
            tables = [
                t for t in tables if any(_matches(str(t.get("name") or ""), p) for p in patterns)
            ]
            payload: dict[str, Any] = {
                "tables": [
                    {
                        "name": t.get("name"),
                        "description": t.get("description"),
                        "columns": [
                            {"name": c.get("name"), "dataType": c.get("dataType")}
                            for c in t.get("columns") or []
                        ],
                    }
                    for t in tables
                ]
            }
        else:
            payload = {
                "tables": [
                    {
                        "name": t.get("name"),
                        "description": t.get("description"),
                        "columnCount": len(t.get("columns") or []),
                    }
                    for t in tables
                ]
            }
        payload["tableCount"] = len(payload["tables"])

        saved = (data.get("functions") or {}).get("savedFunctions") or []
        if saved:
            payload["savedFunctions"] = saved
        payload["note"] = (
            "Built-in KQL functions and per-column descriptions trimmed; pass `tables` for full "
            "columns of matching tables."
        )
        if patterns and not payload["tables"]:
            payload["note"] = (
                f"No table name matched {patterns}. Call without `tables` for the catalog "
                "overview to see the available names. " + payload["note"]
            )
        return ToolResult(structured_content=payload)

    wrap_run(component, run_trimmed)

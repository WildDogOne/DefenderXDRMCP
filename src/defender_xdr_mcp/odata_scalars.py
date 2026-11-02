"""Send OData query scalars the way Graph expects them on the wire.

FastMCP's OpenAPI request director passes query-parameter scalars through
``_serialize_query_params`` untouched unless they are lists or objects
(``serialized[key] = value``), and httpx then stringifies them with Python's
``str()``. For booleans that means ``$count=True`` instead of ``$count=true``,
which Graph rejects with ``BadRequest: 'True' is not a valid count option``
(fastmcp has ``_query_scalar_to_str`` for exactly this, but the plain-scalar
branch never applies it).

The fix belongs at the tool boundary, not in the httpx client: rewrite the
boolean argument to its lowercase string before FastMCP builds the request.
The generated tool schema declares these parameters as booleans, so the model
keeps passing ``true``/``false`` - only the wire value changes.

Register via FastMCP.from_openapi(..., mcp_component_fn=...) alongside
sanitize_component (see server.py).
"""

from __future__ import annotations

from typing import Any


def normalize_odata_scalars(route: Any, component: Any) -> None:
    """FastMCP mcp_component_fn hook: lowercase booleans before request building."""
    schema = getattr(component, "parameters", None)
    if not schema or "properties" not in schema:
        return
    if not any(
        isinstance(prop, dict) and prop.get("type") == "boolean"
        for prop in schema["properties"].values()
    ):
        return  # no boolean query parameters on this tool (e.g. Get*, path-only operations)

    original_run = component.run

    async def run_with_scalar_booleans(arguments: dict[str, Any], _orig=original_run):
        fixed = {
            name: str(value).lower() if isinstance(value, bool) else value
            for name, value in arguments.items()
        }
        return await _orig(fixed)

    # pydantic models (component's base class) reject setting a non-field attribute, so the
    # rebind uses object.__setattr__ to bypass that - same pattern as schema_sanitize.py.
    object.__setattr__(component, "run", run_with_scalar_booleans)

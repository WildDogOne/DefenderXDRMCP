"""Rename Graph API's OData-style property names to ones the MCP protocol accepts.

Anthropic's tool-schema validator requires every property key to match
``^[a-zA-Z0-9_.-]{1,64}$``. Microsoft Graph's own OpenAPI spec uses OData conventions like
``$top``, ``$select``, and ``@odata.type`` throughout - both as query parameters and, via
FastMCP's request-body flattening, as top-level tool arguments. Left as-is, any tool exposing one
of these gets silently dropped from the tool list (see the three tools that failed to load before
this module existed: security_ListIncidents, security_GetIncidents, security_UpdateIncidents -
only security_runHuntingQuery, which has no OData parameters, survived).

The fix only needs to strip ``$`` and ``@`` - Anthropic's regex already allows ``.`` - and it has
to hold in both directions: the schema shown to the model must use the sanitized name, and the
actual HTTP request FastMCP builds still needs the real OData name, since that's what
Microsoft Graph expects on the wire. This module does both: it rewrites the tool's advertised
JSON schema (properties + required) and wraps the tool's run() method to translate incoming
arguments back to their original names before they reach FastMCP's request builder.

Register via FastMCP.from_openapi(..., mcp_component_fn=sanitize_component).
"""

from __future__ import annotations

import re
from typing import Any

_SAFE_KEY = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


def _sanitize_key(key: str) -> str:
    if _SAFE_KEY.match(key):
        return key
    return key.replace("$", "").replace("@", "")


def sanitize_component(route: Any, component: Any) -> None:
    """FastMCP mcp_component_fn hook: rename OData-style properties on a generated tool."""
    schema = getattr(component, "parameters", None)
    if not schema or "properties" not in schema:
        return

    rename_map: dict[str, str] = {}  # sanitized name -> original OData name
    new_properties: dict[str, Any] = {}
    for original_key, value in schema["properties"].items():
        sanitized_key = _sanitize_key(original_key)
        new_properties[sanitized_key] = value
        if sanitized_key != original_key:
            rename_map[sanitized_key] = original_key

    if not rename_map:
        return  # nothing to do - most non-Graph, non-OData operations won't hit this at all

    schema["properties"] = new_properties
    if schema.get("required"):
        forward = {orig: safe for safe, orig in rename_map.items()}
        schema["required"] = [forward.get(name, name) for name in schema["required"]]

    original_run = component.run

    async def run_with_odata_names(arguments: dict[str, Any], _orig=original_run, _map=rename_map):
        # pydantic models (component's base class) reject setting a non-field attribute, so the
        # rebind below uses object.__setattr__ to bypass that - this is standard/necessary when
        # patching behavior onto a pydantic instance post-construction, not a hack around a bug.
        translated = {_map.get(name, name): value for name, value in arguments.items()}
        return await _orig(translated)

    object.__setattr__(component, "run", run_with_odata_names)

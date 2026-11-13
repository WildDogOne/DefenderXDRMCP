"""Drop the top-level ``@odata.type`` discriminator (and ignored fields) from Graph PATCH bodies.

Graph's OpenAPI specs model a PATCH request body as the full resource schema, and that schema
carries ``@odata.type`` as a ``required`` discriminator - it exists so the *polymorphic* read
schemas (an incident collection can hold incident subtypes, an alert collection can hold alert
subtypes, ...) can round-trip a concrete type. FastMCP flattens that body schema into individual
tool arguments, so the tool advertises ``@odata.type`` as a required top-level argument and every
call dutifully sends it back in the body.

For an *update* that is wrong: ``PATCH /security/incidents/{id}`` already knows the resource type
from the URL, and Graph rejects a body that carries the resource's own discriminator with
``400 InvalidRequestBody: Request body is incorrect``. The 400 was verified live against the beta
endpoint (before the incident tools moved to v1.0); on v1.0 the discriminator-free body has been
confirmed to return 200, but the 400 with the discriminator has not been re-tested there:

    {"classification":"falsePositive","determination":"securityTesting"}            -> 200
    {"@odata.type":"#microsoft.graph.security.incident","classification":...}       -> 400

This hook removes the discriminator from the advertised schema (properties + required) for PATCH
routes and drops any value the model still sends, so the outgoing body contains only the
properties actually being updated - which is what the Graph docs say to send ("supply *only* the
values for properties to update"). It only touches the top-level body object: nested discriminators
that Graph genuinely needs, such as a comment's ``@odata.type``
(``#microsoft.graph.security.alertComment``), are left intact.

It also removes body fields Graph accepts on a PATCH but silently ignores (``_IGNORED_PATCH_FIELDS``):
``security_UpdateIncidents`` advertised ``comments``, and a comment sent that way returns 200 but is
never stored. Leaving it in invites a model to "add a comment" that never lands; incident comments
go through ``security_CreateIncidentComments`` instead.

Register via OpenAPIProvider(..., mcp_component_fn=...) alongside sanitize_component (see
server.py). Runs after sanitize_component, so it matches the sanitized name it sees in the schema
and also the raw OData name in case the ordering is ever changed.
"""

from __future__ import annotations

from typing import Any

_DISCRIMINATOR_NAMES = ("@odata.type", "odata.type")

# Tool name -> top-level body fields Graph accepts on PATCH but does not persist.
_IGNORED_PATCH_FIELDS: dict[str, tuple[str, ...]] = {
    "security_UpdateIncidents": ("comments",),
}


def strip_patch_discriminator(route: Any, component: Any) -> None:
    """FastMCP mcp_component_fn hook: no resource discriminator in a PATCH body."""
    if getattr(route, "method", "").upper() != "PATCH":
        return
    schema = getattr(component, "parameters", None)
    if not schema or "properties" not in schema:
        return

    properties = schema["properties"]
    drop = set(_DISCRIMINATOR_NAMES) | set(_IGNORED_PATCH_FIELDS.get(getattr(component, "name", ""), ()))
    present = [name for name in properties if name in drop]
    if not present:
        return  # body has no top-level discriminator (e.g. a PATCH that takes a plain property set)

    for name in present:
        del properties[name]
    if schema.get("required"):
        schema["required"] = [name for name in schema["required"] if name not in drop]

    original_run = component.run

    async def run_without_dropped(arguments: dict[str, Any], _orig=original_run, _drop=frozenset(drop)):
        # Only top-level body fields are dropped; nested discriminators (inside lists/objects) stay.
        cleaned = {name: value for name, value in arguments.items() if name not in _drop}
        return await _orig(cleaned)

    # pydantic models (component's base class) reject setting a non-field attribute, so the
    # rebind uses object.__setattr__ to bypass that - same pattern as schema_sanitize.py.
    object.__setattr__(component, "run", run_without_dropped)

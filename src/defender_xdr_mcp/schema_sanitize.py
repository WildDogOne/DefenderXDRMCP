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

The rewrite is recursive. ``@odata.type`` is not only a top-level body argument - it also appears
inside nested object schemas (an incident's ``comments``, an alert's ``evidence``, a case's
``activities`` ...). Graph marks it ``required`` on those nested types too. Only sanitizing the
top level left those nested keys with a literal ``@`` in the advertised schema, which is invalid
per the same regex and breaks stricter MCP clients, and the argument translation never reached
them, so a comment's ``odata.type`` went out without the ``@`` and Graph rejected the body. The
walker descends through every subschema keyword (``properties``, ``items``, combinators,
``$defs`` ...; see ``iter_subschemas``) so every level is sanitized.

Translating arguments back follows the *original* schema (``$ref``s resolved) rather than one flat
rename table, so only declared OData properties are renamed - free-form user data such as a map's
keys is passed through untouched.

Register via OpenAPIProvider(..., mcp_component_fn=sanitize_component) (see server.py).
"""

from __future__ import annotations

import copy
import re
from collections.abc import Iterator
from typing import Any

_SAFE_KEY = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")

# JSON Schema keywords that hold subschemas, grouped by shape. ``properties`` is handled separately
# because its keys are the property names being renamed. Anything else (enum, description, format,
# ...) is left untouched. FastMCP keeps nested body types as $ref pointers into ``$defs`` and only
# inlines them when the tool is serialized, so the definitions blocks must be walked too.
_SINGLE_KEYS = ("items", "additionalProperties", "not", "if", "then", "else", "contains")
_LIST_KEYS = ("allOf", "anyOf", "oneOf", "prefixItems")
_MAP_KEYS = ("$defs", "definitions", "patternProperties", "dependentSchemas")
_COMBINATOR_KEYS = ("allOf", "anyOf", "oneOf")


def _sanitize_key(key: str) -> str:
    if _SAFE_KEY.match(key):
        return key
    return key.replace("$", "").replace("@", "")


def iter_subschemas(node: Any) -> Iterator[tuple[str, Any]]:
    """Yield ``(label, subschema)`` for every subschema directly under ``node``, except ``properties``.

    Shared by the sanitizer below and ``scripts/check_schema_safety.py`` so the two can't drift
    apart on which keywords they descend into.
    """
    if not isinstance(node, dict):
        return
    for key in _SINGLE_KEYS:
        sub = node.get(key)
        if isinstance(sub, dict):
            yield key, sub
        elif isinstance(sub, list):  # draft-07 tuple form of ``items``
            for i, item in enumerate(sub):
                yield f"{key}[{i}]", item
    for key in _LIST_KEYS:
        subs = node.get(key)
        if isinstance(subs, list):
            for i, sub in enumerate(subs):
                yield f"{key}[{i}]", sub
    for key in _MAP_KEYS:
        subs = node.get(key)
        if isinstance(subs, dict):
            for name, sub in subs.items():
                yield f"{key}.{name}", sub


def _walk_schema(node: Any) -> bool:
    """Rename OData-style property keys anywhere in a JSON schema, in place. Returns True if any changed."""
    if not isinstance(node, dict):
        return False
    changed = False

    properties = node.get("properties")
    if isinstance(properties, dict):
        new_properties: dict[str, Any] = {}
        for original_key, value in properties.items():
            sanitized_key = _sanitize_key(original_key)
            new_properties[sanitized_key] = value
            changed |= sanitized_key != original_key
            changed |= _walk_schema(value)
        node["properties"] = new_properties

    # Rename directly rather than via what this walk has seen so far: a ``required`` entry can name
    # a property declared elsewhere (a base type pulled in through allOf/$ref, walked later).
    required = node.get("required")
    if isinstance(required, list):
        node["required"] = [_sanitize_key(name) if isinstance(name, str) else name for name in required]

    for _, sub in iter_subschemas(node):
        changed |= _walk_schema(sub)
    return changed


def _resolve(node: Any, root: dict[str, Any]) -> Any:
    """Follow local ``$ref`` pointers (``#/$defs/X``) until reaching a non-ref schema."""
    for _ in range(32):  # guards against ref cycles
        if not isinstance(node, dict) or not isinstance(node.get("$ref"), str):
            return node
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return node
        target: Any = root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            target = target.get(part) if isinstance(target, dict) else None
        if target is None:
            return node
        node = target
    return node


def _collect(node: Any, root: dict[str, Any], seen: set[int]) -> Iterator[dict[str, Any]]:
    """Yield ``node`` and every schema it's combined with (allOf/anyOf/oneOf), refs resolved."""
    node = _resolve(node, root)
    if not isinstance(node, dict) or id(node) in seen:
        return
    seen.add(id(node))
    yield node
    for key in _COMBINATOR_KEYS:
        subs = node.get(key)
        if isinstance(subs, list):
            for sub in subs:
                yield from _collect(sub, root, seen)


def _translate_arguments(value: Any, schema: Any, root: dict[str, Any]) -> Any:
    """Map sanitized argument names back to their OData names, guided by the original schema.

    Only keys that are *declared properties* at that point of the schema are renamed. Free-form
    data (an ``additionalProperties`` map, an untyped object) keeps its keys as sent, so a user key
    that happens to be ``filter`` or ``odata.type`` is never rewritten.
    """
    if schema is None:
        return value
    parts = list(_collect(schema, root, set()))
    if isinstance(value, dict):
        declared: dict[str, tuple[str, Any]] = {}
        extra: Any = None
        for part in parts:
            for original, sub in (part.get("properties") or {}).items():
                declared.setdefault(_sanitize_key(original), (original, sub))
            if extra is None and isinstance(part.get("additionalProperties"), dict):
                extra = part["additionalProperties"]
        out: dict[str, Any] = {}
        for name, val in value.items():
            if name in declared:
                original, sub = declared[name]
                out[original] = _translate_arguments(val, sub, root)
            else:
                out[name] = _translate_arguments(val, extra, root)
        return out
    if isinstance(value, list):
        item_schema = next((p["items"] for p in parts if isinstance(p.get("items"), dict)), None)
        return [_translate_arguments(item, item_schema, root) for item in value]
    return value


def sanitize_component(route: Any, component: Any) -> None:
    """FastMCP mcp_component_fn hook: rename OData-style properties on a generated tool."""
    schema = getattr(component, "parameters", None)
    if not schema or "properties" not in schema:
        return

    # Keep the original (OData-named) schema: argument translation walks it to know which keys are
    # declared properties and what their real names are.
    original_schema = copy.deepcopy(schema)
    if not _walk_schema(schema):
        return  # nothing to do - most non-Graph, non-OData operations won't hit this at all

    original_run = component.run

    async def run_with_odata_names(arguments: dict[str, Any], _orig=original_run, _schema=original_schema):
        translated = _translate_arguments(arguments, _schema, _schema)
        return await _orig(translated)

    # pydantic models (component's base class) reject setting a non-field attribute, so the rebind
    # uses object.__setattr__ to bypass that - standard when patching behavior onto a pydantic
    # instance post-construction, not a hack around a bug.
    object.__setattr__(component, "run", run_with_odata_names)

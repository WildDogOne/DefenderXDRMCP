"""Generate src/defender_xdr_mcp/openapi/security.generated.yaml from Microsoft's own Graph v1.0 OpenAPI spec.

Downloads the full (~40+ MB) spec published by Microsoft at
https://github.com/microsoftgraph/msgraph-metadata and slices out just the operations this
project exposes as MCP tools: Defender XDR Incidents (list / get / update) and Advanced Hunting
(runHuntingQuery). Only those operations plus the components (schemas/parameters/responses) they
actually reference are kept, so the generated spec stays small and self-contained.

It also writes src/defender_xdr_mcp/openapi/graph_index.json.gz: a compact, searchable index of
*every* GET operation in the full spec (path, summary, OData options, response type) plus a shallow
description of every schema type. That index backs the opt-in `graph` toolset
(graph_search_operations / graph_describe_operation / graph_get), which reaches all of Graph
without generating one tool per operation.

Re-run this whenever Microsoft updates the upstream spec (e.g. new incident properties, new
hunting query options) to regenerate the MCP server's tool set without hand-editing anything.

Usage:
    uv run python scripts/fetch_spec.py                       # download the upstream spec
    uv run python scripts/fetch_spec.py --spec openapi.yaml   # use an already-downloaded copy
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

import yaml

SOURCE_URL = "https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/master/openapi/v1.0/openapi.yaml"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "src" / "defender_xdr_mcp" / "openapi"
OUTPUT_PATH = OUTPUT_DIR / "security.generated.yaml"
INDEX_PATH = OUTPUT_DIR / "graph_index.json.gz"

# Trim long upstream descriptions in the index - enough for an agent to pick the right endpoint or
# property (Graph puts "Supports $filter (eq, ne, ...)" notes in property descriptions), without
# shipping every paragraph of the docs.
MAX_OPERATION_DESCRIPTION = 600
MAX_PROPERTY_DESCRIPTION = 300

# Prefer the libyaml-backed loader: it parses the 40+ MB spec in seconds instead of minutes.
YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

# Paths -> the HTTP methods we keep on each. Everything else on these paths (create/delete/
# mergeIncidents/$count/etc.) is dropped: it's outside the two capabilities the Defender XDR docs
# name (https://learn.microsoft.com/en-us/defender-xdr/api-overview) — Incidents and Advanced
# Hunting — and outside the three documented Incidents methods (List/Get/Update).
KEPT_OPERATIONS: dict[str, set[str]] = {
    "/security/incidents": {"get"},
    "/security/incidents/{incident-id}": {"get", "patch"},
    "/security/microsoft.graph.security.runHuntingQuery": {"post"},
}

REF_RE = re.compile(r"^#/components/(schemas|parameters|responses|requestBodies|headers)/(.+)$")


def download(url: str) -> str:
    print(f"Downloading {url} ...", file=sys.stderr)
    with urllib.request.urlopen(url) as resp:  # noqa: S310 - trusted, hardcoded Microsoft URL
        return resp.read().decode("utf-8")


def find_refs(node: Any) -> set[tuple[str, str]]:
    """Recursively collect (category, name) for every $ref in node."""
    found: set[tuple[str, str]] = set()
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            m = REF_RE.match(ref)
            if m:
                found.add((m.group(1), m.group(2)))
        for v in node.values():
            found |= find_refs(v)
    elif isinstance(node, list):
        for item in node:
            found |= find_refs(item)
    return found


def close_over_components(
    initial_refs: set[tuple[str, str]], all_components: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Starting from initial_refs, pull in every component transitively referenced."""
    kept: dict[str, dict[str, Any]] = {}
    pending = set(initial_refs)
    seen: set[tuple[str, str]] = set()

    while pending:
        category, name = pending.pop()
        if (category, name) in seen:
            continue
        seen.add((category, name))

        bucket = all_components.get(category, {})
        obj = bucket.get(name)
        if obj is None:
            print(f"WARNING: could not resolve #/components/{category}/{name}", file=sys.stderr)
            continue

        kept.setdefault(category, {})[name] = obj
        pending |= find_refs(obj)

    # `pending` is a set, so discovery order varies run to run; sort for a stable, diffable output.
    return {category: dict(sorted(kept[category].items())) for category in sorted(kept)}


def write_trimmed_spec(spec: dict[str, Any]) -> None:
    filtered_paths: dict[str, Any] = {}
    for path, methods in KEPT_OPERATIONS.items():
        full_path_item = spec["paths"].get(path)
        if full_path_item is None:
            raise SystemExit(f"Path {path!r} not found in upstream spec - has Microsoft renamed it?")

        path_item: dict[str, Any] = {}
        for key, value in full_path_item.items():
            if key in ("get", "post", "patch", "put", "delete", "options", "head", "trace"):
                if key in methods:
                    path_item[key] = value
            else:
                # description, parameters (path-level, e.g. incident-id), etc.
                path_item[key] = value
        filtered_paths[path] = path_item

    # error response is referenced via 4XX/5XX on every kept operation but uses a non-standard
    # key ("error") that find_refs already picks up like any other $ref target.
    initial_refs = find_refs(filtered_paths)
    kept_components = close_over_components(initial_refs, spec["components"])

    output = {
        "openapi": spec["openapi"],
        "info": {
            "title": "Microsoft Defender XDR (via Graph Security API) - Incidents & Advanced Hunting",
            "description": (
                "Trimmed slice of Microsoft's Graph v1.0 OpenAPI spec, generated by "
                "scripts/fetch_spec.py. Covers only Defender XDR Incidents (list/get/update) and "
                "Advanced Hunting (runHuntingQuery), per "
                "https://learn.microsoft.com/en-us/defender-xdr/api-overview. "
                "Do not hand-edit - re-run the generator instead."
            ),
            "version": spec["info"]["version"],
        },
        "servers": [{"url": "https://graph.microsoft.com/v1.0"}],
        "paths": filtered_paths,
        "components": kept_components,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w") as f:
        yaml.safe_dump(output, f, sort_keys=False, width=100)

    n_schemas = len(kept_components.get("schemas", {}))
    n_params = len(kept_components.get("parameters", {}))
    n_responses = len(kept_components.get("responses", {}))
    print(
        f"Wrote {OUTPUT_PATH} - {len(filtered_paths)} paths, "
        f"{n_schemas} schemas, {n_params} parameters, {n_responses} responses kept.",
        file=sys.stderr,
    )


# --- Graph index (backs the opt-in `graph` toolset) -------------------------------------------

def short_type_name(name: str) -> str:
    return name.removeprefix("microsoft.graph.")


def _trim(text: str | None, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _is_null_placeholder(schema: Any) -> bool:
    # Graph models "nullable reference" as anyOf: [{$ref: X}, {type: object, nullable: true}].
    return isinstance(schema, dict) and schema.get("nullable") and set(schema) <= {"type", "nullable"}


def type_str(schema: Any) -> str:
    """Render a property schema as a short human-readable type, e.g. 'user', 'string(date-time)[]'."""
    if not isinstance(schema, dict):
        return "any"
    ref = schema.get("$ref")
    if isinstance(ref, str):
        return short_type_name(ref.rsplit("/", 1)[-1])
    for key in ("anyOf", "oneOf"):
        if key in schema:
            alternatives = [type_str(a) for a in schema[key] if not _is_null_placeholder(a)]
            return "|".join(dict.fromkeys(alternatives)) or "any"
    if len(schema.get("allOf", [])) == 1:
        return type_str(schema["allOf"][0])
    kind = schema.get("type")
    if kind == "array":
        return type_str(schema.get("items")) + "[]"
    if kind == "string" and schema.get("format"):
        return f"string({schema['format']})"
    return kind or "object"


def build_types(schemas: dict[str, Any]) -> dict[str, Any]:
    """One shallow entry per schema: its base type plus its own properties (not inherited ones)."""
    types: dict[str, Any] = {}
    for name, schema in schemas.items():
        if not isinstance(schema, dict):
            continue
        if "enum" in schema:
            types[short_type_name(name)] = {"enum": schema["enum"]}
            continue
        entry: dict[str, Any] = {}
        props: dict[str, Any] = {}
        for part in schema.get("allOf", [schema]):
            if "$ref" in part:
                entry["base"] = type_str(part)
                continue
            for prop_name, prop in (part.get("properties") or {}).items():
                if prop_name.startswith("@odata."):
                    continue
                props[prop_name] = [
                    type_str(prop),
                    _trim(prop.get("description"), MAX_PROPERTY_DESCRIPTION),
                    1 if prop.get("x-ms-navigationProperty") else 0,
                ]
        entry["props"] = props
        types[short_type_name(name)] = entry
    return types


def _resolve(node: Any, components: dict[str, Any], category: str) -> Any:
    ref = node.get("$ref") if isinstance(node, dict) else None
    if isinstance(ref, str) and ref.startswith(f"#/components/{category}/"):
        return components.get(category, {}).get(ref.rsplit("/", 1)[-1], {})
    return node


def classify_response(op: dict[str, Any], components: dict[str, Any]) -> tuple[str | None, bool]:
    """Return (response type, is_collection) for an operation's success response."""
    responses = op.get("responses") or {}
    response = responses.get("2XX") or responses.get("200")
    if response is None:
        return None, False
    response = _resolve(response, components, "responses")
    content = response.get("content") or {}
    if "application/json" not in content:
        return (next(iter(content)) if content else None), False
    schema = content["application/json"].get("schema") or {}

    if isinstance(schema.get("$ref"), str):
        name = schema["$ref"].rsplit("/", 1)[-1]
        if not name.endswith("CollectionResponse"):
            return short_type_name(name), False
        schema = components["schemas"].get(name, {})

    # Collection responses (named or inline) look like allOf: [BasePagination..., {value: [...]}];
    # single-valued function results are inline {properties: {value: ...}}.
    for part in schema.get("allOf", [schema]):
        value = (part.get("properties") or {}).get("value")
        if isinstance(value, dict):
            if value.get("type") == "array":
                return type_str(value.get("items")), True
            return type_str(value), False
    return type_str(schema), False


def build_graph_index(spec: dict[str, Any]) -> dict[str, Any]:
    components = spec["components"]
    operations = []
    for path, item in spec["paths"].items():
        op = item.get("get")
        if op is None:
            continue
        params = [
            _resolve(p, components, "parameters")
            for p in [*item.get("parameters", []), *op.get("parameters", [])]
        ]
        # str(): PyYAML's YAML 1.1 rules turn a few unquoted parameter names (e.g. `on`) into bools.
        names = [str(p.get("name", "")) for p in params]
        odata = sorted({n[1:] for n in names if n.startswith("$")})
        other = [
            f"{n} ({p.get('in')}): {_trim(p.get('description'), 150)}"
            for n, p in zip(names, params)
            if p.get("in") in ("query", "header") and not n.startswith("$")
        ]
        response_type, is_collection = classify_response(op, components)
        entry: dict[str, Any] = {
            "path": path,
            "summary": op.get("summary") or op.get("operationId") or "",
            "description": _trim(op.get("description"), MAX_OPERATION_DESCRIPTION),
            "response": response_type,
            "collection": is_collection,
            "odata": odata,
        }
        if other:
            entry["params"] = other
        docs = (op.get("externalDocs") or {}).get("url")
        if docs:
            entry["docs"] = docs
        operations.append(entry)

    return {
        "graph_version": spec["info"]["version"],
        "base_url": "https://graph.microsoft.com/v1.0",
        "operations": operations,
        "types": build_types(components.get("schemas", {})),
    }


def write_graph_index(spec: dict[str, Any]) -> None:
    index = build_graph_index(spec)
    data = json.dumps(index, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    # mtime=0 keeps the gzip output byte-identical across runs when the spec hasn't changed.
    with INDEX_PATH.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as f:
        f.write(data)
    print(
        f"Wrote {INDEX_PATH} - {len(index['operations'])} GET operations, "
        f"{len(index['types'])} types ({INDEX_PATH.stat().st_size / 1e6:.1f} MB gzipped).",
        file=sys.stderr,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--spec", type=Path, help="use a local copy of the upstream openapi.yaml")
    args = parser.parse_args()

    raw = args.spec.read_text() if args.spec else download(SOURCE_URL)
    print("Parsing YAML...", file=sys.stderr)
    spec = yaml.load(raw, Loader=YAML_LOADER)  # noqa: S506 - CSafeLoader/SafeLoader, both safe

    write_trimmed_spec(spec)
    write_graph_index(spec)


if __name__ == "__main__":
    main()

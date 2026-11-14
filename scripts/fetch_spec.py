"""Generate the xdr OpenAPI specs from Microsoft's own Graph v1.0 and beta specs.

Downloads the full upstream v1.0 (~45 MB) and beta (~70 MB) specs published by Microsoft at
https://github.com/microsoftgraph/msgraph-metadata and slices out just the operations this project
exposes as `xdr` MCP tools, split across two generated specs by API version:

  - security_v1.generated.yaml   - Graph **v1.0**: Defender XDR Incidents (list / get / update),
    alerts (list / get), Advanced Hunting (runHuntingQuery), custom detection rules (list / get).
  - security_beta.generated.yaml - Graph **beta**: incident tasks, the advanced hunting table
    catalog (getHuntingSchema), and case management cases (read / update, comments, tasks).

The rule is: use **v1.0** wherever the operation exists there (stable, production-supported), and
**beta** only for operations that do not (incident tasks, case management). Never the legacy
`api.security.microsoft.com` XDR host, which is being retired. Each generated spec carries its own
`servers` entry, and server.py mounts one FastMCP OpenAPI provider per version so each tool hits
the right base URL. Only the kept operations plus the components (schemas/parameters/responses)
they actually reference are kept, so each spec stays small and self-contained.

It also writes src/defender_xdr_mcp/openapi/graph_index.json.gz: a compact, searchable index of
*every* GET operation in the full spec (path, summary, OData options, response type) plus a shallow
description of every schema type. That index backs the opt-in `graph` toolset
(graph_search_operations / graph_describe_operation / graph_get), which reaches all of Graph
without generating one tool per operation. graph_index_beta.json.gz is the same index built from
the Graph *beta* spec, for endpoints that only exist there (e.g. Defender XDR custom detection
rules, /security/rules/detectionRules).

Re-run this whenever Microsoft updates the upstream spec (e.g. new incident properties, new
hunting query options) to regenerate the MCP server's tool set without hand-editing anything.

Usage:
    uv run python scripts/fetch_spec.py          # download both upstream specs (~40 + ~70 MB)
    uv run python scripts/fetch_spec.py --spec v1.yaml --beta-spec beta.yaml   # use local copies
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
BETA_SOURCE_URL = "https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/master/openapi/beta/openapi.yaml"
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "src" / "defender_xdr_mcp" / "openapi"
OUTPUT_V1_PATH = OUTPUT_DIR / "security_v1.generated.yaml"
OUTPUT_BETA_PATH = OUTPUT_DIR / "security_beta.generated.yaml"
INDEX_PATH = OUTPUT_DIR / "graph_index.json.gz"
BETA_INDEX_PATH = OUTPUT_DIR / "graph_index_beta.json.gz"

# Trim long upstream descriptions in the index - enough for an agent to pick the right endpoint or
# property (Graph puts "Supports $filter (eq, ne, ...)" notes in property descriptions), without
# shipping every paragraph of the docs.
MAX_OPERATION_DESCRIPTION = 600
MAX_PROPERTY_DESCRIPTION = 300

# Prefer the libyaml-backed loader: it parses the 40+ MB spec in seconds instead of minutes.
YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

# Kept operations per API version. The rule: v1.0 wherever the operation exists there (stable,
# production-supported), beta only for what v1.0 lacks. Never the legacy api.security.microsoft.com
# host. Paths -> the HTTP methods we keep on each; everything else on those paths
# (create/delete/$count/etc.) is dropped. Every PATCH writes to the tenant, and so does every POST
# except runHuntingQuery (case comments and case tasks). Detection rules and incident tasks are
# read-only here even though Graph also offers create/update/delete for them - add the method
# below (and an `ask` permission rule) if that's ever wanted.
# getHuntingSchema() (beta only; not in the v1.0 spec) is kept, but the raw response is every
# table's full schema in one ~240 KB blob with no server-side filter - hunting_schema.py trims it
# (table overview by default, full columns via a `tables` argument) so it fits an agent context.
# `<Table> | getschema` via runHuntingQuery covers the same need per table.
# The alerts_v2 pair is the current Defender alert entity (microsoft.graph.security.alert) - the
# one incidents reference. It carries the full alert object: evidence (device/user/url/process/file
# entities with deviceDnsName, userPrincipalName, sha256, url ...), customDetails and additionalData.
# The Graph alert entity has NO devices/users properties (verified live: $select=devices errors), so
# alert attribution comes from evidence - the deprecated /security/alerts returns 404 for XDR alert
# ids and is not kept.
KEPT_OPERATIONS_V1: dict[str, set[str]] = {
    "/security/incidents": {"get"},
    "/security/incidents/{incident-id}": {"get", "patch"},
    "/security/alerts_v2": {"get"},
    "/security/alerts_v2/{alert-id}": {"get"},
    "/security/microsoft.graph.security.runHuntingQuery": {"post"},
    "/security/rules/detectionRules": {"get"},
    "/security/rules/detectionRules/{detectionRule-id}": {"get"},
}
# Query parameters the upstream spec advertises on a kept operation but the live endpoint doesn't
# honor - dropped from the generated spec so callers can't rely on a silently ignored filter.
#   - $search on alerts_v2: not among the documented query parameters of List alerts_v2
#     ($count/$filter/$skip/$top, https://learn.microsoft.com/graph/api/security-list-alerts_v2),
#     and the sibling /security/incidents collection silently ignores it (verified live; that one
#     is kept and implemented client-side by incident_search.py instead).
DROPPED_PARAMETERS_V1: dict[tuple[str, str], set[str]] = {
    ("/security/alerts_v2", "get"): {"search"},
}

KEPT_OPERATIONS_BETA: dict[str, set[str]] = {
    # Incident tasks exist only in beta.
    "/security/incidentTasks": {"get"},
    "/security/incidentTasks/{incidentTask-id}": {"get"},
    # The advanced hunting table catalog (tables + columns + types); beta-only, see the
    # trimming hook in hunting_schema.py.
    "/security/microsoft.graph.security.getHuntingSchema()": {"get"},
    # Unified case management (preview) is beta-only. Cases are read + updated (status, assignee,
    # priority, custom fields); comments are added as activities; tasks are listed, created and
    # updated. Creating/deleting cases, relation and attachment writes are left out.
    # caseTypeConfigurations is read-only upstream and gives the valid status names and custom
    # fields that writes need.
    "/security/caseManagement/cases": {"get"},
    "/security/caseManagement/cases/{case-id}": {"get", "patch"},
    "/security/caseManagement/cases/{case-id}/activities": {"get", "post"},
    "/security/caseManagement/cases/{case-id}/tasks": {"get", "post"},
    "/security/caseManagement/cases/{case-id}/tasks/{task-id}": {"patch"},
    "/security/caseManagement/cases/{case-id}/relations": {"get"},
    "/security/caseManagement/cases/{case-id}/attachments": {"get"},
    "/security/caseManagement/caseTypeConfigurations": {"get"},
}

# Real Graph endpoints that Microsoft's own OpenAPI spec omits, so there is nothing for the trimmer
# above to keep. Each entry is a hand-authored path-item fragment merged into the version's spec
# before component closure, then it flows through the normal pipeline (provider, OData sanitize,
# POST routing, auth) like any generated operation. `find_refs` still follows the `$ref`s inside, so
# referenced components (alertComment, the error response) are pulled in automatically.
#   - Incident comments: `POST /security/incidents/{id}/comments` is live and documented
#     (https://learn.microsoft.com/graph/api/security-incident-post-comments) but the spec only
#     lists the *alert*-level SetComments, not this incident-level action. Comments are append-only:
#     Graph rejects PATCH/DELETE on an individual incident comment. The `@odata.type` discriminator
#     is optional on the wire (the action accepts a bare `comment`), so it is advertised with a
#     default rather than required - sending it must use `#microsoft.graph.security.alertComment`.
SUPPLEMENTAL_OPERATIONS_V1: dict[str, dict[str, Any]] = {
    "/security/incidents/{incident-id}/comments": {
        "post": {
            "tags": ["security.incident"],
            "summary": "Create comment for incident",
            "description": (
                "Add a comment to an incident. Incident comments are append-only - an existing "
                "comment cannot be edited or deleted. The @odata.type discriminator is optional; if "
                "supplied it must be '#microsoft.graph.security.alertComment'."
            ),
            "externalDocs": {
                "description": "Find more info here",
                "url": "https://learn.microsoft.com/graph/api/security-incident-post-comments?view=graph-rest-1.0",
            },
            "operationId": "security.CreateIncidentComments",
            "requestBody": {
                "description": "New comment.",
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "title": "incidentComment",
                            "type": "object",
                            "properties": {
                                "comment": {"type": "string", "description": "The comment text."},
                                "@odata.type": {
                                    "type": "string",
                                    "default": "#microsoft.graph.security.alertComment",
                                    "description": (
                                        "Type discriminator. Optional; if set it must be "
                                        "'#microsoft.graph.security.alertComment'."
                                    ),
                                },
                            },
                        }
                    }
                },
            },
            "responses": {
                "2XX": {
                    "description": "The incident's comments after the new one was added.",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "value": {
                                        "type": "array",
                                        "items": {
                                            "$ref": "#/components/schemas/microsoft.graph.security.alertComment"
                                        },
                                    }
                                },
                            }
                        }
                    },
                },
                "4XX": {"$ref": "#/components/responses/error"},
                "5XX": {"$ref": "#/components/responses/error"},
            },
            "x-ms-docs-operation-type": "action",
        },
        "parameters": [
            {
                "name": "incident-id",
                "in": "path",
                "description": "The unique identifier of incident",
                "required": True,
                "schema": {"type": "string"},
                "x-ms-docs-key-type": "incident",
            }
        ],
    }
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


def body_subtype_refs(
    paths: dict[str, Any], all_components: dict[str, dict[str, Any]]
) -> set[tuple[str, str]]:
    """Discriminator subtypes of each kept operation's request-body schema.

    Polymorphic bodies (e.g. a case-management case or activity) only name their concrete types in
    `discriminator.mapping`, as plain strings that find_refs doesn't follow. FastMCP merges those
    subtypes' fields into the tool's input schema, but only if the subtype schemas are present, and
    that's how fields like a comment's `message` or a generic case's `assignedTo` become arguments.
    Only the body schema's own mapping is followed: following every mapping would drag in most of
    Graph (microsoft.graph.entity maps to ~2,400 types), and FastMCP doesn't flatten deeper ones.
    """
    found: set[tuple[str, str]] = set()
    for path_item in paths.values():
        for method, op in path_item.items():
            if method not in ("post", "patch", "put") or not isinstance(op, dict):
                continue
            for media in op.get("requestBody", {}).get("content", {}).values():
                m = REF_RE.match(media.get("schema", {}).get("$ref", ""))
                if not m or m.group(1) != "schemas":
                    continue
                schema = all_components["schemas"].get(m.group(2), {})
                for part in [schema, *schema.get("allOf", [])]:
                    mapping = (part.get("discriminator") or {}).get("mapping", {})
                    for target in mapping.values():
                        t = REF_RE.match(target)
                        if t:
                            found.add((t.group(1), t.group(2)))
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


def write_trimmed_spec(
    spec: dict[str, Any],
    kept_operations: dict[str, set[str]],
    out_path: Path,
    title: str,
    description: str,
    supplemental: dict[str, dict[str, Any]] | None = None,
    dropped_parameters: dict[tuple[str, str], set[str]] | None = None,
) -> None:
    filtered_paths: dict[str, Any] = {}
    for path, methods in kept_operations.items():
        full_path_item = spec["paths"].get(path)
        if full_path_item is None:
            raise SystemExit(f"Path {path!r} not found in upstream spec - has Microsoft renamed it?")

        path_item: dict[str, Any] = {}
        for key, value in full_path_item.items():
            if key in ("get", "post", "patch", "put", "delete", "options", "head", "trace"):
                if key in methods:
                    dropped = (dropped_parameters or {}).get((path, key))
                    if dropped:
                        value = {
                            **value,
                            "parameters": [
                                param
                                for param in value.get("parameters", [])
                                if param.get("$ref", "").rsplit("/", 1)[-1] not in dropped
                                and param.get("name") not in dropped
                            ],
                        }
                    path_item[key] = value
            else:
                # description, parameters (path-level, e.g. incident-id), etc.
                path_item[key] = value
        filtered_paths[path] = path_item

    # Real endpoints Microsoft's spec omits, injected as hand-authored fragments (see
    # SUPPLEMENTAL_OPERATIONS_*). Merged before component closure so their $refs resolve normally.
    for path, fragment in (supplemental or {}).items():
        filtered_paths[path] = fragment

    # error response is referenced via 4XX/5XX on every kept operation but uses a non-standard
    # key ("error") that find_refs already picks up like any other $ref target.
    initial_refs = find_refs(filtered_paths) | body_subtype_refs(filtered_paths, spec["components"])
    kept_components = close_over_components(initial_refs, spec["components"])

    output = {
        "openapi": spec["openapi"],
        "info": {"title": title, "description": description, "version": spec["info"]["version"]},
        "servers": spec["servers"],
        "paths": filtered_paths,
        "components": kept_components,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        yaml.safe_dump(output, f, sort_keys=False, width=100)

    n_schemas = len(kept_components.get("schemas", {}))
    n_params = len(kept_components.get("parameters", {}))
    n_responses = len(kept_components.get("responses", {}))
    print(
        f"Wrote {out_path} - {len(filtered_paths)} paths, "
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


def build_graph_index(spec: dict[str, Any], api_version: str) -> dict[str, Any]:
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
        "base_url": f"https://graph.microsoft.com/{api_version}",
        "operations": operations,
        "types": build_types(components.get("schemas", {})),
    }


def write_graph_index(spec: dict[str, Any], api_version: str, path: Path) -> None:
    index = build_graph_index(spec, api_version)
    data = json.dumps(index, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    # mtime=0 keeps the gzip output byte-identical across runs when the spec hasn't changed.
    with path.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as f:
        f.write(data)
    print(
        f"Wrote {path} - {len(index['operations'])} GET operations, "
        f"{len(index['types'])} types ({path.stat().st_size / 1e6:.1f} MB gzipped).",
        file=sys.stderr,
    )


def load_spec(local: Path | None, url: str) -> dict[str, Any]:
    raw = local.read_text() if local else download(url)
    print("Parsing YAML...", file=sys.stderr)
    return yaml.load(raw, Loader=YAML_LOADER)  # noqa: S506 - CSafeLoader/SafeLoader, both safe


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--spec", type=Path, help="use a local copy of the upstream v1.0 openapi.yaml")
    parser.add_argument("--beta-spec", type=Path, help="use a local copy of the upstream beta openapi.yaml")
    args = parser.parse_args()

    spec = load_spec(args.spec, SOURCE_URL)
    write_graph_index(spec, "v1.0", INDEX_PATH)
    write_trimmed_spec(
        spec,
        KEPT_OPERATIONS_V1,
        OUTPUT_V1_PATH,
        "Microsoft Defender XDR (via Graph Security API, v1.0)",
        (
            "Trimmed slice of Microsoft's Graph v1.0 OpenAPI spec, generated by scripts/fetch_spec.py. "
            "Covers Defender XDR Incidents (list/get/update), alerts (list/get), Advanced Hunting "
            "(runHuntingQuery) and custom detection rules (list/get). Do not hand-edit - re-run the "
            "generator instead."
        ),
        supplemental=SUPPLEMENTAL_OPERATIONS_V1,
        dropped_parameters=DROPPED_PARAMETERS_V1,
    )
    del spec  # the parsed beta spec is large too; don't hold both in memory

    spec = load_spec(args.beta_spec, BETA_SOURCE_URL)
    write_trimmed_spec(
        spec,
        KEPT_OPERATIONS_BETA,
        OUTPUT_BETA_PATH,
        "Microsoft Defender XDR (via Graph Security API, beta)",
        (
            "Trimmed slice of Microsoft's Graph beta OpenAPI spec, generated by scripts/fetch_spec.py. "
            "Covers Defender XDR incident tasks, the advanced hunting table catalog (getHuntingSchema) "
            "and case management (cases read/update, comments, tasks) - operations not available in "
            "v1.0. Do not hand-edit - re-run the generator instead."
        ),
    )
    write_graph_index(spec, "beta", BETA_INDEX_PATH)


if __name__ == "__main__":
    main()

"""The opt-in `graph` toolset: read-only access to *all* of Microsoft Graph v1.0 in three tools.

This is the one deliberately hand-written part of the server. Generating one MCP tool per Graph
operation doesn't scale: the full v1.0 spec has ~9,400 GET operations, and each generated tool
carries its schema into the agent's context. Instead the agent discovers what it needs on demand:

    graph_search_operations("conditional access")      -> candidate paths
    graph_describe_operation("/identity/conditionalAccess/policies")
                                                       -> OData options, response properties
    graph_get("/identity/conditionalAccess/policies", select="displayName,state")

The tools are still driven by Microsoft's own spec: search/describe read
openapi/graph_index.json.gz, which scripts/fetch_spec.py builds from the same upstream spec as the
XDR tools. Nothing here describes an endpoint by hand.

graph_get only issues GET requests and only to https://graph.microsoft.com/v1.0. What it can read is
whatever the app registration's Application permissions allow - that, not this code, is the real
access boundary (see README "App registration").
"""

from __future__ import annotations

import gzip
import json
import os
import re
from functools import cache
from importlib import resources
from typing import Annotated, Any
from urllib.parse import quote

import httpx2
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from .auth import GRAPH_BASE_URL

INDEX_RESOURCE = resources.files("defender_xdr_mcp.openapi").joinpath("graph_index.json.gz")

# Graph pages can be huge (a /users page with all properties is easily several MB). Anything over
# this many characters gets trimmed before it reaches the agent's context.
MAX_RESPONSE_CHARS = int(os.environ.get("GRAPH_MCP_MAX_RESPONSE_CHARS", "60000"))

# Characters left unescaped in OData query values (they're common in $filter/$select and legal in
# a query string); everything else, including space, & = + # and ", is percent-encoded.
QUERY_SAFE_CHARS = "$,()'*:/@"

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=True)


@cache
def _index() -> dict[str, Any]:
    # Loaded on first use rather than at startup: the XDR-only default never pays for it.
    with INDEX_RESOURCE.open("rb") as raw, gzip.open(raw) as f:
        return json.load(f)


@cache
def _path_matchers() -> list[tuple[re.Pattern[str], dict[str, Any]]]:
    """Regexes that match a concrete path (/users/abc/memberOf) to its template."""
    matchers = []
    for op in _index()["operations"]:
        parts = re.split(r"\{[^}]+\}", op["path"])
        pattern = "[^/]+".join(re.escape(part) for part in parts)
        matchers.append((re.compile(f"^{pattern}$", re.IGNORECASE), op))
    return matchers


def _normalize_path(path: str) -> str:
    path = path.strip()
    if path.lower().startswith(GRAPH_BASE_URL.lower()):
        path = path[len(GRAPH_BASE_URL) :]
    path = path.split("?", 1)[0]
    return "/" + path.strip("/")


def _find_operation(path: str) -> dict[str, Any] | None:
    path = _normalize_path(path)
    candidates = []
    for pattern, op in _path_matchers():
        if op["path"].lower() == path.lower():
            return op
        if pattern.match(path):
            candidates.append(op)
    # Prefer the most literal template: /users/delta() over /users/{user-id}.
    return min(candidates, key=lambda op: op["path"].count("{"), default=None)


def _returns(op: dict[str, Any]) -> str:
    response = op.get("response") or "no content"
    return f"collection of {response}" if op.get("collection") else response


def _flatten_type(name: str) -> tuple[dict[str, list[Any]], list[str]]:
    """All properties of a type including inherited ones, plus its inheritance chain."""
    types = _index()["types"]
    props: dict[str, list[Any]] = {}
    chain: list[str] = []
    current: str | None = name
    while current and current in types and current not in chain:
        chain.append(current)
        for prop_name, prop in types[current].get("props", {}).items():
            props.setdefault(prop_name, prop)
        current = types[current].get("base")
    return props, chain


def _describe_type(name: str) -> dict[str, Any]:
    types = _index()["types"]
    name = name.removeprefix("microsoft.graph.")
    if name not in types:
        raise ToolError(f"Unknown type {name!r}.")
    if "enum" in types[name]:
        return {"type": name, "enum": types[name]["enum"]}

    props, chain = _flatten_type(name)
    properties: dict[str, str] = {}
    navigation: dict[str, str] = {}
    enums: dict[str, list[str]] = {}
    for prop_name, (type_name, description, is_nav) in sorted(props.items()):
        if is_nav:
            navigation[prop_name] = type_name
        else:
            properties[prop_name] = f"{type_name} - {description}" if description else type_name
        for part in type_name.removesuffix("[]").split("|"):
            values = types.get(part, {}).get("enum")
            if values:
                enums[part] = [v for v in values if v != "unknownFutureValue"]

    result: dict[str, Any] = {"type": name, "inherits": chain[1:], "properties": properties}
    if navigation:
        result["navigation_properties"] = navigation
        result["navigation_hint"] = (
            "Navigation properties aren't returned inline: use expand=<name> or GET <path>/<name>."
        )
    if enums:
        result["enum_values"] = enums
    return result


def _graph_error(response: httpx2.Response) -> ToolError:
    try:
        error = response.json().get("error", {})
        detail = f"{error.get('code')}: {error.get('message')}"
    except (ValueError, AttributeError):
        detail = response.text[:500]
    message = f"Graph returned HTTP {response.status_code} - {detail}"
    if response.status_code == 403:
        message += (
            " (The app registration probably lacks the Application permission this endpoint needs;"
            " graph_describe_operation returns the docs link, which lists the required permission.)"
        )
    return ToolError(message)


def _fit(result: dict[str, Any]) -> dict[str, Any]:
    """Trim a response to MAX_RESPONSE_CHARS, preferring to drop whole items from `value`."""
    result.pop("@odata.context", None)
    if len(json.dumps(result, ensure_ascii=False)) <= MAX_RESPONSE_CHARS:
        return result

    items = result.get("value")
    if isinstance(items, list):
        # Binary-search the largest prefix of the page that fits.
        lo, hi = 0, len(items)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(json.dumps({**result, "value": items[:mid]}, ensure_ascii=False)) <= MAX_RESPONSE_CHARS:
                lo = mid
            else:
                hi = mid - 1
        return {
            **result,
            "value": items[:lo],
            "_truncated": {
                "returned_items": lo,
                "omitted_items_on_this_page": len(items) - lo,
                "hint": (
                    f"Response exceeded {MAX_RESPONSE_CHARS} characters. The omitted items are NOT"
                    " reachable via @odata.nextLink - re-run with `select` (fewer properties) or a"
                    " smaller `top` to see them."
                ),
            },
        }

    text = json.dumps(result, ensure_ascii=False)
    return {
        "_truncated_json": text[:MAX_RESPONSE_CHARS],
        "_truncated": {
            "total_chars": len(text),
            "hint": "Response exceeded the size limit; use `select` to request fewer properties.",
        },
    }


def register_graph_tools(server: FastMCP, client: httpx2.AsyncClient) -> None:
    @server.tool(annotations=READ_ONLY, output_schema=None)
    def graph_search_operations(
        query: Annotated[
            str,
            Field(description="Keywords, e.g. 'conditional access', 'role assignments', 'risky users'."),
        ],
        limit: Annotated[int, Field(ge=1, le=100)] = 20,
    ) -> dict[str, Any]:
        """Search every read (GET) operation in the Microsoft Graph v1.0 API by keyword.

        /me paths are excluded: this server authenticates app-only, so use /users/{id} instead.
        Matches against path, summary and description. Use this to find the endpoint for a task,
        then graph_describe_operation for its parameters and properties, then graph_get to call it.
        """
        terms = re.findall(r"[a-z0-9]+", query.lower())
        if not terms:
            raise ToolError("Query must contain at least one keyword.")

        want_count = "count" in terms
        scored = []
        for op in _index()["operations"]:
            path = op["path"]
            # /me needs a signed-in user, which app-only auth never has; /$count variants just
            # duplicate their list endpoint (whose `count` option does the same) unless asked for.
            if path == "/me" or path.startswith("/me/") or (path.endswith("/$count") and not want_count):
                continue
            main = f"{op['path']} {op['summary']}".lower()
            extra = f"{op['description']} {op.get('response') or ''}".lower()
            hits = [2 if t in main else 1 if t in extra else 0 for t in terms]
            if any(hits):
                scored.append((sum(1 for h in hits if h), sum(hits), op))

        # Ops matching every term first, then by score; among equals, shallow literal paths win
        # over deep navigation chains like /users/{id}/onenote/notebooks/{id}/sections/...
        scored.sort(
            key=lambda s: (-s[0], -s[1], s[2]["path"].count("{"), s[2]["path"].count("/"), len(s[2]["path"]))
        )
        return {
            "total_matches": len(scored),
            "matches": [
                {"path": op["path"], "summary": op["summary"], "returns": _returns(op)}
                for _, _, op in scored[:limit]
            ],
            "hint": "graph_describe_operation(path) shows query options and response properties.",
        }

    @server.tool(annotations=READ_ONLY, output_schema=None)
    def graph_describe_operation(
        path: Annotated[
            str | None,
            Field(
                description=(
                    "A Graph path, either a template from graph_search_operations"
                    " (/users/{user-id}/memberOf) or a concrete one (/users/jdoe@contoso.com/memberOf)."
                )
            ),
        ] = None,
        type_name: Annotated[
            str | None,
            Field(
                description=(
                    "Instead of a path: a type name from a previous result (e.g."
                    " 'conditionalAccessConditionSet') to see its properties."
                )
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Describe a Graph GET operation (supported OData options, response properties, docs link)
        or a single Graph type. Properties are shallow: nested complex types are named, not
        expanded - pass one as `type_name` to drill in."""
        if type_name:
            return _describe_type(type_name)
        if not path:
            raise ToolError("Pass either `path` or `type_name`.")

        op = _find_operation(path)
        if op is None:
            raise ToolError(
                f"No GET operation matches {path!r} in Graph v1.0. Use graph_search_operations to"
                " find the right path (the endpoint may be beta-only, or not readable via GET)."
            )

        result: dict[str, Any] = {
            "path": op["path"],
            "summary": op["summary"],
            "description": op["description"],
            "returns": _returns(op),
            "odata_query_options": op["odata"],
        }
        if op.get("params"):
            result["other_parameters"] = op["params"]
        if op.get("docs"):
            result["docs"] = op["docs"] + " (lists required permissions)"

        response_type = op.get("response")
        if response_type in _index()["types"]:
            result["response_type"] = _describe_type(response_type)

        prefix = op["path"].rstrip("/") + "/"
        children = sorted(
            o["path"]
            for o in _index()["operations"]
            if o["path"].startswith(prefix) and "/" not in o["path"][len(prefix) :].rstrip("/")
        )
        if children:
            result["sub_paths"] = children[:50]
        return result

    @server.tool(annotations=READ_ONLY, output_schema=None)
    async def graph_get(
        path: Annotated[
            str,
            Field(
                description=(
                    "Graph v1.0 path with concrete IDs, e.g. /identity/conditionalAccess/policies or"
                    " /users/{id}/memberOf. To page, pass a response's @odata.nextLink URL as-is"
                    " (then leave the other arguments empty)."
                )
            ),
        ],
        select: Annotated[str | None, Field(description="OData $select, comma-separated properties.")] = None,
        filter: Annotated[str | None, Field(description="OData $filter expression.")] = None,
        top: Annotated[int | None, Field(ge=1, description="OData $top: page size.")] = None,
        expand: Annotated[str | None, Field(description="OData $expand.")] = None,
        orderby: Annotated[str | None, Field(description="OData $orderby.")] = None,
        search: Annotated[str | None, Field(description='OData $search, e.g. "displayName:admin".')] = None,
        count: Annotated[bool | None, Field(description="OData $count: include total @odata.count.")] = None,
        advanced_query: Annotated[
            bool,
            Field(
                description=(
                    "Send 'ConsistencyLevel: eventual', needed for directory advanced queries"
                    " (some $filter/$orderby combinations). Set automatically with search/count."
                )
            ),
        ] = False,
    ) -> dict[str, Any]:
        """Read-only GET against Microsoft Graph v1.0, using the server's app-only credentials.

        Large pages are trimmed to fit the context; prefer `select` and `top` to keep responses
        small. Results carry @odata.nextLink when more pages exist.
        """
        odata = {
            "$select": select,
            "$filter": filter,
            "$top": top,
            "$expand": expand,
            "$orderby": orderby,
            "$search": search,
            "$count": None if count is None else str(count).lower(),
        }
        # Encoded by hand rather than via httpx params, which form-encode spaces as '+': Graph wants
        # %20 inside $filter/$search expressions.
        query = "&".join(
            f"{k}={quote(str(v), safe=QUERY_SAFE_CHARS)}" for k, v in odata.items() if v is not None
        )

        path = path.strip()
        if "://" in path:
            # Only absolute URLs on the v1.0 host: the client attaches a Graph bearer token to every
            # request it sends, so this check is what keeps that token from going anywhere else.
            if not path.startswith(GRAPH_BASE_URL + "/"):
                raise ToolError(f"Absolute URLs must start with {GRAPH_BASE_URL}/ (e.g. an @odata.nextLink).")
            url = path
        else:
            url = "/" + path.lstrip("/")
        if ".." in url.split("?", 1)[0].split("/"):
            raise ToolError("Path must not contain '..' segments.")
        if "?" in url and query:
            raise ToolError("Put query options either in the path/nextLink or in the arguments, not both.")

        headers = {}
        if advanced_query or search is not None or count:
            headers["ConsistencyLevel"] = "eventual"

        try:
            response = await client.get(f"{url}?{query}" if query else url, headers=headers)
        except httpx2.TimeoutException as exc:
            raise ToolError(f"Graph request timed out ({type(exc).__name__})") from exc
        except httpx2.RequestError as exc:
            raise ToolError(f"Graph request failed ({type(exc).__name__}): {exc}") from exc

        if response.status_code >= 400:
            raise _graph_error(response)

        content_type = response.headers.get("content-type", "")
        if response.status_code == 204 or not response.content:
            return {"status": response.status_code, "body": None}
        if "json" in content_type:
            body = response.json()
            return _fit(body if isinstance(body, dict) else {"value": body})
        if content_type.startswith("text/"):
            text = response.text
            return {"text": text[:MAX_RESPONSE_CHARS], "truncated": len(text) > MAX_RESPONSE_CHARS}
        return {"content_type": content_type, "bytes": len(response.content), "note": "Binary body not shown."}

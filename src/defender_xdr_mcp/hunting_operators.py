"""Turn the hunting endpoint's useless syntax error into an actionable one.

Verified live (2026-11-13, both v1.0 and beta, also via curl outside this
MCP): the Graph hunting endpoint answers *any* query containing KQL's word-form comparison
operators with ``400 BadRequest "Expected: ;. Fix syntax errors in your query."`` - the KQL parser
it runs never sees those tokens (something upstream of it strips them). ``eq``, ``ne``, ``gt``,
``ge``, ``lt``, ``le`` all fail, even against numbers; the symbolic forms ``==``, ``!=``, ``>``,
``>=``, ``<``, ``<=`` - which KQL defines as identical - pass.

This is deliberately *not* fixed by silently rewriting caller queries, and it cannot be fixed by
consulting the KQL documentation either: the docs define the word forms as exact synonyms of the
symbolic ones, so they would confidently tell a caller the failing query is valid. The quirk is
undocumented endpoint behavior, so the tool surfaces it where the caller hits it: the ``query``
description warns up front, and on a syntax error the hook appends the explanation to Graph's
opaque ``Expected: ;`` message when the rejected query contains word-form operator tokens outside
string literals and ``//`` comments. The token check is otherwise loose (it also matches
``eq``/``lt``/... used as identifiers, e.g. ``project lt``), so the hint names the operators as
the *likely* cause and keeps Graph's original error - a false positive costs one sentence, while a
silent rewrite would change the caller's query.

Related live findings, kept in the tool description:
- ``AlertDevices`` / ``AlertAccounts`` / ``AlertEvents`` are not tables in the tenant's hunting
  catalog (``GET /beta/security/getHuntingSchema``): the alert tables are ``AlertInfo`` and
  ``AlertEvidence`` (plus ``DeviceAlertEvents``, listed but not queryable in this tenant).
  ``AlertEvidence`` is the alert join table: AlertId, EntityType, DeviceName, AccountUpn, SHA256,
  RemoteUrl, FileName, ... - that is the alert -> device/user/indicator join.
"""

from __future__ import annotations

import re
from typing import Any

import httpx2
from fastmcp.exceptions import ToolError

from ._hooks import wrap_run

# operationId of security_runHuntingQuery in security_v1.generated.yaml.
_RUN_HUNTING = "security.runHuntingQuery"

# A word-form operator token: not part of a longer identifier and not member access (`.eq`).
# Loose on purpose - see module docstring.
_WORD_OPERATOR_RE = re.compile(r"(?<![\w.])\b(eq|ne|gt|ge|lt|le)\b(?![\w])", re.IGNORECASE)

# What must not count as an operator: // comments, ``` multi-line strings, verbatim strings
# (@'..'/@"..", quote doubled to escape) and regular strings (backslash escapes).
_NON_CODE_RE = re.compile(
    r"//[^\n]*"
    r"|```.*?(?:```|\Z)"
    r"|@'(?:[^']|'')*(?:'|$)"
    r'|@"(?:[^"]|"")*(?:"|$)'
    r"|'(?:[^'\\\n]|\\.)*(?:'|$)"
    r'|"(?:[^"\\\n]|\\.)*(?:"|$)',
    re.DOTALL | re.MULTILINE,
)


def _has_word_operator(query: str) -> bool:
    """True if a word-form operator token appears outside string literals and comments."""
    return bool(_WORD_OPERATOR_RE.search(_NON_CODE_RE.sub(" ", query)))


def apply_hunting_operators(route: Any, component: Any) -> None:
    """FastMCP mcp_component_fn hook: operator guidance for security_runHuntingQuery."""
    if getattr(route, "operation_id", None) != _RUN_HUNTING:
        return

    props = component.parameters.get("properties") or {}
    if "query" in props:
        props["query"]["description"] = (
            "KQL query. NOTE: Graph's hunting endpoint rejects the word-form comparison "
            "operators (eq/ne/gt/ge/lt/le, even against numbers) with 'Expected: ;', despite KQL "
            "documenting them as exact synonyms - write comparisons as "
            "==/!=/>/>=/</<= instead. Alert attribution tables in the tenant catalog: AlertInfo + "
            "AlertEvidence (AlertId, EntityType, DeviceName, AccountUpn, SHA256, RemoteUrl, ...); "
            "AlertDevices/AlertAccounts/AlertEvents do not exist. Table/column discovery: "
            "security_getHuntingSchema, or `<Table> | getschema`."
        )

    async def run_with_operator_hint(arguments: dict[str, Any], _orig):
        try:
            return await _orig(arguments)
        except httpx2.HTTPStatusError as exc:
            response = exc.response
            query = arguments.get("query")
            if (
                response is not None
                and response.status_code == 400
                and "Expected: ;" in response.text
                and isinstance(query, str)
                and _has_word_operator(query)
            ):
                raise ToolError(
                    "Graph rejected the query with a syntax error. Likely cause: the query "
                    "contains what look like word-form comparison operators (eq/ne/gt/ge/lt/le), "
                    "which the hunting endpoint rejects with 'Expected: ;' even though KQL "
                    "documents them as synonyms. Write them as ==/!=/>/>=/</<= and retry; if the "
                    "error persists, it is an unrelated syntax error. "
                    f"Graph's original error: {response.text[:300]}"
                ) from exc
            raise

    wrap_run(component, run_with_operator_hint)

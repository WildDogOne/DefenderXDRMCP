"""Dev helper: verify every generated tool's schema only uses MCP-safe property names.

Checks every property name at every depth (top-level body/query args, plus every nested schema:
items, combinators, $defs, ... - the same keyword set schema_sanitize walks, via its
`iter_subschemas`, so the two can't drift apart). A nested `@odata.type` -
which Graph marks required on polymorphic types like an incident's comments - is just as invalid
to the MCP/Anthropic key regex as a top-level one, so a top-level-only check would miss it.
"""
import asyncio
import re

from defender_xdr_mcp.schema_sanitize import iter_subschemas
from defender_xdr_mcp.server import TOOLSETS, build_server

SAFE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


def _bad_keys(node, path="root", found=None):
    """Collect every property name that violates the MCP key regex, at any schema depth."""
    if found is None:
        found = []
    if not isinstance(node, dict):
        return found
    properties = node.get("properties")
    if isinstance(properties, dict):
        for key, subschema in properties.items():
            if not SAFE.match(key):
                found.append(f"{path}.{key}")
            _bad_keys(subschema, f"{path}.{key}", found)
    for name in node.get("required") or []:
        if isinstance(name, str) and not SAFE.match(name):
            found.append(f"{path}.required[{name}]")
    for label, subschema in iter_subschemas(node):
        _bad_keys(subschema, f"{path}.{label}", found)
    return found


async def main() -> None:
    server = build_server(TOOLSETS)
    tools = await server.list_tools()
    all_ok = True
    for tool in tools:
        bad = _bad_keys(tool.parameters or {}, tool.name)
        top_props = (tool.parameters or {}).get("properties", {})
        status = "OK" if not bad else f"BAD: {sorted(set(bad))}"
        if bad:
            all_ok = False
        print(f"{tool.name}: {len(top_props)} top-level props - {status}")
    print()
    print("ALL SAFE" if all_ok else "SOME TOOLS STILL HAVE INVALID PROPERTY NAMES")


if __name__ == "__main__":
    asyncio.run(main())

"""Dev helper: verify every generated tool's schema only uses MCP-safe property names."""
import asyncio
import re

from defender_xdr_mcp.server import build_server

SAFE = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


async def main() -> None:
    server = build_server()
    tools = await server.list_tools()
    all_ok = True
    for tool in tools:
        props = (tool.parameters or {}).get("properties", {})
        bad = [k for k in props if not SAFE.match(k)]
        status = "OK" if not bad else f"BAD: {bad}"
        if bad:
            all_ok = False
        print(f"{tool.name}: {len(props)} props - {status}")
    print()
    print("ALL SAFE" if all_ok else "SOME TOOLS STILL HAVE INVALID PROPERTY NAMES")


if __name__ == "__main__":
    asyncio.run(main())

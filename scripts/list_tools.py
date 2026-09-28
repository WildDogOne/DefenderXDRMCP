"""Dev helper: build the server and print the tools it exposes, without calling Graph.

Usage:
    AZURE_TENANT_ID=common AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000 \
    AZURE_CLIENT_SECRET=dummy uv run python scripts/list_tools.py
"""

import asyncio

from defender_xdr_mcp.server import build_server


async def main() -> None:
    server = build_server()
    tools = await server.list_tools()
    for tool in tools:
        print(f"--- {tool.name} ---")
        print((tool.description or "")[:150])
        print()


if __name__ == "__main__":
    asyncio.run(main())

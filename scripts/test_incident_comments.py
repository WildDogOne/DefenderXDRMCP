"""Integration test for security_CreateIncidentComments (add a comment to an incident).

Incident comments are append-only: Graph's `POST /security/incidents/{id}/comments` is the only
supported write (PATCH/DELETE on an individual comment is rejected), and a comment placed in the
UpdateIncidents PATCH body is silently dropped rather than stored. This endpoint is also missing
from Microsoft's OpenAPI spec, so the generator injects it as a supplemental operation - this test
guards both that injection and the request-body serialization.

Part 1 (always runs, no tenant, no network): builds the tool over an httpx MockTransport and checks
the outgoing body - a bare `comment` sends just that, and an `odata.type` argument is turned back
into the literal `@odata.type` Graph expects.

Part 2 (only when live creds + an incident id are supplied): posts a real comment and reads the
incident back to confirm the comment actually persisted (the point of using the action rather than
the PATCH body).

Usage:
    # deterministic part only (dummy creds, no network):
    AZURE_TENANT_ID=common AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000 \
    AZURE_CLIENT_SECRET=dummy uv run python scripts/test_incident_comments.py

    # plus the live happy-path add:
    AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=... \
    DEFENDER_TEST_INCIDENT_ID=177173 uv run python scripts/test_incident_comments.py
"""

import asyncio
import json
import os
import sys

import httpx2

import defender_xdr_mcp.server as srv

_REAL_BUILD_HTTP_CLIENT = srv.build_http_client


async def _mock_part() -> None:
    captured: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        captured.append(request)
        return httpx2.Response(200, json={"value": []}, request=request)

    srv.build_http_client = lambda base_url, **kwargs: httpx2.AsyncClient(
        base_url=base_url, transport=httpx2.MockTransport(handler)
    )

    server = srv.build_server(("xdr",))
    tool = next(t for t in await server.list_tools() if t.name == "security_CreateIncidentComments")

    # Bare comment (the discriminator is optional on the wire).
    await tool.run({"incident-id": "177173", "comment": "integration test"})
    req = captured[-1]
    assert req.method == "POST", req.method
    assert req.url.path.endswith("/security/incidents/177173/comments"), str(req.url)
    assert json.loads(req.content) == {"comment": "integration test"}, req.content

    # Explicit discriminator is translated back to the literal @odata.type Graph needs.
    await tool.run(
        {"incident-id": "177173", "odata.type": "#microsoft.graph.security.alertComment", "comment": "typed"}
    )
    assert json.loads(captured[-1].content) == {
        "@odata.type": "#microsoft.graph.security.alertComment",
        "comment": "typed",
    }, captured[-1].content

    print("part 1 (mock transport): body serialization OK")
    print(f"  {captured[-1].method} {captured[-1].url}")
    print(f"  {captured[-1].content.decode()}")


async def _live_part(incident_id: str) -> None:
    srv.build_http_client = _REAL_BUILD_HTTP_CLIENT  # undo the mock-transport patch from part 1
    server = srv.build_server(("xdr",))
    tool = next(t for t in await server.list_tools() if t.name == "security_CreateIncidentComments")

    marker = f"MCP integration comment {os.getpid()}"
    await tool.run({"incident-id": incident_id, "comment": marker})

    # Confirm it actually persisted - the whole reason to use the action over the PATCH body.
    client = _REAL_BUILD_HTTP_CLIENT("https://graph.microsoft.com/v1.0")
    resp = await client.get(f"https://graph.microsoft.com/v1.0/security/incidents/{incident_id}?$select=id,comments")
    comments = resp.json().get("comments") or []
    assert any(c.get("comment") == marker for c in comments), f"comment did not persist: {comments}"
    print(f"part 2 (live, incident {incident_id}): comment added and read back ({len(comments)} total)")


async def main() -> None:
    await _mock_part()
    incident_id = os.environ.get("DEFENDER_TEST_INCIDENT_ID")
    if incident_id:
        await _live_part(incident_id)
    else:
        print("part 2 (live): skipped - set DEFENDER_TEST_INCIDENT_ID + real AZURE_* creds to run it")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except AssertionError as exc:
        print(f"FAILED: {exc}")
        sys.exit(1)
    print("\nPASS")

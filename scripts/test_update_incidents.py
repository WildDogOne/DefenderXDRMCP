"""Integration test for security_UpdateIncidents request-body serialization.

Regression test for the bug where every incident update failed with
`400 InvalidRequestBody`: FastMCP flattened the beta incident body schema, which marks
`@odata.type` as a *required* discriminator, so the tool always sent
`{"@odata.type": "#microsoft.graph.security.incident", ...}` in the PATCH body - and Graph's
`PATCH /security/incidents/{id}` rejects a body carrying the resource's own discriminator. The
`patch_body` hook now drops it, along with `comments` (Graph accepts comments in this PATCH but
never stores them; `security_CreateIncidentComments` is the real path, see test_incident_comments.py).

Part 1 (always runs, no tenant, no network): builds the tool over an httpx MockTransport and
asserts the outgoing body is exactly the shape Graph documents - no top-level `@odata.type`, no
`comments`, and the path id never leaking into the body.

Part 2 (only when live creds + an incident id are supplied): performs a real happy-path update -
classification + determination, incident left open (status is not touched) - and
asserts Graph accepts it.

Usage:
    # deterministic part only (dummy creds, no network):
    AZURE_TENANT_ID=common AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000 \
    AZURE_CLIENT_SECRET=dummy uv run python scripts/test_update_incidents.py

    # plus the live happy-path update (real AZURE_* creds exported in the environment):
    DEFENDER_TEST_INCIDENT_ID=<a-test-incident-id> uv run python scripts/test_update_incidents.py
"""

import asyncio
import json
import os
import sys

import httpx2

import defender_xdr_mcp.server as srv

_REAL_BUILD_HTTP_CLIENT = srv.build_http_client

# The exact body Graph's docs show for an update: only the properties to change, no discriminator.
EXPECTED_BODY = {
    "classification": "falsePositive",
    "determination": "securityTesting",
}


async def _mock_part() -> None:
    captured: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        captured.append(request)
        return httpx2.Response(200, json={"id": "9182736"}, request=request)

    srv.build_http_client = lambda base_url, **kwargs: httpx2.AsyncClient(
        base_url=base_url, transport=httpx2.MockTransport(handler)
    )

    server = srv.build_server(("xdr",))
    tools = await server.list_tools()
    tool = next(t for t in tools if t.name == "security_UpdateIncidents")

    # The advertised schema must not force a top-level discriminator onto the model.
    props = tool.parameters["properties"]
    assert "@odata.type" not in props and "odata.type" not in props, "top-level discriminator still advertised"
    assert "@odata.type" not in tool.parameters.get("required", []) and "odata.type" not in tool.parameters.get("required", []), (
        "top-level discriminator still required"
    )
    assert "comments" not in props, "comments still advertised (Graph ignores them on PATCH)"

    # Even if a client sends the dropped fields anyway (stale schema), they must not reach Graph.
    await tool.run(
        {
            "incident-id": "9182736",
            "classification": EXPECTED_BODY["classification"],
            "determination": EXPECTED_BODY["determination"],
            "odata.type": "#microsoft.graph.security.incident",
            "comments": [{"odata.type": "#microsoft.graph.security.alertComment", "comment": "ignored"}],
        }
    )

    request = captured[0]
    assert request.method == "PATCH", request.method
    assert request.url.path.endswith("/security/incidents/9182736"), str(request.url)
    sent = json.loads(request.content)
    assert sent == EXPECTED_BODY, f"body mismatch:\n  sent  ={sent}\n  expect={EXPECTED_BODY}"
    assert "@odata.type" not in sent, "top-level discriminator leaked into the body"
    assert "incident-id" not in sent and "id" not in sent, f"path/read-only id leaked into body: {sent}"
    print("part 1 (mock transport): body serialization OK")
    print(f"  PATCH {request.url}")
    print(f"  {request.content.decode()}")


async def _live_part(incident_id: str) -> None:
    srv.build_http_client = _REAL_BUILD_HTTP_CLIENT  # undo the mock-transport patch from part 1
    server = srv.build_server(("xdr",))
    tools = await server.list_tools()
    tool = next(t for t in tools if t.name == "security_UpdateIncidents")
    result = await tool.run(
        {
            "incident-id": incident_id,
            "classification": "falsePositive",
            "determination": "securityTesting",
        }
    )
    content = result.structured_content
    assert content.get("id") == incident_id, content
    assert content.get("classification") == "falsePositive", content
    assert content.get("determination") == "securityTesting", content
    assert content.get("status") != "resolved", f"incident must be left open, got status={content.get('status')}"
    print(f"part 2 (live, incident {incident_id}): update accepted (200), left open as {content.get('status')}")


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

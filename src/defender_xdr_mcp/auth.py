"""Entra ID (Azure AD) app-only auth for calling Microsoft Graph as this MCP server.

Uses the client-credentials flow (no signed-in user) via MSAL, which is synchronous under the
hood. Token acquisition is offloaded to a thread so it never blocks the event loop that FastMCP's
async HTTP transport runs on. MSAL caches the token internally and only makes a network call again
once it's near expiry, so in steady state this thread hop is rare, not per-request.
"""

from __future__ import annotations

import asyncio
import os

import httpx2
import msal

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


class ClientCredentialsAuth(httpx2.Auth):
    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
        )

    def _acquire_token(self) -> str:
        result = self._app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
        if "access_token" not in result:
            raise RuntimeError(
                "Failed to acquire a Graph token: "
                f"{result.get('error')}: {result.get('error_description')}"
            )
        return result["access_token"]

    def sync_auth_flow(self, request: httpx2.Request):
        request.headers["Authorization"] = f"Bearer {self._acquire_token()}"
        yield request

    async def async_auth_flow(self, request: httpx2.Request):
        token = await asyncio.to_thread(self._acquire_token)
        request.headers["Authorization"] = f"Bearer {token}"
        yield request


def build_http_client() -> httpx2.AsyncClient:
    """Build the authenticated httpx client FastMCP will use to actually call Graph."""
    try:
        tenant_id = os.environ["AZURE_TENANT_ID"]
        client_id = os.environ["AZURE_CLIENT_ID"]
        client_secret = os.environ["AZURE_CLIENT_SECRET"]
    except KeyError as exc:
        raise RuntimeError(
            f"Missing required environment variable {exc}. "
            "Copy .env.example to .env and fill in your Entra app registration's "
            "tenant ID, client ID, and client secret."
        ) from exc

    return httpx2.AsyncClient(
        base_url=GRAPH_BASE_URL,
        auth=ClientCredentialsAuth(tenant_id, client_id, client_secret),
        # Advanced hunting queries can legitimately run for a while; Graph itself times a single
        # request out at 3 minutes (see api-advanced-hunting docs), so stay above that.
        timeout=200.0,
    )

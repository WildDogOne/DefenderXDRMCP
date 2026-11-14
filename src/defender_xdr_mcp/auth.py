"""Entra ID (Azure AD) app-only auth for calling Microsoft Graph as this MCP server.

Uses the client-credentials flow (no signed-in user) via MSAL, which is synchronous under the
hood. Token acquisition is offloaded to a thread so it never blocks the event loop that FastMCP's
async HTTP transport runs on. MSAL caches the token internally and only makes a network call again
once it's near expiry, so in steady state this thread hop is rare, not per-request.
"""

from __future__ import annotations

import asyncio
import datetime
import email.utils
import math
import os

import httpx2
import msal

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_ROOT = "https://graph.microsoft.com"


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


def build_auth() -> ClientCredentialsAuth:
    """Build the MSAL-backed auth once, for reuse across every httpx client.

    Each ClientCredentialsAuth owns its own ConfidentialClientApplication and therefore its own
    MSAL token cache. server.py needs one httpx client per Graph API version (each generated spec
    has its own `servers` entry) plus one for the graph toolset, so sharing a single auth keeps
    that to one token acquisition instead of one per client. The Auth object is stateless apart
    from the cache, so handing it to several AsyncClients is safe.
    """
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

    return ClientCredentialsAuth(tenant_id, client_id, client_secret)


# Graph throttles the Defender endpoints at ~40 requests/minute (verified live) and answers 429
# with Retry-After. 429 means the request was not processed, so it is retried for every method.
# 5xx is retried only for GET: a 5xx on a write may already have been applied, and retrying could
# e.g. post a comment twice.
_RETRY_ANY_METHOD = {429}
_RETRY_GET_ONLY = {500, 502, 503, 504}
_MAX_RETRIES = 5
_DEFAULT_RETRY_AFTER = 5.0
_MAX_RETRY_AFTER = 60.0


def _retry_after_seconds(value: str | None) -> float:
    """Parse Retry-After, which is either delta-seconds or an HTTP-date (RFC 9110 10.2.3)."""
    if not value:
        return _DEFAULT_RETRY_AFTER
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return _DEFAULT_RETRY_AFTER
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        seconds = (when - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    if not math.isfinite(seconds):  # "nan"/"inf" parse as floats and would survive the clamp
        return _DEFAULT_RETRY_AFTER
    return min(max(seconds, 0.0), _MAX_RETRY_AFTER)


class RetryingAsyncClient(httpx2.AsyncClient):
    """AsyncClient that retries throttled (429) and, for GETs, transient 5xx responses.

    Honors Retry-After (each wait capped at _MAX_RETRY_AFTER seconds, at most _MAX_RETRIES retries).
    The retry sits in ``send()`` (public API; FastMCP's generated tools call it directly and
    ``get()``/``request()`` go through it) rather than in a custom transport: passing
    ``transport=`` would make httpx2 skip HTTP(S)_PROXY/ALL_PROXY/NO_PROXY, so keeping httpx2's
    own transports keeps proxy support without rebuilding it from httpx2 internals. Every tool
    sharing the client (generated xdr tools, the ListIncidents search scan, the graph toolset)
    gets the same backoff.
    """

    async def send(self, request: httpx2.Request, **kwargs) -> httpx2.Response:
        for attempt in range(_MAX_RETRIES + 1):
            response = await super().send(request, **kwargs)
            status = response.status_code
            retryable = status in _RETRY_ANY_METHOD or (
                status in _RETRY_GET_ONLY and request.method == "GET"
            )
            if not retryable or attempt == _MAX_RETRIES:
                return response
            delay = _retry_after_seconds(response.headers.get("retry-after"))
            await response.aclose()
            await asyncio.sleep(delay)
        raise AssertionError("unreachable")


def build_http_client(base_url: str, auth: ClientCredentialsAuth | None = None) -> httpx2.AsyncClient:
    """Build the authenticated httpx client FastMCP will use to actually call Graph.

    base_url is the generated spec's server URL - https://graph.microsoft.com/v1.0 for the v1.0
    xdr tools and https://graph.microsoft.com/beta for the beta ones; the graph toolset always
    sends absolute URLs, so it doesn't depend on it. Pass the shared auth from build_auth() so
    the clients don't each acquire their own token.
    """
    # Don't pass transport=: httpx2 would then ignore the proxy environment variables.
    return RetryingAsyncClient(
        base_url=base_url,
        auth=auth if auth is not None else build_auth(),
        # Advanced hunting queries can legitimately run for a while; Graph itself times a single
        # request out at 3 minutes (see api-advanced-hunting docs), so stay above that.
        timeout=200.0,
    )

"""Shared plumbing for the ``mcp_component_fn`` hooks that change a generated tool's behavior."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp.tools.base import ToolResult

Run = Callable[[dict[str, Any]], Awaitable[Any]]


def wrap_run(component: Any, fn: Callable[[dict[str, Any], Run], Awaitable[Any]]) -> None:
    """Replace ``component.run`` with ``fn(arguments, original_run)``.

    Hooks stack: each wraps whatever ``run`` the previous hook left behind. pydantic models (the
    component's base class) reject setting a non-field attribute, so the rebind goes through
    ``object.__setattr__`` - standard when patching behavior onto a pydantic instance after
    construction, not a hack around a bug.
    """
    original = component.run

    async def run(arguments: dict[str, Any]) -> Any:
        return await fn(arguments, original)

    object.__setattr__(component, "run", run)


def structured(result: Any) -> Any:
    """The JSON payload of a tool result (FastMCP returns a ToolResult; tests may pass raw data)."""
    return result.structured_content if isinstance(result, ToolResult) else result

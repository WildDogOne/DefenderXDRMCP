"""Make ``security_ListIncidents`` honour ``search`` client-side - Graph silently ignores ``$search``.

The Graph spec advertises ``$search`` on ``GET /security/incidents``, and FastMCP dutifully puts it
on the wire, but the endpoint ignores it: live verification (2026-11-13) showed
the same ``@odata.count`` (the whole open-incident backlog) for ``$search=MalwareBazaar``, ``$search=zzznopezzz``
and no ``$search`` at all - with *and* without the ``ConsistencyLevel: eventual`` header that Graph's
general ``$search`` documentation asks for. A silently-ignored filter is worse than an error, so the
tool does the filtering itself instead of returning wrong counts:

- ``$search`` is dropped from the outgoing request (Graph's search parser also *errors* on some
  otherwise-valid strings, e.g. single quotes, which would look like a caller mistake).
- The backlog is auto-paginated (Graph caps incident ``$top`` at 50 and never emits
  ``@odata.nextLink`` on this collection, so ``$count`` + ``$skip`` drive the paging) with the
  caller's ``$filter`` still applied server-side, and each incident's ``displayName`` is matched
  case-insensitively against the search phrase(s).
- ``|`` inside ``search`` separates alternative phrases ("buckets") and the response carries a
  per-bucket count, so the whole Informational backlog can be bucketed in one tool call:
  ``search: "email messages removed | MalwareBazaar | custom network indicator"``. Buckets may
  overlap: an incident matching several phrases counts in each bucket, but once in the matched
  total, so the bucket counts can sum to more than ``@odata.count``. Repeated phrases are merged.
- Paging runs oldest-first (``createdDateTime asc``) so incidents created during a slow, throttled
  scan land after the cursor instead of shifting already-read rows onto the next page; Graph
  rejects ``id`` in ``$orderby``, so there is no unique tiebreaker and matches are additionally
  de-duplicated by ``id``. An incident whose filtered property (e.g. ``status``) changes mid-scan
  leaves the filtered collection and shifts later rows backward across the ``$skip`` cursor; the
  scan sees that as a drop in ``@odata.count`` between pages and rewinds the cursor by the drop
  (re-read rows are discarded by the ``id`` de-duplication), so shifted rows are not skipped.
  (Only a drop and a rise that cancel out exactly between two pages go unnoticed.)
- The scan ends only when the collection is exhausted: ``skip >= @odata.count``, an empty page,
  or - only when Graph sent no ``@odata.count`` - a short page. A short page alone is not trusted
  while the count says more rows remain.
- ``maxResults`` is a hard bound on how many incidents are *scanned* (default 5000). If pagination is not
  exhausted when the budget runs out the tool **raises** rather than returning a partial count -
  a wrong count is what made the backlog untriageable in the first place. Raise ``maxResults`` to
  scan deeper.
- In search mode ``top``/``skip`` apply to the *matched* incidents (how many to return / how many
  to page past), not to Graph's paging, and the response carries the true matched total.
  ``top: 0`` returns the counts only (no incident rows); an omitted ``top`` returns 10 matches.
  Without a caller ``select`` the returned rows carry only ``id``, ``displayName``, ``severity``,
  ``status`` and ``createdDateTime`` (the scan reads every incident, so it keeps pages small).
- A caller ``orderby`` never changes the scan order (a newest-first scan would let incidents
  created mid-scan push unread rows past the ``$skip`` cursor, silently undercounting). It is
  applied to the matches client-side after the scan instead.

Without ``search`` the tool behaves exactly as before (Graph handles filter/count/select itself).
"""

from __future__ import annotations

from typing import Any

from fastmcp.tools.base import ToolResult

from ._hooks import structured, wrap_run

# operationId of security_ListIncidents in security_v1.generated.yaml.
_LIST_INCIDENTS = "security.ListIncidents"

# Graph rejects $top > 50 on /security/incidents ("The limit of '50' for Top query has been exceeded").
_PAGE_SIZE = 50
_DEFAULT_MAX_RESULTS = 5000
# Incident property matched against the search phrase. (The v1.0 incident type has no title
# property - $select=title errors with 400 - so displayName is the only name field.)
_MATCH_FIELD = "displayName"
# id is always selected: matches are de-duplicated by it (see module docstring).
_REQUIRED_SELECT = ("id", _MATCH_FIELD)
_SCAN_SELECT = ["id", "displayName", "severity", "status", "createdDateTime"]
# Oldest-first, so incidents created mid-scan append after the $skip cursor (see module docstring).
_SCAN_ORDERBY = ["createdDateTime asc"]
_DEFAULT_RETURNED = 10
# Graph orders enum properties by their declared position, not alphabetically.
_ENUM_RANK = {
    "severity": ["unknown", "informational", "low", "medium", "high", "unknownFutureValue"],
}


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    return text


def _parse_buckets(search: str) -> list[str]:
    """Split the search string into alternative phrases on ``|``.

    One layer of quotes is stripped from the whole string and from each phrase; quotes don't
    protect a ``|`` (it always separates). Phrases are de-duplicated case-insensitively (first
    spelling wins): the counts are keyed by phrase, so a repeated phrase would otherwise collapse
    into one key and misalign every bucket after it.
    """
    buckets: list[str] = []
    seen: set[str] = set()
    for part in _unquote(search).split("|"):
        phrase = _unquote(part)
        if phrase and phrase.lower() not in seen:
            seen.add(phrase.lower())
            buckets.append(phrase)
    return buckets


def _haystack(incident: dict[str, Any]) -> str:
    return str(incident.get(_MATCH_FIELD) or "").lower()


def _parse_orderby(orderby: Any) -> list[tuple[str, bool]]:
    """Turn ``["severity desc", "createdDateTime"]`` (or a comma string) into (field, descending)."""
    items = orderby.split(",") if isinstance(orderby, str) else list(orderby or [])
    keys = []
    for item in items:
        parts = str(item).split()
        if not parts:
            continue
        if len(parts) > 2 or (len(parts) == 2 and parts[1].lower() not in ("asc", "desc")):
            raise ValueError(f"orderby: cannot parse {item!r}; expected '<property> [asc|desc]'")
        keys.append((parts[0], len(parts) == 2 and parts[1].lower() == "desc"))
    return keys


def _sort_matches(matches: list[dict[str, Any]], keys: list[tuple[str, bool]]) -> None:
    """Stable multi-key sort of the matches, in place; missing values sort last either way."""
    for field, descending in reversed(keys):
        rank = _ENUM_RANK.get(field)

        def value(incident: dict[str, Any], _field=field, _rank=rank) -> Any:
            v = incident.get(_field)
            if _rank is not None:
                # Enum property: order by declared position; a member the rank list predates
                # sorts after all known ones (Graph's unknownFutureValue semantics) instead of
                # falling through to str and crashing the int/str compare.
                return _rank.index(v) if v in _rank else len(_rank)
            return v if isinstance(v, (int, float)) else str(v)

        present = [m for m in matches if m.get(field) is not None]
        missing = [m for m in matches if m.get(field) is None]
        present.sort(key=value, reverse=descending)
        matches[:] = present + missing


def apply_incident_search(route: Any, component: Any) -> None:
    """FastMCP mcp_component_fn hook: client-side search for security_ListIncidents."""
    if getattr(route, "operation_id", None) != _LIST_INCIDENTS:
        return

    # Advertise the changed semantics plus the new budget knob.
    props = component.parameters.get("properties") or {}
    if "search" in props:
        props["search"]["description"] = (
            "Case-insensitive phrase filter applied CLIENT-SIDE over incident displayName "
            "(Graph silently ignores $search on this collection). Separate alternative phrases "
            "with '|' to get per-bucket counts in one call, e.g. "
            "'MalwareBazaar | custom network indicator'. Buckets may overlap: an incident matching "
            "several phrases counts in each searchCounts bucket but once in @odata.count. In search mode top/skip page through the "
            "MATCHES, and rows carry only id, displayName, severity, status and createdDateTime "
            "unless you pass select."
        )
    props["maxResults"] = {
        "type": "integer",
        "minimum": 1,
        "description": (
            f"With search set: hard cap on incidents scanned (server-side-paginated) before giving up "
            f"(default {_DEFAULT_MAX_RESULTS}). The tool fails loudly instead of returning a "
            "partial count when the budget is exhausted; raise it to scan the whole backlog."
        ),
    }
    component.description = (
        (component.description or "")
        + " NOTE: search is applied client-side (Graph ignores $search here); see the search "
        "parameter for bucket syntax and maxResults for the scan budget."
    )

    async def run_with_client_search(arguments: dict[str, Any], _orig):
        search = arguments.get("search")
        if search is None or not str(search).strip():
            # No (or an empty) search: plain Graph call. Drop an empty search so no bare
            # "$search=" reaches the wire, and drop maxResults, which Graph doesn't know.
            return await _orig(
                {k: v for k, v in arguments.items() if k not in ("search", "maxResults")}
            )
        buckets = _parse_buckets(str(search))
        if not buckets:
            raise ValueError(f"search {search!r} contains no usable phrase")

        args = {k: v for k, v in arguments.items() if k not in ("search", "maxResults")}
        raw_max = arguments.get("maxResults")
        max_results = _DEFAULT_MAX_RESULTS if raw_max is None else int(raw_max)
        if max_results < 1:  # FastMCP doesn't enforce the advertised minimum
            raise ValueError(f"maxResults must be >= 1, got {max_results}")
        top = args.pop("top", None)  # matches to return in search mode; 0 = counts only
        returned = _DEFAULT_RETURNED if top is None else max(int(top), 0)
        offset = int(args.pop("skip", 0) or 0)
        if offset < 0:
            raise ValueError(f"skip must be >= 0, got {offset}")
        args.pop("count", None)  # the matched total below is authoritative
        select = args.get("select") or _SCAN_SELECT
        if isinstance(select, str):
            select = [s.strip() for s in select.split(",") if s.strip()]
        # The scan order is fixed (see module docstring); the caller's orderby sorts the matches.
        sort_keys = _parse_orderby(args.pop("orderby", None))
        for field in (*_REQUIRED_SELECT, *(f for f, _ in sort_keys)):
            if field not in select:
                select = [*select, field]
        args["select"] = select
        args["orderby"] = _SCAN_ORDERBY

        counts = {bucket: 0 for bucket in buckets}
        lowered = [bucket.lower() for bucket in buckets]
        matches: list[dict[str, Any]] = []
        seen: set[str] = set()
        scanned = 0
        skip = 0
        total: int | None = None

        async def fetch(top: int, skip_: int) -> tuple[list[dict[str, Any]], int | None]:
            args["top"], args["skip"], args["count"] = top, skip_, True
            result = await _orig(dict(args))
            data = structured(result)
            if not isinstance(data, dict):
                raise RuntimeError(
                    f"search: Graph returned a non-JSON page at skip={skip_}; cannot continue scan"
                )
            count = data.get("@odata.count")
            return data.get("value") or [], count if isinstance(count, int) else None

        while True:
            # /security/incidents never returns @odata.nextLink (verified live), so $count tells
            # us the collection size and $skip drives the paging. Throttling (429 + Retry-After)
            # is retried by the shared client (auth.RetryingAsyncClient).
            remaining = max_results - scanned
            if remaining <= 0:
                # Without @odata.count a budget that ends exactly at the end of the collection
                # looks the same as one that ends mid-way; one 1-row probe tells them apart.
                if total is None:
                    probe, _ = await fetch(1, skip)
                    if not probe:
                        break
                raise ValueError(
                    f"search: scan budget exhausted after {scanned} incidents ({max_results} "
                    f"maxResults) with more to read - counts so far are partial. "
                    f"Add a narrower filter or raise maxResults."
                )
            requested = min(_PAGE_SIZE, remaining)
            page, count = await fetch(requested, skip)
            if count is not None:
                if total is not None and count < total:
                    # Rows left the filtered collection mid-scan. If they were on pages already
                    # read, later rows shifted backward past the cursor: rewind by the drop and
                    # let the id de-duplication discard what gets re-read.
                    skip = max(skip - (total - count), 0)
                    total = count
                    continue
                total = count
            for incident in page:
                incident_id = incident.get("id")
                if incident_id is not None:
                    if incident_id in seen:  # shifted across a page boundary; count once
                        continue
                    seen.add(incident_id)
                hay = _haystack(incident)
                hit = False
                for bucket, needle in zip(counts, lowered):
                    if needle in hay:
                        counts[bucket] += 1
                        hit = True
                if hit:
                    matches.append(incident)
            scanned += len(page)
            skip += len(page)
            if not page:
                if total is not None and skip < total:
                    raise RuntimeError(
                        f"search: Graph returned an empty page at skip={skip} although "
                        f"@odata.count is {total} - counts so far ({scanned} scanned) are partial. "
                        f"Retry the call."
                    )
                break
            if total is not None:
                if skip >= total:
                    break
            elif len(page) < requested:  # no count to go by: a short page is the only end signal
                break

        _sort_matches(matches, sort_keys)
        payload = {
            "@odata.count": len(matches),
            "searchCounts": counts,
            "scannedCount": scanned,
            "searchMode": "client-side (Graph ignores $search on /security/incidents)",
            "value": matches[offset : offset + returned],
        }
        return ToolResult(structured_content=payload)

    wrap_run(component, run_with_client_search)

"""Datastar SSE response helpers.

Datastar expects server-sent events in a specific format to morph the DOM.
These helpers produce the correct event types without requiring the caller
to remember the exact SSE wire format.

References:
  https://data-star.dev/reference/action-plugins/sse
  Event type: datastar-merge-fragments
  Event type: datastar-merge-signals
"""

from collections.abc import AsyncGenerator

from fastapi import Request
from fastapi.responses import StreamingResponse
from fastapi.templating import Jinja2Templates


def _sse_event(event: str, data_lines: list[str]) -> str:
    """Format a single SSE event with multiple data lines."""
    lines = [f"event: {event}"]
    for line in data_lines:
        lines.append(f"data: {line}")
    lines.append("")  # blank line terminates the event
    lines.append("")
    return "\n".join(lines)


async def _single_event(content: str) -> AsyncGenerator[str, None]:
    yield content


def merge_fragments(html: str, selector: str | None = None) -> StreamingResponse:
    """Return an SSE response that Datastar uses to morph one or more fragments.

    html: The HTML fragment(s) to merge. Datastar identifies target elements
          by the id attributes in the HTML itself.
    selector: Optional CSS selector override (passed as `selector` data line).
    """
    data_lines = []
    if selector:
        data_lines.append(f"selector {selector}")
    # Multi-line HTML must be sent as multiple data: lines
    for line in html.splitlines():
        data_lines.append(f"fragments {line}")

    event_str = _sse_event("datastar-merge-fragments", data_lines)
    return StreamingResponse(
        _single_event(event_str),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def merge_signals(signals: dict) -> StreamingResponse:
    """Return an SSE response that patches Datastar signals on the client."""
    import json
    data_lines = [f"signals {json.dumps(signals)}"]
    event_str = _sse_event("datastar-merge-signals", data_lines)
    return StreamingResponse(
        _single_event(event_str),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def is_datastar_request(request: Request) -> bool:
    """Return True if the request was made by Datastar (expects SSE response)."""
    return request.headers.get("datastar-request") == "true"


def template_or_fragment(
    request: Request,
    templates: Jinja2Templates,
    full_template: str,
    fragment_template: str,
    context: dict,
) -> StreamingResponse | object:
    """Serve a full page or SSE fragment depending on who's asking.

    Initial page loads (browser navigation) return the full HTML document.
    Subsequent Datastar interactions return only the SSE fragment.
    """
    if is_datastar_request(request):
        html = templates.get_template(fragment_template).render(
            {"request": request, **context}
        )
        return merge_fragments(html)
    return templates.TemplateResponse(full_template, {"request": request, **context})

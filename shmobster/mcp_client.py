"""A minimal MCP client over Streamable HTTP (#299).

shmobster has no MCP client; voitta-rag's search is MCP-only, and a CRM is next.
This is the transport half: initialise a session, list a server's tools, and
call one. The per-channel policy half -- which servers and tools a channel may
use, read vs mutate, credential injection -- is `mcp.py`.

Streamable HTTP, as voitta-rag 3.4.4 speaks it: a single POST per JSON-RPC
request to the server URL, `Accept: application/json, text/event-stream`, and
the response is an SSE body whose `data:` lines carry the JSON-RPC frames. This
server assigns no `mcp-session-id`, so none is sent back; when a server does
return one on initialise, we carry it on the follow-up calls.

Deliberately not the `mcp` SDK: it pulls asyncio and a dependency tree for two
calls per turn against a known server, and the waterfall already taught us the
cost of a library whose failure modes we do not control. urllib only."""
import json
import urllib.error
import urllib.request

_PROTOCOL = "2024-11-05"
_CLIENT = {"name": "shmobster", "version": "1"}
_DEFAULT_TIMEOUT = 30.0


class MCPError(RuntimeError):
    """A server or transport failure, carrying a message safe to show a channel
    once scrubbed. Never carries the credentials from the request headers."""


def _parse_sse(body):
    """The last JSON-RPC frame in an SSE body. A single response may arrive as
    several `data:` lines; the result frame is the one we want, and it is last."""
    frame = None
    for line in body.splitlines():
        if not line.startswith("data:"):
            continue
        raw = line[5:].strip()
        if not raw or raw == "[DONE]":
            continue
        try:
            frame = json.loads(raw)
        except ValueError:
            continue
    return frame


def _post(url, headers, payload, timeout):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            session = resp.headers.get("mcp-session-id")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300] if exc.fp else ""
        raise MCPError(f"server returned HTTP {exc.code}: {detail}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise MCPError(f"cannot reach the MCP server: {exc}") from None
    frame = _parse_sse(body)
    if frame is None:
        # A JSON (not SSE) body is valid too; try it before giving up.
        try:
            frame = json.loads(body)
        except ValueError:
            raise MCPError("the MCP server returned no JSON-RPC frame") from None
    if isinstance(frame, dict) and frame.get("error"):
        err = frame["error"]
        raise MCPError(f"MCP error {err.get('code')}: {err.get('message')}")
    return (frame or {}).get("result", {}), session


def _rpc_headers(headers, session):
    out = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    out.update(headers or {})
    if session:
        out["mcp-session-id"] = session
    return out


def _initialise(url, headers, timeout):
    """Returns the session id (or None). Idempotent and cheap; voitta-rag does
    not require it before tools/list, but a spec-conformant server may."""
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": _PROTOCOL, "capabilities": {}, "clientInfo": _CLIENT},
    }
    session = _post(url, _rpc_headers(headers, None), payload, timeout)[1]
    return session


def list_tools(url, headers=None, timeout=_DEFAULT_TIMEOUT):
    """Every tool the server advertises: a list of {name, description,
    inputSchema}. The channel layer filters this to the allow-list."""
    session = _initialise(url, headers, timeout)
    payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    result = _post(url, _rpc_headers(headers, session), payload, timeout)[0]
    retval = result.get("tools", [])
    return retval


def call_tool(url, tool, arguments, headers=None, timeout=_DEFAULT_TIMEOUT):
    """Call one tool and return its result as text. MCP content is a list of
    parts; the text parts are joined, which is what a channel posts and cites."""
    session = _initialise(url, headers, timeout)
    payload = {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments or {}},
    }
    result = _post(url, _rpc_headers(headers, session), payload, timeout)[0]
    if result.get("isError"):
        parts = _text_parts(result.get("content"))
        raise MCPError(f"tool '{tool}' failed: {parts or 'no detail'}")
    retval = _text_parts(result.get("content")) or json.dumps(result.get("structuredContent") or result)
    return retval


def _text_parts(content):
    if not isinstance(content, list):
        return ""
    out = []
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text":
            out.append(part.get("text") or "")
    retval = "\n".join(p for p in out if p)
    return retval

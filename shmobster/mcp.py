"""Per-channel MCP tools (#299): turn a channel's allow-listed MCP servers into
tools the model can call, each gated exactly like a shell command.

Policy shape, under a channel's `mcp` key (default: none, like every capability):

    "mcp": {
      "voitta-rag": {
        "url": "http://localhost:58000/mcp/mcp",
        "headers": {"X-User-Name": "${RAG_USER}"},   # ${VAR}, resolved at load
        "timeout": 30,
        "tools": {
          "search": {
            "mode": "read",
            "defaults": {"include_folders": ["demo-larkspur",
                                             "demo-larkspur/email",
                                             "demo-larkspur/contracts"]}
          }
        }
      }
    }

Three rules, each matching how shell commands already work:

- An **unlisted tool is never exposed** to the model -- the allow-list is the
  tool list, not a filter over the server's full menu.
- A **`read` tool runs without a card**; a **`mutate` tool parks** for a trusted
  approval (#48), and only runs when approved -- the same queue, the same
  resume. The classification is the operator's, in the policy, not the model's.
- **Credentials are injected per server** (the `headers`, already ${VAR}-
  resolved by config) and never enter a prompt, a card, a log or the parked
  request: the queued request stores the server NAME, and headers are re-read
  from the policy at execution time.

`defaults` are arguments the policy forces on every call (voitta-rag needs
`include_folders` on every search, or it searches every indexed folder). They
override whatever the model passes and are dropped from the schema the model
sees, so the model neither has to supply them nor can change them."""
import logging
import re

from . import approvals, config, mcp_client, policy as policy_mod

_PREFIX = "mcp"
# OpenAI tool names are ^[A-Za-z0-9_-]{1,64}$. Build mcp_<server>_<tool> and keep
# a reverse map rather than parsing it back, so a server or tool name with an
# underscore cannot be split wrong.
_NAME_OK = re.compile(r"[^A-Za-z0-9_-]")

# Per-channel resolved tool map, rebuilt each turn by tool_schemas(): the handler
# calls that once at turn start, and dispatch()/names() read what it left. A
# turn is the unit; nothing caches across turns, so a policy edit takes effect
# on the next turn with no restart, matching skills.view().
_RESOLVED = {}


def _sanitize(part):
    retval = _NAME_OK.sub("_", part)
    return retval


def _server_label(server, tool):
    retval = f"{_PREFIX}_{_sanitize(server)}_{_sanitize(tool)}"[:64]
    return retval


def _servers(policy):
    retval = (policy or {}).get("mcp") or {}
    return retval


def configured(policy):
    """Does this channel have any MCP server at all -- cheap, no network."""
    retval = bool(_servers(policy))
    return retval


def _headers(server_cfg):
    retval = {k: v for k, v in (server_cfg.get("headers") or {}).items()
              if isinstance(v, str)}
    return retval


def tool_schemas(channel, policy):
    """The OpenAI tool specs for this channel's allowed MCP tools, and the side
    effect of populating the per-turn resolution map. A server that cannot be
    reached is skipped with a warning rather than failing the turn: the model
    simply does not see its tools this turn."""
    specs = []
    resolved = {}
    for server, cfg in _servers(policy).items():
        url = cfg.get("url")
        allowed = cfg.get("tools") or {}
        if not url or not allowed:
            continue
        headers = _headers(cfg)
        timeout = cfg.get("timeout") or mcp_client._DEFAULT_TIMEOUT
        try:
            live = {t["name"]: t for t in mcp_client.list_tools(url, headers, timeout)}
        except mcp_client.MCPError as exc:
            logging.warning("mcp: %s server %s unreachable, skipping: %s",
                            channel, server, exc)
            continue
        for tool, spec in allowed.items():
            meta = live.get(tool)
            if meta is None:
                logging.warning("mcp: %s allows %s.%s but the server does not offer it",
                                channel, server, tool)
                continue
            mode = (spec or {}).get("mode", "read")
            defaults = (spec or {}).get("defaults") or {}
            label = _server_label(server, tool)
            resolved[label] = {
                "server": server, "tool": tool, "mode": mode,
                "url": url, "timeout": timeout, "defaults": defaults,
            }
            specs.append({
                "type": "function",
                "function": {
                    "name": label,
                    "description": (spec or {}).get("description")
                    or meta.get("description") or f"{server} {tool}",
                    "parameters": _schema_without_defaults(meta.get("inputSchema"), defaults),
                },
            })
    _RESOLVED[channel] = resolved
    retval = specs
    return retval


def _schema_without_defaults(schema, defaults):
    """The tool's JSON Schema with the policy-forced argument keys removed, so
    the model is neither asked for them nor able to override them."""
    if not isinstance(schema, dict):
        retval = {"type": "object", "properties": {}}
        return retval
    props = dict(schema.get("properties") or {})
    for key in defaults:
        props.pop(key, None)
    required = [r for r in (schema.get("required") or []) if r not in defaults]
    retval = {"type": schema.get("type", "object"), "properties": props}
    if required:
        retval["required"] = required
    return retval


def names(channel, policy=None):
    """The prefixed tool names this channel exposes. Reads the per-turn map the
    handler built; rebuilds it if a caller (a test) never called tool_schemas."""
    if channel not in _RESOLVED and policy is not None:
        tool_schemas(channel, policy)
    retval = set(_RESOLVED.get(channel, {}))
    return retval


def _resolve(name, channel, policy):
    entry = _RESOLVED.get(channel, {}).get(name)
    if entry is None and policy is not None:
        tool_schemas(channel, policy)
        entry = _RESOLVED.get(channel, {}).get(name)
    return entry


def dispatch(name, args, policy, channel=None, thread_ts=None, user_id=None):
    """Run a read tool now, or park a mutate tool for approval. Returns the text
    a channel posts: the tool's output, or the two-reader pending message."""
    entry = _resolve(name, channel, policy)
    if entry is None:
        retval = f"unknown MCP tool: {name}"
        return retval
    merged = dict(args or {})
    merged.update(entry["defaults"])  # policy wins over the model
    label = f"{entry['server']}.{entry['tool']}"
    if entry["mode"] == "mutate":
        retval = _park(entry, merged, label, channel, thread_ts, user_id)
        return retval
    server_cfg = _servers(policy).get(entry["server"], {})
    try:
        retval = mcp_client.call_tool(entry["url"], entry["tool"], merged,
                                      _headers(server_cfg), entry["timeout"])
    except mcp_client.MCPError as exc:
        retval = f"MCP {label} failed: {exc}"
    return retval


def _park(entry, merged, label, channel, thread_ts, user_id):
    import json as _json
    # The card shows the server, the tool and the ARGUMENTS -- never the headers,
    # which hold the credential. The queued request stores the server name, not
    # its headers; execution re-reads them from the live policy (#299).
    command = f"MCP {label}({_json.dumps(merged, sort_keys=True)})"
    payload = {"kind": "mcp", "server": entry["server"], "tool": entry["tool"],
               "url": entry["url"], "timeout": entry["timeout"], "arguments": merged}
    req_id = approvals.add(command, channel,
                           f"MCP {label}: a mutating tool parks for approval",
                           requester=user_id, thread_ts=thread_ts, payload=payload)
    retval = (
        f"NOT RUN -- pending approval [{req_id}] (MCP {label} is a mutating tool): {command}\n"
        "Your reply has two readers. Serve both, in this order:\n"
        "1. `tl;dr:` one line for the person who asked -- what you were trying "
        "to do and that it is now waiting on an approval.\n"
        "2. `for the approver:` the server and tool, what it will change, and "
        f"the id {req_id} to quote (approve_command), or the card's button.\n"
        "Do not retry. End your turn now; once it is approved and runs, you are "
        "continued automatically with its output."
    )
    return retval


def run_payload(payload, channel):
    """Execute an approved MCP mutate (#299). Called from admin_tools.run_approved
    for a request whose payload kind is 'mcp'. Headers are re-read from the live
    policy here, so the credential never lived in the queued request."""
    server_cfg = _servers(policy_mod.resolve(channel)).get(payload["server"], {}) if channel else {}
    try:
        retval = mcp_client.call_tool(payload["url"], payload["tool"],
                                      payload.get("arguments") or {},
                                      _headers(server_cfg), payload.get("timeout"))
    except mcp_client.MCPError as exc:
        retval = f"MCP {payload['server']}.{payload['tool']} failed: {exc}"
    return retval


def configured_tools(policy):
    """A human list of this channel's allow-listed MCP tools as
    'server.tool (read|mutate)', from the policy alone -- no network, for
    describe_capabilities. Order follows the policy."""
    out = []
    for server, cfg in _servers(policy).items():
        for tool, spec in (cfg.get("tools") or {}).items():
            mode = (spec or {}).get("mode", "read")
            out.append(f"{server}.{tool} ({mode})")
    retval = out
    return retval


def header_values():
    """Every MCP header value across all policies, for redaction (#72). These
    are where per-server credentials live, so they must be scrubbed like env."""
    out = []
    for pol in list(config.CHANNEL_POLICIES.values()) + [config.DEFAULT_POLICY]:
        for cfg in (_servers(pol)).values():
            for v in (cfg.get("headers") or {}).values():
                if isinstance(v, str):
                    out.append(v)
    retval = out
    return retval

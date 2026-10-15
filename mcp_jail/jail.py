"""Stdio proxy: MCP permission firewall.

Sits between your MCP client and a real MCP server. Every tools/call is
checked against a JSON policy before forwarding; denied calls get a
JSON-RPC error and an audit-log line instead of execution.

Zero client changes: swap the server command for the jail wrapper.

  "my-server": {
    "command": "mcp-jail",
    "args": ["--policy", "~/.mcp-jail/policy.json", "--",
             "npx", "-y", "some-mcp-server"]
  }
"""

from __future__ import annotations

import io
import json
import os
import re
import select
import string
import subprocess
import sys
import time

DEFAULT_POLICY_PATH = os.path.expanduser("~/.mcp-jail/policy.json")
AUDIT_LOG = os.path.expanduser("~/.mcp-jail/audit.jsonl")


def load_policy(path: str) -> dict:
    with open(path) as f:
        pol = json.load(f)
    # compile arg patterns once
    for tool, rules in pol.get("arg_rules", {}).items():
        for key in ("allow", "deny"):
            rules[key] = [re.compile(p) for p in rules.get(key, [])]
    return pol


def default_policy() -> dict:
    return {
        "_comment": "mcp-jail policy. allow_tools/deny_tools are tool names "
                    "('*' = all). arg_rules regex-match the JSON-encoded "
                    "arguments. hide_denied strips denied tools from "
                    "tools/list so agents don't see them.",
        "allow_tools": ["*"],
        "deny_tools": [],
        "arg_rules": {},
        "hide_denied": True,
    }


def tool_allowed(pol: dict, name: str, args: dict) -> tuple[bool, str]:
    deny = pol.get("deny_tools", [])
    allow = pol.get("allow_tools", ["*"])
    if name in deny:
        return False, f"tool '{name}' is denied by policy"
    if "*" not in allow and name not in allow:
        return False, f"tool '{name}' is not in allow_tools"
    rules = pol.get("arg_rules", {}).get(name, {})
    blob = json.dumps(args, sort_keys=True)
    for pat in rules.get("deny", []):
        if pat.search(blob):
            return False, (f"tool '{name}': arguments match deny pattern "
                           f"'{pat.pattern}'")
    allow_pats = rules.get("allow", [])
    if allow_pats and not any(p.search(blob) for p in allow_pats):
        return False, (f"tool '{name}': arguments match no allow pattern")
    return True, ""


def audit(event: dict) -> None:
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    event["at"] = int(time.time())
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _rpc_error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def _read_response(proc, req_id, timeout: float):
    """Read one JSON-RPC response line from the server, with a timeout.

    Returns a discriminated tuple so every caller handles every case:

      ("ok", obj)   -- a valid JSON response arrived
      ("closed",)   -- server closed stdout (EOF): the server is gone
      ("timeout",)  -- nothing arrived within `timeout` seconds
      ("bad", line) -- a non-JSON line arrived

    Callers treat "closed" as fatal (break the loop), "timeout" and
    "bad" as fail-closed (send an error, keep the proxy alive).
    """
    deadline = time.monotonic() + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ("timeout",)
            try:
                ready, _, _ = select.select([proc.stdout], [], [], remaining)
            except (OSError, ValueError):
                return ("closed",)
            if not ready:
                return ("timeout",)
            try:
                line = proc.stdout.readline()
            except (OSError, ValueError):
                return ("closed",)
            if not line:
                return ("closed",)
            line = line.strip()
            if not line:
                continue  # blank line: protocol noise, keep waiting
            try:
                return ("ok", json.loads(line))
            except ValueError:
                return ("bad", line)
    except (OSError, ValueError):
        return ("closed",)


def _handle_response(status, req_id):
    """Map a _read_response status to an action for run()'s loop.

    Returns "send" (an error object was already sent to the client,
    keep going), "break" (server is gone, stop the loop), or the
    response object on success.
    """
    kind = status[0]
    if kind == "ok":
        return status[1]
    if kind == "closed":
        _send(_rpc_error(req_id, -32603, "server closed"))
        return "break"
    if kind == "timeout":
        _send(_rpc_error(req_id, -32603, "server timed out"))
        return "send"
    _send(_rpc_error(req_id, -32603, "bad response from server"))
    return "send"


def run(policy_path: str, server_cmd: list[str],
        timeout: float = 30.0) -> int:
    try:
        pol = load_policy(policy_path)
    except FileNotFoundError:
        sys.stderr.write(f"mcp-jail: no policy at {policy_path}\n"
                         f"mcp-jail: create one — see README\n")
        return 2
    except (json.JSONDecodeError, re.error) as e:
        sys.stderr.write(f"mcp-jail: bad policy: {e}\n")
        return 2

    proc = subprocess.Popen(
        server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=sys.stderr, text=True, bufsize=1)
    assert proc.stdin and proc.stdout

    def forward_to_server(obj: dict) -> None:
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except ValueError:
                continue
            method = req.get("method")
            req_id = req.get("id")

            if method == "tools/list":
                forward_to_server(req)
                out = _handle_response(_read_response(proc, req_id, timeout),
                                       req_id)
                if out == "break":
                    break
                if out == "send":
                    continue
                resp = out
                if pol.get("hide_denied", True):
                    try:
                        tools = resp["result"]["tools"]
                        kept = [t for t in tools
                                if tool_allowed(pol, t["name"], {})[0]]
                        resp["result"]["tools"] = kept
                    except (KeyError, TypeError):
                        pass
                _send(resp)
                continue

            if method == "tools/call":
                params = req.get("params") or {}
                name = params.get("name", "")
                targs = params.get("arguments", {}) or {}
                ok, reason = tool_allowed(pol, name, targs)
                audit({"tool": name, "args": targs,
                       "decision": "allow" if ok else "deny",
                       "reason": reason})
                if not ok:
                    _send(_rpc_error(req_id, -32602,
                                     f"mcp-jail denied: {reason}"))
                    continue
                forward_to_server(req)
                out = _handle_response(_read_response(proc, req_id, timeout),
                                       req_id)
                if out == "break":
                    break
                if out == "send":
                    continue
                _send(out)
                continue

            # passthrough: initialize, notifications, etc.
            forward_to_server(req)
            if req_id is not None:
                out = _handle_response(_read_response(proc, req_id, timeout),
                                       req_id)
                if out == "break":
                    break
                if out == "send":
                    continue
                _send(out)
    except BrokenPipeError:
        pass
    finally:
        try:
            proc.terminate()
        except OSError:
            pass
    return 0


# ---------------------------------------------------------------------------
# learn: observe a server session and generate a tight-fit allowlist policy
# ---------------------------------------------------------------------------

# Fixed menu of character classes, smallest first. Generated string
# patterns are literal-longest-common-prefix + the smallest class here
# covering every observed char. Never `.*`.
_CHAR_CLASSES = [
    ("[0-9]", set(string.digits)),
    ("[a-z]", set(string.ascii_lowercase)),
    ("[a-zA-Z0-9_.-]", set(string.ascii_letters + string.digits + "_.-")),
    ("[a-zA-Z0-9_/.-]", set(string.ascii_letters + string.digits + "_/.-")),
]

_MIN_USEFUL_PREFIX = 2  # shorter shared prefixes fall back to alternation


def _type_tag(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "num"
    if isinstance(v, str):
        return "str"
    if isinstance(v, list):
        return "list"
    return "dict"


def _string_core(bodies: list[str]) -> str:
    """Tightest value-pattern for observed JSON string bodies."""
    lcp = os.path.commonprefix(bodies)
    suffix_chars = set("".join(b[len(lcp):] for b in bodies))
    chosen = None
    for cls, chars in _CHAR_CLASSES:
        if suffix_chars <= chars:
            chosen = cls
            break
    if len(lcp) >= _MIN_USEFUL_PREFIX and chosen is not None:
        if not suffix_chars:
            return re.escape(lcp)  # single distinct value: exact
        return re.escape(lcp) + chosen + "*"
    # no useful shared prefix, or chars outside the menu:
    # exact alternation of observed literals
    return "(?:" + "|".join(re.escape(b) for b in bodies) + ")"


def _arg_pattern(arg: str, values: list) -> str:
    """One allow-pattern shaped for re.search against the JSON args blob.

    tool_allowed() searches each pattern against
    json.dumps(args, sort_keys=True), so the pattern must anchor on the
    argument name: `"argname": <valuepattern>`. Bare `^...$` anchors
    would never match the blob.
    """
    key = json.dumps(arg)  # quoted key, e.g. "cmd"
    tags = {_type_tag(v) for v in values}
    if len(tags) > 1:
        # mixed types: exact alternation of observed JSON literals
        lits = sorted({json.dumps(v, sort_keys=True) for v in values})
        return f"{key}: (?:{'|'.join(re.escape(l) for l in lits)})"
    tag = tags.pop()
    if tag == "null":
        return f"{key}: null"
    if tag == "bool":
        return f"{key}: (?:true|false)"
    if tag == "num":
        return f"{key}: -?\\d+(?:\\.\\d+)?"
    if tag in ("list", "dict"):
        # nested structure: exact observed JSON literals only
        lits = sorted({json.dumps(v, sort_keys=True) for v in values})
        return f"{key}: (?:{'|'.join(re.escape(l) for l in lits)})"
    # strings: derive from the JSON-encoded bodies so the pattern
    # matches the blob verbatim (handles embedded quotes via \")
    bodies = [json.dumps(v)[1:-1] for v in values]
    return f'{key}: "{_string_core(bodies)}"'


def generate_policy(observed_tools: list[str],
                    observed_calls: list[tuple[str, dict]]) -> dict:
    """Build the tightest-fit allowlist policy from observations."""
    tools = sorted(set(observed_tools) | {t for t, _ in observed_calls})
    by_arg: dict[tuple[str, str], list] = {}
    for tool, args in observed_calls:
        if not isinstance(args, dict):
            continue
        for k, v in args.items():
            by_arg.setdefault((tool, k), []).append(v)
    arg_rules: dict[str, dict] = {}
    for (tool, arg), values in sorted(by_arg.items()):
        rules = arg_rules.setdefault(tool, {"allow": [], "deny": []})
        rules["allow"].append(_arg_pattern(arg, values))
    return {
        "_comment": "generated by `mcp-jail learn` — tightest-fit "
                    "allowlist from observed traffic. Review before use: "
                    "it permits exactly what was seen, nothing more.",
        "allow_tools": tools,
        "deny_tools": [],
        "arg_rules": arg_rules,
        "hide_denied": True,
    }


def _spawn(server_cmd: list[str]):
    # sys.stderr may be a redirected StringIO (no fileno) in tests;
    # fall back to inherited stderr then.
    err = sys.stderr
    try:
        err.fileno()
    except (io.UnsupportedOperation, AttributeError, OSError, ValueError):
        err = None
    proc = subprocess.Popen(
        server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=err, text=True, bufsize=1)
    assert proc.stdin and proc.stdout
    return proc


def _learn_from_script(proc, script_path: str, timeout: float,
                       observed_tools: list, observed_calls: list) -> None:
    """Drive canned calls against the server; no client needed."""
    with open(script_path) as f:
        calls = json.load(f)
    if not isinstance(calls, list):
        raise ValueError("script must be a JSON array of "
                         '{"tool": ..., "arguments": {...}}')

    def send(obj: dict) -> None:
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    send({"jsonrpc": "2.0", "id": "learn-init", "method": "initialize",
          "params": {}})
    _read_response(proc, "learn-init", timeout)  # result unused
    send({"jsonrpc": "2.0", "id": "learn-list", "method": "tools/list"})
    status = _read_response(proc, "learn-list", timeout)
    if status[0] == "ok":
        try:
            observed_tools.extend(t["name"]
                                  for t in status[1]["result"]["tools"])
        except (KeyError, TypeError):
            pass
    elif status[0] == "timeout":
        print("learn: tools/list timed out", file=sys.stderr)

    for i, call in enumerate(calls):
        name = call.get("tool", "")
        args = call.get("arguments", {}) or {}
        observed_calls.append((name, args))
        send({"jsonrpc": "2.0", "id": f"learn-{i}", "method": "tools/call",
              "params": {"name": name, "arguments": args}})
        status = _read_response(proc, f"learn-{i}", timeout)
        if status[0] == "timeout":
            print(f"learn: call {i} ({name!r}) timed out "
                  f"after {timeout}s", file=sys.stderr)
        elif status[0] == "closed":
            print("learn: server closed stdout", file=sys.stderr)
            break
        elif status[0] == "bad":
            print(f"learn: call {i} ({name!r}): bad (non-JSON) response "
                  f"from server", file=sys.stderr)


def _learn_live(proc, timeout: float,
                observed_tools: list, observed_calls: list) -> None:
    """Pass-through proxy: log tools/list + tools/call, emit policy at end."""
    def send(obj: dict) -> None:
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except ValueError:
                continue
            method = req.get("method")
            req_id = req.get("id")
            if method == "tools/call":
                params = req.get("params") or {}
                observed_calls.append((params.get("name", ""),
                                       params.get("arguments", {}) or {}))
            send(req)
            if req_id is not None:
                status = _read_response(proc, req_id, timeout)
                if status[0] == "closed":
                    break
                if status[0] == "ok":
                    if method == "tools/list":
                        try:
                            observed_tools.extend(
                                t["name"]
                                for t in status[1]["result"]["tools"])
                        except (KeyError, TypeError):
                            pass
                    _send(status[1])
                elif status[0] == "timeout":
                    print(f"learn: server timed out on {method}",
                          file=sys.stderr)
                else:
                    print(f"learn: bad (non-JSON) response on {method}",
                          file=sys.stderr)
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        pass


def learn(server_cmd: list[str], script: str | None = None,
          out: str | None = None, timeout: float = 30.0) -> int:
    """Observe a server and emit a tight-fit allowlist policy.

    --script mode drives canned calls against the server (no client).
    Live mode proxies stdin/stdout until stdin EOF or Ctrl-C.
    Policy goes to stdout or --out; a summary goes to stderr.
    """
    if script is not None and not os.path.exists(script):
        print(f"mcp-jail learn: no script at {script}", file=sys.stderr)
        return 2
    observed_tools: list = []
    observed_calls: list = []
    proc = _spawn(server_cmd)
    try:
        if script is not None:
            _learn_from_script(proc, script, timeout,
                               observed_tools, observed_calls)
        else:
            _learn_live(proc, timeout, observed_tools, observed_calls)
    finally:
        try:
            proc.terminate()
        except OSError:
            pass
    policy = generate_policy(observed_tools, observed_calls)
    text = json.dumps(policy, indent=2)
    if out:
        with open(out, "w") as f:
            f.write(text + "\n")
        print(f"learn: wrote {out}", file=sys.stderr)
    else:
        print(text)
    n_tools = len(set(observed_tools) | {t for t, _ in observed_calls})
    print(f"learn: observed {n_tools} tool(s), "
          f"{len(observed_calls)} call(s)", file=sys.stderr)
    return 0

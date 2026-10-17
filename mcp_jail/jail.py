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

Transport: newline-delimited JSON-RPC over stdio (the MCP stdio
transport), UTF-8 on the wire regardless of the console code page.
Both pipes are pumped by reader threads into one queue, so the proxy
runs the same way on Windows as on POSIX (no select() on pipes).
"""

from __future__ import annotations

import collections
import io
import json
import os
import queue
import re
import string
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------


def jail_dir() -> str:
    """~/.mcp-jail, resolved at call time (so HOME/USERPROFILE overrides
    in tests and launchers are honoured)."""
    return os.path.join(os.path.expanduser("~"), ".mcp-jail")


def default_policy_path() -> str:
    return os.path.join(jail_dir(), "policy.json")


# Tests (and embedders) may point this at another file; None = default.
AUDIT_LOG: str | None = None
DEFAULT_POLICY_PATH = default_policy_path()


def audit_log_path() -> str:
    return AUDIT_LOG or os.path.join(jail_dir(), "audit.jsonl")


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------

Rule = tuple[tuple[str, ...], "re.Pattern[str]"]


def _parse_path(path: str) -> tuple[str, ...]:
    """'args.*.path' -> ('args', '*', 'path'). '' and '**' mean any path."""
    if not isinstance(path, str):
        raise ValueError(f"arg_rules path must be a string, got {path!r}")
    path = path.strip()
    if path in ("", "**"):
        return ("**",)
    segs = tuple(s.strip() for s in path.split("."))
    if any(not s for s in segs):
        raise ValueError(f"arg_rules path {path!r} has an empty segment")
    return segs


def _path_matches(rule: tuple[str, ...], path: tuple[str, ...]) -> bool:
    """Glob match: '*' = exactly one segment, '**' = zero or more."""
    if not rule:
        return not path
    head, rest = rule[0], rule[1:]
    if head == "**":
        return any(_path_matches(rest, path[i:])
                   for i in range(len(path) + 1))
    if not path:
        return False
    if head == "*" or head == path[0]:
        return _path_matches(rest, path[1:])
    return False


def _compile_rule_set(spec, where: str = "arg_rules") -> list[Rule]:
    """Normalise one allow/deny spec into [(path_segments, pattern)].

    Accepts the documented object form {"path": ["regex", ...]}, the
    shorthand list form ["regex", ...] (== {"**": [...]}: every value at
    any depth), and an already-compiled rule list (idempotent).
    """
    if spec is None:
        return []
    if isinstance(spec, list) and all(
            isinstance(r, tuple) and len(r) == 2 and isinstance(r[0], tuple)
            for r in spec):
        return spec  # already compiled
    if isinstance(spec, (list, tuple)):
        spec = {"**": list(spec)}
    if isinstance(spec, (str, re.Pattern)):
        spec = {"**": [spec]}
    if not isinstance(spec, dict):
        raise ValueError(f"{where}: expected a list of patterns or an "
                         f"object of {{path: [patterns]}}, got {spec!r}")
    rules: list[Rule] = []
    for path, pats in spec.items():
        segs = _parse_path(path)
        if isinstance(pats, (str, re.Pattern)):
            pats = [pats]
        if not isinstance(pats, (list, tuple)):
            raise ValueError(f"{where}.{path}: expected a list of patterns")
        for pat in pats:
            rules.append((segs, pat if isinstance(pat, re.Pattern)
                          else re.compile(pat)))
    return rules


def compile_policy(pol: dict) -> dict:
    """Validate + compile every arg rule in place. Raises ValueError /
    re.error on a malformed policy so run() can fail closed at startup."""
    if not isinstance(pol, dict):
        raise ValueError("policy must be a JSON object")
    rules_by_tool = pol.get("arg_rules") or {}
    if not isinstance(rules_by_tool, dict):
        raise ValueError("arg_rules must be an object keyed by tool name")
    for tool, rules in rules_by_tool.items():
        if not isinstance(rules, dict):
            raise ValueError(f"arg_rules.{tool} must be an object with "
                             f"'allow' and/or 'deny'")
        for key in ("allow", "deny"):
            rules[key] = _compile_rule_set(rules.get(key),
                                           f"arg_rules.{tool}.{key}")
    for key in ("allow_tools", "deny_tools"):
        val = pol.get(key)
        if val is not None and not isinstance(val, (list, tuple, set, dict)):
            raise ValueError(f"{key} must be a list of tool names")
    return pol


def load_policy(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        pol = json.load(f)
    return compile_policy(pol)


def default_policy() -> dict:
    return {
        "_comment": "mcp-jail policy. allow_tools/deny_tools are tool names "
                    "('*' = all; deny wins). arg_rules.<tool>.allow/deny map "
                    "argument paths ('path', 'args.*.path', '**') to regexes "
                    "checked against every value at that path, however "
                    "deeply nested. hide_denied strips tools denied by name "
                    "from tools/list so agents don't see them.",
        "allow_tools": ["*"],
        "deny_tools": [],
        "arg_rules": {},
        "hide_denied": True,
    }


def _leaf_text(v) -> str:
    if isinstance(v, str):
        return v
    return json.dumps(v)  # true/false/null/numbers as JSON text


def _walk(value, path: tuple[str, ...] = ()):
    """Yield (path, text, is_leaf) for every scalar under `value`, plus one
    joined-text entry per array of scalars (so ["rm", "-rf", "/"] is also
    seen as "rm -rf /")."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, path + (str(k),))
    elif isinstance(value, list):
        if value and all(not isinstance(v, (dict, list)) for v in value):
            yield (path, " ".join(_leaf_text(v) for v in value), False)
        for i, v in enumerate(value):
            yield from _walk(v, path + (str(i),))
    else:
        yield (path, _leaf_text(value), True)


def _fmt_path(path: tuple[str, ...]) -> str:
    return ".".join(path) if path else "(arguments)"


def tool_visible(pol: dict, name) -> tuple[bool, str]:
    """Name-level decision: deny_tools / allow_tools only. This is what
    hide_denied uses for tools/list — argument rules are per-call and
    must not hide a tool that is callable with the right arguments."""
    if not isinstance(name, str) or not name:
        return False, "tool name must be a non-empty string"
    deny = pol.get("deny_tools") or []
    allow = pol.get("allow_tools")
    if allow is None:
        allow = ["*"]
    if name in deny:
        return False, f"tool '{name}' is denied by policy"
    if "*" not in allow and name not in allow:
        return False, f"tool '{name}' is not in allow_tools"
    return True, ""


def tool_allowed(pol: dict, name, args) -> tuple[bool, str]:
    """Full per-call decision: tool name, then argument rules.

    Argument rules are matched recursively over objects and arrays:

    - deny: a rule for path P is checked (re.search) against every value
      at P *and below it* — wrapping a value in an object or array never
      hides it. Arrays of scalars are also checked as one space-joined
      string.
    - allow: when a tool has allow rules, EVERY value in the arguments
      must match an allow rule whose path matches the value's path
      exactly ('*' = one segment, '**' = any segments). Unknown paths are
      denied — default-deny, which is what `learn` generates.
    """
    ok, reason = tool_visible(pol, name)
    if not ok:
        return False, reason
    rules_by_tool = pol.get("arg_rules") or {}
    rules = rules_by_tool.get(name) or {}
    deny = _compile_rule_set(rules.get("deny"), f"arg_rules.{name}.deny")
    allow = _compile_rule_set(rules.get("allow"), f"arg_rules.{name}.allow")
    if args is None:
        args = {}
    entries = list(_walk(args))
    for path, text, _leaf in entries:
        for rpath, pat in deny:
            if _path_matches(rpath + ("**",), path) and pat.search(text):
                return False, (f"tool '{name}': argument {_fmt_path(path)} "
                               f"matches deny pattern '{pat.pattern}'")
    if allow:
        for path, text, leaf in entries:
            if not leaf:
                continue
            if not any(_path_matches(rpath, path) and pat.search(text)
                       for rpath, pat in allow):
                return False, (f"tool '{name}': argument {_fmt_path(path)} "
                               f"matches no allow pattern")
    return True, ""


def filter_tools_list(pol: dict, result) -> None:
    """hide_denied: drop tools denied by name from one tools/list page,
    in place. Keeps nextCursor and every other field. Entries that are
    not {"name": str, ...} are dropped too (never fail open)."""
    if not isinstance(result, dict):
        return
    tools = result.get("tools")
    if not isinstance(tools, list):
        return
    result["tools"] = [t for t in tools
                       if isinstance(t, dict)
                       and tool_visible(pol, t.get("name"))[0]]


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def audit(event: dict) -> None:
    """Append one JSON line to the audit log. An unwritable log is
    reported on stderr but never takes the firewall down: the decision
    has already been enforced."""
    path = audit_log_path()
    event["at"] = int(time.time())
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        try:
            print(f"mcp-jail: cannot write audit log {path}: {e}",
                  file=sys.stderr)
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------------------
# transport: newline-delimited JSON over binary pipes, reader threads
# ---------------------------------------------------------------------------

PARSE_ERROR, INVALID_REQUEST = -32700, -32600
INVALID_PARAMS, INTERNAL_ERROR = -32602, -32603


def _rpc_error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def _id_key(req_id) -> str:
    """Exact-type identity for a JSON-RPC id: 1, "1" and 1.0 differ."""
    return json.dumps(req_id, sort_keys=True)


def _encode(obj) -> bytes:
    return (json.dumps(obj) + "\n").encode("utf-8")


def _binary_in(stream):
    """Return a bytes line reader for a text or binary stream."""
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        return buf
    if isinstance(stream, (io.RawIOBase, io.BufferedIOBase)):
        return stream
    return _TextAsBytes(stream)


class _TextAsBytes:
    """readline() adapter: text stream (e.g. StringIO in tests) -> bytes."""

    def __init__(self, stream):
        self._s = stream

    def readline(self) -> bytes:
        line = self._s.readline()
        return line.encode("utf-8") if line else b""


class _Writer:
    """Single-owner writer: bytes to a binary stream, or UTF-8 text to a
    text stream that has no .buffer (StringIO in tests)."""

    def __init__(self, stream):
        self._s = stream
        self._binary = getattr(stream, "buffer", None)
        if self._binary is None and isinstance(
                stream, (io.RawIOBase, io.BufferedIOBase)):
            self._binary = stream

    def write(self, data: bytes) -> None:
        if self._binary is not None:
            self._binary.write(data)
            self._binary.flush()
        else:
            self._s.write(data.decode("utf-8"))
            self._s.flush()

    def send(self, obj) -> None:
        self.write(_encode(obj))


class _Reader(threading.Thread):
    """Pump lines from a binary stream into a queue as (tag, line);
    (tag, None) marks EOF or a broken pipe."""

    def __init__(self, stream, tag: str, q: "queue.Queue"):
        super().__init__(name=f"mcp-jail-{tag}-reader", daemon=True)
        self._stream, self._tag, self._q = stream, tag, q

    def run(self) -> None:
        try:
            while True:
                line = self._stream.readline()
                if not line:
                    break
                # Frames are newline-delimited; a Windows text-mode peer
                # ends them with CRLF. Normalise the terminator only --
                # the JSON bytes themselves are never touched.
                self._q.put((self._tag, line.rstrip(b"\r\n") + b"\n"))
        except (OSError, ValueError):
            pass
        finally:
            self._q.put((self._tag, None))


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
        stderr=err)
    assert proc.stdin and proc.stdout
    return proc


def _stop(proc) -> None:
    """Stop the server and reap it (no zombies, no ResourceWarning).

    Portable: terminate()/kill() only - no killpg, no SIGKILL. Our end of
    its stdin is closed first (EOF lets a well-behaved server exit on its
    own); its stdout is closed last, after the process is gone, so a
    reader thread still blocked in readline() sees EOF instead of a
    close() that waits on the buffer lock.
    """
    try:
        if proc.stdin:
            proc.stdin.close()
    except OSError:
        pass
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    except OSError:
        pass
    try:
        if proc.stdout:
            proc.stdout.close()
    except OSError:
        pass


def _parse(line: bytes):
    """Decode one wire line. Returns (obj, None) or (None, error_text)."""
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as e:
        return None, f"invalid UTF-8: {e.reason}"
    text = text.strip()
    if not text:
        return None, ""  # blank line: protocol noise
    try:
        return json.loads(text), None
    except ValueError as e:
        return None, f"invalid JSON: {e}"


class _Pending:
    """Requests forwarded to the server that still owe a response, keyed
    by exact-type id. Duplicate ids queue up FIFO."""

    def __init__(self):
        self._by_key: dict[str, collections.deque] = {}
        self._seq = 0

    def add(self, req_id, method: str, deadline: float | None) -> None:
        self._seq += 1
        self._by_key.setdefault(_id_key(req_id), collections.deque()).append(
            {"id": req_id, "method": method, "deadline": deadline,
             "seq": self._seq})

    def pop(self, req_id) -> dict | None:
        key = _id_key(req_id)
        dq = self._by_key.get(key)
        if not dq:
            return None
        entry = dq.popleft()
        if not dq:
            del self._by_key[key]
        return entry

    def __len__(self) -> int:
        return sum(len(dq) for dq in self._by_key.values())

    def expired(self, now: float) -> list[dict]:
        out = []
        for key in list(self._by_key):
            dq = self._by_key[key]
            keep = collections.deque()
            for e in dq:
                (out if e["deadline"] is not None and e["deadline"] <= now
                 else keep).append(e)
            if keep:
                self._by_key[key] = keep
            else:
                del self._by_key[key]
        return out

    def drain(self) -> list[dict]:
        out = [e for dq in self._by_key.values() for e in dq]
        self._by_key.clear()
        return out

    def oldest(self) -> dict | None:
        """Remove and return the longest-waiting entry (used to attribute
        a non-JSON server line to the request it most likely answers)."""
        best_key, best = None, None
        for key, dq in self._by_key.items():
            if best is None or dq[0]["seq"] < best["seq"]:
                best_key, best = key, dq[0]
        if best is None:
            return None
        dq = self._by_key[best_key]
        dq.popleft()
        if not dq:
            del self._by_key[best_key]
        return best

    def next_deadline(self) -> float | None:
        ds = [e["deadline"] for dq in self._by_key.values() for e in dq
              if e["deadline"] is not None]
        return min(ds) if ds else None


class _Proxy:
    """The proxy loop. One consumer thread (this one) reads both pumps
    from a single queue and is the only writer to either side."""

    def __init__(self, proc, client_in, client_out, timeout: float | None,
                 pol: dict | None, observer=None):
        self.proc = proc
        self.q: "queue.Queue" = queue.Queue()
        self.client = _Writer(client_out)
        self.server = _Writer(proc.stdin)
        self.timeout = timeout if timeout and timeout > 0 else None
        self.pol = pol
        self.observer = observer
        self.pending = _Pending()
        self._client_in = _binary_in(client_in)

    # -- helpers ----------------------------------------------------------

    def _log(self, msg: str) -> None:
        try:
            print(f"mcp-jail: {msg}", file=sys.stderr)
        except (OSError, ValueError):
            pass

    def _deadline(self) -> float | None:
        return (time.monotonic() + self.timeout) if self.timeout else None

    def _forward(self, msg: dict, raw: bytes | None = None) -> None:
        if raw is not None and not raw.endswith(b"\n"):
            raw = raw + b"\n"
        self.server.write(raw if raw is not None else _encode(msg))

    # -- client -> server ---------------------------------------------------

    def _on_client_line(self, line: bytes) -> None:
        msg, err = _parse(line)
        if err is not None:
            if err:  # not a blank line
                self.client.send(_rpc_error(None, PARSE_ERROR,
                                            f"Parse error: {err}"))
            return
        if isinstance(msg, list):
            # JSON-RPC batch: split it. Each element is handled on its
            # own; the server answers forwarded elements individually.
            if not msg:
                self.client.send(_rpc_error(None, INVALID_REQUEST,
                                            "Invalid Request: empty batch"))
                return
            for item in msg:
                self._on_client_message(item, None)
            return
        self._on_client_message(msg, line)

    def _on_client_message(self, msg, raw: bytes | None) -> None:
        if not isinstance(msg, dict):
            self.client.send(_rpc_error(None, INVALID_REQUEST,
                                        "Invalid Request: not an object"))
            return
        if "method" not in msg:
            # A response from the client to a server-originated request
            # (sampling, roots, elicitation): pass through untouched.
            self._forward(msg, raw)
            return
        method = msg.get("method")
        has_id = "id" in msg and msg.get("id") is not None
        req_id = msg.get("id")
        if not isinstance(method, str):
            if has_id:
                self.client.send(_rpc_error(req_id, INVALID_REQUEST,
                                            "Invalid Request: method must "
                                            "be a string"))
            return
        if method == "tools/call":
            params = msg.get("params")
            params = params if isinstance(params, dict) else {}
            name = params.get("name")
            targs = params.get("arguments")
            if targs is None:
                targs = {}
            if self.pol is None:
                ok, reason = True, ""
            else:
                ok, reason = tool_allowed(self.pol, name, targs)
                audit({"tool": name if isinstance(name, str) else repr(name),
                       "args": targs,
                       "decision": "allow" if ok else "deny",
                       "reason": reason})
            if self.observer is not None and ok:
                self.observer.on_call(name, targs)
            if not ok:
                # Same id, same type, as the request. A notification
                # (no id) never gets a response — it is just dropped.
                if has_id:
                    self.client.send(_rpc_error(req_id, INVALID_PARAMS,
                                                f"mcp-jail denied: {reason}"))
                return
        if has_id:
            self.pending.add(req_id, method, self._deadline())
        self._forward(msg, raw)

    # -- server -> client ---------------------------------------------------

    def _on_server_line(self, line: bytes) -> None:
        msg, err = _parse(line)
        if err is not None:
            if err:
                # A server that prints to stdout is corrupting the protocol
                # stream. Fail the longest-waiting request closed (the one
                # this garbage most likely answers) and keep the proxy
                # alive; with nothing in flight just log it.
                entry = self.pending.oldest()
                if entry is not None:
                    self.client.send(_rpc_error(entry["id"], INTERNAL_ERROR,
                                                "bad response from server"))
                else:
                    self._log(f"ignoring non-JSON line from server: {err}")
            return
        if isinstance(msg, list):
            kept = [m for m in msg if self._on_server_message(m, None)]
            if kept:
                self.client.send(kept)
            return
        self._on_server_message(msg, line)

    def _on_server_message(self, msg, raw: bytes | None) -> bool:
        """Deliver one server message. Returns True if the (possibly
        modified) message should be delivered as part of a batch."""
        if not isinstance(msg, dict):
            return False
        if "method" in msg:
            # Server-originated request or notification: pass through.
            if raw is not None:
                self.client.write(raw if raw.endswith(b"\n") else raw + b"\n")
            return True
        if "id" not in msg:
            self._log("ignoring server message with neither method nor id")
            return False
        entry = self.pending.pop(msg.get("id"))
        if entry is None:
            # Late (already timed out) or unsolicited: the client already
            # has its answer for this id, a second one would confuse it.
            self._log(f"dropping response with unknown id {msg.get('id')!r}")
            return False
        if entry["method"] == "tools/list" and "result" in msg:
            if self.observer is not None:
                self.observer.on_tools(msg["result"])
            if self.pol is not None and self.pol.get("hide_denied", True):
                filter_tools_list(self.pol, msg["result"])
                raw = None  # re-serialise the filtered page
        if raw is not None:
            self.client.write(raw if raw.endswith(b"\n") else raw + b"\n")
        else:
            self.client.send(msg)
        return True

    # -- loop ---------------------------------------------------------------

    def _fail_pending(self, entries, message: str) -> None:
        for e in entries:
            self.client.send(_rpc_error(e["id"], INTERNAL_ERROR, message))

    def serve(self) -> int:
        _Reader(self._client_in, "client", self.q).start()
        _Reader(self.proc.stdout, "server", self.q).start()
        client_open = True
        try:
            while True:
                if not client_open and not len(self.pending):
                    break
                deadline = self.pending.next_deadline()
                wait = None
                if deadline is not None:
                    wait = max(0.0, deadline - time.monotonic())
                try:
                    tag, line = self.q.get(timeout=wait)
                except queue.Empty:
                    self._fail_pending(self.pending.expired(time.monotonic()),
                                       "server timed out")
                    continue
                if tag == "client":
                    if line is None:
                        client_open = False
                        continue
                    self._on_client_line(line)
                else:
                    if line is None:
                        self._fail_pending(self.pending.drain(),
                                           "server closed")
                        break
                    self._on_server_line(line)
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        except (OSError, ValueError) as e:  # a pipe went away under us
            self._log(f"transport closed: {e}")
        return 0


def run(policy_path: str, server_cmd: list[str], timeout: float = 30.0,
        stdin=None, stdout=None) -> int:
    """Run the jail: policy-check stdin -> server, pass server -> stdout.

    `stdin`/`stdout` default to the process's own (binary) streams; tests
    pass in-memory streams.
    """
    try:
        pol = load_policy(policy_path)
    except FileNotFoundError:
        sys.stderr.write(f"mcp-jail: no policy at {policy_path}\n"
                         f"mcp-jail: create one - see README\n")
        return 2
    except (json.JSONDecodeError, re.error, ValueError) as e:
        sys.stderr.write(f"mcp-jail: bad policy: {e}\n")
        return 2
    proc = _spawn(server_cmd)
    try:
        return _Proxy(proc, stdin or sys.stdin, stdout or sys.stdout,
                      timeout, pol).serve()
    finally:
        _stop(proc)


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
    return "str"


def _string_core(bodies: list[str]) -> str:
    """Tightest value-pattern for observed string values."""
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
    return "(?:" + "|".join(re.escape(b) for b in sorted(set(bodies))) + ")"


def _value_pattern(values: list) -> str:
    """One anchored allow-pattern for the scalar values seen at a path.

    tool_allowed() matches a value's text with re.search, so patterns are
    anchored ^...$ to pin the whole value.
    """
    tags = {_type_tag(v) for v in values}
    if len(tags) > 1:
        lits = sorted({_leaf_text(v) for v in values})
        return "^(?:" + "|".join(re.escape(l) for l in lits) + ")$"
    tag = tags.pop()
    if tag == "null":
        return "^null$"
    if tag == "bool":
        return "^(?:true|false)$"
    if tag == "num":
        return r"^-?\d+(?:\.\d+)?$"
    return "^" + _string_core([str(v) for v in values]) + "$"


def _scalars(value, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _scalars(v, path + (str(k),))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _scalars(v, path + (str(i),))
    else:
        yield path, value


def _observed_paths(args) -> list[tuple[str, object]]:
    """Flatten call arguments to (path, scalar) with numeric segments
    (array indices) generalised to '*', so tags.0/tags.1 become tags.*."""
    out = []
    for path, value in _scalars(args):
        segs = tuple("*" if s.isdigit() else s for s in path)
        out.append((".".join(segs) if segs else "**", value))
    return out


def generate_policy(observed_tools: list[str],
                    observed_calls: list[tuple[str, dict]]) -> dict:
    """Build the tightest-fit allowlist policy from observations."""
    tools = sorted({t for t in observed_tools if isinstance(t, str)}
                   | {t for t, _ in observed_calls if isinstance(t, str)})
    by_path: dict[tuple[str, str], list] = {}
    for tool, args in observed_calls:
        if not isinstance(tool, str):
            continue
        for gen_path, value in _observed_paths(args):
            by_path.setdefault((tool, gen_path), []).append(value)
    arg_rules: dict[str, dict] = {}
    for (tool, gen_path), values in sorted(by_path.items()):
        rules = arg_rules.setdefault(tool, {"allow": {}, "deny": {}})
        rules["allow"][gen_path] = [_value_pattern(values)]
    return {
        "_comment": "generated by `mcp-jail learn` - tightest-fit "
                    "allowlist from observed traffic. Review before use: "
                    "it permits exactly what was seen, nothing more. "
                    "Every argument value must match the allow pattern "
                    "for its path; unseen paths are denied.",
        "allow_tools": tools,
        "deny_tools": [],
        "arg_rules": arg_rules,
        "hide_denied": True,
    }


class _Recorder:
    """Observer for learn: collects tool names and (tool, args) calls."""

    def __init__(self):
        self.tools: list[str] = []
        self.calls: list[tuple[str, dict]] = []

    def on_call(self, name, args) -> None:
        self.calls.append((name, args))

    def on_tools(self, result) -> None:
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            for t in result["tools"]:
                if isinstance(t, dict) and isinstance(t.get("name"), str):
                    self.tools.append(t["name"])


class _Session:
    """Synchronous request/response client for a server subprocess,
    built on the same reader-thread transport (used by learn --script).

    request() returns a discriminated tuple:
      ("ok", obj)   -- the response with the matching id arrived
      ("closed",)   -- server closed stdout
      ("timeout",)  -- nothing matching arrived within `timeout` seconds
      ("bad", text) -- a non-JSON line arrived instead
    Notifications are ignored; server-originated requests get a
    -32601 error so the server never waits on a client that isn't there.
    """

    def __init__(self, proc):
        self.proc = proc
        self.q: "queue.Queue" = queue.Queue()
        self.out = _Writer(proc.stdin)
        self.closed = False
        _Reader(proc.stdout, "server", self.q).start()

    def request(self, msg: dict, timeout: float):
        self.out.send(msg)
        want = _id_key(msg.get("id"))
        deadline = time.monotonic() + timeout
        while True:
            if self.closed:
                return ("closed",)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ("timeout",)
            try:
                _tag, line = self.q.get(timeout=remaining)
            except queue.Empty:
                return ("timeout",)
            if line is None:
                self.closed = True
                return ("closed",)
            obj, err = _parse(line)
            if err is not None:
                if err:
                    return ("bad", line.decode("utf-8", "replace").strip())
                continue
            if not isinstance(obj, dict):
                continue
            if "method" in obj:
                if obj.get("id") is not None:
                    self.out.send(_rpc_error(obj["id"], -32601,
                                             "mcp-jail learn: client requests "
                                             "are not supported"))
                continue
            if "id" in obj and _id_key(obj["id"]) == want:
                return ("ok", obj)


def _learn_from_script(proc, script_path: str, timeout: float,
                       rec: _Recorder) -> None:
    """Drive canned calls against the server; no client needed."""
    with open(script_path, encoding="utf-8") as f:
        calls = json.load(f)
    if not isinstance(calls, list):
        raise ValueError("script must be a JSON array of "
                         '{"tool": ..., "arguments": {...}}')
    session = _Session(proc)
    session.request({"jsonrpc": "2.0", "id": "learn-init",
                     "method": "initialize", "params": {}}, timeout)
    status = session.request({"jsonrpc": "2.0", "id": "learn-list",
                              "method": "tools/list"}, timeout)
    if status[0] == "ok":
        rec.on_tools(status[1].get("result"))
    elif status[0] == "timeout":
        print("learn: tools/list timed out", file=sys.stderr)

    for i, call in enumerate(calls):
        if not isinstance(call, dict):
            continue
        name = call.get("tool", "")
        args = call.get("arguments")
        if args is None:
            args = {}
        rec.on_call(name, args)
        status = session.request(
            {"jsonrpc": "2.0", "id": f"learn-{i}", "method": "tools/call",
             "params": {"name": name, "arguments": args}}, timeout)
        if status[0] == "timeout":
            print(f"learn: call {i} ({name!r}) timed out "
                  f"after {timeout}s", file=sys.stderr)
        elif status[0] == "closed":
            print("learn: server closed stdout", file=sys.stderr)
            break
        elif status[0] == "bad":
            print(f"learn: call {i} ({name!r}): bad (non-JSON) response "
                  f"from server", file=sys.stderr)


def learn(server_cmd: list[str], script: str | None = None,
          out: str | None = None, timeout: float = 30.0,
          stdin=None, stdout=None) -> int:
    """Observe a server and emit a tight-fit allowlist policy.

    --script mode drives canned calls against the server (no client).
    Live mode proxies stdin/stdout (everything allowed, nothing hidden)
    until stdin EOF or Ctrl-C.  Policy goes to stdout or --out; a summary
    goes to stderr.
    """
    if script is not None and not os.path.exists(script):
        print(f"mcp-jail learn: no script at {script}", file=sys.stderr)
        return 2
    rec = _Recorder()
    proc = _spawn(server_cmd)
    try:
        if script is not None:
            _learn_from_script(proc, script, timeout, rec)
        else:
            try:
                _Proxy(proc, stdin or sys.stdin, stdout or sys.stdout,
                       timeout, None, observer=rec).serve()
            except KeyboardInterrupt:
                pass
    finally:
        _stop(proc)
    policy = generate_policy(rec.tools, rec.calls)
    text = json.dumps(policy, indent=2)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"learn: wrote {out}", file=sys.stderr)
    else:
        print(text)
    n_tools = len(set(rec.tools) | {t for t, _ in rec.calls})
    print(f"learn: observed {n_tools} tool(s), "
          f"{len(rec.calls)} call(s)", file=sys.stderr)
    return 0

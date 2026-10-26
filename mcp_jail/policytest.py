"""`mcp-jail verify-policy`: replay a recorded session against a policy and
check each call is allowed or refused as you expect, without starting any
server. It asks the same function the running jail asks (evaluate_call), so
a passing test means the live jail decides the same way.

A session file is JSON, either a list of calls (the shape `learn --script`
reads; every call is expected to be allowed) or

  {"version": 1, "calls": [
     {"tool": "read_file", "arguments": {"path": "/tmp/a"}, "expect": "allow"},
     {"tool": "delete_file", "expect": "deny"},
     {"method": "resources/list", "expect": "deny"} ]}

`learn --record FILE` writes one from a real session.
"""

from __future__ import annotations

import json
import os

from . import jail as jail_mod

SESSION_VERSION = 1
_EXPECT = ("allow", "deny")


def load_session(path: str) -> "list[dict]":
    """Read and check a session file. Raises ValueError/OSError with a
    message fit for the user."""
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except ValueError as e:
            raise ValueError(f"not valid JSON ({e})") from None
    if isinstance(data, dict):
        if data.get("version") != SESSION_VERSION:
            raise ValueError(f'"version" must be {SESSION_VERSION}')
        extra = set(data) - {"version", "calls", "note"}
        if extra:
            raise ValueError(f"unknown key {sorted(extra)[0]!r}")
        calls = data.get("calls")
    else:
        calls = data
    if not isinstance(calls, list):
        raise ValueError('needs a list of calls (or {"version": 1, '
                         '"calls": [...]})')
    out = []
    for i, call in enumerate(calls):
        if not isinstance(call, dict):
            raise ValueError(f"call {i} is not an object")
        has_tool, has_method = "tool" in call, "method" in call
        if has_tool == has_method:
            raise ValueError(f'call {i} needs exactly one of "tool" and '
                             f'"method"')
        key = "tool" if has_tool else "method"
        if not isinstance(call[key], str) or not call[key]:
            raise ValueError(f'call {i}: "{key}" must be a non-empty string')
        expect = call.get("expect", "allow")
        if expect not in _EXPECT:
            raise ValueError(f'call {i}: "expect" must be "allow" or "deny"')
        args = call.get("arguments")
        if args is not None and not isinstance(args, dict):
            raise ValueError(f'call {i}: "arguments" must be a JSON object')
        params = call.get("params")
        if params is not None and not isinstance(params, dict):
            raise ValueError(f'call {i}: "params" must be a JSON object')
        out.append({"key": key, "name": call[key], "arguments": args,
                    "params": params, "expect": expect})
    return out


def decide(pol: dict, call: dict) -> "tuple[bool, str]":
    """(allowed, reason) the live jail would give this recorded call."""
    if call["key"] == "tool":
        method = "tools/call"
        params = {"name": call["name"], "arguments": call["arguments"] or {}}
    else:
        method = call["name"]
        params = dict(call["params"] or {})
        if call["arguments"] is not None:
            params["arguments"] = call["arguments"]
    if jail_mod.method_denied(pol, method):
        return False, f"method '{method}' is denied by policy"
    mkey = jail_mod.normalize_tool_name(method)
    if not jail_mod.method_policed(pol, method):
        return True, ""
    _name, _args, ok, reason = jail_mod.evaluate_call(pol, mkey, params)
    return ok, reason


def verify_policy(policy_path: str, session_path: str, as_json: bool = False,
                  out=None) -> int:
    """Exit 0: every call got the decision expected; 1: at least one did not;
    2: the policy or the session could not be used."""
    emit = out or print
    policy_path = jail_mod.expand_path(policy_path)
    session_path = jail_mod.expand_path(session_path)
    try:
        pol = jail_mod.load_policy(policy_path)
    except FileNotFoundError:
        jail_mod._say(f"mcp-jail verify-policy: no policy at {policy_path}")
        return 2
    except (OSError, ValueError) as e:
        jail_mod._say(f"mcp-jail verify-policy: bad policy {policy_path}: {e}")
        return 2
    try:
        calls = load_session(session_path)
    except FileNotFoundError:
        jail_mod._say(f"mcp-jail verify-policy: no session at {session_path}")
        return 2
    except (OSError, ValueError) as e:
        jail_mod._say(f"mcp-jail verify-policy: bad session {session_path}: "
                      f"{e}")
        return 2
    rows, failed = [], 0
    for i, call in enumerate(calls):
        ok, reason = decide(pol, call)
        got = "allow" if ok else "deny"
        passed = got == call["expect"]
        failed += not passed
        rows.append({"index": i, call["key"]: call["name"],
                     "expect": call["expect"], "got": got,
                     "pass": passed, "reason": reason})
    if as_json:
        emit(json.dumps({"version": 1, "total": len(rows), "failed": failed,
                         "results": rows}, indent=2))
    else:
        for r in rows:
            what = r.get("tool") or "method " + str(r.get("method"))
            line = (f"{'ok  ' if r['pass'] else 'FAIL'} "
                    f"{_one_line(what)}: expected {r['expect']}, got {r['got']}")
            if r["reason"]:
                line += f" ({_one_line(r['reason'])})"
            emit(line)
        emit(f"\n{len(rows) - failed} of {len(rows)} as expected"
             + (f", {failed} not" if failed else ""))
    return 1 if failed else 0


def _one_line(text: str) -> str:
    return "".join(ch if ch.isprintable()
                   else ch.encode("unicode_escape").decode("ascii")
                   for ch in str(text))


def write_session(path: str, calls: "list[tuple[str, dict]]") -> None:
    """Write observed calls as a session file (every one expected allowed)."""
    doc = {"version": SESSION_VERSION,
           "calls": [{"tool": n, "arguments": a, "expect": "allow"}
                     for n, a in calls]}
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

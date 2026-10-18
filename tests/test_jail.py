"""mcp-jail tests: fake upstream server over stdio, no network.

Portable by construction: no symlinks, no select(), no signals; every
text file is opened with an explicit encoding; HOME/USERPROFILE/APPDATA
point at a throwaway directory for the whole module so nothing here ever
reads or writes the real user's ~/.mcp-jail.
"""

import argparse
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from mcp_jail import cli as cli_mod
from mcp_jail import jail as jail_mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --------------------------------------------------------------------------
# environment isolation (module-wide): fake home + tolerant cleanup
# --------------------------------------------------------------------------

_ENV_VARS = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
             "XDG_CONFIG_HOME", "XDG_DATA_HOME")
_saved_env: dict = {}
_fake_home = ""


def _rmtree(path: str) -> None:
    """shutil.rmtree that copes with read-only files (Windows)."""
    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass
    if hasattr(shutil, "rmtree") and sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: _onerror(f, p, e))
    else:
        shutil.rmtree(path, onerror=_onerror)


def setUpModule():
    global _fake_home
    _fake_home = tempfile.mkdtemp(prefix="mjh")
    for var in _ENV_VARS:
        _saved_env[var] = os.environ.get(var)
        os.environ[var] = _fake_home
    # servers the jail starts in this process inherit the environment: one
    # that forgot to flush must hang here as it would for a real client
    _saved_env["PYTHONUNBUFFERED"] = os.environ.pop("PYTHONUNBUFFERED", None)


def tearDownModule():
    for var, old in _saved_env.items():
        if old is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = old
    _rmtree(_fake_home)


def mktemp() -> str:
    return tempfile.mkdtemp(prefix="mj")


def child_env() -> dict:
    """Environment for a real subprocess running mcp-jail. This sandbox sets
    PYTHONUNBUFFERED, which hides a child that forgot to flush: drop it."""
    env = dict(os.environ)
    env.pop("PYTHONUNBUFFERED", None)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


# --------------------------------------------------------------------------
# fake servers
# --------------------------------------------------------------------------

FAKE_SERVER = r"""
import json, sys
TOOLS = [{"name": "read_file", "description": "read"},
         {"name": "run_cmd", "description": "run"},
         {"name": "delete_all", "description": "danger"}]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if m == "initialize":
        r = {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05", "capabilities": {}}}
    elif m == "tools/list":
        r = {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    elif m == "tools/call":
        r = {"jsonrpc": "2.0", "id": rid,
             "result": {"content": [{"type": "text", "text": "did:" + req["params"]["name"]}]}}
    else:
        r = {"jsonrpc": "2.0", "id": rid, "result": {}}
    sys.stdout.write(json.dumps(r) + "\n")
    sys.stdout.flush()
"""

# Emits a notification before every response, never answers
# notifications, and echoes the call arguments back (UTF-8 on the wire).
FAKE_NOTIFY = r"""
import json, sys
inp = sys.stdin.buffer
out = sys.stdout.buffer
for raw in iter(inp.readline, b""):
    line = raw.decode("utf-8").strip()
    if not line:
        continue
    req = json.loads(line)
    rid = req.get("id")
    if rid is None:
        continue
    out.write((json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
               "params": {"level": "info", "data": "working on %s" % (rid,)}}) + "\n").encode())
    args = (req.get("params") or {}).get("arguments")
    out.write((json.dumps({"jsonrpc": "2.0", "id": rid,
               "result": {"echo": rid, "args": args}}, ensure_ascii=False) + "\n").encode("utf-8"))
    out.flush()
"""

# Records every line it receives into the file named by argv[1]; answers
# requests with their id, in REVERSE order of arrival once it has seen
# two pending requests (to prove responses are matched by id, not order).
FAKE_RECORDER = r"""
import json, sys
log = open(sys.argv[1], "a", encoding="utf-8")
pending = []
def answer(req):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req["id"],
                                 "result": {"echo": req["id"]}}) + "\n")
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    log.write(line + "\n"); log.flush()
    req = json.loads(line)
    if "method" not in req or req.get("id") is None:
        continue  # notification or a client response: nothing to answer
    pending.append(req)
    if len(pending) == 2:
        for r in reversed(pending):
            answer(r)
        pending = []
        sys.stdout.flush()
    elif req.get("params", {}).get("flush"):
        for r in pending:
            answer(r)
        pending = []
        sys.stdout.flush()
"""

# Two-page tools/list (cursor), delete_all on page 2 next to a tool
# entry without a name.
FAKE_PAGED = r"""
import json, sys
PAGES = {None: ({"tools": [{"name": "read_file"}, {"name": "delete_all"}], "nextCursor": "p2"}),
         "p2": ({"tools": [{"name": "run_cmd"}, {"description": "nameless"}, {"name": "delete_all"}]})}
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if m == "tools/list":
        cur = (req.get("params") or {}).get("cursor")
        r = {"jsonrpc": "2.0", "id": rid, "result": PAGES[cur]}
    else:
        r = {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": "did"}]}}
    sys.stdout.write(json.dumps(r) + "\n")
    sys.stdout.flush()
"""

# On its first request, asks the CLIENT something (sampling) and only
# answers the original request once the client has replied, echoing the
# client's answer. Also writes an oddly formatted response for id "raw".
FAKE_ASKER = r"""
import json, sys
waiting = None
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    if "method" not in req:          # the client's answer to our question
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": waiting,
                                     "result": {"client_said": req.get("result")}}) + "\n")
        sys.stdout.flush()
        continue
    rid = req.get("id")
    if rid == "raw":
        sys.stdout.write('{"result":{"b":1.0,"a":"\\u00e9\\u65e5"},"id":"raw","jsonrpc":"2.0"}\n')
        sys.stdout.flush()
        continue
    if rid == "crlf":                # a Windows text-mode peer: CRLF frames
        sys.stdout.buffer.write(b'{"result":{"ok":true},"id":"crlf","jsonrpc":"2.0"}\r\n')
        sys.stdout.flush()
        continue
    waiting = rid
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": "srv-q1",
                                 "method": "sampling/createMessage",
                                 "params": {"messages": []}}) + "\n")
    sys.stdout.flush()
"""

FAKE_FLAKY = r"""
import json, sys
# V9: emits a garbage non-JSON line when asked to call the "garbage" tool
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if m == "tools/call" and req.get("params", {}).get("name") == "garbage":
        sys.stdout.write("THIS IS NOT JSON\n")
        sys.stdout.flush()
    else:
        r = {"jsonrpc": "2.0", "id": rid, "result": {"ok": True}}
        sys.stdout.write(json.dumps(r) + "\n")
        sys.stdout.flush()
"""

FAKE_HANG = r"""
import json, sys, time
# V10: never responds to tools/call
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if m == "tools/call":
        time.sleep(30)
    else:
        r = {"jsonrpc": "2.0", "id": rid, "result": {}}
        sys.stdout.write(json.dumps(r) + "\n")
        sys.stdout.flush()
"""

# Answers tools/call late (after `delay` seconds given in the arguments).
FAKE_SLOW = r"""
import json, sys, time
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    rid = req.get("id")
    if req.get("method") == "tools/call":
        time.sleep(float(req["params"]["arguments"].get("delay", 0)))
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"late": True}}) + "\n")
    sys.stdout.flush()
"""


def write_server(tmp: str, src: str = FAKE_SERVER, name: str = "srv.py") -> str:
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(src)
    return p


def write_policy(tmp: str, pol: dict) -> str:
    p = os.path.join(tmp, "policy.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(pol, f)
    return p


ALLOW_ALL = {"allow_tools": ["*"], "deny_tools": [], "arg_rules": {},
             "hide_denied": False}


def drive_rc(policy_path: str, server_cmd: list, requests, timeout: float = 30.0,
             join: float = 20, grace=None) -> tuple:
    """Run the jail in-process on in-memory streams; return (exit code, raw
    output lines). `requests` may be dicts (serialised) or raw strings.
    `grace` is passed on only when given (the jail's default otherwise)."""
    chunks = []
    for r in requests:
        chunks.append(r if isinstance(r, str) else json.dumps(r))
    inp = io.BytesIO(("\n".join(chunks) + "\n").encode("utf-8"))
    out = io.BytesIO()
    code = []

    extra = {} if grace is None else {"grace": grace}

    def target():
        code.append(jail_mod.run(policy_path, server_cmd, timeout=timeout,
                                 stdin=inp, stdout=out, **extra))

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout=join)
    if t.is_alive():
        raise AssertionError("proxy did not finish (hung?)")
    return (code[0] if code else None,
            [ln for ln in out.getvalue().split(b"\n") if ln.strip()])


def drive_raw(policy_path: str, server_cmd: list, requests, timeout: float = 30.0,
              join: float = 20) -> list[bytes]:
    """drive_rc without the exit code."""
    return drive_rc(policy_path, server_cmd, requests, timeout, join)[1]


def drive_jail(policy_path: str, server_path: str, requests, timeout: float = 30.0,
               server_args: list | None = None) -> list[dict]:
    raw = drive_raw(policy_path, [sys.executable, server_path] + (server_args or []),
                    requests, timeout=timeout)
    return [json.loads(ln) for ln in raw]


# --------------------------------------------------------------------------
# policy: tool names
# --------------------------------------------------------------------------


class TestPolicy(unittest.TestCase):
    def test_allow_deny(self):
        pol = {"allow_tools": ["*"], "deny_tools": ["delete_all"],
               "arg_rules": {}}
        ok, _ = jail_mod.tool_allowed(pol, "read_file", {})
        self.assertTrue(ok)
        ok, reason = jail_mod.tool_allowed(pol, "delete_all", {})
        self.assertFalse(ok)
        self.assertIn("denied", reason)

    def test_allowlist(self):
        pol = {"allow_tools": ["read_file"], "deny_tools": {},
               "arg_rules": {}}
        ok, _ = jail_mod.tool_allowed(pol, "read_file", {})
        self.assertTrue(ok)
        ok, _ = jail_mod.tool_allowed(pol, "run_cmd", {})
        self.assertFalse(ok)

    def test_arg_rules(self):
        pol = {"allow_tools": ["*"], "deny_tools": [],
               "arg_rules": {"run_cmd": {"deny": [r"rm -rf"],
                                         "allow": []}}}
        pol["arg_rules"]["run_cmd"]["deny"] = [re.compile(r"rm -rf")]
        ok, _ = jail_mod.tool_allowed(pol, "run_cmd", {"cmd": "ls"})
        self.assertTrue(ok)
        ok, reason = jail_mod.tool_allowed(pol, "run_cmd", {"cmd": "rm -rf /"})
        self.assertFalse(ok)
        self.assertIn("deny pattern", reason)

    def test_non_string_tool_name_is_denied_not_crash(self):
        pol = {"allow_tools": ["*"], "deny_tools": [],
               "arg_rules": {"x": {"allow": ["^a$"]}}}
        for bad in ({"name": "x"}, ["x"], None, 7, ""):
            ok, reason = jail_mod.tool_allowed(pol, bad, {})
            self.assertFalse(ok, repr(bad))
            self.assertIn("tool name", reason)


# --------------------------------------------------------------------------
# policy: recursive argument rules (panel finding 1)
# --------------------------------------------------------------------------


def compiled(pol: dict) -> dict:
    return jail_mod.compile_policy(json.loads(json.dumps(pol)))


class TestArgRulePaths(unittest.TestCase):
    """Argument rules are matched over the whole argument tree with a
    path syntax; nesting a value in an object or array hides nothing."""

    def test_nested_object_cannot_hide_denied_value(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"deny": {"path": ["^/etc/"]}}}})
        self.assertFalse(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/etc/passwd"})[0])
        ok, reason = jail_mod.tool_allowed(
            pol, "read_file", {"path": {"$ref": "/etc/passwd"}})
        self.assertFalse(ok, "value wrapped in an object bypassed deny")
        self.assertIn("path.$ref", reason)
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/tmp/ok"})[0])

    def test_array_cannot_hide_denied_value(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"deny": [r"\.\."]},
            "run_cmd": {"deny": {"cmd": ["rm -rf"]}}}})
        self.assertFalse(jail_mod.tool_allowed(
            pol, "read_file", {"path": "../secret"})[0])
        self.assertFalse(jail_mod.tool_allowed(
            pol, "read_file", {"path": ["..", "secret"]})[0],
            "path split into array elements bypassed deny")
        self.assertFalse(jail_mod.tool_allowed(
            pol, "read_file", {"paths": [["..", "secret"]]})[0])
        # argv-style split of a denied command is seen space-joined
        self.assertFalse(jail_mod.tool_allowed(
            pol, "run_cmd", {"cmd": ["rm", "-rf", "/"]})[0])
        self.assertTrue(jail_mod.tool_allowed(
            pol, "run_cmd", {"cmd": ["ls", "-la"]})[0])

    def test_path_wildcards(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "edit": {"deny": {"files.*.path": ["^/etc/"],
                              "**.secret": ["."]}}}})
        self.assertFalse(jail_mod.tool_allowed(pol, "edit", {
            "files": [{"path": "/tmp/a"}, {"path": "/etc/shadow"}]})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "edit", {
            "files": [{"path": "/tmp/a"}], "etc": "/etc/x"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "edit", {
            "deep": {"er": {"secret": "x"}}})[0])

    def test_plain_list_means_every_value_anywhere(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "t": {"deny": ["evil"]}}})
        self.assertFalse(jail_mod.tool_allowed(
            pol, "t", {"a": [{"b": {"c": "so evil"}}]})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"a": "good"})[0])

    def test_allow_requires_every_value_to_match(self):
        pol = compiled(jail_mod.generate_policy(
            ["read_file", "run_cmd"],
            [("read_file", {"path": "/tmp/a.txt"}),
             ("read_file", {"path": "/tmp/b.txt"}),
             ("run_cmd", {"cmd": "ls", "count": 3})]))
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/tmp/c.txt"})[0])
        # a matching value smuggled in a nested object must not unlock the
        # call: the top-level path value is what the tool will use
        ok, reason = jail_mod.tool_allowed(
            pol, "read_file", {"path": "/etc/passwd", "x": {"path": "/tmp/a"}})
        self.assertFalse(ok, reason)
        # allow patterns are not OR'd across arguments
        ok, reason = jail_mod.tool_allowed(
            pol, "run_cmd", {"cmd": "rm -rf /", "count": 3})
        self.assertFalse(ok, reason)
        self.assertIn("cmd", reason)
        # and an unobserved extra argument is denied (default-deny)
        self.assertFalse(jail_mod.tool_allowed(
            pol, "run_cmd", {"cmd": "ls", "count": 3, "shell": True})[0])

    def test_allow_path_is_exact(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"allow": {"path": ["^/tmp/"]}}}})
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/tmp/a"})[0])
        self.assertFalse(jail_mod.tool_allowed(
            pol, "read_file", {"path": {"$ref": "/tmp/a"}})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "read_file", {})[0])
        # an empty object/array is a value too (round 4): it needs a rule
        # at its path like any other value - unknown keys never slip in
        for extra in ({"tags": []}, {"opts": {}}):
            ok, reason = jail_mod.tool_allowed(
                pol, "read_file", {"path": "/tmp/a", **extra})
            self.assertFalse(ok, extra)
            self.assertIn("matches no allow pattern", reason)
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"allow": {"path": ["^/tmp/"],
                                    "tags": [{"type": "array"}]}}}})
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/tmp/a", "tags": []})[0])
        self.assertFalse(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/tmp/a", "tags": ["x"]})[0])
        self.assertFalse(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/tmp/a", "tags": {}})[0])

    def test_scalars_are_matched_as_json_text(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "t": {"allow": {"n": [r"^\d+$"], "b": ["^true$"],
                            "z": ["^null$"]}}}})
        self.assertTrue(jail_mod.tool_allowed(
            pol, "t", {"n": 3, "b": True, "z": None})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"n": -1})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"b": False})[0])

    def test_generated_policy_generalises_array_indices(self):
        pol = jail_mod.generate_policy(
            [], [("t", {"tags": ["x", "y"], "cfg": {"a": 1}})])
        self.assertEqual(sorted(pol["arg_rules"]["t"]["allow"]),
                         ["cfg.a", "tags.*"])
        c = compiled(pol)
        self.assertTrue(jail_mod.tool_allowed(
            c, "t", {"tags": ["y", "x", "x"], "cfg": {"a": 42}})[0])
        self.assertFalse(jail_mod.tool_allowed(
            c, "t", {"tags": ["z"], "cfg": {"a": 1}})[0])

    def test_malformed_rules_fail_closed_at_startup(self):
        tmp = mktemp()
        for bad in ({"arg_rules": {"t": {"allow": 5}}},
                    {"arg_rules": {"t": {"deny": {"a": ["("]}}}},
                    {"arg_rules": {"t": ["x"]}},
                    {"arg_rules": {"t": {"deny": {"a..b": ["x"]}}}}):
            with self.assertRaises((ValueError, re.error), msg=repr(bad)):
                jail_mod.compile_policy(json.loads(json.dumps(bad)))
            p = write_policy(tmp, bad)
            err = io.StringIO()
            with redirect_stderr(err):
                code = jail_mod.run(p, [sys.executable, "-c", "pass"])
            self.assertEqual(code, 2)
            self.assertIn("bad policy", err.getvalue())


# --------------------------------------------------------------------------
# proxy behaviour
# --------------------------------------------------------------------------


class ProxyCase(unittest.TestCase):
    def setUp(self):
        self.tmp = mktemp()
        self.server = write_server(self.tmp)
        self._old_audit = jail_mod.AUDIT_LOG
        jail_mod.AUDIT_LOG = os.path.join(self.tmp, "audit.jsonl")

    def tearDown(self):
        jail_mod.AUDIT_LOG = self._old_audit
        _rmtree(self.tmp)

    def srv(self, src: str, name: str) -> str:
        return write_server(self.tmp, src, name)


class TestProxy(ProxyCase):
    def test_allowed_call_proxied(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"p": "x"}}}])
        self.assertEqual(len(resps), 1)
        text = resps[0]["result"]["content"][0]["text"]
        self.assertEqual(text, "did:read_file")

    def test_denied_call_blocked(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": False})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "delete_all", "arguments": {}}}])
        self.assertEqual(len(resps), 1)
        self.assertIn("error", resps[0])
        self.assertIn("denied", resps[0]["error"]["message"])
        # audit log recorded the deny
        with open(jail_mod.AUDIT_LOG, encoding="utf-8") as f:
            entry = json.loads(f.read().strip().splitlines()[-1])
        self.assertEqual(entry["decision"], "deny")
        self.assertEqual(entry["tool"], "delete_all")

    def test_hide_denied_tools(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": True})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
        names = [t["name"] for t in resps[0]["result"]["tools"]]
        self.assertIn("read_file", names)
        self.assertNotIn("delete_all", names)

    def test_arg_deny_pattern_live(self):
        pol = write_policy(self.tmp, {
            "allow_tools": ["*"], "deny_tools": [],
            "arg_rules": {"run_cmd": {"deny": ["rm -rf"], "allow": []}},
            "hide_denied": False})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "run_cmd", "arguments": {"cmd": "rm -rf /"}}}
        ])
        self.assertIn("error", resps[0])

    def test_passthrough_initialize(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"], "deny_tools": [],
                                      "arg_rules": {}})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}])
        self.assertEqual(resps[0]["result"]["protocolVersion"], "2024-11-05")

    def test_utf8_arguments_survive_the_wire(self):
        srv = self.srv(FAKE_NOTIFY, "notify.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        path = "/tmp/ü/日本/café.txt"
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": path}}}])
        results = [r for r in resps if "result" in r]
        self.assertEqual(results[0]["result"]["args"], {"path": path})


class TestHideDenied(ProxyCase):
    """Panel finding 3: hide_denied must hide exactly the tools that are
    denied by name, on every page, and tools/call must agree with it."""

    def test_arg_rules_do_not_hide_callable_tools(self):
        # a `learn` policy has allow rules for every tool it saw; those
        # tools must still be listed (the old code hid all of them)
        gen = jail_mod.generate_policy(
            ["read_file", "run_cmd"],
            [("read_file", {"path": "/tmp/a"}), ("run_cmd", {"cmd": "ls"})])
        pol = write_policy(self.tmp, gen)
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": "/tmp/a"}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": "/etc/pw"}}},
        ])
        by_id = {r["id"]: r for r in resps}
        names = [t["name"] for t in by_id[1]["result"]["tools"]]
        self.assertEqual(names, ["read_file", "run_cmd"])  # delete_all hidden
        self.assertIn("result", by_id[2])
        self.assertIn("error", by_id[3])

    def test_hidden_tool_call_is_denied(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": True})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "delete_all", "arguments": {}}}])
        by_id = {r["id"]: r for r in resps}
        self.assertNotIn("delete_all",
                         [t["name"] for t in by_id[1]["result"]["tools"]])
        self.assertIn("error", by_id[2])
        self.assertIn("denied", by_id[2]["error"]["message"])

    def test_paginated_list_filtered_on_every_page(self):
        srv = self.srv(FAKE_PAGED, "paged.py")
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": True})
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
             "params": {"cursor": "p2"}}])
        by_id = {r["id"]: r for r in resps}
        page1, page2 = by_id[1]["result"], by_id[2]["result"]
        self.assertEqual([t["name"] for t in page1["tools"]], ["read_file"])
        self.assertEqual(page1.get("nextCursor"), "p2")  # pagination intact
        self.assertEqual([t["name"] for t in page2["tools"]], ["run_cmd"])
        self.assertNotIn("nextCursor", page2)

    def test_malformed_tool_entry_does_not_fail_open(self):
        # page 2 of FAKE_PAGED has an entry without a name next to a
        # denied tool: the old code hit KeyError and sent the page unfiltered
        srv = self.srv(FAKE_PAGED, "paged.py")
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": True})
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list",
             "params": {"cursor": "p2"}}])
        names = [t.get("name") for t in resps[0]["result"]["tools"]]
        self.assertNotIn("delete_all", names)
        self.assertNotIn(None, names)

    def test_hide_denied_false_lists_everything(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": False})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
        self.assertIn("delete_all",
                      [t["name"] for t in resps[0]["result"]["tools"]])

    def test_filter_tools_list_unit(self):
        pol = {"allow_tools": ["a"], "deny_tools": [], "arg_rules": {}}
        result = {"tools": [{"name": "a"}, {"name": "b"}, "junk", {}],
                  "nextCursor": "n"}
        jail_mod.filter_tools_list(pol, result)
        self.assertEqual(result, {"tools": [{"name": "a"}], "nextCursor": "n"})


class TestIdMatching(ProxyCase):
    """Panel finding 2: responses are matched by exact id; denials carry
    the request's id and type; notifications never get a response."""

    def test_denied_notification_gets_no_response(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": False})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "method": "tools/call",
             "params": {"name": "delete_all", "arguments": {}}},
            {"jsonrpc": "2.0", "id": "after", "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}}])
        self.assertEqual([r.get("id") for r in resps], ["after"])
        with open(jail_mod.AUDIT_LOG, encoding="utf-8") as f:
            decisions = [json.loads(l)["decision"] for l in f if l.strip()]
        self.assertEqual(decisions, ["deny", "allow"])  # still audited

    def test_allowed_notification_forwarded_without_response(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_RECORDER, "rec.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"n": 1}}},
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}, "flush": True}},
        ], timeout=5, server_args=[log])
        self.assertEqual([r["id"] for r in resps], [9])
        with open(log, encoding="utf-8") as f:
            seen = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(seen), 2)
        self.assertNotIn("id", seen[0])
        self.assertEqual(seen[0]["params"]["arguments"], {"n": 1})

    def test_server_notifications_do_not_shift_responses(self):
        srv = self.srv(FAKE_NOTIFY, "notify.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"a": 1}}},
            {"jsonrpc": "2.0", "id": "two", "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"a": 2}}}])
        notes = [r for r in resps if r.get("method")]
        results = [r for r in resps if "result" in r]
        self.assertEqual(len(notes), 2, resps)  # passed through, in order
        self.assertEqual([r["id"] for r in results], [1, "two"])
        self.assertEqual([r["result"]["echo"] for r in results], [1, "two"])
        self.assertIsInstance(results[0]["id"], int)
        self.assertIsInstance(results[1]["id"], str)

    def test_string_and_number_ids_are_distinct_and_order_independent(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_RECORDER, "rec.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        # the recorder answers the two in REVERSE order
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}},
            {"jsonrpc": "2.0", "id": "1", "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}}],
            timeout=5, server_args=[log])
        self.assertEqual([(type(r["id"]).__name__, r["id"]) for r in resps],
                         [("str", "1"), ("int", 1)])
        for r in resps:
            self.assertEqual(r["result"]["echo"], r["id"])
            self.assertIs(type(r["result"]["echo"]), type(r["id"]))

    def test_duplicate_ids_each_get_a_response(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_RECORDER, "rec.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"n": 1}}},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"n": 2}}}],
            timeout=5, server_args=[log])
        self.assertEqual([r["id"] for r in resps], [7, 7])

    def test_denial_keeps_id_type(self):
        pol = write_policy(self.tmp, {"allow_tools": [], "deny_tools": [],
                                      "arg_rules": {}, "hide_denied": False})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": "s-1", "method": "tools/call",
             "params": {"name": "x", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 0, "method": "tools/call",
             "params": {"name": "x", "arguments": {}}}])
        self.assertEqual([r["id"] for r in resps], ["s-1", 0])
        self.assertTrue(all(r["error"]["code"] == -32602 for r in resps))

    def test_batch_is_split_per_element(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": False})
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "delete_all", "arguments": {}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ]
        resps = drive_jail(pol, self.server, [json.dumps(batch)])
        by_id = {r["id"]: r for r in resps}
        self.assertEqual(set(by_id), {1, 2})
        self.assertEqual(by_id[1]["result"]["content"][0]["text"], "did:read_file")
        self.assertIn("denied", by_id[2]["error"]["message"])

    def test_parse_and_invalid_request_errors(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, self.server, [
            "{not json", "[]", "42",
            {"jsonrpc": "2.0", "id": 5, "method": 12},
            {"jsonrpc": "2.0", "id": 6, "method": "initialize", "params": {}}])
        codes = [r["error"]["code"] for r in resps if "error" in r]
        self.assertEqual(codes, [-32700, -32600, -32600, -32600])
        self.assertTrue(all(r["id"] is None for r in resps[:3]))
        self.assertEqual(resps[3]["id"], 5)
        self.assertEqual(resps[4]["id"], 6)
        self.assertIn("result", resps[4])

    def test_server_to_client_request_round_trip(self):
        srv = self.srv(FAKE_ASKER, "asker.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}},
            # the client's answer to the server's sampling request
            {"jsonrpc": "2.0", "id": "srv-q1", "result": {"role": "user"}},
        ])
        self.assertEqual(resps[0]["method"], "sampling/createMessage")
        self.assertEqual(resps[0]["id"], "srv-q1")
        self.assertEqual(resps[1]["id"], 1)
        self.assertEqual(resps[1]["result"]["client_said"], {"role": "user"})

    def test_upstream_response_is_delivered_re_serialised(self):
        srv = self.srv(FAKE_ASKER, "asker.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        raw = drive_raw(pol, [sys.executable, srv], [
            {"jsonrpc": "2.0", "id": "raw", "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}}])
        self.assertEqual(
            raw, [b'{"result":{"b":1.0,"a":"\\u00e9\\u65e5"},"id":"raw","jsonrpc":"2.0"}'])

    def test_crlf_frames_from_upstream_are_delivered_as_lf(self):
        # Windows text-mode servers end every frame with CRLF; the proxy
        # normalises the terminator and leaves the JSON bytes alone.
        srv = self.srv(FAKE_ASKER, "asker.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        raw = drive_raw(pol, [sys.executable, srv], [
            {"jsonrpc": "2.0", "id": "crlf", "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}}])
        self.assertEqual(raw, [b'{"result":{"ok":true},"id":"crlf","jsonrpc":"2.0"}'])
        self.assertNotIn(b"\r", b"".join(raw))

    def test_late_response_after_timeout_is_dropped(self):
        srv = self.srv(FAKE_SLOW, "slow.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "t", "arguments": {"delay": 1.5}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "t", "arguments": {"delay": 2.0}}}],
            timeout=0.5)
        self.assertEqual([r["id"] for r in resps], [1, 2])
        for r in resps:
            self.assertIn("timed out", r["error"]["message"])
        # exactly one message per id: the late results were dropped
        time.sleep(0.1)


# --------------------------------------------------------------------------
# transport (panel finding 4): no select(), works through real pipes
# --------------------------------------------------------------------------


class TestTransport(ProxyCase):
    def test_no_select_or_posix_only_calls_in_package(self):
        pkg = os.path.join(REPO, "mcp_jail")
        for name in os.listdir(pkg):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(pkg, name), encoding="utf-8") as f:
                src = f.read()
            for banned in ("import select", "select.select(", "import fcntl",
                           "os.killpg(", "signal.SIGKILL"):
                self.assertNotIn(banned, src, f"{name} uses {banned}")

    def test_end_to_end_subprocess_both_directions(self):
        """The real entry point as a subprocess, talking to the fake
        server through real OS pipes, read by a thread (never select)."""
        srv = self.srv(FAKE_NOTIFY, "notify.py")
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": True})
        env = child_env()
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_jail", "--policy", pol, "--timeout", "10",
             "--", sys.executable, srv],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, cwd=self.tmp)
        lines: list[bytes] = []

        def pump():
            for ln in iter(proc.stdout.readline, b""):
                lines.append(ln)

        t = threading.Thread(target=pump, daemon=True)
        t.start()
        try:
            reqs = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "read_file",
                            "arguments": {"path": "café/日"}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "delete_all", "arguments": {}}},
            ]
            for r in reqs:
                proc.stdin.write((json.dumps(r) + "\n").encode("utf-8"))
                proc.stdin.flush()
            proc.stdin.close()
            proc.wait(timeout=20)
            t.join(timeout=5)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            err = proc.stderr.read()
            proc.stdout.close()
            proc.stderr.close()
        self.assertEqual(proc.returncode, 0, err)
        msgs = [json.loads(ln.decode("utf-8")) for ln in lines if ln.strip()]
        by_id = {m["id"]: m for m in msgs if "id" in m}
        self.assertEqual(set(by_id), {1, 2, 3})
        self.assertEqual(by_id[2]["result"]["args"], {"path": "café/日"})
        self.assertIn("denied", by_id[3]["error"]["message"])
        self.assertEqual(sum(1 for m in msgs if m.get("method")), 2)


class TestHardening(ProxyCase):
    """Round-3 panel findings: response handling must never kill the proxy."""

    def test_v9_bad_response_line(self):
        # V9: a non-JSON line from the server answers nothing (round 4:
        # it is logged and skipped, not charged to a pending request);
        # the call it never answered is caught by --timeout, proxy alive
        server = self.srv(FAKE_FLAKY, "flaky.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        err = io.StringIO()
        with redirect_stderr(err):
            resps = drive_jail(pol, server, [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "garbage", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                 "params": {"name": "read_file", "arguments": {}}},
            ], timeout=1.0)
        by_id = {r["id"]: r for r in resps}
        self.assertEqual(set(by_id), {1, 2})
        self.assertEqual(by_id[1]["error"]["code"], -32603)
        self.assertIn("timed out", by_id[1]["error"]["message"])
        self.assertIn("ignoring non-JSON line", err.getvalue())
        self.assertIn("THIS IS NOT JSON", err.getvalue())
        # proxy survived: the next call still works
        self.assertEqual(by_id[2].get("result"), {"ok": True})

    def test_v10_server_timeout(self):
        # V10: server that never responds -> timeout error, no hang
        server = self.srv(FAKE_HANG, "hang.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        start = time.monotonic()
        resps = drive_jail(pol, server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}},
        ], timeout=1.0)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 15,
                        "proxy hung on a silent server instead of timing out")
        self.assertEqual(len(resps), 1)
        self.assertIn("error", resps[0])
        self.assertEqual(resps[0]["error"]["code"], -32603)
        self.assertIn("timed out", resps[0]["error"]["message"])

    def test_v11_null_params(self):
        # V11: tools/call with params:null -> clean -32602 denial, no crash
        pol = write_policy(self.tmp, {"allow_tools": ["read_file"],
                                      "deny_tools": [], "arg_rules": {},
                                      "hide_denied": False})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": None},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"p": "x"}}},
        ])
        self.assertEqual(len(resps), 2)
        self.assertIn("error", resps[0])
        self.assertEqual(resps[0]["error"]["code"], -32602)
        # proxy alive: the follow-up valid call is proxied through
        text = resps[1]["result"]["content"][0]["text"]
        self.assertEqual(text, "did:read_file")

    def test_server_exit_fails_pending_and_stops(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, write_server(self.tmp, "import sys\nsys.stdin.readline()\n", "quit.py"), [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}}])
        self.assertEqual(len(resps), 1)
        self.assertEqual(resps[0]["id"], 1)
        self.assertIn("server closed", resps[0]["error"]["message"])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


class TestCLI(unittest.TestCase):
    def setUp(self):
        self._old_audit = jail_mod.AUDIT_LOG
        jail_mod.AUDIT_LOG = None  # exercise the HOME-relative default

    def tearDown(self):
        jail_mod.AUDIT_LOG = self._old_audit

    def test_init_policy(self):
        tmp = mktemp()
        p = os.path.join(tmp, "sub", "policy.json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main(["--init-policy", "--path", p])
        self.assertEqual(code, 0)
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("allow_tools", data)
        jail_mod.load_policy(p)  # the starter policy compiles

    def test_no_server(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main([])
        self.assertEqual(code, 2)

    def test_bad_policy(self):
        tmp = mktemp()
        p = os.path.join(tmp, "bad.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write("{not json")
        code = jail_mod.run(p, [sys.executable, "-c", "pass"])
        self.assertEqual(code, 2)

    def test_missing_policy(self):
        code = jail_mod.run(os.path.join(mktemp(), "nope", "policy.json"),
                            [sys.executable, "-c", "pass"])
        self.assertEqual(code, 2)

    def test_default_paths_follow_home_env(self):
        # setUpModule pointed HOME/USERPROFILE at a throwaway dir: every
        # default path must land there, never in the real home
        self.assertTrue(jail_mod.default_policy_path().startswith(_fake_home))
        self.assertTrue(jail_mod.audit_log_path().startswith(_fake_home))
        self.assertEqual(cli_mod.build_parser().get_default("policy"),
                         jail_mod.default_policy_path())
        jail_mod.audit({"tool": "t", "decision": "allow", "reason": ""})
        self.assertTrue(os.path.isfile(
            os.path.join(_fake_home, ".mcp-jail", "audit.jsonl")))

    def test_audit_output_survives_cp1252_console(self):
        jail_mod.audit({"tool": "café_日本", "decision": "deny",
                        "reason": "tool 'café_日本' is denied"})
        raw = io.BytesIO()
        console = io.TextIOWrapper(raw, encoding="cp1252", errors="strict",
                                   write_through=True)
        with redirect_stdout(console):
            code = cli_mod.main(["--audit"])
        console.flush()
        self.assertEqual(code, 0)
        text = raw.getvalue().decode("cp1252")
        self.assertIn("DENY", text)
        self.assertIn("café", text)  # encodable chars kept, others replaced

    def test_version_matches_pyproject(self):
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
            data = tomllib.load(f)
        self.assertEqual(data["project"]["version"], cli_mod.VERSION)
        self.assertEqual(data["project"]["scripts"]["mcp-jail"],
                         "mcp_jail.cli:main")
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(cli_mod.VERSION, buf.getvalue())


# --------------------------------------------------------------------------
# learn
# --------------------------------------------------------------------------


class TestLearn(ProxyCase):
    def test_learn_script_policy(self):
        script = os.path.join(self.tmp, "calls.json")
        with open(script, "w", encoding="utf-8") as f:
            json.dump([
                {"tool": "read_file",
                 "arguments": {"path": "/tmp/a.txt"}},
                {"tool": "read_file",
                 "arguments": {"path": "/tmp/b.txt"}},
                {"tool": "run_cmd",
                 "arguments": {"cmd": "ls", "count": 3, "verbose": True,
                               "mode": None, "tags": ["x", "y"],
                               "cfg": {"a": 1}}},
            ], f)
        out = os.path.join(self.tmp, "gen.json")
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.learn([sys.executable, self.server],
                                  script=script, out=out, timeout=5)
        self.assertEqual(code, 0)
        with open(out, encoding="utf-8") as f:
            raw = json.load(f)
        # allowlist is exactly the CALLED tools, no "*": the fake server
        # advertises delete_all in tools/list but the script never calls
        # it, so it is reported for review and denied
        self.assertEqual(raw["allow_tools"], ["read_file", "run_cmd"])
        self.assertEqual(raw["_not_called"], ["delete_all"])
        self.assertTrue(raw["strict_args"])
        # per-path allow rules in the documented object form
        self.assertEqual(sorted(raw["arg_rules"]["run_cmd"]["allow"]),
                         ["cfg.a", "cmd", "count", "mode", "tags.*", "verbose"])

        pol = jail_mod.load_policy(out)  # compiles the generated regexes
        ok, _ = jail_mod.tool_allowed(pol, "read_file",
                                      {"path": "/tmp/a.txt"})
        self.assertTrue(ok, "observed shape must be accepted")
        ok, reason = jail_mod.tool_allowed(pol, "read_file",
                                           {"path": "/etc/passwd"})
        self.assertFalse(ok, f"unobserved shape must be rejected: {reason}")
        ok, _ = jail_mod.tool_allowed(pol, "run_cmd",
                                      {"cmd": "ls", "count": 3,
                                       "verbose": True, "mode": None,
                                       "tags": ["x", "y"], "cfg": {"a": 1}})
        self.assertTrue(ok, "observed shape must be accepted")
        ok, reason = jail_mod.tool_allowed(
            pol, "run_cmd",
            {"cmd": "evil", "count": "nope", "verbose": "maybe",
             "mode": "x", "tags": ["z"], "cfg": {"b": 2}})
        self.assertFalse(ok, f"unobserved shape must be rejected: {reason}")
        ok, _ = jail_mod.tool_allowed(pol, "drop_table", {})
        self.assertFalse(ok, "unobserved tool must be rejected")
        ok, _ = jail_mod.tool_allowed(pol, "delete_all", {})
        self.assertFalse(ok, "listed-but-never-called tool must be rejected")

        summary = err.getvalue()
        self.assertIn("3 tool(s) listed", summary)
        self.assertIn("2 tool(s) called", summary)
        self.assertIn("3 successful call", summary)

    def test_learn_script_ignores_server_notifications(self):
        srv = self.srv(FAKE_NOTIFY, "notify.py")
        script = os.path.join(self.tmp, "calls.json")
        with open(script, "w", encoding="utf-8") as f:
            json.dump([{"tool": "read_file", "arguments": {"path": "/tmp/a"}},
                       {"tool": "read_file", "arguments": {"path": "/tmp/b"}}], f)
        err = io.StringIO()
        out = io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            code = jail_mod.learn([sys.executable, srv], script=script, timeout=5)
        self.assertEqual(code, 0)
        self.assertNotIn("timed out", err.getvalue())
        pol = json.loads(out.getvalue())
        self.assertEqual(pol["allow_tools"], ["read_file"])
        self.assertEqual(pol["arg_rules"]["read_file"]["allow"],
                         {"path": [{"type": "string",
                                    "pattern": r"\A" + jail_mod._TRAVERSAL_GUARD
                                    + r"/tmp/[a-z]*\Z"}]})

    def test_learn_live_mode_records_and_passes_through(self):
        inp = io.BytesIO(("\n".join(json.dumps(r) for r in [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "run_cmd", "arguments": {"cmd": "ls"}}},
        ]) + "\n").encode("utf-8"))
        client_out = io.BytesIO()
        out = os.path.join(self.tmp, "live.json")
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.learn([sys.executable, self.server], out=out,
                                  timeout=5, stdin=inp, stdout=client_out)
        self.assertEqual(code, 0)
        resps = [json.loads(l) for l in client_out.getvalue().split(b"\n") if l.strip()]
        self.assertEqual([r["id"] for r in resps], [1, 2, 3])
        # nothing hidden while learning: the full tool list went through
        self.assertEqual(len(resps[1]["result"]["tools"]), 3)
        with open(out, encoding="utf-8") as f:
            pol = json.load(f)
        # only the called tool is allowed; the two merely listed are
        # reported for the reviewer and denied
        self.assertEqual(pol["allow_tools"], ["run_cmd"])
        self.assertEqual(pol["_not_called"], ["delete_all", "read_file"])
        self.assertEqual(pol["arg_rules"], {"run_cmd": {
            "allow": {"cmd": [{"type": "string", "pattern": r"\Als\Z"}]},
            "deny": {}}})


# --------------------------------------------------------------------------
# Round 3 panel findings
# --------------------------------------------------------------------------

# Parses with FIRST-duplicate-key-wins semantics (the opposite of Python),
# records every raw line it receives, and reports which tool it ran.
FAKE_FIRSTWINS = r"""
import json, sys
log = open(sys.argv[1], "a", encoding="utf-8")
def first_wins(pairs):
    d = {}
    for k, v in pairs:
        d.setdefault(k, v)
    return d
inp, out = sys.stdin.buffer, sys.stdout.buffer
for raw in iter(inp.readline, b""):
    line = raw.decode("utf-8").strip()
    if not line:
        continue
    log.write(line + "\n"); log.flush()
    req = json.loads(line, object_pairs_hook=first_wins)
    rid = req.get("id")
    if rid is None:
        continue
    p = req.get("params") or {}
    r = {"jsonrpc": "2.0", "id": rid,
         "result": {"ran": p.get("name"), "args": p.get("arguments")}}
    out.write((json.dumps(r) + "\n").encode("utf-8")); out.flush()
"""

# Answers every request with a JSON ARRAY: [response] for calls,
# [response, notification] for tools/list.
FAKE_BATCHER = r"""
import json, sys
inp, out = sys.stdin.buffer, sys.stdout.buffer
TOOLS = [{"name": "read_file"}, {"name": "delete_all"}]
for raw in iter(inp.readline, b""):
    line = raw.decode("utf-8").strip()
    if not line:
        continue
    msg = json.loads(line)
    rid = msg.get("id")
    if rid is None:
        continue
    if msg.get("method") == "tools/list":
        batch = [{"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}},
                 {"jsonrpc": "2.0", "method": "notifications/message",
                  "params": {"level": "info", "data": "in-batch note"}}]
    else:
        batch = [{"jsonrpc": "2.0", "id": rid, "result": {"echo": rid}}]
    out.write((json.dumps(batch) + "\n").encode("utf-8")); out.flush()
"""

# tools/call "broken" -> JSON-RPC error; "toolerr" -> MCP isError result;
# everything else succeeds. Lists delete_all, which nobody calls.
FAKE_ERRORS = r"""
import json, sys
TOOLS = [{"name": "read_file"}, {"name": "broken"}, {"name": "toolerr"},
         {"name": "delete_all"}]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if rid is None:
        continue
    if m == "tools/list":
        r = {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    elif m == "tools/call":
        name = req["params"]["name"]
        if name == "broken":
            r = {"jsonrpc": "2.0", "id": rid,
                 "error": {"code": -32602, "message": "unknown tool"}}
        elif name == "toolerr":
            r = {"jsonrpc": "2.0", "id": rid,
                 "result": {"isError": True,
                            "content": [{"type": "text", "text": "no such file"}]}}
        else:
            r = {"jsonrpc": "2.0", "id": rid,
                 "result": {"content": [{"type": "text", "text": "ok"}]}}
    else:
        r = {"jsonrpc": "2.0", "id": rid, "result": {}}
    sys.stdout.write(json.dumps(r) + "\n")
    sys.stdout.flush()
"""


def call(req_id, name, args, **extra):
    msg = {"jsonrpc": "2.0", "method": "tools/call",
           "params": {"name": name, "arguments": args}}
    if req_id is not None or "id" in extra:
        msg["id"] = req_id
    msg.update(extra)
    return msg


class TestLearnAllowlist(ProxyCase):
    """J-1: learn allowlists what was CALLED, never what was merely listed,
    and a learned policy never passes unseen argument shapes."""

    def test_listed_but_never_called_tools_are_denied(self):
        gen = jail_mod.generate_policy(
            ["delete_all", "read_file", "run_cmd"],
            [("read_file", {"path": "/tmp/a"})])
        self.assertEqual(gen["allow_tools"], ["read_file"])
        self.assertEqual(gen["_not_called"], ["delete_all", "run_cmd"])
        pol = compiled(gen)
        self.assertTrue(jail_mod.tool_allowed(pol, "read_file", {"path": "/tmp/a"})[0])
        # the old policy listed them in allow_tools with no arg rules:
        # anything went
        self.assertFalse(jail_mod.tool_allowed(pol, "delete_all", {})[0])
        self.assertFalse(jail_mod.tool_allowed(
            pol, "run_cmd", {"cmd": "rm -rf /"})[0])
        # end to end: the fake server lists delete_all, the script calls
        # only read_file
        script = os.path.join(self.tmp, "calls.json")
        with open(script, "w", encoding="utf-8") as f:
            json.dump([{"tool": "read_file", "arguments": {"path": "/tmp/a"}}], f)
        out = os.path.join(self.tmp, "gen.json")
        with redirect_stderr(io.StringIO()):
            code = jail_mod.learn([sys.executable, self.server], script=script,
                                  out=out, timeout=5)
        self.assertEqual(code, 0)
        pol = jail_mod.load_policy(out)
        self.assertEqual(pol["allow_tools"], ["read_file"])
        for tool in ("delete_all", "run_cmd"):
            ok, reason = jail_mod.tool_allowed(pol, tool, {"x": "anything"})
            self.assertFalse(ok, tool)
            self.assertIn("not in allow_tools", reason)

    def test_tool_called_without_arguments_accepts_only_empty_arguments(self):
        gen = jail_mod.generate_policy(
            [], [("ping", {}), ("read_file", {"path": "/tmp/a"})])
        self.assertTrue(gen["strict_args"])
        self.assertEqual(gen["arg_rules"]["ping"], {"allow": {}, "deny": {}})
        pol = compiled(gen)
        self.assertTrue(jail_mod.tool_allowed(pol, "ping", {})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "ping", None)[0])
        ok, reason = jail_mod.tool_allowed(pol, "ping", {"target": "10.0.0.1"})
        self.assertFalse(ok, "no allow patterns must not mean anything goes")
        self.assertIn("strict_args", reason)
        # the documented opt-out: "allow": "*" admits any arguments...
        gen["arg_rules"]["ping"]["allow"] = "*"
        gen["arg_rules"]["ping"]["deny"] = ["evil"]
        pol = compiled(gen)
        self.assertTrue(jail_mod.tool_allowed(pol, "ping", {"target": "x"})[0])
        # ...but deny rules still apply
        self.assertFalse(jail_mod.tool_allowed(pol, "ping", {"target": "evil"})[0])
        # and the policy still fails closed at load on a bad allow spec
        with self.assertRaises((ValueError, re.error)):
            jail_mod.compile_policy({"arg_rules": {"ping": {"allow": "("}}})
        # a tool allowed by name but missing from arg_rules is strict too
        pol = compiled({"allow_tools": ["*"], "arg_rules": {}, "strict_args": True})
        self.assertFalse(jail_mod.tool_allowed(pol, "anything", {"a": 1})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "anything", {})[0])

    def test_hand_written_policies_keep_their_meaning(self):
        # no strict_args: a tool without allow patterns accepts anything
        # not denied (the README's deny-only examples)
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"deny": {"path": ["^/etc/"]}, "allow": {}}}})
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/tmp/a", "mode": "r"})[0])
        self.assertFalse(jail_mod.default_policy()["strict_args"])
        with self.assertRaises(ValueError):
            jail_mod.compile_policy({"strict_args": "yes"})


class TestPolicyPath(unittest.TestCase):
    """J-2: ~ and environment variables in --policy / --path / --out are
    expanded by mcp-jail itself: MCP clients pass arguments from a JSON
    config, no shell in between."""

    def test_tilde_and_env_vars_expand(self):
        d = os.path.join(_fake_home, ".mcp-jail")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "policy.json"), "w", encoding="utf-8") as f:
            json.dump(ALLOW_ALL, f)
        for spec in ("~/.mcp-jail/policy.json",
                     os.path.join("${HOME}", ".mcp-jail", "policy.json")):
            err = io.StringIO()
            with redirect_stderr(err):
                code = jail_mod.run(spec, [sys.executable, "-c", "pass"],
                                    stdin=io.BytesIO(b""), stdout=io.BytesIO())
            self.assertEqual(code, 0, f"{spec}: {err.getvalue()}")
        # a genuinely missing policy still says so, with the expanded path
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.run("~/.mcp-jail/nope.json", [sys.executable, "-c", "pass"],
                                stdin=io.BytesIO(b""), stdout=io.BytesIO())
        self.assertEqual(code, 2)
        self.assertIn(os.path.join(_fake_home, ".mcp-jail", "nope.json"),
                      err.getvalue())

    def test_init_policy_path_expands_too(self):
        with redirect_stdout(io.StringIO()):
            code = cli_mod.main(["--init-policy", "--path",
                                 "~/.mcp-jail/sub/policy.json"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(
            os.path.join(_fake_home, ".mcp-jail", "sub", "policy.json")))


class TestDuplicateKeys(ProxyCase):
    """J-3: the policy is evaluated on the parsed object, so the server
    must receive exactly that object - never bytes it might parse
    differently (first-duplicate-key-wins)."""

    def test_duplicate_keys_are_rejected_and_checked_object_is_forwarded(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_FIRSTWINS, "firstwins.py")
        pol = write_policy(self.tmp, {
            "allow_tools": ["*"], "deny_tools": ["delete_all"],
            "arg_rules": {"read_file": {"deny": {"path": ["^/etc/"]}}},
            "hide_denied": False})
        good = ('  { "params" : {"arguments": {"path": "/tmp/ok"} , "name":"read_file"},'
                ' "id":3, "method":"tools/call", "jsonrpc":"2.0" }  ')
        resps = drive_jail(pol, srv, [
            # Python keeps the LAST duplicate: the old proxy checked
            # read_file / "/tmp/ok" and forwarded the raw bytes, and the
            # server ran delete_all on /etc/passwd
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
            '{"name":"delete_all","name":"read_file","arguments":{"path":"/tmp/ok"}}}',
            '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":'
            '{"name":"read_file","arguments":{"path":"/etc/passwd","path":"/tmp/ok"}}}',
            # and the bytes of a legitimate request are not what the
            # server sees: it sees the checked object, re-encoded
            good,
        ], server_args=[log])
        self.assertEqual(len(resps), 3)
        for r in resps[:2]:
            self.assertEqual(r["error"]["code"], -32600)
            self.assertIn("duplicate key", r["error"]["message"])
            self.assertIsNone(r["id"])
        self.assertEqual(resps[2]["result"]["ran"], "read_file")
        with open(log, encoding="utf-8") as f:
            seen = [l.rstrip("\n") for l in f if l.strip()]
        self.assertEqual(len(seen), 1, "a duplicate-key document reached the server")
        self.assertEqual(seen[0], json.dumps(json.loads(good), separators=(",", ":")))
        self.assertNotEqual(seen[0], good.strip())

    def test_duplicate_keys_from_the_server_fail_the_request_closed(self):
        srv = self.srv(FAKE_ASKER, "asker.py")  # answers id "raw" with odd JSON
        pol = write_policy(self.tmp, ALLOW_ALL)
        # a normal response still passes byte-for-byte
        raw = drive_raw(pol, [sys.executable, srv], [call("raw", "read_file", {})])
        self.assertEqual(
            raw, [b'{"result":{"b":1.0,"a":"\\u00e9\\u65e5"},"id":"raw","jsonrpc":"2.0"}'])
        # a duplicate-key document in the wire format is refused by _parse
        obj, code, err = jail_mod._parse(b'{"id":1,"id":2,"result":{}}\n')
        self.assertIsNone(obj)
        self.assertEqual(code, -32600)
        self.assertIn("duplicate key", err)
        # NaN/Infinity are not JSON either
        self.assertEqual(jail_mod._parse(b'{"a": NaN}')[1], -32700)


class TestTraversal(unittest.TestCase):
    """J-4: an allowlist on paths is not a door to /../../etc/passwd."""

    def test_learned_path_patterns_block_dotdot_segments(self):
        gen = jail_mod.generate_policy([], [
            ("read_file", {"path": p}) for p in
            ("/srv/data/a/x.txt", "/srv/data/b/y.txt", "/srv/data/c/z.txt")])
        rule = gen["arg_rules"]["read_file"]["allow"]["path"][0]
        self.assertEqual(rule["type"], "string")
        pat = rule["pattern"]
        self.assertTrue(pat.startswith(r"\A" + jail_mod._TRAVERSAL_GUARD + "/srv/data/"))
        # the regex alone, as any other consumer of the policy would use it
        self.assertIsNone(re.search(pat, "/srv/data/../../etc/passwd"))
        self.assertIsNotNone(re.search(pat, "/srv/data/d/w.txt"))
        pol = compiled(gen)
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/srv/data/d/w.txt"})[0])
        for bad in ("/srv/data/../../etc/passwd", "/srv/data/..",
                    "/srv/data/a/../b/x.txt"):
            ok, reason = jail_mod.tool_allowed(pol, "read_file", {"path": bad})
            self.assertFalse(ok, bad)
            self.assertIn("'..'", reason)

    def test_allow_rules_never_admit_dotdot_segments(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"allow": {"path": ["^/tmp/"]}}}})
        for good in ("/tmp/a..b", "/tmp/..hidden", "/tmp/x/", "/tmp/.a"):
            self.assertTrue(jail_mod.tool_allowed(pol, "read_file", {"path": good})[0], good)
        for bad in ("/tmp/../etc/passwd", "/tmp/..", "/tmp/a/../../etc",
                    "/tmp/..\\x", "/tmp/x\\..\\y"):
            ok, reason = jail_mod.tool_allowed(pol, "read_file", {"path": bad})
            self.assertFalse(ok, bad)
            self.assertIn("'..' path segment", reason)
        # explicit opt-in: a pattern that spells out \.\. means it
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"allow": {"path": [r"^/tmp/\.\./shared/"]}}}})
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/tmp/../shared/a"})[0])
        # a bare ".." value learned as a literal is exact and stays allowed
        pol = compiled(jail_mod.generate_policy([], [("cd", {"dir": ".."})]))
        self.assertTrue(jail_mod.tool_allowed(pol, "cd", {"dir": ".."})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "cd", {"dir": "../x"})[0])


class TestDeepNesting(ProxyCase):
    """J-5: absurd nesting is an attack on the proxy's stack, not a reason
    for it to die."""

    def test_deep_json_does_not_kill_the_proxy(self):
        pol = write_policy(self.tmp, {
            "allow_tools": ["*"], "deny_tools": [],
            "arg_rules": {"read_file": {"deny": {"path": ["^/etc/"]}}},
            "hide_denied": False})
        deep_array = "[" * 100000 + "]" * 100000
        deep_obj = '{"a":' * 2000 + '1' + "}" * 2000
        # 300 levels: every supported Python parses it (3.11's C decoder
        # hits its recursion limit near 990), yet it is far past the cap
        mid = '"/tmp/ok"'
        for _ in range(300):
            mid = '{"a":' + mid + '}'
        head = '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":{"path":'
        resps = drive_jail(pol, self.server, [
            head % 1 + deep_array + "}}}",
            head % 2 + deep_obj + "}}}",
            head % 3 + mid + "}}}",
            call(4, "read_file", {"path": "/tmp/ok"}),
        ])
        self.assertEqual(len(resps), 4, resps)
        # 100k-deep: no JSON parser gets through that -> parse error
        self.assertEqual((resps[0]["id"], resps[0]["error"]["code"]), (None, -32700))
        # 2000-deep: parse error, or (a parser with a deeper C stack)
        # denied for exceeding the argument depth cap - never a crash
        self.assertIn((resps[1]["id"], resps[1]["error"]["code"]),
                      [(None, -32700), (2, -32602)])
        # 300-deep parses, and the old recursive argument walk died in it
        self.assertEqual((resps[2]["id"], resps[2]["error"]["code"]), (3, -32602))
        self.assertIn("deeper than", resps[2]["error"]["message"])
        # proxy alive, next call proxied
        self.assertEqual(resps[3]["result"]["content"][0]["text"], "did:read_file")

    def test_argument_depth_cap_is_a_denial_not_an_exception(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "t": {"deny": {"path": ["^/etc/"]}}}})
        shallow = "/tmp/ok"
        for _ in range(50):
            shallow = {"a": shallow}
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"path": shallow})[0])
        deep = "/tmp/ok"
        for _ in range(jail_mod.MAX_ARG_DEPTH + 5):
            deep = {"a": deep}
        ok, reason = jail_mod.tool_allowed(pol, "t", {"path": deep})
        self.assertFalse(ok)
        self.assertIn("deeper than", reason)
        # the deny still sees through moderately deep wrapping
        self.assertFalse(jail_mod.tool_allowed(
            pol, "t", {"path": {"a": {"b": [{"c": "/etc/shadow"}]}}})[0])
        # learn copes with it as well (no RecursionError, nothing learned)
        gen = jail_mod.generate_policy([], [("t", {"path": deep}), ("t", {"ok": 1})])
        self.assertEqual(list(gen["arg_rules"]["t"]["allow"]), ["ok"])

    def test_deep_batch_element_gets_an_error_not_a_crash(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        deep = "1"
        for _ in range(300):  # parses on every Python (3.11 dies near 990)
            deep = '{"a":' + deep + '}'
        resps = drive_jail(pol, self.server, [
            '[{"jsonrpc":"2.0","id":1,"method":"initialize","params":' + deep + '},'
            + json.dumps(call(2, "read_file", {})) + ']'])
        by_id = {r["id"]: r for r in resps}
        self.assertEqual(set(by_id), {1, 2})
        self.assertIn("result", by_id[2])
        # element 1 was either forwarded fine or refused cleanly
        self.assertTrue("result" in by_id[1] or by_id[1]["error"]["code"] == -32600)


class TestAuditLog(ProxyCase):
    """J-6: the audit log is private and does not hoard the arguments of
    every allowed call (tokens, file contents, ...)."""

    def test_log_is_private_and_holds_args_only_for_denies(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": False})
        drive_jail(pol, self.server, [
            call(1, "read_file", {"token": "SECRET-TOKEN-123"}),
            call(2, "delete_all", {"what": "everything"})])
        if os.name != "nt":
            mode = stat.S_IMODE(os.stat(jail_mod.AUDIT_LOG).st_mode)
            self.assertEqual(mode, 0o600, oct(mode))
        with open(jail_mod.AUDIT_LOG, encoding="utf-8") as f:
            text = f.read()
        entries = [json.loads(l) for l in text.splitlines() if l.strip()]
        self.assertEqual([e["decision"] for e in entries], ["allow", "deny"])
        self.assertNotIn("args", entries[0])
        self.assertEqual(entries[1]["args"], {"what": "everything"})
        self.assertNotIn("SECRET-TOKEN-123", text)

    def test_audit_args_modes_and_truncation(self):
        long_value = "x" * 1000
        for mode, expect_allow, expect_deny in (("all", True, True),
                                                ("none", False, False),
                                                ("denied", False, True)):
            if os.path.exists(jail_mod.AUDIT_LOG):
                os.remove(jail_mod.AUDIT_LOG)
            pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                          "deny_tools": ["delete_all"],
                                          "arg_rules": {}, "hide_denied": False,
                                          "audit_args": mode})
            drive_jail(pol, self.server, [
                call(1, "read_file", {"v": long_value}),
                call(2, "delete_all", {"v": long_value, "n": [1, {"k": "v"}]})])
            with open(jail_mod.AUDIT_LOG, encoding="utf-8") as f:
                entries = [json.loads(l) for l in f if l.strip()]
            self.assertEqual("args" in entries[0], expect_allow, mode)
            self.assertEqual("args" in entries[1], expect_deny, mode)
            for e in entries:
                if "args" in e:
                    self.assertEqual(e["args"]["v"], "x" * 200 + "...(+800)")
                    self.assertLess(len(json.dumps(e)), 600)
            if expect_deny:
                self.assertEqual(entries[1]["args"]["n"], [1, {"k": "v"}])
        with self.assertRaises(ValueError):
            jail_mod.compile_policy({"audit_args": "sometimes"})
        self.assertEqual(jail_mod.default_policy()["audit_args"], "denied")

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_existing_world_readable_log_is_tightened(self):
        with open(jail_mod.AUDIT_LOG, "w", encoding="utf-8") as f:
            f.write("")
        os.chmod(jail_mod.AUDIT_LOG, 0o644)
        jail_mod.audit({"tool": "t", "decision": "deny", "reason": "r"})
        self.assertEqual(stat.S_IMODE(os.stat(jail_mod.AUDIT_LOG).st_mode), 0o600)


class TestServerBatch(ProxyCase):
    """J-7: a batch response from the server is delivered exactly once."""

    def test_batch_response_delivered_exactly_once(self):
        srv = self.srv(FAKE_BATCHER, "batcher.py")
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": True})
        raw = drive_raw(pol, [sys.executable, srv], [
            call(1, "read_file", {}),
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
        lines = [json.loads(l) for l in raw]
        flat = [m for l in lines for m in (l if isinstance(l, list) else [l])]
        ids = sorted(m["id"] for m in flat if "id" in m)
        self.assertEqual(ids, [1, 2], f"a response was delivered twice: {lines}")
        # delivered as the arrays the server sent, one line each
        self.assertEqual([len(l) for l in lines], [1, 2])
        self.assertEqual(lines[0][0]["result"], {"echo": 1})
        page, note = lines[1]
        # the tools/list page inside the batch was filtered...
        self.assertEqual([t["name"] for t in page["result"]["tools"]], ["read_file"])
        # ...and the notification riding along was kept
        self.assertEqual(note["method"], "notifications/message")


class TestServerCommand(ProxyCase):
    """J-8: a missing server command is a clean exit 2, not a traceback."""

    def test_missing_server_command_is_a_clean_exit_2(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        missing = "mcp-jail-no-such-command-xyz"
        self.assertIsNone(shutil.which(missing))
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.run(pol, [missing, "--flag"],
                                stdin=io.BytesIO(b""), stdout=io.BytesIO())
        self.assertEqual(code, 2)
        self.assertIn("not found", err.getvalue())
        self.assertIn(missing, err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            code = jail_mod.learn([missing], stdin=io.BytesIO(b""),
                                  stdout=io.BytesIO())
        self.assertEqual(code, 2)
        self.assertIn("not found", err.getvalue())
        with redirect_stderr(io.StringIO()):
            self.assertEqual(cli_mod.main(["--policy", pol, "--", missing]), 2)

    def test_server_command_is_resolved_with_which(self):
        # the same lookup Windows needs for `npx` -> npx.cmd (PATHEXT):
        # a bare command name resolves through PATH
        name = os.path.basename(sys.executable)
        if shutil.which(name) is None:
            self.skipTest("interpreter not on PATH by its basename")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, self.server, [call(1, "read_file", {})])
        self.assertIn("result", resps[0])
        out = drive_raw(pol, [name, self.server], [call(1, "read_file", {})])
        self.assertIn(b"did:read_file", out[0])


class TestShutdown(ProxyCase):
    """J-9: the server exiting while the client still holds our stdin open
    used to abort the proxy with a fatal `_enter_buffered_busy` (rc -6). It
    still ends the session without a crash - and, since R5-7, with the exit
    code that says the server failed."""

    def test_server_exit_with_client_stdin_open_exits_3_without_a_crash(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        quit_srv = write_server(self.tmp, "import sys\nsys.stdin.readline()\n",
                                "quit.py")
        env = child_env()
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_jail", "--policy", pol, "--",
             sys.executable, quit_srv],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, cwd=self.tmp)
        try:
            proc.stdin.write(json.dumps(call(1, "read_file", {})).encode() + b"\n")
            proc.stdin.flush()  # and keep stdin OPEN, like a real client
            try:
                rc = proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                self.fail("proxy did not exit after the server did")
            out = proc.stdout.read()
            err = proc.stderr.read()
        finally:
            for s in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    s.close()
                except OSError:
                    pass
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        self.assertEqual(rc, 3, err)
        self.assertNotIn(b"Fatal Python error", err)
        self.assertNotIn(b"Traceback", err)
        self.assertIn(b"server exited or closed its output", err)
        resps = [json.loads(l) for l in out.splitlines() if l.strip()]
        self.assertEqual(resps[0]["id"], 1)
        self.assertIn("server closed", resps[0]["error"]["message"])

    def test_text_streams_are_refused_not_shimmed(self):
        # the text-stream fallbacks are gone: protocol I/O is bytes only
        with self.assertRaises(TypeError):
            jail_mod._Writer(io.StringIO())
        with self.assertRaises(TypeError):
            jail_mod._binary_in(io.StringIO())
        self.assertFalse(hasattr(jail_mod, "DEFAULT_POLICY_PATH"))


class TestLearnRecordsSuccessOnly(ProxyCase):
    """J-10: learn records a call only once the server answered it
    successfully, and learned number patterns accept exponent notation."""

    def test_script_mode_skips_failed_calls(self):
        srv = self.srv(FAKE_ERRORS, "errors.py")
        script = os.path.join(self.tmp, "calls.json")
        with open(script, "w", encoding="utf-8") as f:
            json.dump([{"tool": "read_file", "arguments": {"path": "/tmp/a"}},
                       {"tool": "broken", "arguments": {"x": 1}},
                       {"tool": "toolerr", "arguments": {"path": "/nope"}}], f)
        err, out = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            code = jail_mod.learn([sys.executable, srv], script=script, timeout=5)
        self.assertEqual(code, 0)
        pol = json.loads(out.getvalue())
        self.assertEqual(pol["allow_tools"], ["read_file"])
        self.assertEqual(pol["_not_called"], ["broken", "delete_all", "toolerr"])
        self.assertEqual(err.getvalue().count("not learned"), 2)

    def test_live_mode_skips_failed_calls_and_notifications(self):
        srv = self.srv(FAKE_ERRORS, "errors.py")
        inp = io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            call(2, "read_file", {"path": "/tmp/a"}),
            call(3, "broken", {"x": 1}),
            call(4, "toolerr", {"path": "/nope"}),
            call(None, "ping", {"n": 1}),  # a notification: never answered
        ]))
        out = os.path.join(self.tmp, "live.json")
        with redirect_stderr(io.StringIO()):
            code = jail_mod.learn([sys.executable, srv], out=out, timeout=5,
                                  stdin=inp, stdout=io.BytesIO())
        self.assertEqual(code, 0)
        with open(out, encoding="utf-8") as f:
            pol = json.load(f)
        self.assertEqual(pol["allow_tools"], ["read_file"])
        self.assertEqual(list(pol["arg_rules"]), ["read_file"])

    def test_number_pattern_accepts_exponent_notation(self):
        pat = jail_mod._value_pattern([1e-05])
        for text in (json.dumps(1e-05), "1e-05", "1e+20", "2E10", "5", "-3.5", "0"):
            self.assertRegex(text, pat)
        for text in ("abc", "1e", "0x10", "1.", ".5", "NaN"):
            self.assertNotRegex(text, pat)
        pol = compiled(jail_mod.generate_policy(
            [], [("read_file", {"path": "/srv/data/c/z.txt", "ratio": 1e-05})]))
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/srv/data/c/z.txt", "ratio": 1e-05})[0])
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/srv/data/c/z.txt", "ratio": 5})[0])


class TestNonObjectArguments(ProxyCase):
    """J-11: `arguments` that is not an object cannot be checked against
    path-keyed rules - fail closed."""

    def test_fail_closed(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"deny": {"path": ["^/etc/"]}}}})
        for bad in ("notadict", ["/etc/passwd"], 7, True, "/etc/passwd"):
            ok, reason = jail_mod.tool_allowed(pol, "read_file", bad)
            self.assertFalse(ok, repr(bad))
            self.assertIn("JSON object", reason)
        self.assertTrue(jail_mod.tool_allowed(pol, "read_file", None)[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "read_file", {})[0])
        wire = write_policy(self.tmp, {"allow_tools": ["*"], "deny_tools": [],
                                       "arg_rules": {"read_file": {"deny": {"path": ["^/etc/"]}}},
                                       "hide_denied": False})
        resps = drive_jail(wire, self.server, [
            call(1, "read_file", "notadict"),
            call(2, "read_file", ["/etc/passwd"]),
            call(3, "read_file", {"path": "/tmp/ok"})])
        self.assertEqual([r.get("error", {}).get("code") for r in resps[:2]],
                         [-32602, -32602])
        self.assertIn("result", resps[2])


class TestDenyKeyCase(ProxyCase):
    """J-12: deny paths match key names case-insensitively; a request
    with id null is answered, not silently dropped."""

    def test_deny_paths_match_keys_case_insensitively(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"deny": {"path": ["^/etc/"]}},
            "edit": {"deny": {"**.path": ["^/etc/"]}}}})
        for key in ("Path", "PATH", "pAtH"):
            self.assertFalse(jail_mod.tool_allowed(
                pol, "read_file", {key: "/etc/passwd"})[0], key)
        self.assertFalse(jail_mod.tool_allowed(
            pol, "edit", {"Files": [{"PATH": "/etc/shadow"}]})[0])
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"Path": "/tmp/ok"})[0])
        # allow paths stay exact: an allowlist admits the shape it learned
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "read_file": {"allow": {"path": ["^/tmp/"]}}}})
        self.assertFalse(jail_mod.tool_allowed(
            pol, "read_file", {"Path": "/tmp/a"})[0])

    def test_null_id_request_is_answered_not_dropped(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": None, "method": "tools/list"},
            call(None, "read_file", {}, id=None),
            call(1, "read_file", {})])
        self.assertEqual(len(resps), 3, resps)
        for r in resps[:2]:
            self.assertIsNone(r["id"])
            self.assertEqual(r["error"]["code"], -32600)
            self.assertIn("null", r["error"]["message"])
        self.assertIn("result", resps[2])


class TestDocs(unittest.TestCase):
    """J-13: README, LICENSE and --help tell the truth."""

    def readme(self) -> str:
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            return f.read()

    def test_readme_has_no_hard_coded_test_count(self):
        # a number in the README is wrong the next time a test is added
        self.assertNotRegex(self.readme(), r"\b\d+ tests\b")

    def test_license_and_install_docs(self):
        with open(os.path.join(REPO, "LICENSE"), encoding="utf-8") as f:
            lic = f.read()
        self.assertIn("MIT License", lic)
        self.assertIn("Dan Calas", lic)
        readme = self.readme()
        self.assertNotIn("TBD", readme)
        self.assertIn("pip install git+https://github.com/calasdan-sketch/mcp-jail", readme)
        self.assertNotIn("git clone <repo>", readme)
        self.assertNotRegex(readme, r"(?m)^\s*#?\s*(?:or: )?alias ")
        for word in ("strict_args", "audit_args", "0600", "duplicate", "re-serialised",
                     "case-insensitive", "`..`"):
            self.assertIn(word, readme, word)
        # the packaging metadata needs tomllib (3.11+): only this part skips
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
            proj = tomllib.load(f)["project"]
        self.assertEqual(proj["license"], "MIT")
        self.assertEqual(proj["license-files"], ["LICENSE"])

    def test_help_text_covers_every_flag(self):
        parser = cli_mod.build_parser()
        self.assertIs(parser.formatter_class, argparse.RawDescriptionHelpFormatter)
        for action in parser._actions:
            if action.option_strings and action.option_strings != ["-h", "--help"]:
                self.assertTrue(action.help, f"{action.option_strings} has no help")
        text = parser.format_help()
        for flag in ("--init-policy", "--force", "--audit", "--limit", "--policy"):
            self.assertIn(flag, text)
        self.assertIn("mcp-jail learn", text)


# --------------------------------------------------------------------------
# Round 4 panel findings
# --------------------------------------------------------------------------

HAVE_MCP = importlib.util.find_spec("mcp") is not None

# A real MCP server on the official Python SDK (mcp 2.x MCPServer, or
# 1.x FastMCP). `--banner` makes it print a startup line to STDOUT first,
# as many npm servers do.
REAL_SDK_SERVER = r"""
import sys
try:
    from mcp.server.mcpserver import MCPServer as Server   # mcp >= 2
except ImportError:
    from mcp.server.fastmcp import FastMCP as Server       # mcp 1.x
mcp = Server("realsrv")

@mcp.tool()
def echo(text: str, count: int = 1) -> str:
    "Echo text."
    return text * count

@mcp.tool()
def delete_all() -> str:
    "Pretend to delete everything."
    return "boom"

if "--banner" in sys.argv:
    sys.stdout.write("realsrv starting on stdio...\n")
    sys.stdout.flush()
mcp.run()
"""

# Behaves like an SDK server on the handshake: initialize must carry
# protocolVersion/capabilities/clientInfo, and until the client's
# notifications/initialized arrives every other request gets -32602.
# Logs every line it receives to argv[1]; argv[2] == "refuse" makes it
# refuse initialize outright; "quit" makes it exit right after it.
FAKE_STRICT = r"""
import json, sys
log = open(sys.argv[1], "a", encoding="utf-8")
mode = sys.argv[2] if len(sys.argv) > 2 else ""
TOOLS = [{"name": "echo"}, {"name": "delete_all"}]
initialized = False
def send(r):
    sys.stdout.write(json.dumps(r) + "\n"); sys.stdout.flush()
def bad(rid):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "Invalid request parameters"}}
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    log.write(line + "\n"); log.flush()
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if m == "notifications/initialized":
        initialized = True
        continue
    if rid is None:
        continue
    if m == "initialize":
        p = req.get("params") or {}
        if mode == "refuse":
            send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": "unsupported protocol version"}})
        elif not (isinstance(p.get("protocolVersion"), str) and isinstance(p.get("capabilities"), dict)
                  and isinstance(p.get("clientInfo"), dict)):
            send(bad(rid))
        else:
            send({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-03-26",
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "strict", "version": "1"}}})
        if mode == "quit":
            sys.exit(0)
    elif not initialized:
        send(bad(rid))
    elif m == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif m == "tools/call":
        send({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": "ok"}]}})
    else:
        send({"jsonrpc": "2.0", "id": rid, "result": {}})
"""

# Prints a banner to stdout at startup and a log line before every
# response (console.log-style). The tool "dup" is answered with a
# duplicate-key document; "resource" style requests get a result too.
FAKE_BANNER = r"""
import json, sys
sys.stdout.write("banner server starting on stdio...\n"); sys.stdout.flush()
TOOLS = [{"name": "read_file"}, {"name": "dup"}, {"name": "delete_all"}]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    m, rid = req.get("method"), req.get("id")
    if rid is None:
        continue
    sys.stdout.write("[log] handling %s\n" % m); sys.stdout.flush()
    if m == "initialize":
        r = {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-06-18", "capabilities": {}}}
    elif m == "tools/list":
        r = {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    elif m == "tools/call" and req["params"]["name"] == "dup":
        sys.stdout.write('{"jsonrpc":"2.0","id":%s,"result":{"a":1,"a":2}}\n' % json.dumps(rid)); sys.stdout.flush()
        continue
    else:
        r = {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": "did:" + str(m)}]}}
    sys.stdout.write(json.dumps(r) + "\n"); sys.stdout.flush()
"""


def init_request(req_id=1) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "0"}}}


def write_script(tmp: str, calls: list) -> str:
    p = os.path.join(tmp, "calls.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(calls, f)
    return p


class TestLearnHandshake(ProxyCase):
    """R4-1: learn speaks MCP. `initialize` with empty params and no
    `notifications/initialized` made every SDK-based server answer
    -32602 to everything: 0 tools listed, 0 called, empty policy."""

    def test_fake_sdk_like_server_gets_a_full_handshake(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_STRICT, "strict.py")
        script = write_script(self.tmp, [{"tool": "echo", "arguments": {"text": "hi"}}])
        out = os.path.join(self.tmp, "gen.json")
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.learn([sys.executable, srv, log], script=script,
                                  out=out, timeout=10)
        self.assertEqual(code, 0, err.getvalue())
        with open(out, encoding="utf-8") as f:
            pol = json.load(f)
        self.assertEqual(pol["allow_tools"], ["echo"])
        self.assertEqual(pol["_not_called"], ["delete_all"])
        self.assertIn("2 tool(s) listed", err.getvalue())
        # the server's protocol revision is reported, not silently assumed
        self.assertIn("2025-03-26", err.getvalue())
        with open(log, encoding="utf-8") as f:
            seen = [json.loads(l) for l in f if l.strip()]
        methods = [m.get("method") for m in seen]
        self.assertEqual(methods[:3], ["initialize", "notifications/initialized",
                                       "tools/list"])
        init = seen[0]["params"]
        self.assertEqual(init["protocolVersion"], jail_mod.PROTOCOL_VERSION)
        self.assertEqual(init["capabilities"], {})
        self.assertEqual(init["clientInfo"]["name"], "mcp-jail")
        self.assertEqual(init["clientInfo"]["version"], cli_mod.VERSION)
        self.assertNotIn("id", seen[1])  # a notification, never a request

    def test_initialize_error_stops_learn_cleanly(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_STRICT, "strict.py")
        script = write_script(self.tmp, [{"tool": "echo", "arguments": {"text": "hi"}}])
        out = os.path.join(self.tmp, "gen.json")
        err, outbuf = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(outbuf):
            code = jail_mod.learn([sys.executable, srv, log, "refuse"],
                                  script=script, out=out, timeout=10)
        self.assertEqual(code, 2)
        self.assertIn("refused initialize", err.getvalue())
        self.assertIn("unsupported protocol version", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        self.assertFalse(os.path.exists(out), "an empty policy was written")
        self.assertEqual(outbuf.getvalue(), "")
        with open(log, encoding="utf-8") as f:
            seen = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([m.get("method") for m in seen], ["initialize"])

    @unittest.skipUnless(HAVE_MCP, "official MCP Python SDK not installed")
    def test_learn_against_a_real_sdk_server(self):
        srv = self.srv(REAL_SDK_SERVER, "realsrv.py")
        script = write_script(self.tmp, [
            {"tool": "echo", "arguments": {"text": "hi", "count": 2}},
            {"tool": "echo", "arguments": {"text": "ho"}}])
        out = os.path.join(self.tmp, "gen.json")
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.learn([sys.executable, srv], script=script,
                                  out=out, timeout=30)
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("2 tool(s) listed", err.getvalue())
        self.assertIn("1 tool(s) called in 2 successful", err.getvalue())
        pol = jail_mod.load_policy(out)
        self.assertEqual(pol["allow_tools"], ["echo"])
        self.assertEqual(pol["_not_called"], ["delete_all"])
        self.assertTrue(jail_mod.tool_allowed(
            pol, "echo", {"text": "hi", "count": 3})[0])
        self.assertFalse(jail_mod.tool_allowed(
            pol, "echo", {"text": "hi", "count": "3"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "delete_all", {})[0])

    @unittest.skipUnless(HAVE_MCP, "official MCP Python SDK not installed")
    def test_proxy_passes_a_real_sdk_session(self):
        srv = self.srv(REAL_SDK_SERVER, "realsrv.py")
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": True})
        resps = drive_jail(pol, srv, [
            init_request(1),
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            call(3, "echo", {"text": "hi", "count": 2}),
            call(4, "delete_all", {}),
        ], timeout=30)
        by_id = {r["id"]: r for r in resps if "id" in r}
        self.assertEqual(set(by_id), {1, 2, 3, 4}, resps)
        self.assertIn("protocolVersion", by_id[1]["result"])
        self.assertEqual([t["name"] for t in by_id[2]["result"]["tools"]], ["echo"])
        self.assertEqual(by_id[3]["result"]["content"][0]["text"], "hihi")
        self.assertIn("denied", by_id[4]["error"]["message"])


class TestWindowsTraversal(unittest.TestCase):
    """R4-2: the learned traversal guard only knew `/`, and the matcher
    skipped its own backslash-aware veto for every guarded pattern (the
    guard itself spells `\\.\\.`): a learned Windows pattern admitted
    C:\\Users\\dan\\proj\\../.ssh/id_rsa."""

    WIN = ["C:\\Users\\dan\\proj\\a/b.txt", "C:\\Users\\dan\\proj\\c.txt"]

    def test_learned_windows_pattern_blocks_backslash_dotdot(self):
        gen = jail_mod.generate_policy([], [("read_file", {"path": p}) for p in self.WIN])
        pat = gen["arg_rules"]["read_file"]["allow"]["path"][0]["pattern"]
        self.assertTrue(pat.startswith(r"\A" + jail_mod._TRAVERSAL_GUARD))
        pol = compiled(gen)
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "C:\\Users\\dan\\proj\\x.txt"})[0])
        for bad in ("C:\\Users\\dan\\proj\\../.ssh/id_rsa", "C:\\Users\\dan\\proj\\..",
                    "C:\\Users\\dan\\proj\\..\\.ssh\\id_rsa", "C:\\Users\\dan\\proj\\a/../../x"):
            ok, reason = jail_mod.tool_allowed(pol, "read_file", {"path": bad})
            self.assertFalse(ok, bad)
            self.assertIn("'..'", reason)
            # the regex alone refuses it too (policy file honest on its own)
            self.assertIsNone(re.search(pat, bad), bad)

    def test_guard_in_a_hand_written_pattern_is_not_an_opt_in(self):
        guarded = "^" + jail_mod._TRAVERSAL_GUARD + r"C:\\x\\[a-zA-Z0-9_/.-]*$"
        old_guarded = "^" + jail_mod._OLD_TRAVERSAL_GUARD + r"C:\\x\\[a-zA-Z0-9_/.-]*$"
        for pat in (guarded, old_guarded):
            pol = compiled({"allow_tools": ["*"], "arg_rules": {
                "r": {"allow": {"p": [pat]}}}})
            self.assertTrue(jail_mod.tool_allowed(pol, "r", {"p": "C:\\x\\y"})[0])
            for bad in ("C:\\x\\../y", "C:\\x\\..", "C:\\x\\..\\y"):
                ok, reason = jail_mod.tool_allowed(pol, "r", {"p": bad})
                self.assertFalse(ok, (pat, bad))
                self.assertIn("'..'", reason)
        # spelling \.\. OUTSIDE the guard is the opt-in, as documented
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "r": {"allow": {"p": [r"^C:\\x\\\.\.\\shared\\[a-z]+$"]}}}})
        self.assertTrue(jail_mod.tool_allowed(pol, "r", {"p": "C:\\x\\..\\shared\\a"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "r", {"p": "C:\\x\\..\\other\\a"})[0])
        self.assertTrue(jail_mod._opts_into_dotdot(r"^/tmp/\.\./x$"))
        self.assertFalse(jail_mod._opts_into_dotdot(jail_mod._TRAVERSAL_GUARD + "x"))
        self.assertFalse(jail_mod._opts_into_dotdot(jail_mod._OLD_TRAVERSAL_GUARD + "x"))


class TestServerBannerLines(ProxyCase):
    """R4-3: a non-JSON line on the server's stdout answers nothing. It
    used to fail the longest-waiting request, whose real answer was then
    dropped as unknown — every npm server that console.log()s a banner
    broke the handshake."""

    def test_banner_and_log_lines_are_ignored_and_responses_delivered(self):
        srv = self.srv(FAKE_BANNER, "banner.py")
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": True})
        err = io.StringIO()
        with redirect_stderr(err):
            resps = drive_jail(pol, srv, [
                init_request(1),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                call(3, "read_file", {"path": "/tmp/a"}),
            ], timeout=10)
        by_id = {r["id"]: r for r in resps}
        self.assertEqual(set(by_id), {1, 2, 3}, resps)
        self.assertEqual(by_id[1]["result"]["protocolVersion"], "2025-06-18")
        self.assertEqual([t["name"] for t in by_id[2]["result"]["tools"]],
                         ["read_file", "dup"])
        self.assertEqual(by_id[3]["result"]["content"][0]["text"], "did:tools/call")
        self.assertNotIn("dropping response", err.getvalue())
        self.assertIn("ignoring non-JSON line from server: 'banner server starting",
                      err.getvalue())

    def test_duplicate_key_response_fails_its_own_request_by_id(self):
        srv = self.srv(FAKE_BANNER, "banner.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        with redirect_stderr(io.StringIO()):
            resps = drive_jail(pol, srv, [
                call(1, "dup", {}),
                call(2, "read_file", {}),
            ], timeout=10)
        by_id = {r["id"]: r for r in resps}
        self.assertEqual(set(by_id), {1, 2})
        self.assertEqual(by_id[1]["error"]["code"], -32603)
        self.assertIn("duplicate key", by_id[1]["error"]["message"])
        self.assertIn("result", by_id[2])

    def test_learn_script_mode_ignores_banner_lines(self):
        srv = self.srv(FAKE_BANNER, "banner.py")
        script = write_script(self.tmp, [{"tool": "read_file", "arguments": {"path": "/tmp/a"}}])
        err, out = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            code = jail_mod.learn([sys.executable, srv], script=script, timeout=10)
        self.assertEqual(code, 0, err.getvalue())
        pol = json.loads(out.getvalue())
        self.assertEqual(pol["allow_tools"], ["read_file"])
        self.assertIn("3 tool(s) listed", err.getvalue())
        self.assertIn("ignoring non-JSON line", err.getvalue())
        self.assertNotIn("bad (non-JSON) response", err.getvalue())

    @unittest.skipUnless(HAVE_MCP, "official MCP Python SDK not installed")
    def test_real_sdk_server_with_a_stdout_banner(self):
        srv = self.srv(REAL_SDK_SERVER, "realsrv.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        with redirect_stderr(io.StringIO()):
            resps = drive_jail(pol, srv, [
                init_request(1),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            ], timeout=30, server_args=["--banner"])
        by_id = {r["id"]: r for r in resps if "id" in r}
        self.assertEqual(set(by_id), {1, 2}, resps)
        self.assertIn("result", by_id[1])
        self.assertEqual(sorted(t["name"] for t in by_id[2]["result"]["tools"]),
                         ["delete_all", "echo"])


class TestLearnRobustness(ProxyCase):
    """R4-4: learn never ends in a traceback - not when the server exits
    early, not on a bad --script, and --out is checked before the
    session so a learned policy is never lost."""

    def _learn(self, server_cmd, **kw):
        err, out = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            code = jail_mod.learn(server_cmd, **kw)
        self.assertNotIn("Traceback", err.getvalue())
        return code, err.getvalue(), out.getvalue()

    def test_server_exiting_early_is_a_clean_exit_2(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_STRICT, "strict.py")
        script = write_script(self.tmp, [{"tool": "echo", "arguments": {"text": "hi"}}])
        out = os.path.join(self.tmp, "gen.json")
        code, err, _ = self._learn([sys.executable, srv, log, "quit"],
                                   script=script, out=out, timeout=10)
        self.assertEqual(code, 2)
        self.assertIn("server closed", err)
        self.assertFalse(os.path.exists(out))
        # the same with the session API: a write to a dead server is
        # ("closed",), not BrokenPipeError
        proc = jail_mod._spawn([sys.executable, "-c", "pass"])
        try:
            proc.wait(timeout=10)
            session = jail_mod._Session(proc)
            self.assertEqual(session.request({"jsonrpc": "2.0", "id": 1,
                                              "method": "ping"}, 2)[0], "closed")
            self.assertFalse(session.notify({"jsonrpc": "2.0", "method": "x"}))
        finally:
            jail_mod._stop(proc)

    def test_partial_policy_goes_to_stdout_when_the_server_dies_midway(self):
        # the quitting server answers initialize then exits; nothing is
        # learned. A server dying mid-script leaves what was learned.
        srv = self.srv("import json, sys\n"
                       "for line in sys.stdin:\n"
                       "    req = json.loads(line)\n"
                       "    if req.get('id') is None: continue\n"
                       "    if req.get('method') == 'tools/call' and req['params']['name'] == 'die':\n"
                       "        sys.exit(0)\n"
                       "    r = {'jsonrpc': '2.0', 'id': req['id'], 'result': {'protocolVersion': '2025-06-18', 'tools': [], 'content': []}}\n"
                       "    sys.stdout.write(json.dumps(r) + '\\n'); sys.stdout.flush()\n",
                       "midway.py")
        script = write_script(self.tmp, [{"tool": "ok", "arguments": {"n": 1}},
                                         {"tool": "die"}, {"tool": "never"}])
        out = os.path.join(self.tmp, "gen.json")
        code, err, stdout = self._learn([sys.executable, srv], script=script,
                                        out=out, timeout=10)
        self.assertEqual(code, 2)
        self.assertIn("server closed during call 1 ('die'); 2 call(s) not driven", err)
        self.assertIn("partial policy", err)
        self.assertFalse(os.path.exists(out), "--out written from a failed session")
        pol = json.loads(stdout)
        self.assertEqual(pol["allow_tools"], ["ok"])

    def test_out_directory_is_created_up_front_or_refused(self):
        script = write_script(self.tmp, [{"tool": "read_file", "arguments": {"path": "/tmp/a"}}])
        out = os.path.join(self.tmp, "new", "deeper", "policy.json")
        code, err, _ = self._learn([sys.executable, self.server], script=script,
                                   out=out, timeout=10)
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.isfile(out))
        # --out naming a directory, or living under a file, is refused
        # BEFORE the server is spawned (a missing command is not reached)
        missing = "mcp-jail-no-such-command-xyz"
        for bad in (self.tmp, os.path.join(script, "policy.json")):
            code, err, _ = self._learn([missing], script=script, out=bad)
            self.assertEqual(code, 2, bad)
            self.assertIn("--out", err)
            self.assertNotIn("not found", err)

    def test_failed_final_write_prints_the_policy_instead_of_losing_it(self):
        script = write_script(self.tmp, [{"tool": "read_file", "arguments": {"path": "/tmp/a"}}])
        out = os.path.join(self.tmp, "gen.json")
        real_open = open

        def flaky_open(path, *a, **kw):
            if path == out:
                raise OSError(28, "No space left on device")
            return real_open(path, *a, **kw)

        with mock.patch("mcp_jail.jail.open", flaky_open, create=True):
            code, err, stdout = self._learn([sys.executable, self.server],
                                            script=script, out=out, timeout=10)
        self.assertEqual(code, 2)
        self.assertIn("cannot write", err)
        self.assertIn("policy follows on stdout", err)
        self.assertEqual(json.loads(stdout)["allow_tools"], ["read_file"])

    def test_bad_script_is_refused_before_the_session(self):
        missing = "mcp-jail-no-such-command-xyz"
        cases = {
            "notjson.json": ("not json", "not valid JSON"),
            "object.json": ('{"tool": "x"}', "must be a JSON array"),
            "noname.json": ('[{"arguments": {}}]', 'entry 0 needs a "tool" name'),
            "badargs.json": ('[{"tool": "x", "arguments": [1]}]', '"arguments" must be a JSON object'),
            "notobj.json": ('[1]', "entry 0 is not an object"),
        }
        for name, (text, expect) in cases.items():
            p = os.path.join(self.tmp, name)
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            code, err, _ = self._learn([missing], script=p)
            self.assertEqual(code, 2, name)
            self.assertIn("bad --script", err)
            self.assertIn(expect, err)
            self.assertNotIn("not found", err)  # never got as far as spawning
        with redirect_stderr(io.StringIO()):
            self.assertEqual(cli_mod.main(["learn", "--script", os.path.join(self.tmp, "notjson.json"),
                                           "--", missing]), 2)
        # a good script with optional arguments is fine
        good = write_script(self.tmp, [{"tool": "ping"}, {"tool": "x", "arguments": None}])
        self.assertEqual(len(jail_mod.load_script(good)), 2)


class TestEndAnchors(unittest.TestCase):
    """R4-5: `re`'s `$` also matches before a trailing newline, so a
    learned `^ls$` admitted "ls\\n". Learned patterns are \\A...\\Z and
    the matcher reads `$` in any allow pattern as end-of-string."""

    def test_trailing_newline_is_not_admitted(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "run": {"allow": {"cmd": ["^hi$"], "alt": ["^(?:a|b)$"]}}}})
        self.assertTrue(jail_mod.tool_allowed(pol, "run", {"cmd": "hi"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "run", {"cmd": "hi\n"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "run", {"cmd": "hi\nrm -rf /"})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "run", {"alt": "b"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "run", {"alt": "b\n"})[0])
        gen = compiled(jail_mod.generate_policy([], [("run", {"cmd": "ls"})]))
        self.assertEqual(gen["arg_rules"]["run"]["allow"][0].pattern.pattern, r"\Als\Z")
        self.assertTrue(jail_mod.tool_allowed(gen, "run", {"cmd": "ls"})[0])
        self.assertFalse(jail_mod.tool_allowed(gen, "run", {"cmd": "ls\n"})[0])

    def test_dollar_rewrite_leaves_literals_and_classes_alone(self):
        f = jail_mod._strict_end_anchors
        self.assertEqual(f("^hi$"), r"^hi\Z")
        self.assertEqual(f("^(?:a$|b$)"), r"^(?:a\Z|b\Z)")
        self.assertEqual(f(r"^\$5$"), r"^\$5\Z")       # escaped: a literal dollar
        self.assertEqual(f("^[$]$"), r"^[$]\Z")        # inside a class: literal
        self.assertEqual(f("^[^]$]+$"), r"^[^]$]+\Z")  # `]` first in a class
        self.assertEqual(f(r"^\\$"), r"^\\\Z")         # escaped backslash, then $
        self.assertEqual(f("^/tmp/"), "^/tmp/")
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "t": {"allow": {"p": [r"^\$[0-9]+$", "^[$a-z]+$"]}}}})
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"p": "$12"})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"p": "a$b"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"p": "$12\n"})[0])
        # deny patterns are untouched (search semantics, fail closed)
        pol = compiled({"allow_tools": ["*"], "arg_rules": {"t": {"deny": ["^rm$"]}}})
        self.assertEqual(pol["arg_rules"]["t"]["deny"][0].pattern.pattern, "^rm$")
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"p": "rm\n"})[0])


class TestTypedRules(unittest.TestCase):
    """R4-6: scalars were compared as text, so "3" passed a learned
    number pattern. Learned rules carry the JSON type; hand-written plain
    patterns keep matching any scalar by its text."""

    def test_learned_rules_pin_the_type(self):
        gen = jail_mod.generate_policy([], [
            ("t", {"n": 3, "b": True, "z": None, "s": "3", "e": {}, "l": []})])
        allow = gen["arg_rules"]["t"]["allow"]
        self.assertEqual(allow["n"], [{"type": "number", "pattern": jail_mod._NUMBER_PATTERN}])
        self.assertEqual(allow["b"], [{"type": "boolean", "pattern": r"\A(?:true|false)\Z"}])
        self.assertEqual(allow["z"], [{"type": "null", "pattern": r"\Anull\Z"}])
        self.assertEqual(allow["s"], [{"type": "string", "pattern": r"\A3\Z"}])
        self.assertEqual(allow["e"], [{"type": "object", "pattern": r"\A\{\}\Z"}])
        self.assertEqual(allow["l"], [{"type": "array", "pattern": r"\A\[\]\Z"}])
        pol = compiled(gen)
        good = {"n": 3, "b": True, "z": None, "s": "3", "e": {}, "l": []}
        self.assertTrue(jail_mod.tool_allowed(pol, "t", good)[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {**good, "n": -2.5e3, "b": False})[0])
        for key, bad in (("n", "3"), ("b", "true"), ("z", "null"), ("s", 3),
                         ("n", True), ("e", []), ("l", {}), ("e", {"k": 1}), ("l", ["x"])):
            ok, reason = jail_mod.tool_allowed(pol, "t", {**good, key: bad})
            self.assertFalse(ok, (key, bad))
            self.assertIn(key, reason)
        # a path seen with two types gets one typed rule per type
        gen = jail_mod.generate_policy([], [("t", {"v": 1}), ("t", {"v": "one"})])
        self.assertEqual([r["type"] for r in gen["arg_rules"]["t"]["allow"]["v"]],
                         ["number", "string"])
        pol = compiled(gen)
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"v": 7})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"v": "one"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"v": "7"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"v": True})[0])

    def test_hand_written_rules(self):
        # plain patterns: any scalar, by text (backward compatible)
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "t": {"allow": {"n": [r"^\d+$"]}}}})
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"n": 3})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"n": "3"})[0])
        # typed: type alone, pattern alone, both; shorthand positions
        pol = compiled({"allow_tools": ["*"], "arg_rules": {
            "t": {"allow": {"n": [{"type": "number"}],
                            "s": {"type": "string", "pattern": "^[a-z]+$"},
                            "any": [{"pattern": "^x$"}]},
                  "deny": [{"type": "string", "pattern": "evil"}]}}})
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"n": 1.5, "s": "abc", "any": "x"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"n": "1"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"s": 5})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"s": "ABC"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"s": "evil"})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"any": "x"})[0])
        # malformed typed rules fail closed at load
        for bad in ({"type": "integer"}, {"type": "number", "regex": "x"}, {},
                    {"type": "number", "pattern": 5}, 7):
            with self.assertRaises(ValueError, msg=repr(bad)):
                jail_mod.compile_policy({"arg_rules": {"t": {"allow": {"n": [bad]}}}})


class TestToolNameNormalisation(ProxyCase):
    """R4-7: deny_tools was an exact string match; `Delete_All`,
    `delete_all ` and `delete_all\\u200b` walked past it."""

    VARIANTS = ("Delete_All", "delete_all ", "delete_all\u200b", "\ufeffdelete_all",
                "\uff44elete_all", "delete_al\u006c", "DELETE_ALL\t")

    def test_deny_tools_matches_normalised_names(self):
        pol = {"allow_tools": ["*"], "deny_tools": ["delete_all"]}
        for name in self.VARIANTS:
            ok, reason = jail_mod.tool_allowed(pol, name, {})
            self.assertFalse(ok, repr(name))
            self.assertIn("denied", reason)
        self.assertTrue(jail_mod.tool_allowed(pol, "delete_some", {})[0])
        self.assertEqual(jail_mod.normalize_tool_name(" Delete_All\u200b "), "delete_all")
        # an allow list is matched the same way, and arg_rules follow the
        # normalised name: a Path-cased call cannot shed its rules
        pol = compiled({"allow_tools": ["read_file"], "arg_rules": {
            "read_file": {"deny": {"path": ["^/etc/"]}}}})
        self.assertTrue(jail_mod.tool_allowed(pol, "Read_File", {"path": "/tmp/a"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "Read_File", {"path": "/etc/pw"})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "read_files", {})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "\u200b", {})[0])
        with self.assertRaises(ValueError):
            jail_mod.compile_policy({"arg_rules": {"read_file": {}, "Read_File": {}}})

    def test_proxy_denies_and_hides_variants(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"],
                                      "deny_tools": ["delete_all"],
                                      "arg_rules": {}, "hide_denied": True})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            call(2, "Delete_All", {}),
            call(3, "delete_all\u200b", {}),
            call(4, "read_file", {})])
        by_id = {r["id"]: r for r in resps}
        self.assertNotIn("delete_all", [t["name"] for t in by_id[1]["result"]["tools"]])
        self.assertIn("denied", by_id[2]["error"]["message"])
        self.assertIn("denied", by_id[3]["error"]["message"])
        self.assertIn("result", by_id[4])
        # hide_denied also drops a listed variant spelling
        self.assertEqual(jail_mod.filter_tools_list(
            {"deny_tools": ["delete_all"]}, r := {"tools": [{"name": "Delete_All"}, {"name": "ok"}]}), None)
        self.assertEqual([t["name"] for t in r["tools"]], ["ok"])


class TestMethodScope(ProxyCase):
    """R4-8: only tools/call was policed. deny_methods refuses whole
    JSON-RPC methods; policed_methods runs more methods through the tool
    policy (prompts/get by name, resources/read by uri)."""

    def test_deny_methods(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"], "deny_tools": [],
                                      "arg_rules": {}, "hide_denied": False,
                                      "deny_methods": ["resources/*", "prompts/get"]})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "resources/read",
             "params": {"uri": "file:///etc/passwd"}},
            {"jsonrpc": "2.0", "id": 2, "method": "prompts/get", "params": {"name": "p"}},
            {"jsonrpc": "2.0", "method": "resources/subscribe", "params": {"uri": "x"}},
            {"jsonrpc": "2.0", "id": 3, "method": "prompts/list"},
            call(4, "read_file", {}),
        ])
        by_id = {r["id"]: r for r in resps}
        self.assertEqual(set(by_id), {1, 2, 3, 4})
        for rid in (1, 2):
            self.assertEqual(by_id[rid]["error"]["code"], -32601)
            self.assertIn("denied by policy", by_id[rid]["error"]["message"])
        self.assertIn("result", by_id[3])  # prompts/list is not prompts/get
        self.assertIn("result", by_id[4])
        with open(jail_mod.AUDIT_LOG, encoding="utf-8") as f:
            entries = [json.loads(l) for l in f if l.strip()]
        denied = [e for e in entries if e["decision"] == "deny"]
        self.assertEqual([e.get("method") for e in denied],
                         ["resources/read", "prompts/get", "resources/subscribe"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            jail_mod.AUDIT_LOG = jail_mod.AUDIT_LOG  # (unchanged) --audit reads it
            cli_mod.cmd_audit(argparse.Namespace(limit=50))
        self.assertIn("DENY  method resources/read", buf.getvalue())

    def test_policed_methods_run_through_the_tool_policy(self):
        pol = write_policy(self.tmp, {
            "allow_tools": ["read_file", "summarise", "file:///srv/data/a.txt"],
            "deny_tools": [], "hide_denied": False,
            "arg_rules": {"summarise": {"allow": {"lang": ["^en$"]}}},
            "policed_methods": ["tools/call", "prompts/get", "resources/read"]})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "prompts/get",
             "params": {"name": "summarise", "arguments": {"lang": "en"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "prompts/get",
             "params": {"name": "summarise", "arguments": {"lang": "en; rm -rf /"}}},
            {"jsonrpc": "2.0", "id": 3, "method": "prompts/get", "params": {"name": "other"}},
            {"jsonrpc": "2.0", "id": 4, "method": "resources/read",
             "params": {"uri": "file:///srv/data/a.txt"}},
            {"jsonrpc": "2.0", "id": 5, "method": "resources/read",
             "params": {"uri": "file:///etc/passwd"}},
            {"jsonrpc": "2.0", "id": 6, "method": "completion/complete",
             "params": {"ref": {"name": "anything"}}},  # not policed: passes
        ])
        by_id = {r["id"]: r for r in resps}
        self.assertEqual(set(by_id), {1, 2, 3, 4, 5, 6})
        self.assertIn("result", by_id[1])
        self.assertIn("denied", by_id[2]["error"]["message"])
        self.assertIn("not in allow_tools", by_id[3]["error"]["message"])
        self.assertIn("result", by_id[4])
        self.assertIn("file:///etc/passwd", by_id[5]["error"]["message"])
        self.assertIn("result", by_id[6])
        with open(jail_mod.AUDIT_LOG, encoding="utf-8") as f:
            entries = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(entries[1]["method"], "prompts/get")
        self.assertEqual(entries[1]["tool"], "summarise")

    def test_scope_defaults_and_validation(self):
        pol = jail_mod.default_policy()
        self.assertEqual(pol["policed_methods"], ["tools/call"])
        self.assertEqual(pol["deny_methods"], [])
        jail_mod.compile_policy(pol)
        gen = jail_mod.generate_policy([], [("t", {})])
        self.assertEqual(gen["policed_methods"], ["tools/call"])
        # tools/call is policed even when policed_methods leaves it out
        self.assertTrue(jail_mod.method_policed({"policed_methods": ["prompts/get"]}, "tools/call"))
        self.assertFalse(jail_mod.method_policed({}, "prompts/get"))
        self.assertTrue(jail_mod.method_denied({"deny_methods": ["resources/*"]}, "resources/read"))
        self.assertFalse(jail_mod.method_denied({"deny_methods": ["resources/*"]}, "tools/call"))
        for bad in ("resources/read", [1], [""]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                jail_mod.compile_policy({"deny_methods": bad})
            with self.assertRaises(ValueError, msg=repr(bad)):
                jail_mod.compile_policy({"policed_methods": bad})
        # README states the scope
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        for word in ("policed_methods", "deny_methods", "resources/read", "prompts/get"):
            self.assertIn(word, readme)


class TestStrictArgsEmptyContainers(unittest.TestCase):
    """R4-9: {"q": {}} and {"q": []} passed strict_args as "empty
    arguments". An empty container is a value; only {} is empty."""

    def test_empty_containers_are_values(self):
        pol = compiled({"allow_tools": ["*"], "arg_rules": {}, "strict_args": True})
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "t", None)[0])
        for args in ({"q": {}}, {"q": []}, {"q": {"r": []}}, {"q": [{}]}):
            ok, reason = jail_mod.tool_allowed(pol, "t", args)
            self.assertFalse(ok, args)
            self.assertIn("strict_args", reason)
        # learned from a call that carried an empty container: that exact
        # shape is accepted, a filled container at the same path is not
        gen = jail_mod.generate_policy([], [("t", {"q": {}, "tags": []})])
        self.assertEqual(sorted(gen["arg_rules"]["t"]["allow"]), ["q", "tags"])
        pol = compiled(gen)
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"q": {}, "tags": []})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"q": {"a": 1}, "tags": []})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"q": {}, "tags": ["x"]})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"q": [], "tags": []})[0])
        # deny rules see empty containers as text too
        pol = compiled({"allow_tools": ["*"], "arg_rules": {"t": {"deny": {"opts": [r"^\{\}$"]}}}})
        self.assertFalse(jail_mod.tool_allowed(pol, "t", {"opts": {}})[0])
        self.assertTrue(jail_mod.tool_allowed(pol, "t", {"opts": {"a": 1}})[0])


class TestBrokenPipe(unittest.TestCase):
    """R4-10: `mcp-jail --audit | head` must not end in a traceback."""

    def setUp(self):
        self._old_audit = jail_mod.AUDIT_LOG
        jail_mod.AUDIT_LOG = None

    def tearDown(self):
        jail_mod.AUDIT_LOG = self._old_audit

    def test_broken_pipe_in_main_is_a_quiet_exit_0(self):
        for i in range(5):
            jail_mod.audit({"tool": f"t{i}", "decision": "deny", "reason": "r"})

        class Broken(io.TextIOBase):
            def write(self, s):
                raise BrokenPipeError(32, "Broken pipe")

        err = io.StringIO()
        with redirect_stdout(Broken()), redirect_stderr(err):
            code = cli_mod.main(["--audit"])
        self.assertEqual(code, 0)
        self.assertNotIn("Traceback", err.getvalue())

    def test_reader_going_away_end_to_end(self):
        for i in range(200):
            jail_mod.audit({"tool": f"t{i}", "decision": "deny", "reason": "x" * 100})
        env = child_env()
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_jail", "--audit", "--limit", "200"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        proc.stdout.close()  # the reader (`head`) is gone before we write
        try:
            _, err = proc.communicate(timeout=20)
        finally:
            if proc.poll() is None:
                proc.kill()
        self.assertEqual(proc.returncode, 0, err)
        self.assertNotIn(b"Traceback", err)
        self.assertNotIn(b"Exception ignored", err)


# --------------------------------------------------------------------------
# Round 5 panel findings
# --------------------------------------------------------------------------


class TestPolicyKeys(ProxyCase):
    """R5-1: a mistyped policy key was silently ignored, and a policy that
    ignores its own `alow_tools` allows every tool. Unknown keys are
    refused at startup, at every level, with a suggestion."""

    def test_mistyped_top_level_key_is_refused_with_a_suggestion(self):
        for typo, want in (("alow_tools", "allow_tools"),
                           ("deny_tool", "deny_tools"),
                           ("arg_rule", "arg_rules"),
                           ("strict_arg", "strict_args"),
                           ("hide_deny", "hide_denied"),
                           ("policed_method", "policed_methods"),
                           ("deny_method", "deny_methods"),
                           ("audit_arg", "audit_args")):
            with self.assertRaises(ValueError, msg=typo) as cm:
                jail_mod.compile_policy({typo: ["read_file"]})
            msg = str(cm.exception)
            self.assertIn(repr(typo), msg)
            self.assertIn(f"did you mean {want!r}", msg)
            for key in jail_mod.POLICY_KEYS:  # the message lists what is allowed
                self.assertIn(key, msg)
        # a key nothing resembles: refused, no suggestion
        with self.assertRaises(ValueError) as cm:
            jail_mod.compile_policy({"zzzzzz": 1})
        self.assertNotIn("did you mean", str(cm.exception))

    def test_the_panel_repro_does_not_start_the_server(self):
        # {"alow_tools": ["read_file"]} made every tool callable
        marker = os.path.join(self.tmp, "started.txt")
        srv = self.srv("open(%r, 'w').write('x')\n" % marker, "marker.py")
        pol = write_policy(self.tmp, {"alow_tools": ["read_file"]})
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.run(pol, [sys.executable, srv],
                                stdin=io.BytesIO(b""), stdout=io.BytesIO())
        self.assertEqual(code, 2)
        self.assertIn("bad policy", err.getvalue())
        self.assertIn("did you mean 'allow_tools'", err.getvalue())
        self.assertFalse(os.path.exists(marker),
                         "the server was started under a refused policy")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(cli_mod.main(
                ["--policy", pol, "--", sys.executable, srv]), 2)
        self.assertFalse(os.path.exists(marker))

    def test_unknown_keys_are_refused_at_every_level(self):
        # arg_rules.<tool> takes only allow / deny: `denied` used to mean
        # "no deny rules at all"
        for bad, want in (
                ({"arg_rules": {"read_file": {"denied": {"path": ["^/etc/"]}}}},
                 "did you mean 'deny'"),
                ({"arg_rules": {"read_file": {"allow": {}, "alow": {}}}},
                 "did you mean 'allow'"),
                ({"arg_rules": {"read_file": {"deny": ["x"], "extra": 1}}},
                 "unknown key 'extra'")):
            with self.assertRaises(ValueError, msg=repr(bad)) as cm:
                jail_mod.compile_policy(bad)
            self.assertIn(want, str(cm.exception))
            self.assertIn("arg_rules.read_file", str(cm.exception))
        # the typed rules were already strict; they stay so
        with self.assertRaises(ValueError):
            jail_mod.compile_policy({"arg_rules": {"t": {"deny": {"a": [
                {"type": "string", "patern": "x"}]}}}})
        # and the bypass itself: the typo'd deny used to let /etc/passwd by
        pol = compiled({"arg_rules": {"read_file": {"deny": {"path": ["^/etc/"]}}}})
        self.assertFalse(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/etc/passwd"})[0])

    def test_notes_generated_policies_and_the_starter_policy_still_load(self):
        jail_mod.compile_policy(jail_mod.default_policy())
        gen = jail_mod.generate_policy(["a", "b"], [("a", {"x": 1})])
        self.assertIn("_not_called", gen)
        jail_mod.compile_policy(gen)
        jail_mod.compile_policy({"_comment": "anything", "allow_tools": ["a"]})
        # a policy without allow_tools allows what deny_tools leaves alone
        pol = compiled({"deny_tools": ["delete_all"]})
        self.assertTrue(jail_mod.tool_allowed(pol, "read_file", {})[0])
        self.assertFalse(jail_mod.tool_allowed(pol, "delete_all", {})[0])

    def test_internal_markers_cannot_come_from_a_file(self):
        # "_compiled": true in a policy FILE must not skip the validation
        for bad in ({"_compiled": True},
                    {"_compiled": True, "_rules_by_norm": {}},
                    {"_rules_by_norm": {}}):
            p = write_policy(self.tmp, bad)
            with self.assertRaises(ValueError, msg=repr(bad)) as cm:
                jail_mod.load_policy(p)
            self.assertIn("reserved", str(cm.exception))
            code = jail_mod.run(p, [sys.executable, "-c", "pass"],
                                stdin=io.BytesIO(b""), stdout=io.BytesIO())
            self.assertEqual(code, 2)
        # a forged marker on an in-process dict does not skip it either
        with self.assertRaises(ValueError):
            jail_mod.compile_policy({"_compiled": True, "alow_tools": []})

    def test_duplicate_keys_in_a_policy_file_are_refused(self):
        # the last duplicate used to win silently: the deny list vanished
        p = os.path.join(self.tmp, "dup.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write('{"allow_tools": ["*"], "deny_tools": ["delete_all"], '
                    '"deny_tools": []}')
        with self.assertRaises(ValueError) as cm:
            jail_mod.load_policy(p)
        self.assertIn("duplicate key 'deny_tools'", str(cm.exception))
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.run(p, [sys.executable, "-c", "pass"],
                                stdin=io.BytesIO(b""), stdout=io.BytesIO())
        self.assertEqual(code, 2)
        self.assertIn("duplicate key", err.getvalue())

    def test_tool_name_lists_must_hold_names(self):
        # a nested list or a number in deny_tools was skipped silently
        for key in ("allow_tools", "deny_tools"):
            for bad in ([["delete_all"]], [5], [None], [""],
                        ["ok", {"name": "x"}]):
                with self.assertRaises(ValueError, msg=(key, bad)):
                    jail_mod.compile_policy({key: bad})
        with self.assertRaises(ValueError):
            jail_mod.compile_policy({"allow_tools": "*"})
        with self.assertRaises(ValueError):
            jail_mod.compile_policy({"hide_denied": "yes"})
        jail_mod.compile_policy({"allow_tools": ["a", "b"], "deny_tools": [],
                                 "hide_denied": False})


# A server written the way a Java/Jackson one is: its lines come from
# BufferedReader.readLine(), which ends a line at \n, \r OR \r\n, and its
# JSON reader ignores whatever follows the first value on a line. Logs the
# tools it ran to argv[1] ("ran:<name>").
FAKE_JAVA = r"""
import json, re, sys
log = open(sys.argv[1], "a", encoding="utf-8")
dec = json.JSONDecoder()
buf = b""
def handle(line):
    text = line.decode("utf-8", "replace").strip()
    if not text:
        return
    try:
        req, _ = dec.raw_decode(text)        # trailing tokens are ignored
    except ValueError:
        return
    if not isinstance(req, dict):
        return
    if req.get("method") == "tools/call":
        log.write("ran:" + str(req["params"]["name"]) + "\n"); log.flush()
    rid = req.get("id")
    if rid is None:
        return
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"ok": True}}) + "\n")
    sys.stdout.flush()
inp = sys.stdin.buffer
while True:
    chunk = inp.read1(65536)
    if not chunk:
        break
    buf += chunk
    parts = re.split(rb"\r\n|\r|\n", buf)
    buf = parts.pop()
    for p in parts:
        handle(p)
"""

# A server written the way a Go one is: encoding/json matches keys to struct
# fields case-insensitively (Unicode simple folding: U+017F reads as "s"), and
# when several keys match the same field the last one wins. Logs the tools it
# ran to argv[1] ("ran:<name>").
FAKE_GO = r"""
import json, sys
log = open(sys.argv[1], "a", encoding="utf-8")
def field(obj, name):
    val = None
    for k, v in obj.items():
        if k.casefold() == name:
            val = v
    return val
for raw in iter(sys.stdin.buffer.readline, b""):
    line = raw.decode("utf-8").strip()
    if not line:
        continue
    req = json.loads(line)
    method, rid = field(req, "method"), field(req, "id")
    if method == "tools/call":
        params = field(req, "params") or {}
        log.write("ran:" + str(field(params, "name")) + "\n")
        log.write("args:" + json.dumps(field(params, "arguments")) + "\n"); log.flush()
    if rid is None:
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"ok": True}}) + "\n")
    sys.stdout.flush()
"""

# A server that routes on the method name without regard to case, the way a
# lowercasing router does (and reads the other fields exactly). Logs
# "ran:<name>" for what it takes to be a tools/call.
FAKE_LOOSE_METHOD = r"""
import json, sys
log = open(sys.argv[1], "a", encoding="utf-8")
for raw in iter(sys.stdin.buffer.readline, b""):
    line = raw.decode("utf-8").strip()
    if not line:
        continue
    req = json.loads(line)
    rid = req.get("id")
    if str(req.get("method")).casefold() == "tools/call":
        log.write("ran:" + str((req.get("params") or {}).get("name")) + "\n"); log.flush()
    if rid is None:
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"ok": True}}) + "\n")
    sys.stdout.flush()
"""

# Waits for the first request, then writes the bytes in the file named by
# argv[1] to stdout exactly as they are (to put hostile framing on the wire).
FAKE_EMIT = r"""
import sys
data = open(sys.argv[1], "rb").read()
sys.stdin.buffer.readline()
sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
for _ in iter(sys.stdin.buffer.readline, b""):
    pass
"""


def ran_tools(path: str) -> list:
    """What a FAKE_JAVA / FAKE_GO server logged as executed."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [l.strip()[4:] for l in f if l.startswith("ran:")]


def audit_records() -> list:
    if not os.path.exists(jail_mod.AUDIT_LOG):
        return []
    with open(jail_mod.AUDIT_LOG, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


DENY_DELETE = {"allow_tools": ["*"], "deny_tools": ["delete_all"],
               "arg_rules": {}, "hide_denied": False}


class TestLineSmuggling(ProxyCase):
    """R5-4: a message the policy let through was forwarded byte for byte,
    bare CR and all. A server that ends lines on CR (Java's readLine,
    Python's universal newlines) split it into two messages and ran the
    second - a tools/call nobody had checked or logged."""

    CARRIER = ('{"jsonrpc":"2.0","id":1,"method":"ping","x":\r'
               '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":'
               '{"name":"delete_all","arguments":{}}}}')

    def attack(self, requests, patch_control: bool = False):
        log = os.path.join(self.tmp, "ran.txt")
        srv = self.srv(FAKE_JAVA, "java.py")
        pol = write_policy(self.tmp, DENY_DELETE)
        if patch_control:
            # switch the raw-control-character refusal off: the forwarded
            # bytes alone must keep the second message from existing
            with mock.patch.object(jail_mod, "_CONTROL", re.compile(r"(?!)")):
                resps = drive_jail(pol, srv, requests, timeout=3,
                                   server_args=[log])
        else:
            resps = drive_jail(pol, srv, requests, timeout=3, server_args=[log])
        return resps, ran_tools(log)

    def test_the_panel_repro_is_blocked_and_logged(self):
        resps, ran = self.attack([self.CARRIER, {"jsonrpc": "2.0", "id": 3,
                                                 "method": "ping"}])
        self.assertEqual(ran, [], "the smuggled delete_all reached the server")
        by_id = {r["id"]: r for r in resps}
        # the carrier is refused, under its own id, and says why
        self.assertEqual(by_id[1]["error"]["code"], -32600)
        self.assertIn("control character", by_id[1]["error"]["message"])
        self.assertIn("result", by_id[3])        # the session carries on
        records = [r for r in audit_records() if r.get("rejected")]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["rejected"], "client")
        self.assertEqual(records[0]["decision"], "deny")
        self.assertIn("control character", records[0]["reason"])

    def test_a_notification_carrier_is_blocked_too(self):
        carrier = self.CARRIER.replace('"id":1,"method":"ping"',
                                       '"method":"notifications/x"')
        resps, ran = self.attack([carrier, {"jsonrpc": "2.0", "id": 3,
                                            "method": "ping"}])
        self.assertEqual(ran, [])
        self.assertEqual([r.get("id") for r in resps], [None, 3])
        self.assertEqual(resps[0]["error"]["code"], -32600)
        self.assertEqual(len([r for r in audit_records() if r.get("rejected")]), 1)

    def test_forwarded_bytes_alone_defeat_the_split(self):
        # even with the refusal switched off the server sees ONE message:
        # what is forwarded is the re-serialised object, not the client's CR
        resps, ran = self.attack([self.CARRIER, {"jsonrpc": "2.0", "id": 3,
                                                 "method": "ping"}],
                                 patch_control=True)
        self.assertEqual(ran, [], "the re-serialised line still split")
        self.assertEqual({r["id"] for r in resps}, {1, 3})
        self.assertTrue(all("result" in r for r in resps))

    def test_through_the_real_entry_point(self):
        # a real stdin pipe (raw fd reads), the real __main__
        log = os.path.join(self.tmp, "ran.txt")
        srv = self.srv(FAKE_JAVA, "java.py")
        pol = write_policy(self.tmp, DENY_DELETE)
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_jail", "--policy", pol, "--timeout", "3",
             "--", sys.executable, srv, log],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=child_env(), cwd=self.tmp)
        try:
            out, err = proc.communicate(
                (self.CARRIER + "\n" + json.dumps(
                    {"jsonrpc": "2.0", "id": 3, "method": "ping"}) + "\n"
                 ).encode("utf-8"), timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        self.assertEqual(ran_tools(log), [])
        msgs = [json.loads(l) for l in out.splitlines() if l.strip()]
        self.assertEqual({m["id"] for m in msgs}, {1, 3}, err)

    def test_other_raw_control_characters_are_refused(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_RECORDER, "rec.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, srv, [
            '{"jsonrpc":"2.0",\t"id":5,"method":"ping"}',          # TAB
            '{"jsonrpc":"2.0","id":6,"method":"ping"\x0b}',        # VT
            '{"jsonrpc":"2.0","id":7,"method":"ping"}\x0c',        # FF
            {"jsonrpc": "2.0", "id": 8, "method": "ping",
             "params": {"flush": True}}],
            timeout=5, server_args=[log])
        by_id = {r["id"]: r for r in resps}
        # TAB parses (it is JSON whitespace) and is refused under its own id;
        # VT / FF are not JSON whitespace at all: a parse error
        self.assertEqual(by_id[5]["error"]["code"], -32600)
        self.assertIn("U+0009", by_id[5]["error"]["message"])
        self.assertEqual([r["error"]["code"] for r in resps if r["id"] is None],
                         [-32700, -32700])
        self.assertIn("result", by_id[8])
        with open(log, encoding="utf-8") as f:
            seen = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([m["id"] for m in seen], [8])

    def test_parse_refuses_control_characters_but_not_text(self):
        obj, code, err = jail_mod._parse(b'{"a":\r1}\n')
        self.assertIsNone(obj)
        self.assertEqual(code, jail_mod.INVALID_REQUEST)
        self.assertIn("control character U+000D", err)
        # U+2028 / U+0085 / DEL are text, legitimate inside a string (a
        # Word document pasted into a tool argument): accepted, and they
        # leave as escapes (see TestCanonicalWire)
        raw = '{"a":"x\u2028y\u0085z\x7f"}\n'.encode("utf-8")
        obj, code, _ = jail_mod._parse(raw)
        self.assertIsNone(code)
        self.assertEqual(obj, {"a": "x\u2028y\u0085z\x7f"})
        self.assertEqual(jail_mod._parse(b"   \n"), (None, None, ""))


class TestCanonicalWire(ProxyCase):
    """R5-4: both directions carry the re-serialised object - compact JSON,
    pure ASCII, finite numbers - never the peer's bytes, so the jail and
    whatever sits behind it cannot parse a line differently."""

    def test_server_receives_compact_ascii_json(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_RECORDER, "rec.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, srv, [
            '  { "jsonrpc" : "2.0", "id": 7 , "method": "ping",  '
            '"params": {"s": "é日 \u2028 \\u2028", "n": 1E2, "big": '
            '123456789012345678901234567890, "f": 0.5, "z": [ ] } }  ',
            {"jsonrpc": "2.0", "id": 8, "method": "ping", "params": {"flush": True}}],
            timeout=5, server_args=[log])
        self.assertEqual(len(resps), 2)
        with open(log, encoding="utf-8") as f:
            seen = [l.rstrip("\n") for l in f if l.strip()]
        self.assertEqual(seen[0],
                         '{"jsonrpc":"2.0","id":7,"method":"ping","params":'
                         '{"s":"\\u00e9\\u65e5 \\u2028 \\u2028","n":100.0,'
                         '"big":123456789012345678901234567890,"f":0.5,"z":[]}}')
        self.assertTrue(seen[0].isascii())

    def test_server_responses_are_delivered_re_serialised(self):
        emit = os.path.join(self.tmp, "emit.bin")
        with open(emit, "wb") as f:
            f.write('{ "jsonrpc": "2.0", "id": 1,'.encode("utf-8")
                    + ' "result": {"t": "é\u2028", "n": 1E2} }\r\n'.encode("utf-8"))
        srv = self.srv(FAKE_EMIT, "emit.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        raw = drive_raw(pol, [sys.executable, srv, emit],
                        [{"jsonrpc": "2.0", "id": 1, "method": "ping"}], timeout=5)
        self.assertEqual(raw, [b'{"jsonrpc":"2.0","id":1,"result":'
                               b'{"t":"\\u00e9\\u2028","n":100.0}}'])

    def test_a_server_line_cannot_smuggle_a_second_message_to_the_client(self):
        # the mirror image: a server puts a bare CR in a notification and the
        # client's reader (readLine, universal newlines) splits it in two
        emit = os.path.join(self.tmp, "emit.bin")
        forged = (b'{"jsonrpc":"2.0","method":"notifications/message","params":'
                  b'{"x":\r{"jsonrpc":"2.0","id":99,"result":{"forged":true}}}}\n'
                  b'{"jsonrpc":"2.0","id":1,"result":{"real":true}}\n')
        with open(emit, "wb") as f:
            f.write(forged)
        srv = self.srv(FAKE_EMIT, "emit.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        raw = drive_raw(pol, [sys.executable, srv, emit],
                        [{"jsonrpc": "2.0", "id": 1, "method": "ping"}], timeout=5)
        wire = b"\n".join(raw)
        parts = [p for p in re.split(rb"\r\n|\r|\n", wire) if p.strip()]
        self.assertFalse(any(b"forged" in p for p in parts), parts)
        self.assertEqual([json.loads(p)["id"] for p in parts], [1])  # the real answer
        records = [r for r in audit_records() if r.get("rejected") == "server"]
        self.assertEqual(len(records), 1)
        self.assertIn("control character", records[0]["reason"])

    def test_a_response_with_a_control_character_fails_its_request_closed(self):
        emit = os.path.join(self.tmp, "emit.bin")
        with open(emit, "wb") as f:
            f.write(b'{"jsonrpc":"2.0",\t"id":1,"result":{"ok":true}}\n')
        srv = self.srv(FAKE_EMIT, "emit.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = [json.loads(l) for l in drive_raw(
            pol, [sys.executable, srv, emit],
            [{"jsonrpc": "2.0", "id": 1, "method": "ping"}], timeout=5)]
        self.assertEqual(len(resps), 1)
        self.assertEqual(resps[0]["id"], 1)
        self.assertEqual(resps[0]["error"]["code"], -32603)
        self.assertIn("bad response from server", resps[0]["error"]["message"])
        self.assertIn("control character", resps[0]["error"]["message"])

    def test_numbers_that_json_cannot_carry_are_refused_both_ways(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, self.server, [
            '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"n":1e999}}',
            '{"jsonrpc":"2.0","id":2,"method":"ping","params":{"n":-1e999}}',
            '{"jsonrpc":"2.0","id":3,"method":"ping","params":{"n":NaN}}',
            {"jsonrpc": "2.0", "id": 4, "method": "ping"}])
        # 1e999 is well-formed JSON the jail will not carry: refused under
        # its own id; NaN is not JSON at all
        self.assertEqual([(r["id"], r["error"]["code"]) for r in resps[:3]],
                         [(1, -32600), (2, -32600), (3, -32700)])
        self.assertIn("number out of range", resps[0]["error"]["message"])
        self.assertIn("result", resps[3])
        emit = os.path.join(self.tmp, "emit.bin")
        with open(emit, "wb") as f:
            f.write(b'{"jsonrpc":"2.0","id":1,"result":{"n":1e999}}\n')
        srv = self.srv(FAKE_EMIT, "emit.py")
        # a 30 s timeout and a 20 s join: only an answer by id, not the
        # timeout, lets this finish
        out = [json.loads(l) for l in drive_raw(
            pol, [sys.executable, srv, emit],
            [{"jsonrpc": "2.0", "id": 1, "method": "ping"}], timeout=30)]
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["error"]["code"], -32603)
        self.assertIn("number out of range", out[0]["error"]["message"])

    def test_messages_that_are_not_requests_or_responses_are_refused(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_RECORDER, "rec.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": 1},                           # nothing
            {"jsonrpc": "2.0", "id": 2, "result": 1, "error": {}},  # both
            {"jsonrpc": "2.0", "id": 3, "method": "ping", "result": {}},
            {"jsonrpc": "2.0", "result": {}},                      # no id
            {"jsonrpc": "2.0", "id": 4, "method": "ping",
             "params": {"flush": True}}], timeout=5, server_args=[log])
        errors = {r["id"]: r["error"]["code"] for r in resps if "error" in r}
        self.assertEqual(errors[1], -32600)
        self.assertEqual(errors[2], -32600)
        self.assertEqual(errors[3], -32600)
        self.assertEqual(errors[None], -32600)
        self.assertIn(4, [r["id"] for r in resps if "result" in r])
        with open(log, encoding="utf-8") as f:
            seen = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([m["id"] for m in seen], [4])


def go_view(line: bytes) -> dict:
    """One line from the jail as a client with a Go-style JSON reader sees it:
    keys matched without regard to case, the last duplicate winning."""
    view = {}
    for key, value in json.loads(line).items():
        view[key.casefold()] = value
    return view


class TestProtocolKeySpelling(ProxyCase):
    """R5-2: the jail looked for the exact lowercase `method` / `params`; a
    message spelled METHOD / PARAMS was forwarded as something that is not a
    request - and a server that matches JSON keys without regard to case (Go's
    encoding/json, C#'s System.Text.Json when told to, Jackson when told to)
    ran it as a tools/call nobody had checked. A key that reads as an envelope
    key in another spelling is refused, not normalised."""

    PANEL = '{"METHOD":"tools/call","PARAMS":{"name":"delete_all","arguments":{}}}'
    DEL = {"name": "delete_all", "arguments": {}}
    OK = {"name": "read_file", "arguments": {}}

    # (the key that must be named, the attack, the error code the client gets)
    ATTACKS = [
        ("METHOD", PANEL, -32600),             # the panel's repro, verbatim
        ("METHOD", {"jsonrpc": "2.0", "id": 2, "result": {},   # dressed as a client response
                    "METHOD": "tools/call", "PARAMS": DEL}, -32600),
        ("METHOD", {"jsonrpc": "2.0", "id": 3, "method": "ping",  # last duplicate wins
                    "METHOD": "tools/call", "params": DEL}, -32600),
        ("PARAMS", {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": OK, "PARAMS": DEL}, -32600),
        ("NAME", {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                  "params": {"name": "read_file", "NAME": "delete_all",
                             "arguments": {}}}, -32602),
        ("param\\u017f", {"jsonrpc": "2.0", "id": 6, "method": "tools/call",   # U+017F reads as "s"
                         "params": OK, "param\u017f": DEL}, -32600),
        ("Id", {"jsonrpc": "2.0", "id": 7, "Id": 8, "method": "tools/call",
                "params": OK}, -32600),
        ("RESULT", {"jsonrpc": "2.0", "id": 9, "result": {}, "RESULT": {}}, -32600),
    ]

    def go(self, requests, pol=None, timeout=3, tag="x"):
        log = os.path.join(self.tmp, "ran-%s.txt" % tag)
        srv = self.srv(FAKE_GO, "go.py")
        path = write_policy(self.tmp, pol or DENY_DELETE)
        resps = drive_jail(path, srv, requests, timeout=timeout, server_args=[log])
        return resps, ran_tools(log)

    def test_every_spelling_variant_is_refused_before_the_server_sees_it(self):
        for n, (key, msg, code) in enumerate(self.ATTACKS):
            with self.subTest(key=key, n=n):
                resps, ran = self.go([msg, {"jsonrpc": "2.0", "id": 90, "method": "ping"}],
                                     tag="a%d" % n)
                self.assertEqual(ran, [], "the server ran the smuggled tools/call")
                answers = [r for r in resps if r.get("id") != 90]
                self.assertEqual(len(answers), 1, resps)
                self.assertEqual(answers[0]["error"]["code"], code)
                self.assertIn(key, answers[0]["error"]["message"])
                self.assertIn("result", [r for r in resps if r.get("id") == 90][0])
        # one audit record each, every one a deny that names the key
        records = audit_records()
        self.assertEqual(len(records), len(self.ATTACKS))
        for rec, (key, _msg, _code) in zip(records, self.ATTACKS):
            self.assertEqual(rec["decision"], "deny")
            self.assertIn(key, rec["reason"])

    def test_the_panel_repro_no_id_is_dropped_with_a_record(self):
        resps, ran = self.go([self.PANEL, {"jsonrpc": "2.0", "id": 2, "method": "ping"}])
        self.assertEqual(ran, [])
        self.assertEqual(len(audit_records()), 1)
        self.assertEqual(audit_records()[0]["rejected"], "client")
        self.assertIn("METHOD", audit_records()[0]["reason"])

    def test_arguments_in_another_case_cannot_dodge_the_argument_rules(self):
        pol = {"allow_tools": ["*"], "deny_tools": [], "hide_denied": False,
               "arg_rules": {"read_file": {"deny": {"**.path": ["^/etc/"]}}}}
        resps, ran = self.go([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": "/tmp/ok"},
                        "ARGUMENTS": {"path": "/etc/passwd"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": "/tmp/ok"}}}],
            pol=pol)
        self.assertEqual(ran, ["read_file"], "only the clean call may run")
        by_id = {r["id"]: r for r in resps}
        self.assertEqual(by_id[1]["error"]["code"], -32602)
        self.assertIn("ARGUMENTS", by_id[1]["error"]["message"])
        self.assertIn("result", by_id[2])

    def test_a_server_that_matches_keys_loosely_still_cannot_be_reached(self):
        # the control: this is what the unguarded message does to such a server
        log = os.path.join(self.tmp, "direct.txt")
        srv = self.srv(FAKE_GO, "go.py")
        proc = subprocess.run([sys.executable, srv, log],
                              input=(self.PANEL + "\n").encode("utf-8"),
                              stdout=subprocess.PIPE, timeout=30, env=child_env())
        self.assertEqual(ran_tools(log), ["delete_all"], proc.stdout)

    def test_method_value_spellings_are_judged_as_the_method(self):
        log = os.path.join(self.tmp, "ran.txt")
        srv = self.srv(FAKE_LOOSE_METHOD, "loose.py")
        pol = write_policy(self.tmp, DENY_DELETE)
        variants = ["Tools/Call", "TOOLS/CALL", "tool\u017f/call", "tools/call\u200b"]
        resps = drive_jail(pol, srv, [
            {"jsonrpc": "2.0", "id": n, "method": m, "params": self.DEL}
            for n, m in enumerate(variants, 1)], timeout=3, server_args=[log])
        self.assertEqual(ran_tools(log), [])
        self.assertEqual([r["error"]["code"] for r in sorted(resps, key=lambda r: r["id"])],
                         [-32602] * len(variants))
        self.assertTrue(all("denied" in r["error"]["message"] for r in resps))

    def test_deny_methods_and_policed_methods_see_through_the_spelling(self):
        pol = {"deny_methods": ["resources/*", "prompts/get"],
               "policed_methods": ["tools/call", "sampling/createMessage"],
               "deny_tools": ["secret"]}
        jail_mod.compile_policy(pol)
        for m in ("resources/list", "RESOURCES/LIST", "Resources/Read",
                  "resource\u017f/read", "Prompts/Get", "prompts/get\u200b"):
            self.assertTrue(jail_mod.method_denied(pol, m), m)
        for m in ("prompts/list", "resource/read", "xresources/read"):
            self.assertFalse(jail_mod.method_denied(pol, m), m)
        for m in ("tools/call", "Tools/Call", "TOOLS/CALL", "tool\u017f/call",
                  "tools/call\u200b", "Sampling/CreateMessage"):
            self.assertTrue(jail_mod.method_policed(pol, m), m)
        for m in ("tools/list", "tools/calls", "sampling/create"):
            self.assertFalse(jail_mod.method_policed(pol, m), m)
        # a pattern is folded too: "Resources/*" in a policy denies resources/*
        up = {"deny_methods": ["Resources/*"]}
        self.assertTrue(jail_mod.method_denied(up, "resources/list"))

    def test_deny_methods_end_to_end(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"], "deny_tools": [],
                                      "hide_denied": False,
                                      "deny_methods": ["resources/*"]})
        resps = drive_jail(pol, self.server, [
            {"jsonrpc": "2.0", "id": 1, "method": "RESOURCES/READ", "params": {"uri": "x"}},
            {"jsonrpc": "2.0", "id": 2, "method": "Resources/List"},
            {"jsonrpc": "2.0", "id": 3, "method": "ping"}])
        by_id = {r["id"]: r for r in resps}
        self.assertEqual(by_id[1]["error"]["code"], -32601)
        self.assertEqual(by_id[2]["error"]["code"], -32601)
        self.assertIn("result", by_id[3])

    def test_key_clash_helper(self):
        clash, keys = jail_mod._key_clash, jail_mod._ENVELOPE_KEYS
        self.assertIsNone(clash({"jsonrpc": "2.0", "id": 1, "method": "x",
                                 "params": {}, "result": 1, "error": 2}, keys))
        for bad in ("METHOD", "Method", "mEtHoD", "param\u017f", "PARAM\u017f",
                    "\uff4d\uff45\uff54\uff48\uff4f\uff44", "method\u200b", " method",
                    "Id", "ID", "Result", "ERROR", "JSONRPC"):
            self.assertEqual(clash({"id": 1, bad: 1}, keys), bad, ascii(bad))
        # not a spelling of an envelope key: left alone
        for fine in ("foo", "_meta", "methods", "m\u0435thod", "method_"):
            self.assertIsNone(clash({fine: 1}, keys), ascii(fine))


class TestServerKeySpelling(ProxyCase):
    """R5-2, server -> client: the jail filters `result.tools`; a client that
    reads keys without regard to case reads the last spelling, which the
    filter never saw."""

    POL = {"allow_tools": ["*"], "deny_tools": ["delete_all"], "arg_rules": {},
           "hide_denied": True}

    def emit(self, line: bytes, request=None):
        path = os.path.join(self.tmp, "emit.bin")
        with open(path, "wb") as f:
            f.write(line)
        srv = self.srv(FAKE_EMIT, "emit.py")
        pol = write_policy(self.tmp, self.POL)
        raw = drive_raw(pol, [sys.executable, srv, path],
                        [request or {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}],
                        timeout=30)
        return [go_view(l) for l in raw]

    @staticmethod
    def names(views):
        return [t.get("name") for v in views
                for t in (v.get("result") or {}).get("tools", [])]

    def test_a_second_spelling_of_result_fails_the_request_closed(self):
        views = self.emit(b'{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"}]},'
                          b'"RESULT":{"tools":[{"name":"delete_all"}]}}\n')
        self.assertNotIn("delete_all", self.names(views))
        self.assertEqual(len(views), 1)
        self.assertEqual(views[0]["error"]["code"], -32603)
        self.assertIn("RESULT", views[0]["error"]["message"])
        self.assertEqual(audit_records()[-1]["rejected"], "server")

    def test_a_second_spelling_of_tools_fails_the_request_closed(self):
        views = self.emit(b'{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"}],'
                          b'"TOOLS":[{"name":"delete_all"}]}}\n')
        self.assertNotIn("delete_all", self.names(views))
        self.assertEqual(views[0]["error"]["code"], -32603)

    def test_a_tool_entry_with_a_second_spelling_of_name_is_hidden(self):
        views = self.emit(b'{"jsonrpc":"2.0","id":1,"result":{"tools":['
                          b'{"name":"read_file","NAME":"delete_all"},{"name":"ok"}]}}\n')
        self.assertEqual(self.names(views), ["ok"])
        pol = {"deny_tools": ["delete_all"]}
        res = {"tools": [{"name": "ok", "Name": "delete_all"}, {"name": "fine"}]}
        jail_mod.filter_tools_list(pol, res)
        self.assertEqual(res["tools"], [{"name": "fine"}])

    def test_server_messages_with_envelope_key_clashes_are_refused(self):
        views = self.emit(b'{"jsonrpc":"2.0","method":"notifications/message",'
                          b'"PARAMS":{"x":1}}\n'
                          b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
        self.assertEqual([v["id"] for v in views], [1])
        self.assertEqual(audit_records()[-1]["rejected"], "server")
        self.assertIn("PARAMS", audit_records()[-1]["reason"])


def rpc_msg(req_id, method, params=None):
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


class TestSelectors(ProxyCase):
    """R5-3: resources/read was judged by params.name, with params.uri only a
    fallback - so {"uri": "file:///etc/passwd", "name": "harmless"} walked past
    a deny on the uri (and past an allowlist: name=<allowed>, uri=<anything>).
    Each policed method is judged by the field that really selects what the
    call touches, and a second selector beside it is refused, not preferred."""

    SECRET_URI = "file:///etc/passwd"

    def verdicts(self, policy, *calls):
        """{request id: "allow" or the error message the client got}"""
        pol = write_policy(self.tmp, dict(ALLOW_ALL, **policy))
        resps = drive_jail(pol, self.server, [rpc_msg(i, m, p)
                                              for i, (m, p) in enumerate(calls, 1)])
        return {r["id"]: ("allow" if "result" in r else r["error"]["message"])
                for r in resps}

    def assertDenied(self, verdict, *words):
        self.assertNotEqual(verdict, "allow")
        self.assertIn("mcp-jail denied", verdict)
        for w in words:
            self.assertIn(w, verdict)

    def test_resources_read_is_judged_by_uri_whatever_name_says(self):
        v = self.verdicts(
            {"deny_tools": [self.SECRET_URI], "policed_methods": ["resources/read"]},
            ("resources/read", {"uri": self.SECRET_URI, "name": "harmless"}),  # the panel's repro
            ("resources/read", {"uri": self.SECRET_URI}),
            ("resources/read", {"name": self.SECRET_URI}),     # name selects nothing here
            ("resources/read", {"uri": "file:///srv/ok.txt"}))
        self.assertDenied(v[1], "'uri'", "'name'")
        self.assertDenied(v[2], "denied by policy")
        self.assertDenied(v[3], "uri")
        self.assertEqual(v[4], "allow")

    def test_an_allowlist_is_not_satisfied_through_name(self):
        v = self.verdicts(
            {"allow_tools": ["file:///srv/ok.txt"], "policed_methods": ["resources/read"]},
            # judged by `name` (allowed), served by `uri` (anything)
            ("resources/read", {"uri": self.SECRET_URI, "name": "file:///srv/ok.txt"}),
            ("resources/read", {"uri": "file:///srv/ok.txt"}),
            ("resources/read", {"uri": self.SECRET_URI}))
        self.assertDenied(v[1])
        self.assertEqual(v[2], "allow")
        self.assertDenied(v[3], "not in allow_tools")

    def test_subscribe_and_unsubscribe_are_judged_by_uri_too(self):
        for method in ("resources/subscribe", "resources/unsubscribe"):
            with self.subTest(method=method):
                v = self.verdicts(
                    {"deny_tools": [self.SECRET_URI], "policed_methods": [method]},
                    (method, {"uri": self.SECRET_URI, "name": "harmless"}),
                    (method, {"uri": self.SECRET_URI}),
                    (method, {"uri": "file:///srv/ok.txt"}))
                self.assertDenied(v[1])
                self.assertDenied(v[2], "denied by policy")
                self.assertEqual(v[3], "allow")

    def test_prompts_get_and_tools_call_are_judged_by_name(self):
        v = self.verdicts(
            {"deny_tools": ["secret_prompt"], "policed_methods": ["prompts/get"]},
            ("prompts/get", {"name": "secret_prompt"}),
            ("prompts/get", {"name": "ok"}),
            ("prompts/get", {"name": "ok", "uri": "secret_prompt"}),   # a second selector
            ("prompts/get", {"uri": "secret_prompt"}),                 # no name
            ("tools/call", {"name": "read_file", "uri": "delete_all"}))
        self.assertDenied(v[1], "denied by policy")
        self.assertEqual(v[2], "allow")
        self.assertDenied(v[3], "'name'", "'uri'")
        self.assertDenied(v[4], "name")
        self.assertDenied(v[5], "'name'", "'uri'")

    def test_completion_complete_is_judged_by_its_ref(self):
        pol = {"deny_tools": ["secret_prompt", self.SECRET_URI],
               "policed_methods": ["completion/complete"]}
        arg = {"name": "x", "value": "y"}        # the argument being completed: no selector
        v = self.verdicts(
            pol,
            ("completion/complete", {"ref": {"type": "ref/prompt", "name": "secret_prompt"}, "argument": arg}),
            ("completion/complete", {"ref": {"type": "ref/prompt", "name": "ok"}, "argument": arg}),
            ("completion/complete", {"ref": {"type": "ref/resource", "uri": self.SECRET_URI}, "argument": arg}),
            ("completion/complete", {"ref": {"type": "ref/resource", "uri": "file:///srv/ok"}, "argument": arg}),
            ("completion/complete", {"ref": {"type": "ref/other", "name": "ok"}, "argument": arg}),
            ("completion/complete", {"argument": arg}),                       # no ref
            ("completion/complete", {"ref": "secret_prompt", "argument": arg}),
            ("completion/complete", {"ref": {"type": "ref/prompt", "name": "ok",
                                             "uri": self.SECRET_URI}, "argument": arg}),
            ("completion/complete", {"ref": {"type": "ref/resource", "uri": "file:///srv/ok",
                                             "name": "secret_prompt"}, "argument": arg}),
            ("completion/complete", {"ref": {"type": "ref/prompt", "name": "ok"},
                                     "name": "secret_prompt", "argument": arg}),
            ("completion/complete", {"ref": {"type": "ref/prompt", "name": "ok",
                                             "NAME": "secret_prompt"}, "argument": arg}))
        self.assertDenied(v[1], "denied by policy")
        self.assertEqual(v[2], "allow")
        self.assertDenied(v[3], "denied by policy")
        self.assertEqual(v[4], "allow")
        self.assertDenied(v[5], "ref/other")
        self.assertDenied(v[6], "ref")
        self.assertDenied(v[7], "object")
        self.assertDenied(v[8], "'uri'")
        self.assertDenied(v[9], "'name'")
        self.assertDenied(v[10], "'name'")
        self.assertDenied(v[11], "NAME")

    def test_a_method_added_through_policed_methods_needs_exactly_one_selector(self):
        v = self.verdicts(
            {"deny_tools": ["secret"], "policed_methods": ["acme/fetch"]},
            ("acme/fetch", {"name": "secret"}),
            ("acme/fetch", {"uri": "secret"}),
            ("acme/fetch", {"name": "ok"}),
            ("acme/fetch", {"uri": "ok"}),
            ("acme/fetch", {"name": "ok", "uri": "secret"}),
            ("acme/fetch", {}))
        self.assertDenied(v[1], "denied by policy")
        self.assertDenied(v[2], "denied by policy")
        self.assertEqual(v[3], "allow")
        self.assertEqual(v[4], "allow")
        self.assertDenied(v[5], "exactly one")
        self.assertDenied(v[6], "exactly one")

    def test_audit_records_name_the_method_and_the_selector(self):
        self.verdicts(
            {"deny_tools": [self.SECRET_URI], "policed_methods": ["resources/read"]},
            ("resources/read", {"uri": self.SECRET_URI}),
            ("resources/read", {"uri": "file:///a", "name": "b"}))
        first, second = audit_records()
        self.assertEqual((first["method"], first["tool"], first["decision"]),
                         ("resources/read", self.SECRET_URI, "deny"))
        self.assertEqual((second["method"], second["decision"]), ("resources/read", "deny"))
        self.assertNotIn("tool", second)        # nothing could be said to select
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli_mod.cmd_audit(argparse.Namespace(limit=50))
        self.assertIn("DENY  " + self.SECRET_URI, buf.getvalue())
        self.assertIn("DENY  method resources/read", buf.getvalue())

    def test_readme_says_what_each_method_is_judged_by(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        for method in ("resources/read", "resources/subscribe", "resources/unsubscribe",
                       "prompts/get", "completion/complete", "ref/prompt", "ref/resource"):
            self.assertIn(method, readme)


# A server that never reads its stdin (stuck in a loop, deadlocked, busy for
# good): the pipe to it fills up. Writes its pid to argv[1].
FAKE_DEAF = r"""
import os, sys, time
with open(sys.argv[1], "w") as f:
    f.write(str(os.getpid()))
time.sleep(60)
"""

# Does not read for the first 1.5 s, then reads everything and answers.
FAKE_LATE_READER = r"""
import json, sys, time
time.sleep(1.5)
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    if req.get("id") is None:
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": {"ok": True}}) + "\n")
    sys.stdout.flush()
"""

# The same, and it ignores SIGTERM (but notes that it was sent one).
FAKE_DEAF_PROUD = r"""
import os, signal, sys, time
def noted(*_):
    with open(sys.argv[1] + ".term", "w") as f:
        f.write("x")
signal.signal(signal.SIGTERM, noted)
with open(sys.argv[1], "w") as f:
    f.write(str(os.getpid()))
time.sleep(60)
"""

BLOB = "x" * 300000        # far more than a pipe holds (64 KiB; 4 KiB on Windows)


def big_call(req_id) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"blob": BLOB}}}


class TestWedgedServer(ProxyCase):
    """R5-5: the proxy wrote to the server's stdin from the one thread that
    also answers the client. A server that stops reading fills the pipe, the
    write blocks for good, and --timeout - which is only looked at between
    messages - never fires: the jail hangs, and so does everyone behind it.
    Writes now go through a thread of their own; a server that has not taken a
    message off its stdin within --timeout of receiving it is stopped."""

    @staticmethod
    def give_up(proc) -> None:
        """Put down a jail that hung, without waiting on pipes that a
        leftover server may still hold open."""
        proc.kill()
        proc.wait(timeout=10)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

    def pid_gone(self, pidfile: str) -> bool:
        with open(pidfile, encoding="utf-8") as f:
            pid = int(f.read())
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        return False

    def test_a_server_that_never_reads_cannot_hang_the_jail(self):
        pidfile = os.path.join(self.tmp, "pid.txt")
        srv = self.srv(FAKE_DEAF, "deaf.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_jail", "--policy", pol, "--timeout", "2",
             "--", sys.executable, srv, pidfile],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=child_env(), cwd=self.tmp)
        requests = b"".join(json.dumps(big_call(i)).encode("utf-8") + b"\n"
                            for i in range(1, 6))
        started = time.monotonic()
        try:
            out, err = proc.communicate(requests, timeout=25)
        except subprocess.TimeoutExpired:
            self.give_up(proc)
            self.fail("the jail hung on a server that never reads its input")
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(proc.returncode, 3, err)
        msgs = [json.loads(l) for l in out.splitlines() if l.strip()]
        self.assertEqual(sorted(m["id"] for m in msgs), [1, 2, 3, 4, 5])
        for m in msgs:                      # every caller is answered
            self.assertEqual(m["error"]["code"], -32603)
            self.assertIn("stopped reading", m["error"]["message"])
        self.assertIn(b"stopped reading", err)
        self.assertNotIn(b"Traceback", err)
        if os.name != "nt":                 # the server is not left behind
            self.assertTrue(self.pid_gone(pidfile))

    def test_the_same_in_process_with_the_exit_code(self):
        pidfile = os.path.join(self.tmp, "pid.txt")
        srv = self.srv(FAKE_DEAF, "deaf.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        code, raw = drive_rc(pol, [sys.executable, srv, pidfile],
                             [big_call(1), big_call(2)], timeout=2)
        self.assertEqual(code, 3)
        self.assertEqual(sorted(json.loads(l)["id"] for l in raw), [1, 2])

    @unittest.skipIf(os.name == "nt", "POSIX signals")
    def test_a_stalled_server_is_killed_outright_not_asked_to_leave(self):
        # a server that has stopped reading is not going to act on SIGTERM
        # either: it must never get the chance to ignore it
        pidfile = os.path.join(self.tmp, "pid.txt")
        srv = self.srv(FAKE_DEAF_PROUD, "proud.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        code, _raw = drive_rc(pol, [sys.executable, srv, pidfile],
                              [big_call(1), big_call(2)], timeout=2)
        self.assertEqual(code, 3)
        self.assertTrue(self.pid_gone(pidfile))
        self.assertFalse(os.path.exists(pidfile + ".term"),
                         "the stalled server was sent SIGTERM instead of being killed")

    def test_an_unanswerable_notification_is_a_stall_too(self):
        # no id, so no pending request for --timeout to expire: the write
        # itself has to be timed
        pidfile = os.path.join(self.tmp, "pid.txt")
        srv = self.srv(FAKE_DEAF, "deaf.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        note = {"jsonrpc": "2.0", "method": "notifications/x", "params": {"blob": BLOB}}
        code, raw = drive_rc(pol, [sys.executable, srv, pidfile], [note, note],
                             timeout=2)
        self.assertEqual(code, 3)
        self.assertEqual(raw, [])

    def test_a_server_that_is_only_slow_to_start_reading_is_left_alone(self):
        srv = self.srv(FAKE_LATE_READER, "late.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        code, raw = drive_rc(pol, [sys.executable, srv],
                             [big_call(1), big_call(2), big_call(3)], timeout=10)
        self.assertEqual(code, 0)
        self.assertEqual(sorted(json.loads(l)["id"] for l in raw), [1, 2, 3])
        self.assertTrue(all("result" in json.loads(l) for l in raw))

    def test_a_burst_bigger_than_the_pipe_reaches_the_server_whole_and_in_order(self):
        # the writer is another thread now, and 300 x 2 KB is more than a
        # pipe holds, so it has to wait for the server again and again. The
        # last message is a request: its answer proves the server read
        # everything before it, in order
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_RECORDER, "rec.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        notes = [{"jsonrpc": "2.0", "method": "notifications/n%d" % i,
                  "params": {"pad": "z" * 2000}} for i in range(300)]
        last = {"jsonrpc": "2.0", "id": "last", "method": "tools/call",
                "params": {"name": "read_file", "arguments": {}, "flush": True}}
        code, raw = drive_rc(pol, [sys.executable, srv, log], notes + [last],
                             timeout=10)
        self.assertEqual(code, 0)
        self.assertEqual([json.loads(l)["id"] for l in raw], ["last"])
        with open(log, encoding="utf-8") as f:
            seen = [json.loads(l) for l in f if l.strip()]
        self.assertEqual([m.get("method") for m in seen[:300]],
                         ["notifications/n%d" % i for i in range(300)])
        self.assertEqual([m.get("id") for m in seen[300:]], ["last"])

    def test_put_after_close_or_abort_is_refused(self):
        sin = jail_mod._ServerInput(io.BytesIO(), 1.0, lambda payload: None)
        self.assertTrue(sin.put(b"a"))
        sin.close()
        self.assertFalse(sin.put(b"b"))
        sin = jail_mod._ServerInput(io.BytesIO(), 1.0, lambda payload: None)
        sin.abort()
        self.assertFalse(sin.put(b"c"))

    def test_timeout_zero_waits_for_ever_and_stalls_nothing(self):
        sin = jail_mod._ServerInput(io.BytesIO(), None, lambda payload: None)
        self.assertTrue(sin.put(b"x"))
        self.assertIsNone(sin.stall_deadline())
        self.assertFalse(sin.stalled(time.monotonic() + 10 ** 6))
        sin.close()

    def test_server_input_on_a_full_pipe_stalls_then_reports_the_break(self):
        r, w = os.pipe()
        wstream = os.fdopen(w, "wb")
        events = []
        sin = jail_mod._ServerInput(wstream, 0.5, events.append)
        sin.start()
        try:
            self.assertTrue(sin.put(b"y" * 2000000))    # never read: it blocks
            self.assertEqual(sin.stall_deadline() is None, False)
            self.assertFalse(sin.stalled(time.monotonic()))
            time.sleep(0.7)
            self.assertTrue(sin.stalled(time.monotonic()))
            self.assertTrue(sin.alive())
            os.close(r)                                  # the "server" goes away
            r = None
            sin.join(10)
            self.assertFalse(sin.alive(), "the writer did not end with the pipe")
            self.assertEqual(len(events), 1)
            self.assertIsInstance(events[0], OSError)
            self.assertFalse(sin.put(b"more"))
        finally:
            sin.abort()
            if r is not None:
                os.close(r)
            wstream.close()

    def test_windows_descriptor_is_put_in_binary_mode(self):
        # a text-mode CRT descriptor would turn every "\n" we write into
        # "\r\n"; this can only be checked with a stand-in for msvcrt here
        calls = []

        class FakeMsvcrt:
            @staticmethod
            def setmode(fd, flags):
                calls.append((fd, flags))
                return 0x8000

        r, w = os.pipe()
        wstream = os.fdopen(w, "wb")
        try:
            with mock.patch.object(jail_mod, "_WINDOWS", True), \
                    mock.patch.dict(sys.modules, {"msvcrt": FakeMsvcrt}), \
                    mock.patch.object(os, "O_BINARY", 0x8000, create=True):
                sin = jail_mod._ServerInput(wstream, 1.0, lambda payload: None)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1], 0x8000)
            self.assertNotEqual(calls[0][0], w)       # the duplicate, not the original
            sin.close()
        finally:
            os.close(r)
            wstream.close()


class TestLearnWedgedServer(ProxyCase):
    """R5-5, learn --script: the scripted client wrote to the server from the
    thread that waits for its answers, so a server that stopped reading froze
    learn for good, whatever --timeout said."""

    DEAF_AFTER_LIST = r"""
import json, sys, time
for line in sys.stdin:
    req = json.loads(line)
    if req.get("id") is None:
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req["id"],
                                 "result": {"tools": [{"name": "read_file"}]}}) + "\n")
    sys.stdout.flush()
    if req.get("method") == "tools/list":
        break
time.sleep(60)          # and never reads again
"""

    def test_script_mode_gives_up_on_a_server_that_stops_reading(self):
        srv = self.srv(self.DEAF_AFTER_LIST, "deaf2.py")
        script = write_script(self.tmp, [{"tool": "read_file", "arguments": {"blob": BLOB}}] * 2)
        out = os.path.join(self.tmp, "learned.json")
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_jail", "learn", "--script", script,
             "--out", out, "--timeout", "2", "--", sys.executable, srv],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=child_env(), cwd=self.tmp)
        try:
            so, se = proc.communicate(b"", timeout=40)
        except subprocess.TimeoutExpired:
            TestWedgedServer.give_up(proc)
            self.fail("learn hung on a server that stopped reading")
        self.assertNotIn(b"Traceback", se)
        self.assertIn(b"timed out", se)


class TestExitCodes(ProxyCase):
    """R5-7: serve() returned 0 whatever had happened, so a CI job that wrapped
    a server that died on start-up saw success. 0 is a clean session; 3 means
    the server failed while the jail was relaying."""

    def run_session(self, server_src: str, requests, timeout: float = 5, policy=None):
        srv = self.srv(server_src, "srv2.py")
        pol = write_policy(self.tmp, policy or ALLOW_ALL)
        code, raw = drive_rc(pol, [sys.executable, srv], requests, timeout=timeout)
        return code, [json.loads(l) for l in raw]

    def test_a_clean_session_exits_0(self):
        code, resps = self.run_session(FAKE_SERVER, [call(1, "read_file", {})])
        self.assertEqual(code, 0)
        self.assertIn("result", resps[0])

    def test_a_denied_call_is_still_a_clean_session(self):
        code, resps = self.run_session(
            FAKE_SERVER, [call(1, "delete_all", {})],
            policy=dict(ALLOW_ALL, deny_tools=["delete_all"]))
        self.assertEqual(code, 0)
        self.assertEqual(resps[0]["error"]["code"], -32602)

    def test_a_server_that_exits_at_once_exits_3(self):
        # the panel's repro: the server is gone before it reads a line
        code, resps = self.run_session("import sys\nsys.exit(0)\n",
                                       [call(1, "read_file", {})])
        self.assertEqual(code, 3)
        self.assertIn("server closed", resps[0]["error"]["message"])

    def test_a_server_that_crashes_midway_exits_3(self):
        src = ("import json, sys\n"
               "for line in sys.stdin:\n"
               "    req = json.loads(line)\n"
               "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': {}}) + '\\n')\n"
               "    sys.stdout.flush()\n"
               "    if req['id'] == 2:\n"
               "        sys.exit(1)\n")
        code, resps = self.run_session(src, [call(1, "a", {}), call(2, "a", {}), call(3, "a", {})])
        self.assertEqual(code, 3)
        self.assertEqual([r["id"] for r in resps if "result" in r], [1, 2])

    def test_a_request_that_times_out_exits_3(self):
        code, resps = self.run_session(FAKE_HANG, [call(1, "slow", {})], timeout=1)
        self.assertEqual(code, 3)
        self.assertEqual(resps[0]["error"]["message"], "server timed out")

    def test_a_late_answer_that_fits_in_the_timeout_is_not_a_failure(self):
        src = FAKE_SLOW
        code, resps = self.run_session(src, [call(1, "t", {"delay": 0.5})], timeout=10)
        self.assertEqual(code, 0)
        self.assertIn("result", resps[0])

    def test_the_exit_code_reaches_the_real_entry_point(self):
        srv = self.srv("import sys\nsys.exit(0)\n", "gone.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        proc = subprocess.run(
            [sys.executable, "-m", "mcp_jail", "--policy", pol, "--",
             sys.executable, srv],
            input=json.dumps(call(1, "read_file", {})).encode() + b"\n",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env(),
            cwd=self.tmp, timeout=60)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertNotIn(b"Traceback", proc.stderr)

    def test_exit_codes_are_documented(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertIn("Exit codes", readme)
        for code in ("`0`", "`2`", "`3`"):
            self.assertIn(code, readme)
        text = cli_mod.build_parser().format_help()
        self.assertIn("exit status", text.lower())


class TestLearnLiveServerLoss(ProxyCase):
    """R5-7, learn without --script: a server that exits mid-session is a
    failed session like the scripted one (exit 2, --out untouched, what was
    learned goes to stdout) - it used to be a clean exit 0."""

    def test_live_learn_with_a_server_that_dies(self):
        src = ("import json, sys\n"
               "for line in sys.stdin:\n"
               "    req = json.loads(line)\n"
               "    if req.get('id') is None: continue\n"
               "    if req['id'] == 2:\n"
               "        sys.exit(0)          # dies with request 2 unanswered\n"
               "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': {'content': []}}) + '\\n')\n"
               "    sys.stdout.flush()\n")
        srv = self.srv(src, "dies.py")
        out = os.path.join(self.tmp, "learned.json")
        err, so = io.StringIO(), io.StringIO()
        stdin = io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in (
            call(1, "ok", {"n": 1}), call(2, "other", {}))))
        with redirect_stderr(err), redirect_stdout(so):
            code = jail_mod.learn([sys.executable, srv], out=out, timeout=10,
                                  stdin=stdin, stdout=io.BytesIO())
        self.assertEqual(code, 2, err.getvalue())
        self.assertIn("the server", err.getvalue())
        self.assertFalse(os.path.exists(out), "--out written from a failed session")
        self.assertEqual(json.loads(so.getvalue())["allow_tools"], ["ok"])


class TestAuditDisplay(ProxyCase):
    """R5-6: `mcp-jail --audit` printed the reason (and the tool, and the
    method) as it found it: a denied tool whose NAME carried a newline put a
    forged "allow ..." line into the report, an escape sequence went to the
    terminal, and a record that was not an object crashed it. Every field is
    shown as printable text, on one line."""

    def show(self, records, limit=50) -> list:
        with open(jail_mod.AUDIT_LOG, "w", encoding="utf-8") as f:
            for r in records:
                f.write((r if isinstance(r, str) else json.dumps(r)) + "\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli_mod.cmd_audit(argparse.Namespace(limit=limit)), 0)
        return buf.getvalue().splitlines()

    @staticmethod
    def records_in(lines) -> list:
        return [l for l in lines if l.startswith(("DENY ", "allow "))]

    def test_a_newline_in_a_reason_cannot_forge_a_line(self):
        lines = self.show([
            {"tool": "read_file", "decision": "deny",
             "reason": "nope\nallow delete_all granted"},
            {"tool": "b", "decision": "allow", "reason": ""}])
        recs = self.records_in(lines)
        self.assertEqual(len(recs), 2, lines)
        self.assertIn("nope\\nallow delete_all granted", recs[0])
        self.assertFalse(any(l.startswith("allow delete_all") for l in lines))
        self.assertTrue(lines[-1].startswith("1 denied in last 2"), lines)

    def test_end_to_end_a_tool_name_with_a_newline(self):
        pol = write_policy(self.tmp, {"allow_tools": ["read_file"], "deny_tools": [],
                                      "arg_rules": {}, "hide_denied": False})
        drive_jail(pol, self.server, [call(1, "evil\nallow read_file ok", {})])
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli_mod.cmd_audit(argparse.Namespace(limit=50))
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(self.records_in(lines)), 1, lines)
        self.assertIn("evil\\nallow read_file ok", lines[0])

    def test_control_and_formatting_characters_are_shown_as_escapes(self):
        nasty = "a\x1b[2Jb\u202ec\u00a0d\u2028e\x00f\rg\u200bh"
        lines = self.show([{"tool": nasty, "decision": "deny", "reason": nasty,
                            "method": nasty}])
        text = "\n".join(lines)
        self.assertTrue(all(ch.isprintable() or ch == "\n" for ch in text), ascii(text))
        for shown in ("\\x1b[2J", "\\u202e", "\\xa0", "\\u2028", "\\x00", "\\r", "\\u200b"):
            self.assertIn(shown, text)
        # ordinary non-ASCII text is left alone
        lines = self.show([{"tool": "caf\u00e9_\u65e5\u672c", "decision": "deny",
                            "reason": "r"}])
        self.assertIn("caf\u00e9_\u65e5\u672c", lines[0])

    def test_records_that_are_not_objects_are_skipped(self):
        lines = self.show(["[1]", "5", '"x"', "null", "{bad json", "",
                           {"tool": "t", "decision": "deny", "reason": "r"}])
        self.assertEqual(len(self.records_in(lines)), 1, lines)

    def test_fields_that_are_not_strings(self):
        lines = self.show([{"tool": 5, "decision": "deny", "reason": {"a": "b\nc"}},
                           {"decision": ["x"], "tool": ["a\nb"]},
                           {"tool": None, "method": 7, "decision": "deny", "reason": None}])
        self.assertEqual(len(self.records_in(lines)), 3, lines)

    def test_rejected_messages_are_listed_as_such(self):
        lines = self.show([
            {"decision": "deny", "rejected": "client", "reason": "raw control character U+000D"},
            {"decision": "deny", "rejected": "server", "reason": "duplicate key 'id'"}])
        recs = self.records_in(lines)
        self.assertEqual(recs[0], "DENY  client message raw control character U+000D")
        self.assertEqual(recs[1], "DENY  server message duplicate key 'id'")

    def test_a_log_that_is_not_utf8_is_still_shown(self):
        with open(jail_mod.AUDIT_LOG, "wb") as f:
            f.write(b'{"tool": "x\xff", "decision": "deny", "reason": "r"}\n')
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli_mod.cmd_audit(argparse.Namespace(limit=50)), 0)
        self.assertEqual(len(self.records_in(buf.getvalue().splitlines())), 1)


# Reads slowly, so the end of a burst is still waiting in its pipe when the
# client has gone; notes every line it gets.
FAKE_SLOW_RECORDER = r"""
import sys, time
log = open(sys.argv[1], "a", encoding="utf-8")
for line in sys.stdin:
    time.sleep(0.005)
    log.write(line); log.flush()
"""

# Answers each request after a moment, and says goodbye when its input closes.
FAKE_BYE = r"""
import json, sys, time
for line in sys.stdin:
    req = json.loads(line)
    if req.get("id") is None:
        continue
    time.sleep(0.005)
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req["id"],
                                 "result": {"n": req["id"]}}) + "\n")
    sys.stdout.flush()
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                             "params": {"level": "info", "data": "bye"}}) + "\n")
sys.stdout.flush()
"""

# Notices that its input has closed, and carries on regardless. With a second
# argument it also ignores SIGTERM (noting that it was sent one).
FAKE_STUBBORN = r"""
import os, signal, sys, time
pidfile = sys.argv[1]
with open(pidfile, "w") as f:
    f.write(str(os.getpid()))
if len(sys.argv) > 2:
    def noted(*_):
        with open(pidfile + ".term", "w") as f:
            f.write("x")
    signal.signal(signal.SIGTERM, noted)
for line in sys.stdin:
    pass
with open(pidfile + ".eof", "w") as f:
    f.write("eof")
time.sleep(60)
"""

# Leaves when its input closes, but a helper it started goes on holding the
# output pipe open for a couple of seconds more.
FAKE_LEAVES_A_HELPER = r"""
import subprocess, sys
subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
for line in sys.stdin:
    pass
"""

NOTE = {"jsonrpc": "2.0", "method": "notifications/x", "params": {}}


class TestGracefulShutdown(ProxyCase):
    """Once the client's input ends and every request is answered, the jail
    does what the MCP stdio transport asks of a client that is leaving: it
    closes the server's input, gives the server --grace seconds to finish
    what it was sent and exit (everything it still says is relayed), then
    stops it: SIGTERM, then a kill (terminate() on Windows). It used to stop
    the server the moment its own work was done, and a server that had not
    yet read the last of a burst from its pipe lost it."""

    pid_gone = TestWedgedServer.pid_gone

    def timed(self, *args, **kw):
        started = time.monotonic()
        result = drive_rc(*args, **kw)
        return result, time.monotonic() - started

    def stubborn(self, *extra):
        pidfile = os.path.join(self.tmp, "pid.txt")
        srv = self.srv(FAKE_STUBBORN, "stubborn.py")
        return pidfile, [sys.executable, srv, pidfile] + list(extra)

    def test_a_burst_of_notifications_then_the_end_of_input_reaches_the_server_whole(self):
        log = os.path.join(self.tmp, "seen.txt")
        srv = self.srv(FAKE_SLOW_RECORDER, "slow_rec.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        notes = [{"jsonrpc": "2.0", "method": "notifications/n%d" % i,
                  "params": {"pad": "z" * 2000}} for i in range(100)]
        for attempt in range(2):
            if os.path.exists(log):
                os.remove(log)
            code, raw = drive_rc(pol, [sys.executable, srv, log], notes,
                                 timeout=10)
            self.assertEqual((code, raw), (0, []))
            with open(log, encoding="utf-8") as f:
                seen = [json.loads(l)["method"] for l in f if l.strip()]
            self.assertEqual(seen, ["notifications/n%d" % i for i in range(100)],
                             f"attempt {attempt}")

    def test_a_burst_of_requests_then_the_end_of_input_is_answered_in_full(self):
        srv = self.srv(FAKE_BYE, "bye.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        reqs = [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
                 "params": {"name": "read_file",
                            "arguments": {"pad": "z" * 2000}}}
                for i in range(1, 81)]
        for attempt in range(2):
            code, raw = drive_rc(pol, [sys.executable, srv], reqs, timeout=10)
            self.assertEqual(code, 0)
            answers = [m for m in map(json.loads, raw) if "id" in m]
            self.assertEqual(sorted(m["id"] for m in answers), list(range(1, 81)),
                             f"attempt {attempt}")
            self.assertTrue(all("result" in m for m in answers))

    def test_what_the_server_says_when_its_input_closes_is_still_relayed(self):
        srv = self.srv(FAKE_BYE, "bye.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        code, raw = drive_rc(pol, [sys.executable, srv], [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}}])
        msgs = [json.loads(l) for l in raw]
        self.assertEqual(code, 0)
        self.assertEqual(msgs[0].get("id"), 1)
        self.assertEqual([m.get("method") for m in msgs[1:]],
                         ["notifications/message"])

    def test_a_server_that_leaves_when_its_input_closes_is_not_waited_on_longer(self):
        srv = self.srv(FAKE_BYE, "bye.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        err = io.StringIO()
        with redirect_stderr(err):
            (code, raw), took = self.timed(
                pol, [sys.executable, srv],
                [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "read_file", "arguments": {}}}],
                grace=30)
        self.assertEqual(code, 0)
        self.assertLess(took, 10)
        self.assertNotIn("did not exit", err.getvalue())

    def test_a_server_that_ignores_the_end_of_its_input_is_stopped_after_the_grace(self):
        pidfile, cmd = self.stubborn()
        pol = write_policy(self.tmp, ALLOW_ALL)
        err = io.StringIO()
        with redirect_stderr(err):
            (code, raw), took = self.timed(pol, cmd, [NOTE], grace=2.0)
        self.assertEqual((code, raw), (0, []))
        self.assertGreaterEqual(took, 2.0)      # it was given its two seconds
        self.assertLess(took, 20)
        self.assertTrue(os.path.exists(pidfile + ".eof"))   # its input was closed
        self.assertIn("did not exit within 2s", err.getvalue())
        if os.name != "nt":
            self.assertTrue(self.pid_gone(pidfile))

    @unittest.skipIf(os.name == "nt", "POSIX signals; terminate() on Windows "
                     "is TerminateProcess, which nothing can ignore")
    def test_a_server_that_ignores_sigterm_as_well_is_killed(self):
        pidfile, cmd = self.stubborn("proud")
        pol = write_policy(self.tmp, ALLOW_ALL)
        with mock.patch.object(jail_mod, "_TERM_WAIT", 0.5), \
                redirect_stderr(io.StringIO()):
            code, raw = drive_rc(pol, cmd, [NOTE], grace=2.0)
        self.assertEqual((code, raw), (0, []))
        self.assertTrue(os.path.exists(pidfile + ".eof"))
        self.assertTrue(os.path.exists(pidfile + ".term"))  # asked politely first
        self.assertTrue(self.pid_gone(pidfile))             # then not asked

    @unittest.skipIf(os.name == "nt", "whether a helper inherits the pipe is "
                     "a Windows handle-inheritance question; POSIX descriptors "
                     "are simply inherited")
    def test_a_helper_that_holds_the_servers_output_open_is_named_as_the_wait(self):
        # mcp-jail cannot close the pipe under its own reader, so it does wait
        # for the helper (see Limitations); it says why instead of blaming a
        # server that has in fact gone
        srv = self.srv(FAKE_LEAVES_A_HELPER, "helper.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        err = io.StringIO()
        with redirect_stderr(err):
            code, raw = drive_rc(pol, [sys.executable, srv], [NOTE], grace=0.5)
        self.assertEqual((code, raw), (0, []))
        self.assertIn("server has exited, but something it started still "
                      "has its output open", err.getvalue())
        self.assertNotIn("did not exit", err.getvalue())

    def test_grace_0_stops_the_server_at_once(self):
        pidfile, cmd = self.stubborn()
        pol = write_policy(self.tmp, ALLOW_ALL)
        err = io.StringIO()
        with redirect_stderr(err):
            (code, raw), took = self.timed(pol, cmd, [NOTE], grace=0)
        self.assertEqual((code, raw), (0, []))
        self.assertLess(took, 10)
        self.assertNotIn("did not exit", err.getvalue())
        # it may have been stopped before it wrote its pid down
        if os.name != "nt" and os.path.exists(pidfile):
            self.assertTrue(self.pid_gone(pidfile))

    def test_a_failed_session_does_not_wait_for_the_grace(self):
        # the server stopped reading: it is killed, not given 30 s to leave
        pidfile = os.path.join(self.tmp, "pid.txt")
        srv = self.srv(FAKE_DEAF, "deaf.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        with redirect_stderr(io.StringIO()):
            (code, raw), took = self.timed(
                pol, [sys.executable, srv, pidfile],
                [big_call(1), big_call(2)], timeout=2, grace=30)
        self.assertEqual(code, 3)
        self.assertLess(took, 20)

    def test_a_server_that_timed_out_is_not_given_the_grace_either(self):
        # it never answers the request and ignores the end of its input
        pidfile, cmd = self.stubborn()
        pol = write_policy(self.tmp, ALLOW_ALL)
        with redirect_stderr(io.StringIO()):
            (code, raw), took = self.timed(
                pol, cmd,
                [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "read_file", "arguments": {}}}],
                timeout=1, grace=30)
        self.assertEqual(code, 3)
        self.assertLess(took, 20)
        self.assertEqual([json.loads(l)["error"]["message"] for l in raw],
                         ["server timed out"])

    def test_the_command_line_passes_the_grace_on(self):
        pidfile, cmd = self.stubborn()
        pol = write_policy(self.tmp, ALLOW_ALL)
        started = time.monotonic()
        proc = subprocess.run(
            [sys.executable, "-m", "mcp_jail", "--policy", pol, "--grace", "1",
             "--"] + cmd,
            input=b"", capture_output=True, env=child_env(), cwd=self.tmp,
            timeout=60)
        took = time.monotonic() - started
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertGreaterEqual(took, 1.0)
        self.assertLess(took, 30)
        self.assertIn(b"did not exit within 1s", proc.stderr)
        if os.name != "nt" and os.path.exists(pidfile):
            self.assertTrue(self.pid_gone(pidfile))

    def test_grace_defaults_to_5_seconds_and_is_in_the_help(self):
        self.assertEqual(jail_mod.DEFAULT_GRACE, 5.0)
        args = cli_mod.build_parser().parse_args(["--", "x"])
        self.assertEqual(args.grace, 5.0)
        self.assertIn("--grace", cli_mod.build_parser().format_help())
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            cli_mod.cmd_learn(["--help"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("--grace", out.getvalue())

    def test_readme_describes_the_shutdown_and_no_longer_owns_up_to_the_race(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())
        for needle in ("`--grace N` (default 5; `0` stops the server at once)",
                       "SIGTERM"):
            self.assertTrue(needle in readme, f"the README does not say {needle}")
        limits = readme.split("## Limitations", 1)[1].split(" ## ", 1)[0]
        self.assertFalse("stopped as soon as" in limits,
                         "the Limitations still own up to the race")
        self.assertTrue("holds the server's *output* open is waited for" in limits,
                        "the Limitations do not say a helper holding the "
                        "output delays the exit")


class TestSecondsOptions(ProxyCase):
    """--timeout and --grace are a number of seconds. float() also takes
    "nan", "inf" and a minus sign: nan and a negative value quietly meant "no
    timeout", and inf (or 1e12) died with an OverflowError traceback in the
    first wait."""

    OPTIONS = ("--timeout", "--grace")
    BAD = ["nan", "NaN", "inf", "-inf", "Infinity", "-1", "-0.5", "abc", ""]
    GOOD = ["0", "0.5", "30", "1e3", "1e12"]

    def refused(self, parse, args) -> str:
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            parse(args)
        self.assertEqual(cm.exception.code, 2)
        return err.getvalue()

    def test_the_parser_refuses_a_bad_value_and_names_the_option(self):
        for opt in self.OPTIONS:
            for bad in self.BAD:
                with self.subTest(option=opt, value=bad):
                    text = self.refused(cli_mod.build_parser().parse_args,
                                        [opt, bad, "--", "x"])
                    self.assertIn(opt, text)
                    self.assertNotIn("Traceback", text)

    def test_learn_refuses_them_too(self):
        for opt in self.OPTIONS:
            for bad in self.BAD:
                with self.subTest(option=opt, value=bad):
                    text = self.refused(cli_mod.cmd_learn, [opt, bad, "--", "x"])
                    self.assertIn(opt, text)

    def test_ordinary_values_are_still_accepted(self):
        for opt in self.OPTIONS:
            for good in self.GOOD:
                with self.subTest(option=opt, value=good):
                    args = cli_mod.build_parser().parse_args([opt, good, "--", "x"])
                    self.assertEqual(getattr(args, opt[2:]), float(good))

    def test_a_bad_value_ends_in_exit_2_and_never_starts_the_server(self):
        started = os.path.join(self.tmp, "started")
        pol = write_policy(self.tmp, ALLOW_ALL)
        for opt in self.OPTIONS:
            for bad in ("nan", "inf", "-1"):
                with self.subTest(option=opt, value=bad):
                    proc = subprocess.run(
                        [sys.executable, "-m", "mcp_jail", "--policy", pol,
                         opt, bad, "--", sys.executable, "-c",
                         "open(%r, 'w').close()" % started],
                        input=b"", capture_output=True, env=child_env(),
                        cwd=self.tmp, timeout=60)
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertIn(opt.encode(), proc.stderr)
                    self.assertNotIn(b"Traceback", proc.stderr)
                    self.assertFalse(os.path.exists(started))

    def test_the_library_entry_points_refuse_them_without_a_server(self):
        started = os.path.join(self.tmp, "started")
        cmd = [sys.executable, "-c", "open(%r, 'w').close()" % started]
        pol = write_policy(self.tmp, ALLOW_ALL)
        for name in ("timeout", "grace"):
            for bad in (float("nan"), float("inf"), -1.0):
                with self.subTest(option=name, value=bad):
                    err = io.StringIO()
                    with redirect_stderr(err):
                        run_code = jail_mod.run(pol, cmd, stdin=io.BytesIO(b""),
                                                stdout=io.BytesIO(), **{name: bad})
                        learn_code = jail_mod.learn(cmd, stdin=io.BytesIO(b""),
                                                    stdout=io.BytesIO(), **{name: bad})
                    self.assertEqual((run_code, learn_code), (2, 2))
                    self.assertEqual(err.getvalue().count("--" + name), 2,
                                     err.getvalue())
                    self.assertFalse(os.path.exists(started))

    def test_a_huge_timeout_is_not_a_crash(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, self.server,
                           [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}],
                           timeout=1e12)
        self.assertEqual([r["id"] for r in resps], [1])

    def test_learn_with_timeout_0_waits_for_ever_like_the_proxy_does(self):
        # it used to be a deadline that had already passed: every answer a
        # moment too late
        src = ("import json, sys, time\n"
               "for line in sys.stdin:\n"
               "    req = json.loads(line)\n"
               "    time.sleep(0.5)\n"
               "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', "
               "'id': req['id'], 'result': {}}) + '\\n')\n"
               "    sys.stdout.flush()\n")
        proc = jail_mod._spawn([sys.executable, self.srv(src, "slow.py")])
        session = jail_mod._Session(proc)
        try:
            status = session.request(
                {"jsonrpc": "2.0", "id": 1, "method": "ping"}, 0)
        finally:
            session.close()
            jail_mod._stop(proc)
        self.assertEqual(status[0], "ok")

    def test_readme_says_which_values_are_refused(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())     # line breaks do not matter
        for needle in ("`nan`, `inf` and negative values are refused",
                       "is a directory, or cannot be read"):
            self.assertTrue(needle in readme, f"the README does not say {needle}")

    def test_a_policy_path_that_cannot_be_read_is_exit_2_not_a_traceback(self):
        # a directory is IsADirectoryError on POSIX and PermissionError on
        # Windows; both are OSError
        started = os.path.join(self.tmp, "started")
        cmd = [sys.executable, "-c", "open(%r, 'w').close()" % started]
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.run(self.tmp, cmd, stdin=io.BytesIO(b""),
                                stdout=io.BytesIO())
        self.assertEqual(code, 2)
        self.assertIn("cannot read the policy", err.getvalue())
        self.assertFalse(os.path.exists(started))

    def test_a_policy_nested_beyond_the_parser_is_exit_2_too(self):
        path = os.path.join(self.tmp, "deep.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("[" * 200000)
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.run(path, [sys.executable, "-c", "pass"],
                                stdin=io.BytesIO(b""), stdout=io.BytesIO())
        self.assertEqual(code, 2)
        self.assertIn("bad policy", err.getvalue())


class TestHarnessIsHermetic(unittest.TestCase):
    """Most tests run the jail in this process (drive_rc), so the servers it
    starts inherit this process's environment. PYTHONUNBUFFERED in it would
    hide a server that forgot to flush, which hangs for a real client."""

    def test_a_server_the_jail_starts_does_not_inherit_pythonunbuffered(self):
        proc = jail_mod._spawn(
            [sys.executable, "-c",
             "import os; print(os.environ.get('PYTHONUNBUFFERED'))"])
        try:
            out = proc.stdout.read()
        finally:
            jail_mod._stop(proc)
        self.assertEqual(out.strip(), b"None")
        self.assertNotIn("PYTHONUNBUFFERED", child_env())


if __name__ == "__main__":
    unittest.main()

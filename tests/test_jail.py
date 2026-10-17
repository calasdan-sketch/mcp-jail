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


def tearDownModule():
    for var, old in _saved_env.items():
        if old is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = old
    _rmtree(_fake_home)


def mktemp() -> str:
    return tempfile.mkdtemp(prefix="mj")


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


def drive_raw(policy_path: str, server_cmd: list, requests, timeout: float = 30.0,
              join: float = 20) -> list[bytes]:
    """Run the jail in-process on in-memory streams; return raw output
    lines. `requests` may be dicts (serialised) or raw strings."""
    chunks = []
    for r in requests:
        chunks.append(r if isinstance(r, str) else json.dumps(r))
    inp = io.BytesIO(("\n".join(chunks) + "\n").encode("utf-8"))
    out = io.BytesIO()

    def target():
        jail_mod.run(policy_path, server_cmd, timeout=timeout,
                     stdin=inp, stdout=out)

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout=join)
    if t.is_alive():
        raise AssertionError("proxy did not finish (hung?)")
    return [ln for ln in out.getvalue().split(b"\n") if ln.strip()]


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

    def test_upstream_response_passed_through_untouched(self):
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
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
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
        self.assertEqual(seen[0], json.dumps(json.loads(good)))
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
    used to abort the proxy with a fatal `_enter_buffered_busy` (rc -6)."""

    def test_server_exit_with_client_stdin_open_is_clean(self):
        pol = write_policy(self.tmp, ALLOW_ALL)
        quit_srv = write_server(self.tmp, "import sys\nsys.stdin.readline()\n",
                                "quit.py")
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
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
        self.assertEqual(rc, 0, err)
        self.assertNotIn(b"Fatal Python error", err)
        self.assertNotIn(b"Traceback", err)
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

    def test_readme_test_count_matches_suite(self):
        m = re.search(r"# (\d+) tests", self.readme())
        self.assertIsNotNone(m, "README lacks the '# N tests' note")
        suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        self.assertEqual(int(m.group(1)), suite.countTestCases())

    def test_license_and_install_docs(self):
        with open(os.path.join(REPO, "LICENSE"), encoding="utf-8") as f:
            lic = f.read()
        self.assertIn("MIT License", lic)
        self.assertIn("Dan Calas", lic)
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
            proj = tomllib.load(f)["project"]
        self.assertEqual(proj["license"], "MIT")
        self.assertEqual(proj["license-files"], ["LICENSE"])
        readme = self.readme()
        self.assertNotIn("TBD", readme)
        self.assertIn("pip install git+https://github.com/calasdan-sketch/mcp-jail", readme)
        self.assertNotIn("git clone <repo>", readme)
        self.assertNotRegex(readme, r"(?m)^\s*#?\s*(?:or: )?alias ")
        for word in ("strict_args", "audit_args", "0600", "duplicate", "re-serialised",
                     "case-insensitive", "`..`"):
            self.assertIn(word, readme, word)

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
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
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


if __name__ == "__main__":
    unittest.main()

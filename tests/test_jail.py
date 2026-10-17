"""mcp-jail tests: fake upstream server over stdio, no network.

Portable by construction: no symlinks, no select(), no signals; every
text file is opened with an explicit encoding; HOME/USERPROFILE/APPDATA
point at a throwaway directory for the whole module so nothing here ever
reads or writes the real user's ~/.mcp-jail.
"""

import argparse
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
        self.assertTrue(jail_mod.tool_allowed(
            pol, "read_file", {"path": "/tmp/a", "tags": []})[0])

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
        # V9: non-JSON line from the server -> JSON-RPC error, proxy alive
        server = self.srv(FAKE_FLAKY, "flaky.py")
        pol = write_policy(self.tmp, ALLOW_ALL)
        resps = drive_jail(pol, server, [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "garbage", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {}}},
        ])
        self.assertEqual(len(resps), 2)
        self.assertIn("error", resps[0])
        self.assertEqual(resps[0]["error"]["code"], -32603)
        self.assertIn("bad response", resps[0]["error"]["message"])
        # proxy survived: the next call still works
        self.assertEqual(resps[1].get("result"), {"ok": True})

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
                         {"path": ["^" + jail_mod._TRAVERSAL_GUARD
                                   + "/tmp/[a-z]*$"]})

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
        self.assertEqual(pol["arg_rules"], {"run_cmd": {"allow": {"cmd": ["^ls$"]},
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
        pat = gen["arg_rules"]["read_file"]["allow"]["path"][0]
        self.assertTrue(pat.startswith("^" + jail_mod._TRAVERSAL_GUARD + "/srv/data/"))
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


if __name__ == "__main__":
    unittest.main()

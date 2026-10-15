"""mcp-jail tests: fake upstream server over stdio, no network."""

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

from mcp_jail import cli as cli_mod
from mcp_jail import jail as jail_mod

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


def write_server(tmp: str) -> str:
    p = os.path.join(tmp, "fake_server.py")
    with open(p, "w") as f:
        f.write(FAKE_SERVER)
    return p


def write_policy(tmp: str, pol: dict) -> str:
    p = os.path.join(tmp, "policy.json")
    with open(p, "w") as f:
        json.dump(pol, f)
    return p


def drive_jail(policy_path: str, server_path: str,
               requests: list[dict], timeout: float = 30.0) -> list[dict]:
    """Run the jail in-process with piped stdin/stdout, feed requests."""
    inp = "\n".join(json.dumps(r) for r in requests) + "\n"
    # run jail in a thread with swapped stdio
    out_buf = io.StringIO()
    results: list[dict] = []

    import threading

    def target():
        old_in, old_out = sys.stdin, sys.stdout
        sys.stdin = io.StringIO(inp)
        sys.stdout = out_buf
        try:
            try:
                jail_mod.run(policy_path, [sys.executable, server_path],
                             timeout=timeout)
            except TypeError:
                # pre-fix run() has no timeout kwarg; exercise the old path
                jail_mod.run(policy_path, [sys.executable, server_path])
        finally:
            sys.stdin, sys.stdout = old_in, old_out

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout=20)
    for ln in out_buf.getvalue().splitlines():
        ln = ln.strip()
        if ln:
            results.append(json.loads(ln))
    return results


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
        import re
        pol["arg_rules"]["run_cmd"]["deny"] = [re.compile(r"rm -rf")]
        ok, _ = jail_mod.tool_allowed(pol, "run_cmd", {"cmd": "ls"})
        self.assertTrue(ok)
        ok, reason = jail_mod.tool_allowed(pol, "run_cmd", {"cmd": "rm -rf /"})
        self.assertFalse(ok)
        self.assertIn("deny pattern", reason)


class TestProxy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.server = write_server(self.tmp)
        # isolate audit log
        self._old_audit = jail_mod.AUDIT_LOG
        jail_mod.AUDIT_LOG = os.path.join(self.tmp, "audit.jsonl")

    def tearDown(self):
        jail_mod.AUDIT_LOG = self._old_audit

    def test_allowed_call_proxied(self):
        pol = write_policy(self.tmp, {"allow_tools": ["*"], "deny_tools": [],
                                      "arg_rules": {}, "hide_denied": False})
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
        with open(jail_mod.AUDIT_LOG) as f:
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


class TestCLI(unittest.TestCase):
    def test_init_policy(self):
        tmp = tempfile.mkdtemp()
        p = os.path.join(tmp, "sub", "policy.json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main(["--init-policy", "--path", p])
        self.assertEqual(code, 0)
        with open(p) as f:
            data = json.load(f)
        self.assertIn("allow_tools", data)

    def test_no_server(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main([])
        self.assertEqual(code, 2)

    def test_bad_policy(self):
        tmp = tempfile.mkdtemp()
        p = os.path.join(tmp, "bad.json")
        with open(p, "w") as f:
            f.write("{not json")
        code = jail_mod.run(p, [sys.executable, "-c", "pass"])
        self.assertEqual(code, 2)

    def test_missing_policy(self):
        code = jail_mod.run("/nope/policy.json",
                            [sys.executable, "-c", "pass"])
        self.assertEqual(code, 2)


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


class TestHardening(unittest.TestCase):
    """Round-3 panel findings: response handling must never kill the proxy."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._old_audit = jail_mod.AUDIT_LOG
        jail_mod.AUDIT_LOG = os.path.join(self.tmp, "audit.jsonl")

    def tearDown(self):
        jail_mod.AUDIT_LOG = self._old_audit

    def _write(self, name: str, src: str) -> str:
        p = os.path.join(self.tmp, name)
        with open(p, "w") as f:
            f.write(src)
        return p

    def test_v9_bad_response_line(self):
        # V9: non-JSON line from the server -> JSON-RPC error, proxy alive
        server = self._write("flaky.py", FAKE_FLAKY)
        pol = write_policy(self.tmp, {"allow_tools": ["*"], "deny_tools": [],
                                      "arg_rules": {}, "hide_denied": False})
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
        server = self._write("hang.py", FAKE_HANG)
        pol = write_policy(self.tmp, {"allow_tools": ["*"], "deny_tools": [],
                                      "arg_rules": {}, "hide_denied": False})
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
        server = self._write("srv.py", FAKE_SERVER)
        pol = write_policy(self.tmp, {"allow_tools": ["read_file"],
                                      "deny_tools": [], "arg_rules": {},
                                      "hide_denied": False})
        resps = drive_jail(pol, server, [
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


class TestLearn(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.server = write_server(self.tmp)
        self._old_audit = jail_mod.AUDIT_LOG
        jail_mod.AUDIT_LOG = os.path.join(self.tmp, "audit.jsonl")

    def tearDown(self):
        jail_mod.AUDIT_LOG = self._old_audit

    def test_learn_script_policy(self):
        script = os.path.join(self.tmp, "calls.json")
        with open(script, "w") as f:
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
        with open(out) as f:
            raw = json.load(f)
        # allowlist is exactly the observed tools, no "*"
        # (fake server advertises delete_all in tools/list, and the
        # script calls read_file + run_cmd)
        self.assertEqual(raw["allow_tools"],
                         ["delete_all", "read_file", "run_cmd"])

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

        summary = err.getvalue()
        self.assertIn("3 tool", summary)
        self.assertIn("3 call", summary)


if __name__ == "__main__":
    unittest.main()

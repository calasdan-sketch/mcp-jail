"""mcp-jail 0.7.0: --lockfile / --on-drift, --shadow, verify-policy, learn
--record. A fixture server changes its tool list after the first call; the
lock was made from the list it gave before."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from mcp_jail import cli as cli_mod
from mcp_jail import jail as jail_mod
from mcp_jail import lockfile as lf
from mcp_jail import lockguard
from mcp_jail import policytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "tests", "fixtures", "mutating_mcp_server.py")
VECTORS = os.path.join(REPO, "tests", "vectors", "lockfile_v1.json")

_spec = importlib.util.spec_from_file_location("mutating_fixture", FIXTURE)
fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fixture)

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "1"}}}
INITED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
POLICY = {"allow_tools": ["*"], "deny_tools": [], "arg_rules": {},
          "hide_denied": False}


def call(i, name, **args):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": name, "arguments": args}}


def lst(i, cursor=None):
    msg = {"jsonrpc": "2.0", "id": i, "method": "tools/list"}
    if cursor:
        msg["params"] = {"cursor": cursor}
    return msg


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mj10-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        env = mock.patch.dict(os.environ, {"HOME": self.tmp,
                                           "USERPROFILE": self.tmp})
        env.start()
        self.addCleanup(env.stop)
        self.log = os.path.join(self.tmp, "audit.jsonl")
        old = jail_mod.AUDIT_LOG
        jail_mod.AUDIT_LOG = self.log
        self.addCleanup(setattr, jail_mod, "AUDIT_LOG", old)
        self.policy = self.write("policy.json", POLICY)

    def write(self, name, obj):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as f:
            if isinstance(obj, str):
                f.write(obj)
            else:
                json.dump(obj, f)
        return path

    def cmd(self, *extra):
        return [sys.executable, FIXTURE, "--after-calls", "1", *extra]

    def make_lock(self, server_cmd=None, tools=None, name="fx", path=None):
        server_cmd = server_cmd or self.cmd()
        tools = tools if tools is not None else fixture.tools("description",
                                                              False)
        entries, bad = lf.tools_entries(tools)
        self.assertEqual(bad, [])
        lock = lf.new_lock("test")
        lock["servers"][name] = lf.server_entry(
            lf.command_fingerprint(server_cmd[0], server_cmd[1:]), entries)
        path = path or os.path.join(self.tmp, "mcp.lock")
        with open(path, "w", encoding="utf-8") as f:
            f.write(lf.dump_lock(lock))
        return path

    def drive(self, requests, server_cmd=None, join=30, **kw):
        """Run the jail on pipes and talk to it like a client: each request
        waits for its answer before the next is sent (a notification does
        not), so a tools/list is reviewed before the call that follows."""
        server_cmd = server_cmd or self.cmd()
        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()
        stdin, stdout = os.fdopen(in_r, "rb"), os.fdopen(out_w, "wb")
        wfile, rfile = os.fdopen(in_w, "wb"), os.fdopen(out_r, "rb")
        code, err = [], io.StringIO()

        def target():
            with redirect_stderr(err):
                code.append(jail_mod.run(self.policy, server_cmd,
                                         timeout=20, stdin=stdin,
                                         stdout=stdout, grace=1, **kw))
            stdout.close()
        t = threading.Thread(target=target, daemon=True)
        t.start()
        replies = {}
        try:
            for r in requests:
                wfile.write(json.dumps(r).encode() + b"\n")
                wfile.flush()
                if "id" not in r:
                    continue
                while r["id"] not in replies:
                    ln = rfile.readline()
                    if not ln:           # the jail ended (startup refused)
                        raise EOFError
                    m = json.loads(ln)
                    if "id" in m:
                        replies[m["id"]] = m
        except (EOFError, BrokenPipeError):
            pass
        finally:
            try:
                wfile.close()
            except BrokenPipeError:
                pass
            t.join(join)
            stdin.close()
            rfile.close()
        if t.is_alive():
            raise AssertionError("the jail did not finish")
        self.err = err.getvalue()
        return code[0], replies

    def session(self, **kw):
        return self.drive([INIT, INITED, lst(2), call(3, "read_file", path="/a"),
                           lst(4), call(5, "read_file", path="/a"),
                           call(6, "echo", text="hi")], **kw)

    def audit_records(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log, encoding="utf-8") as f:
            return [json.loads(ln) for ln in f if ln.strip()]

    @staticmethod
    def names(reply):
        return [t["name"] for t in reply["result"]["tools"]]


class TestOnDrift(Base):
    def test_unchanged_server_passes_untouched(self):
        cmd = self.cmd()[:-2] + ["--after-calls", "99"]
        lock = self.make_lock(cmd)
        code, r = self.drive([INIT, INITED, lst(2), call(3, "echo", text="x"),
                              lst(4)], server_cmd=cmd, lockfile=lock,
                             on_drift="block")
        self.assertEqual(code, 0)
        self.assertEqual(self.names(r[2]), ["read_file", "echo"])
        self.assertIn("result", r[3])
        self.assertEqual(self.names(r[4]), ["read_file", "echo"])
        self.assertFalse([a for a in self.audit_records() if "drift" in a])

    def test_block_refuses_the_changed_list_and_the_tool(self):
        code, r = self.session(lockfile=self.make_lock(), on_drift="block")
        self.assertEqual(code, 0)
        self.assertEqual(self.names(r[2]), ["read_file", "echo"])   # before
        self.assertIn("result", r[3])                    # the clean call ran
        self.assertIn("error", r[4])
        self.assertIn("description changed", r[4]["error"]["message"])
        self.assertIn("error", r[5])
        self.assertIn("lockfile", r[5]["error"]["message"])
        self.assertIn("result", r[6])                    # echo is unchanged

    def test_block_is_the_default_mode(self):
        code, r = self.session(lockfile=self.make_lock())
        self.assertIn("error", r[4])
        self.assertIn("error", r[5])

    def test_strip_hides_only_the_changed_tool(self):
        code, r = self.session(lockfile=self.make_lock(), on_drift="strip")
        self.assertEqual(self.names(r[4]), ["echo"])
        self.assertIn("error", r[5])
        self.assertIn("result", r[6])

    def test_strip_also_removes_a_tool_that_was_added(self):
        cmd = self.cmd("--mutation", "add")
        code, r = self.session(server_cmd=cmd, lockfile=self.make_lock(cmd),
                               on_drift="strip")
        self.assertEqual(self.names(r[4]), ["read_file", "echo"])
        code, r = self.drive([INIT, INITED, lst(2), call(3, "echo", text="x"),
                              lst(4), call(5, "send_file")], server_cmd=cmd,
                             lockfile=self.make_lock(cmd), on_drift="strip")
        self.assertIn("error", r[5])
        self.assertIn("new tool", r[5]["error"]["message"])

    def test_schema_change_is_drift(self):
        cmd = self.cmd("--mutation", "schema")
        code, r = self.session(server_cmd=cmd, lockfile=self.make_lock(cmd),
                               on_drift="block")
        self.assertIn("schema changed", r[4]["error"]["message"])

    def test_new_tool_is_drift_in_block_mode(self):
        cmd = self.cmd("--mutation", "add")
        code, r = self.session(server_cmd=cmd, lockfile=self.make_lock(cmd),
                               on_drift="block")
        self.assertIn("error", r[4])
        self.assertIn("send_file", r[4]["error"]["message"])

    def test_warn_passes_everything_and_says_so(self):
        code, r = self.session(lockfile=self.make_lock(), on_drift="warn")
        self.assertEqual(self.names(r[4]), ["read_file", "echo"])
        self.assertIn("result", r[5])
        self.assertIn("description changed", self.err)
        rec = [a for a in self.audit_records() if "drift" in a]
        self.assertTrue(rec)
        self.assertEqual({a["decision"] for a in rec}, {"allow"})

    def test_ask_yes_allows_the_change_for_the_session(self):
        asked = []
        code, r = self.session(lockfile=self.make_lock(), on_drift="ask",
                               ask=lambda q: asked.append(q) or True)
        self.assertEqual(len(asked), 1)
        self.assertIn("read_file", asked[0])
        self.assertEqual(self.names(r[4]), ["read_file", "echo"])
        self.assertIn("result", r[5])

    def test_ask_no_blocks(self):
        code, r = self.session(lockfile=self.make_lock(), on_drift="ask",
                               ask=lambda q: False)
        self.assertIn("error", r[4])
        self.assertIn("error", r[5])

    def test_ask_without_a_terminal_blocks(self):
        with mock.patch.object(lockguard, "_terminal_streams",
                               side_effect=OSError("no tty")):
            self.assertFalse(lockguard.ask_on_terminal("?"))

    def test_ask_is_not_asked_twice_for_the_same_change(self):
        asked = []
        reqs = [INIT, INITED, lst(2), call(3, "read_file", path="/a"),
                lst(4), lst(5), call(6, "read_file", path="/a")]
        code, r = self.drive(reqs, lockfile=self.make_lock(),
                             on_drift="ask",
                             ask=lambda q: asked.append(q) or True)
        self.assertEqual(len(asked), 1)
        self.assertIn("result", r[6])

    def test_ask_time_does_not_count_against_the_servers_timeout(self):
        p = jail_mod._Pending()
        p.add(1, "tools/call", 100.0)
        p.extend(50.0)
        self.assertEqual(p.peek(1)["deadline"], 150.0)
        self.assertEqual(p._heap[0][0], 150.0)

    def test_removed_tool_is_only_a_hint(self):
        cmd = self.cmd("--mutation", "remove")
        code, r = self.session(server_cmd=cmd, lockfile=self.make_lock(cmd),
                               on_drift="block")
        self.assertEqual(self.names(r[4]), ["read_file"])
        self.assertIn("result", r[5])
        removed = [a for a in self.audit_records()
                   if a.get("drift") == lf.REMOVED_TOOL]
        self.assertEqual([a["decision"] for a in removed], ["allow"])

    def test_annotation_change_is_a_hint_not_drift(self):
        cmd = self.cmd("--mutation", "annotations")
        code, r = self.session(server_cmd=cmd, lockfile=self.make_lock(cmd),
                               on_drift="block")
        self.assertEqual(self.names(r[4]), ["read_file", "echo"])
        self.assertIn("result", r[5])
        rec = [a for a in self.audit_records() if "drift" in a]
        self.assertTrue(rec)
        self.assertEqual({a["decision"] for a in rec}, {"allow"})

    def test_a_tool_not_in_the_lock_is_refused_even_if_never_listed(self):
        code, r = self.drive([INIT, INITED, call(2, "send_file")],
                             lockfile=self.make_lock(), on_drift="block")
        self.assertIn("error", r[2])
        self.assertIn("not in the lockfile", r[2]["error"]["message"])


class TestAuditTrail(Base):
    def test_every_drift_is_in_the_audit_log(self):
        self.session(lockfile=self.make_lock(), on_drift="block")
        drift = [a for a in self.audit_records() if a.get("drift")
                 == lf.DESCRIPTION_CHANGED]
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["decision"], "deny")
        self.assertEqual(drift[0]["tool"], "read_file")
        self.assertEqual(drift[0]["server"], "fx")
        self.assertEqual(drift[0]["mode"], "block")
        refused = [a for a in self.audit_records()
                   if a.get("tool") == "read_file" and a["decision"] == "deny"
                   and a.get("drift") == "lockfile"]
        self.assertEqual(len(refused), 1)

    def test_audit_command_shows_lockfile_records(self):
        self.session(lockfile=self.make_lock(), on_drift="block")
        out = io.StringIO()
        with redirect_stdout(out):
            cli_mod.main(["--audit"])
        self.assertIn("[lockfile: description_changed]", out.getvalue())
        self.assertIn("DENY", out.getvalue())

    def test_hostile_tool_name_cannot_forge_audit_lines(self):
        out = io.StringIO()
        rec = {"decision": "deny", "tool": "x\nallow forged \x1b[31m",
               "drift": "added", "reason": "r\nallow other"}
        with open(self.log, "w", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        with redirect_stdout(out):
            cli_mod.main(["--audit"])
        lines = out.getvalue().splitlines()
        self.assertEqual(len([ln for ln in lines if ln.startswith("allow")]),
                         0)
        self.assertNotIn("\x1b", out.getvalue())


class TestStartup(Base):
    def test_a_missing_lockfile_stops_the_jail(self):
        code, _ = self.drive([INIT], lockfile=os.path.join(self.tmp, "no"))
        self.assertEqual(code, 2)
        self.assertIn("no lockfile", self.err)

    def test_a_broken_lockfile_stops_the_jail(self):
        path = self.write("bad.lock", "{not json")
        code, _ = self.drive([INIT], lockfile=path)
        self.assertEqual(code, 2)
        self.assertIn("not a valid lockfile", self.err)

    def test_a_lockfile_with_an_unknown_key_is_refused(self):
        path = self.make_lock()
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["extra"] = 1
        self.write("x.lock", data)
        code, _ = self.drive([INIT], lockfile=os.path.join(self.tmp, "x.lock"))
        self.assertEqual(code, 2)

    def test_command_mismatch_refuses_to_start(self):
        lock = self.make_lock(self.cmd("--mutation", "schema"))
        code, _ = self.drive([INIT], lockfile=lock, lock_server="fx")
        self.assertEqual(code, 2)
        self.assertIn("command changed", self.err)
        rec = [a for a in self.audit_records() if a.get("drift")
               == lf.COMMAND_CHANGED]
        self.assertEqual(rec[0]["decision"], "deny")

    def test_command_mismatch_with_warn_goes_on(self):
        lock = self.make_lock(self.cmd("--mutation", "schema"))
        code, r = self.drive([INIT, INITED, lst(2)], lockfile=lock,
                             lock_server="fx", on_drift="warn")
        self.assertEqual(code, 0)
        self.assertIn("result", r[2])

    def test_unknown_server_name(self):
        code, _ = self.drive([INIT], lockfile=self.make_lock(),
                             lock_server="nope")
        self.assertEqual(code, 2)
        self.assertIn("no server named 'nope'", self.err)

    def test_no_server_matches_the_command(self):
        lock = self.make_lock(server_cmd=[sys.executable, "other.py"])
        code, _ = self.drive([INIT], lockfile=lock)
        self.assertEqual(code, 2)
        self.assertIn("--lock-server", self.err)

    def test_lock_server_names_the_entry(self):
        lock = self.make_lock(self.cmd("--mutation", "schema"), name="a")
        code, r = self.drive([INIT, INITED, lst(2)], lockfile=lock,
                             lock_server="a", on_drift="warn")
        self.assertEqual(code, 0)

    def test_bad_on_drift_value(self):
        code, _ = self.drive([INIT], lockfile=self.make_lock(),
                             on_drift="maybe")
        self.assertEqual(code, 2)

    def test_cli_rejects_a_bad_on_drift(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as c:
            cli_mod.main(["--on-drift", "maybe", "--", "x"])
        self.assertEqual(c.exception.code, 2)

    def test_cli_shadow_report_needs_shadow(self):
        err = io.StringIO()
        with redirect_stderr(err):
            rc = cli_mod.main(["--policy", self.policy, "--shadow-report",
                               "r.json", "--", sys.executable, "-c", "pass"])
        self.assertEqual(rc, 2)


class TestPagination(Base):
    PAGES = r"""
import json, sys
T = [{"name": "a", "description": "A", "inputSchema": {"type": "object"}},
     {"name": "b", "description": "B", "inputSchema": {"type": "object"}}]
for raw in sys.stdin:
    req = json.loads(raw)
    rid = req.get("id")
    if rid is None:
        continue
    cur = (req.get("params") or {}).get("cursor")
    if req["method"] == "tools/list":
        res = ({"tools": [T[0]], "nextCursor": "p2"} if not cur
               else {"tools": [T[1]]})
    else:
        res = {}
    print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}), flush=True)
"""

    def test_a_removed_tool_is_only_reported_on_a_complete_list(self):
        srv = self.write("pages.py", self.PAGES)
        cmd = [sys.executable, srv]
        tools = [{"name": "a", "description": "A",
                  "inputSchema": {"type": "object"}},
                 {"name": "b", "description": "B",
                  "inputSchema": {"type": "object"}}]
        lock = self.make_lock(cmd, tools)
        code, r = self.drive([INIT, INITED, lst(2), lst(3, "p2")],
                             server_cmd=cmd, lockfile=lock, on_drift="block")
        self.assertEqual(self.names(r[2]), ["a"])      # page 1 is not "b gone"
        self.assertEqual(self.names(r[3]), ["b"])
        self.assertFalse([a for a in self.audit_records()
                          if a.get("drift") == lf.REMOVED_TOOL
                          and a["decision"] == "deny"])


class TestShadow(Base):
    def test_shadow_forwards_everything_and_reports(self):
        report = os.path.join(self.tmp, "shadow.json")
        code, r = self.session(lockfile=self.make_lock(), on_drift="block",
                               shadow=True, shadow_report=report)
        self.assertEqual(code, 0)
        self.assertEqual(self.names(r[4]), ["read_file", "echo"])
        self.assertIn("result", r[5])
        self.assertIn("would have been blocked", self.err)
        with open(report, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["would_have_blocked_calls"], 1)
        kinds = {i["kind"] for i in data["would_have_blocked"]}
        self.assertEqual(kinds, {"call", "lockfile"})

    def test_shadow_audit_says_would_deny(self):
        self.session(lockfile=self.make_lock(), shadow=True)
        decisions = {a["decision"] for a in self.audit_records()}
        self.assertIn("would-deny", decisions)
        self.assertNotIn("deny", decisions)

    def test_shadow_with_a_policy_denial(self):
        self.policy = self.write("p2.json", {"allow_tools": ["echo"],
                                             "deny_tools": [], "arg_rules": {},
                                             "hide_denied": False})
        code, r = self.drive([INIT, INITED, call(2, "read_file", path="/a"),
                              call(3, "echo", text="x")], shadow=True)
        self.assertIn("result", r[2])            # it reached the server
        self.assertIn("would have been", self.err)
        self.assertIn("read_file", self.err)

    def test_shadow_reports_nothing_when_nothing_differs(self):
        report = os.path.join(self.tmp, "s.json")
        self.drive([INIT, INITED, call(2, "echo", text="x")],
                   lockfile=self.make_lock(), shadow=True,
                   shadow_report=report)
        with open(report, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["would_have_blocked"], [])
        self.assertIn("changed nothing", self.err)

    def test_shadow_never_asks(self):
        asked = []
        self.session(lockfile=self.make_lock(), on_drift="ask", shadow=True,
                     ask=lambda q: asked.append(q) or True)
        self.assertEqual(asked, [])

    def test_shadow_text_cleans_hostile_names(self):
        text = jail_mod.shadow_text({
            "calls_seen": 1, "would_have_blocked_calls": 1,
            "would_have_blocked": [{"kind": "call", "subject": "a\nb\x1b",
                                    "reason": "r", "count": 2}]})
        self.assertNotIn("\x1b", text)
        self.assertEqual(len(text.splitlines()), 2)
        self.assertIn("x2", text)

    def test_cli_flags_reach_run(self):
        with mock.patch.object(jail_mod, "run", return_value=0) as run:
            rc = cli_mod.main(["--policy", self.policy, "--lockfile", "m.lock",
                               "--lock-server", "s", "--on-drift", "strip",
                               "--shadow", "--shadow-report", "r.json",
                               "--", "srv", "arg"])
        self.assertEqual(rc, 0)
        kw = run.call_args.kwargs
        self.assertEqual((kw["lockfile"], kw["lock_server"], kw["on_drift"],
                          kw["shadow"], kw["shadow_report"]),
                         ("m.lock", "s", "strip", True, "r.json"))
        self.assertEqual(run.call_args.args[1], ["srv", "arg"])


class TestTwoLaunches(Base):
    def test_a_server_that_changes_between_sessions(self):
        state = os.path.join(self.tmp, "launches")
        cmd = [sys.executable, FIXTURE, "--after-launches", "2",
               "--state", state]
        lock = self.make_lock(cmd)
        code, r = self.drive([INIT, INITED, lst(2)], server_cmd=cmd,
                             lockfile=lock, on_drift="block")
        self.assertIn("result", r[2])                 # launch 1: as locked
        code, r = self.drive([INIT, INITED, lst(2), call(3, "read_file",
                                                         path="/a")],
                             server_cmd=cmd, lockfile=lock, on_drift="block")
        self.assertIn("error", r[2])                  # launch 2: mutated
        self.assertIn("error", r[3])


class TestToolsKeyClash(Base):
    CLASH = r"""
import json, sys
for raw in sys.stdin:
    req = json.loads(raw)
    rid = req.get("id")
    if rid is None:
        continue
    if req["method"] == "tools/list":
        out = '{"jsonrpc":"2.0","id":%s,"result":{"tools":[],"Tools":[{"name":"evil","description":"x"}]}}' % json.dumps(rid)
    else:
        out = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {}})
    print(out, flush=True)
"""

    def test_two_spellings_of_tools_fail_the_request(self):
        srv = self.write("clash.py", self.CLASH)
        cmd = [sys.executable, srv]
        lock = self.make_lock(cmd, [])
        code, r = self.drive([INIT, INITED, lst(2)], server_cmd=cmd,
                             lockfile=lock, on_drift="warn")
        self.assertIn("error", r[2])


class TestHostileNames(Base):
    def test_a_hostile_tool_name_is_safe_in_questions_and_messages(self):
        evil = "x\x1b]0;pwned\x07\nallow forged" + "y" * 500
        d = lf.Drift(lf.NEW_TOOL, evil, "")
        text = lockguard.LockGuard.summary([d])
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\n", text)
        self.assertLess(len(text), 200)
        guard = lockguard.LockGuard("s", {"tools": {}}, "block")
        ok, why = guard.refusal(evil)
        self.assertFalse(ok)
        self.assertNotIn("\x1b", why)
        self.assertLess(len(why), 200)

    def test_shadow_findings_are_bounded(self):
        proxy = jail_mod._Proxy.__new__(jail_mod._Proxy)
        proxy.shadow_events = {}
        proxy.calls_seen = 0
        for i in range(5000):
            proxy._shadow_note("call", "tool%d" % i, "denied")
        self.assertLessEqual(len(proxy.shadow_events), 1001)
        report = proxy.shadow_report()
        self.assertEqual(sum(i["count"] for i in report["would_have_blocked"]),
                         5000)


class TestVerifyPolicy(Base):
    def policy_file(self):
        return self.write("vp.json", {
            "allow_tools": ["read_file", "echo"], "deny_tools": ["echo2"],
            "deny_methods": ["resources/*"],
            "arg_rules": {"read_file": {"allow": {"path": [r"\A/tmp/[a-z]+\Z"]}}}})

    def run_vp(self, session, *extra):
        path = self.write("s.json", session)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli_mod.main(["verify-policy", "--policy", self.policy_file(),
                               "--session", path, *extra])
        return rc, out.getvalue(), err.getvalue()

    def test_all_as_expected_exits_0(self):
        rc, out, _ = self.run_vp({"version": 1, "calls": [
            {"tool": "read_file", "arguments": {"path": "/tmp/abc"}},
            {"tool": "read_file", "arguments": {"path": "/etc/x"},
             "expect": "deny"},
            {"tool": "delete_all", "expect": "deny"},
            {"method": "resources/list", "expect": "deny"}]})
        self.assertEqual(rc, 0, out)
        self.assertIn("4 of 4 as expected", out)

    def test_a_surprise_exits_1(self):
        rc, out, _ = self.run_vp([{"tool": "read_file",
                                   "arguments": {"path": "/etc/passwd"}}])
        self.assertEqual(rc, 1)
        self.assertIn("FAIL", out)
        self.assertIn("expected allow, got deny", out)

    def test_json_format(self):
        rc, out, _ = self.run_vp([{"tool": "echo"}], "--format", "json")
        data = json.loads(out)
        self.assertEqual((rc, data["total"], data["failed"]), (0, 1, 0))
        self.assertEqual(data["results"][0]["got"], "allow")

    def test_bad_session_exits_2(self):
        for bad in ('{"version": 2, "calls": []}', "[1]", '[{"tool": "a", '
                    '"method": "b"}]', '[{"tool": "a", "expect": "maybe"}]',
                    '{"version": 1, "calls": [], "x": 1}', "{"):
            rc, out, err = self.run_vp(bad)
            self.assertEqual(rc, 2, bad)
            self.assertIn("bad session", err)

    def test_missing_files_exit_2(self):
        err = io.StringIO()
        with redirect_stderr(err):
            rc = policytest.verify_policy(os.path.join(self.tmp, "none"),
                                          os.path.join(self.tmp, "none2"))
        self.assertEqual(rc, 2)
        rc = policytest.verify_policy(self.policy_file(),
                                      os.path.join(self.tmp, "none2"))
        self.assertEqual(rc, 2)

    def test_decisions_equal_the_live_jail(self):
        """verify-policy and the running proxy give the same answer."""
        pol_path = self.policy_file()
        calls = [("read_file", {"path": "/tmp/abc"}),
                 ("read_file", {"path": "/etc/x"}),
                 ("echo", {"text": "hi"}), ("delete_all", {}),
                 ("ECHO", {})]
        for name, args in calls:
            ok, _ = policytest.decide(
                jail_mod.load_policy(pol_path),
                {"key": "tool", "name": name, "arguments": args,
                 "params": None})
            self.policy = pol_path
            code, r = self.drive([INIT, INITED, call(2, name, **args)],
                                 server_cmd=[sys.executable, FIXTURE])
            live = "error" not in r[2]
            self.assertEqual(ok, live, name)

    def test_hostile_names_are_printed_safely(self):
        rc, out, _ = self.run_vp([{"tool": "a\x1b[31m\nallow", "expect": "allow"}])
        self.assertNotIn("\x1b", out)

    def test_a_session_file_with_a_directory_path(self):
        err = io.StringIO()
        with redirect_stderr(err):
            rc = policytest.verify_policy(self.policy_file(), self.tmp)
        self.assertEqual(rc, 2)


class TestLearnRecord(Base):
    def test_record_writes_a_session_that_verifies(self):
        script = self.write("calls.json", [
            {"tool": "read_file", "arguments": {"path": "/tmp/a"}},
            {"tool": "echo", "arguments": {"text": "hi"}}])
        out_pol = os.path.join(self.tmp, "learned.json")
        rec = os.path.join(self.tmp, "sub", "session.json")
        with redirect_stderr(io.StringIO()):
            rc = cli_mod.main(["learn", "--script", script, "--out", out_pol,
                               "--record", rec, "--", sys.executable, FIXTURE])
        self.assertEqual(rc, 0)
        with open(rec, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["version"], 1)
        self.assertEqual([c["tool"] for c in data["calls"]],
                         ["read_file", "echo"])
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli_mod.main(["verify-policy", "--policy", out_pol,
                               "--session", rec])
        self.assertEqual(rc, 0, out.getvalue())

    def test_record_to_a_directory_is_refused(self):
        with redirect_stderr(io.StringIO()):
            rc = jail_mod.learn([sys.executable, FIXTURE], record=self.tmp)
        self.assertEqual(rc, 2)


class TestSharedVectors(Base):
    def vectors(self):
        with open(VECTORS, encoding="utf-8") as f:
            return json.load(f)

    def test_vector_lock_text_is_what_this_code_writes(self):
        v = self.vectors()
        lock = lf.new_lock("mcp-audit 0.3.0")
        for key, s in v["lock"]["servers"].items():
            entries, bad = lf.tools_entries(s["tools"])
            self.assertEqual(bad, [])
            fp = (lf.command_fingerprint(url=s["url"]) if s.get("url")
                  else lf.command_fingerprint(s["command"], s["args"]))
            lock["servers"][key] = lf.server_entry(fp, entries)
        self.assertEqual(lf.dump_lock(lock), v["lock"]["text"])

    def test_vector_lock_parses(self):
        lock = lf.parse_lock(self.vectors()["lock"]["text"])
        self.assertEqual(sorted(lock["servers"]), ["files", "remote"])

    def test_vector_tool_hashes_and_canonical_forms(self):
        v = self.vectors()
        for case in v["tools"]:
            self.assertEqual(lf.tool_hashes(case["tool"])["sha256"],
                             case["sha256"], case["label"])
        for case in v["canonical"]:
            self.assertEqual(lf.canonical(case["value"]).decode("utf-8"),
                             case["canonical"], case["label"])
            self.assertEqual(lf.hash_value(case["value"]), case["sha256"])

    def test_vector_command_fingerprints(self):
        for c in self.vectors()["commands"]:
            self.assertEqual(lf.command_fingerprint(c["command"], c["args"],
                                                    c.get("url")),
                             c["fingerprint"], c["label"])

    def test_invalid_values_are_refused(self):
        for case in self.vectors()["invalid"]:
            with self.assertRaises(lf.LockError, msg=case["label"]):
                lf.canonical(case["value"])

    def test_the_vector_lock_verifies_a_server_through_the_jail(self):
        """A lock written from the vectors (as mcp-audit writes it) is the
        one the jail enforces."""
        v = self.vectors()
        srv = self.write("vec.py", r"""
import json, sys
V = json.load(open(sys.argv[1], encoding="utf-8"))
T = V["lock"]["servers"]["files"]["tools"]
for raw in sys.stdin:
    req = json.loads(raw)
    rid = req.get("id")
    if rid is None:
        continue
    res = {"tools": T} if req["method"] == "tools/list" else {}
    print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}), flush=True)
""")
        cmd = [sys.executable, srv, VECTORS]
        s = v["lock"]["servers"]["files"]
        entries, _ = lf.tools_entries(s["tools"])
        lock = lf.new_lock("t")
        lock["servers"]["files"] = lf.server_entry(
            lf.command_fingerprint(cmd[0], cmd[1:]), entries)
        path = os.path.join(self.tmp, "v.lock")
        with open(path, "w", encoding="utf-8") as f:
            f.write(lf.dump_lock(lock))
        code, r = self.drive([INIT, INITED, lst(2)], server_cmd=cmd,
                             lockfile=path, on_drift="block")
        self.assertEqual(self.names(r[2]), ["read_file", "ping"])

    def test_the_spec_is_the_one_the_vectors_name(self):
        with open(os.path.join(REPO, "docs", "LOCKFILE.md"), "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(digest, self.vectors()["spec_sha256"])


class TestPackaging(unittest.TestCase):
    def test_the_sdist_carries_what_its_own_tests_read(self):
        with open(os.path.join(REPO, "MANIFEST.in"), encoding="utf-8") as f:
            manifest = f.read()
        for needed in ("recursive-include .github", "recursive-include docs",
                       "recursive-include tests"):
            self.assertIn(needed, manifest)


class TestEndToEndCli(Base):
    def test_the_command_line_blocks_the_rug_pull(self):
        lock = self.make_lock()
        reqs = "\n".join(json.dumps(m) for m in
                         [INIT, INITED, call(2, "read_file", path="/a"),
                          lst(3)]) + "\n"
        env = dict(os.environ, PYTHONPATH=REPO, HOME=self.tmp,
                   USERPROFILE=self.tmp)
        p = subprocess.run(
            [sys.executable, "-m", "mcp_jail", "--policy", self.policy,
             "--lockfile", lock, "--"] + self.cmd(),
            input=reqs.encode(), capture_output=True, env=env, timeout=60,
            cwd=self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        replies = [json.loads(ln) for ln in p.stdout.splitlines() if ln.strip()]
        by_id = {m["id"]: m for m in replies if "id" in m}
        self.assertIn("error", by_id[3])


if __name__ == "__main__":
    unittest.main()

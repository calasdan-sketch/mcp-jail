"""Round-10 regression tests: the audit log shared by several jails, ids at
the end of a response that is too long, the cap on --max-message-bytes, the
starter-policy warning with strict_args, and learn honouring the limit."""
from __future__ import annotations

import io
import json
import os
import shutil
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

SERVER = r"""
import json, sys
BIG = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
for raw in sys.stdin.buffer:
    req = json.loads(raw)
    rid, m = req.get("id"), req.get("method")
    if rid is None:
        continue
    pad = "a" * BIG
    if m == "bigtail":
        out = '{"jsonrpc":"2.0","result":{"pad":"%s"},"id":%s}' % (pad, json.dumps(rid))
    elif m == "bignested":
        out = '{"jsonrpc":"2.0","result":{"pad":"%s","x":{"id":99}}}' % pad
    elif m == "bigstring":
        out = '{"jsonrpc":"2.0","result":{"pad":"%s,\\"id\\":99}"}}' % pad
    elif m == "bigboth":
        out = '{"jsonrpc":"2.0","id":%s,"result":{"pad":"%s"},"id":77}' % (json.dumps(rid), pad)
    elif m == "tools/call":
        out = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": "x" * BIG}]}})
    elif m == "tools/list":
        out = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": "echo", "description": "d", "inputSchema": {"type": "object"}}]}})
    else:
        out = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"ok": True}})
    sys.stdout.write(out + "\n")
    sys.stdout.flush()
"""
POLICY = {"allow_tools": ["*"], "deny_tools": [], "arg_rules": {},
          "hide_denied": False}


def slurp(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def request(rid, method, pad=0):
    return (json.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                        "params": {"p": "a" * pad}}) + "\n").encode()


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
        self.server = os.path.join(self.tmp, "srv.py")
        with open(self.server, "w", encoding="utf-8") as f:
            f.write(SERVER)
        self.policy = os.path.join(self.tmp, "policy.json")
        with open(self.policy, "w", encoding="utf-8") as f:
            json.dump(POLICY, f)

    def records(self):
        try:
            with open(self.log, encoding="utf-8") as f:
                return [json.loads(x) for x in f if x.strip()]
        except FileNotFoundError:
            return []

    def drive(self, lines, max_message, timeout=10.0):
        inp = io.BytesIO(b"".join(lines))
        out = io.BytesIO()
        code = []

        def target():
            code.append(jail_mod.run(
                self.policy, [sys.executable, self.server], timeout=timeout,
                stdin=inp, stdout=out, max_message=max_message))
        errs = io.StringIO()
        started = time.monotonic()
        with redirect_stderr(errs):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            t.join(60)
        self.assertFalse(t.is_alive(), "the jail did not finish")
        took = time.monotonic() - started
        replies = [json.loads(x) for x in out.getvalue().split(b"\n")
                   if x.strip()]
        return code[0], replies, errs.getvalue(), took


class TestSeveralJailsShareTheLog(Base):
    LIMIT = 4000

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {
            "MCP_JAIL_AUDIT_MAX_MB": str(self.LIMIT / 1048576)})
        env.start()
        self.addCleanup(env.stop)

    def fill(self, n):
        with open(self.log, "w", encoding="utf-8") as f:
            for i in range(n):
                f.write(json.dumps({"old": i, "pad": "p" * 80}) + "\n")

    def test_two_jails_that_both_see_a_full_log_rotate_it_once(self):
        """HIGH-ish: the second rename moved the NEW log over the rotated
        one, and the history was lost."""
        self.fill(60)                       # well over the limit
        old_lines = slurp(self.log)
        seen = threading.Barrier(2, timeout=10)
        first_wrote = threading.Event()
        real_getsize, real_replace = os.path.getsize, os.replace
        local = threading.local()

        def getsize(p):
            size = real_getsize(p)
            if p == self.log and not getattr(local, "seen", False):
                local.seen = True
                seen.wait()                 # both have looked, both see "full"
            return size

        def replace(src, dst):
            if src == self.log and threading.current_thread().name == "B":
                first_wrote.wait(10)        # B renames after A has written
            return real_replace(src, dst)

        def run(name):
            jail_mod.audit({"who": name})
            if name == "A":
                first_wrote.set()

        with mock.patch("os.path.getsize", getsize), \
                mock.patch("os.replace", replace):
            ta = threading.Thread(target=run, args=("A",), name="A")
            tb = threading.Thread(target=run, args=("B",), name="B")
            ta.start()
            tb.start()
            ta.join(30)
            tb.join(30)
        self.assertFalse(ta.is_alive() or tb.is_alive())
        with open(self.log + ".1", encoding="utf-8") as f:
            self.assertEqual(f.read(), old_lines, "the history was replaced")
        who = sorted(r["who"] for r in self.records())
        self.assertEqual(who, ["A", "B"])

    def writer_source(self, lines, tag):
        return ("import os, sys\n"
                "from mcp_jail import jail\n"
                "jail.AUDIT_LOG = sys.argv[1]\n"
                "for i in range(%d):\n"
                "    jail.audit({'tag': '%s', 'i': i, 'pad': 'x' * 40})\n"
                % (lines, tag))

    def test_real_processes_writing_together_lose_nothing(self):
        total = 0
        procs = []
        env = dict(os.environ, PYTHONPATH=REPO)
        for tag in "abcd":
            n = 40
            total += n
            procs.append(subprocess.Popen(
                [sys.executable, "-c", self.writer_source(n, tag), self.log],
                env=env, stderr=subprocess.PIPE))
        for p in procs:
            _out, err = p.communicate(timeout=60)
            self.assertEqual(p.returncode, 0, err)
        # 160 lines of ~100 bytes is about 16 KB: more than one rotation is
        # unavoidable with a 4 KB limit, but every record that is left is
        # whole, and the two files never hold more than a few limits
        rows = []
        for path in (self.log + ".1", self.log):
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    rows += [json.loads(x) for x in f if x.strip()]
        self.assertTrue(rows)
        for r in rows:
            self.assertIn(r["tag"], "abcd")
        self.assertLess(os.path.getsize(self.log), self.LIMIT + 400)

    def test_threads_rotate_without_ever_emptying_the_rotated_file(self):
        self.fill(60)
        errors = []

        def work(tag):
            try:
                for i in range(15):
                    jail_mod.audit({"tag": tag, "i": i})
            except Exception as e:      # pragma: no cover
                errors.append(e)
        threads = [threading.Thread(target=work, args=(t,)) for t in "abcdef"]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        self.assertEqual(errors, [])
        self.assertTrue(os.path.getsize(self.log + ".1") >= self.LIMIT)

    def test_a_lock_that_cannot_be_got_means_no_rotation_not_a_hang(self):
        self.fill(60)
        before = slurp(self.log)

        class Busy:
            def __enter__(self):
                return False

            def __exit__(self, *a):
                return False
        with mock.patch.object(jail_mod, "_exclusive", lambda p: Busy()):
            jail_mod.audit({"x": 1})
        self.assertFalse(os.path.exists(self.log + ".1"))
        self.assertTrue(slurp(self.log).startswith(before))

    @unittest.skipIf(os.name == "nt", "flock")
    def test_a_lock_held_by_another_process_is_waited_for_then_skipped(self):
        import fcntl
        self.fill(60)
        fd = os.open(self.log + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        started = time.monotonic()
        with mock.patch.object(jail_mod, "_LOCK_WAIT", 0.3):
            jail_mod.audit({"x": 1})
        self.assertLess(time.monotonic() - started, 5)
        self.assertFalse(os.path.exists(self.log + ".1"))
        self.assertEqual(self.records()[-1], {"x": 1, "at": mock.ANY})

    def test_a_small_log_takes_no_lock_at_all(self):
        with mock.patch.object(jail_mod, "_exclusive",
                               side_effect=AssertionError("locked")):
            jail_mod.audit({"x": 1})
        self.assertEqual(len(self.records()), 1)

    def test_the_lock_file_is_private(self):
        self.fill(60)
        jail_mod.audit({"x": 1})
        if os.name != "nt":
            mode = os.stat(self.log + ".lock").st_mode & 0o777
            self.assertEqual(mode & 0o077, 0)


class TestAnIdAtTheEndOfAHugeResponse(Base):
    LIMIT = 4096

    def test_a_response_with_its_id_last_fails_that_request_at_once(self):
        code, replies, err, took = self.drive(
            [request(5, "bigtail")], self.LIMIT, timeout=20.0)
        by_id = {r["id"]: r for r in replies}
        self.assertEqual(by_id[5]["error"]["code"], jail_mod.INTERNAL_ERROR)
        self.assertIn("too large", by_id[5]["error"]["message"])
        self.assertLess(took, 8, "it waited for the timeout")

    def test_a_string_id_at_the_end(self):
        code, replies, err, took = self.drive(
            [request("abc-1", "bigtail")], self.LIMIT, timeout=20.0)
        self.assertEqual(replies[0]["id"], "abc-1")
        self.assertIn("error", replies[0])
        self.assertLess(took, 8)

    def test_other_requests_are_not_failed(self):
        code, replies, err, took = self.drive(
            [request(1, "ping"), request(2, "bigtail"), request(3, "ping")],
            self.LIMIT, timeout=20.0)
        by_id = {r["id"]: r for r in replies}
        self.assertIn("result", by_id[1])
        self.assertIn("error", by_id[2])
        self.assertIn("result", by_id[3])

    def test_an_id_inside_a_nested_object_is_not_trusted(self):
        code, replies, err, took = self.drive(
            [request(5, "bignested")], self.LIMIT, timeout=1.0)
        by_id = {r["id"]: r for r in replies}
        self.assertIn("timed out", by_id[5]["error"]["message"].lower())

    def test_an_id_inside_a_string_is_not_trusted(self):
        code, replies, err, took = self.drive(
            [request(5, "bigstring")], self.LIMIT, timeout=1.0)
        by_id = {r["id"]: r for r in replies}
        self.assertNotIn(99, by_id)
        self.assertIn("error", by_id[5])
        self.assertIn("timed out", by_id[5]["error"]["message"].lower())

    def test_the_id_at_the_start_wins_over_one_at_the_end(self):
        code, replies, err, took = self.drive(
            [request(5, "bigboth")], self.LIMIT, timeout=20.0)
        by_id = {r["id"]: r for r in replies}
        self.assertIn("too large", by_id[5]["error"]["message"])
        self.assertNotIn(77, by_id)

    def test_the_tail_is_kept_when_the_message_is_many_chunks_long(self):
        code, replies, err, took = self.drive(
            [request(5, "bigtail")], self.LIMIT, timeout=20.0)
        # a 5 MB server line: several 64 KiB reads
        self.assertEqual(replies[0]["id"], 5)

    def test_tail_id_unit(self):
        tail_id = jail_mod._tail_id
        no = jail_mod._NO_ID
        self.assertEqual(tail_id(b'...,"id":7}\n'), 7)
        self.assertEqual(tail_id(b'...,"id": -7 } \r\n'), -7)
        self.assertEqual(tail_id(b'...,"id":"x y"}'), "x y")
        for bad in (b'...,"id":7}}', b'..."id":7}', b',"id":true}',
                    b',"id":null}', b',"id":1.5}', b',"id":[1]}',
                    b',"id":12345678901234567890}', b'',
                    b',\\"id\\":7}', b',"id":7},"x":1}'):
            self.assertIs(tail_id(bad), no, bad)

    def test_the_client_side_gets_it_too(self):
        big = (b'{"jsonrpc":"2.0","method":"ping","params":{"p":"'
               + b"a" * 9000 + b'"},"id":41}\n')
        code, replies, err, took = self.drive([big], self.LIMIT)
        self.assertEqual(replies[0]["id"], 41)
        self.assertEqual(replies[0]["error"]["code"], jail_mod.INVALID_REQUEST)


class TestTheMessageLimitHasAnUpperBound(Base):
    def test_the_command_line_refuses_more_than_a_tebibyte(self):
        parser = cli_mod.build_parser()
        ok = parser.parse_args(["--max-message-bytes", str(2 ** 40), "--",
                                "x"])
        self.assertEqual(ok.max_message_bytes, 2 ** 40)
        for bad in (str(2 ** 40 + 1), "99999999999999999999999", str(2 ** 63)):
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit) as stop:
                parser.parse_args(["--max-message-bytes", bad, "--", "x"])
            self.assertEqual(stop.exception.code, 2, bad)
            self.assertIn("maximum", err.getvalue())

    def test_run_refuses_it_too(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.run(self.policy, [sys.executable, self.server],
                                max_message=2 ** 40 + 1)
        self.assertEqual(code, 2)
        self.assertIn("at most", err.getvalue())

    def test_the_largest_allowed_limit_works_end_to_end(self):
        code, replies, err, took = self.drive([request(1, "ping")], 2 ** 40)
        self.assertEqual(replies[0]["result"], {"ok": True})
        self.assertNotIn("Traceback", err)

    def test_from_the_real_command_line(self):
        env = dict(os.environ, PYTHONPATH=REPO, HOME=self.tmp,
                   USERPROFILE=self.tmp)
        for value, want in ((str(2 ** 40), 0), ("99999999999999999999999", 2)):
            p = subprocess.run(
                [sys.executable, "-m", "mcp_jail", "--policy", self.policy,
                 "--max-message-bytes", value, "--", sys.executable,
                 self.server],
                input=request(1, "ping"), env=env, capture_output=True,
                timeout=60)
            self.assertNotIn(b"Traceback", p.stderr, value)
            self.assertEqual(p.returncode, want, (value, p.stderr))


class TestTheStarterWarning(Base):
    def test_the_untouched_starter_still_warns(self):
        self.assertTrue(jail_mod._is_unedited_starter(jail_mod.default_policy()))

    def test_strict_args_means_it_blocks_something(self):
        pol = jail_mod.default_policy()
        pol["strict_args"] = True
        self.assertFalse(jail_mod._is_unedited_starter(pol))
        self.assertFalse(jail_mod._blocks_nothing(pol))

    def test_run_does_not_say_it_blocks_nothing_when_strict(self):
        pol = jail_mod.default_policy()
        pol["strict_args"] = True
        with open(self.policy, "w", encoding="utf-8") as f:
            json.dump(pol, f)
        code, replies, err, took = self.drive([request(1, "ping")],
                                              jail_mod.DEFAULT_MAX_MESSAGE)
        self.assertNotIn("blocks nothing", err)

    def test_run_still_says_it_for_the_plain_starter(self):
        with open(self.policy, "w", encoding="utf-8") as f:
            json.dump(jail_mod.default_policy(), f)
        code, replies, err, took = self.drive([request(1, "ping")],
                                              jail_mod.DEFAULT_MAX_MESSAGE)
        self.assertIn("blocks nothing", err)


class TestLearnHonoursTheLimit(Base):
    def script(self):
        path = os.path.join(self.tmp, "calls.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump([{"tool": "echo", "arguments": {"a": "b"}}], f)
        return path

    def learn(self, limit, big):
        out = os.path.join(self.tmp, "out.json")
        err = io.StringIO()
        server = [sys.executable, self.server, str(big)]
        with redirect_stderr(err):
            code = jail_mod.learn(server, script=self.script(), out=out,
                                  timeout=2.0, max_message=limit)
        return code, err.getvalue(), out

    def test_a_response_over_the_limit_is_skipped_and_says_so(self):
        code, err, out = self.learn(2048, 5000)
        self.assertIn("2048", err)
        self.assertIn("--max-message-bytes", err)
        self.assertIn("timed out", err)

    def test_the_default_limit_reads_it(self):
        code, err, out = self.learn(jail_mod.DEFAULT_MAX_MESSAGE, 5000)
        self.assertEqual(code, 0, err)
        with open(out, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["allow_tools"], ["echo"])

    def test_learn_refuses_a_bad_limit(self):
        for bad in (10, 2 ** 40 + 1, True, "x"):
            code, err, out = self.learn(bad, 10)
            self.assertEqual(code, 2, bad)

    def test_the_learn_command_line_takes_the_option(self):
        env = dict(os.environ, PYTHONPATH=REPO, HOME=self.tmp,
                   USERPROFILE=self.tmp)
        out = os.path.join(self.tmp, "p.json")
        p = subprocess.run(
            [sys.executable, "-m", "mcp_jail", "learn", "--script",
             self.script(), "--out", out, "--timeout", "2",
             "--max-message-bytes", "2048", "--", sys.executable,
             self.server, "5000"],
            env=env, capture_output=True, text=True, timeout=60)
        self.assertIn("2048", p.stderr)
        p = subprocess.run(
            [sys.executable, "-m", "mcp_jail", "learn", "--max-message-bytes",
             "10", "--", "x"], env=env, capture_output=True, text=True,
            timeout=60)
        self.assertEqual(p.returncode, 2)

    def test_live_learn_passes_the_limit_to_the_proxy(self):
        seen = {}
        real = jail_mod._Proxy

        class Spy(real):
            def __init__(self, *a, **kw):
                seen.update(kw)
                super().__init__(*a, **kw)
        inp, out = io.BytesIO(b""), io.BytesIO()
        with mock.patch.object(jail_mod, "_Proxy", Spy), \
                redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            jail_mod.learn([sys.executable, self.server], stdin=inp,
                           stdout=out, timeout=5, max_message=4096)
        self.assertEqual(seen.get("max_message"), 4096)


if __name__ == "__main__":
    unittest.main()

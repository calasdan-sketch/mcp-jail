"""Round-9 regression tests: a quadratic line reader and unbounded messages,
the starter policy, an unwritable --path, the audit log's size, the README and
the package metadata."""
from __future__ import annotations

import io
import json
import os
import queue
import shutil
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

# A server that answers every request, and a big one for method "big"
# (the id first, so the jail can fail that request by id) or "bigtail"
# (the id after the payload, so it cannot).
SERVER = r"""
import json, sys
for raw in sys.stdin.buffer:
    req = json.loads(raw)
    rid, m = req.get("id"), req.get("method")
    if rid is None:
        continue
    if m == "big":
        sys.stdout.write('{"jsonrpc":"2.0","id":%s,"result":{"pad":"%s"}}\n'
                         % (json.dumps(rid), "a" * 100000))
    elif m == "bigtail":
        sys.stdout.write('{"jsonrpc":"2.0","result":{"pad":"%s"},"id":%s}\n'
                         % ("a" * 100000, json.dumps(rid)))
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                     "result": {"ok": True}}) + "\n")
    sys.stdout.flush()
"""
POLICY = {"allow_tools": ["*"], "deny_tools": [], "arg_rules": {},
          "hide_denied": False}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mj9-")
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
        with redirect_stderr(errs):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            t.join(60)
        self.assertFalse(t.is_alive(), "the jail did not finish")
        replies = [json.loads(x) for x in out.getvalue().split(b"\n")
                   if x.strip()]
        return code[0], replies, errs.getvalue()


def request(rid, method, pad=0):
    return (json.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                        "params": {"p": "a" * pad}}) + "\n").encode()


class TestTheFdReaderIsLinear(unittest.TestCase):
    def feed(self, size):
        """Read one line of `size` bytes through an _FdLineReader."""
        r, w = os.pipe()
        data = b"x" * size + b"\n"

        def push():
            with os.fdopen(w, "wb") as f:
                f.write(data)
        t = threading.Thread(target=push, daemon=True)
        t.start()
        reader = jail_mod._FdLineReader(r)
        started = time.perf_counter()
        line = reader.readline()
        took = time.perf_counter() - started
        t.join()
        os.close(r)
        self.assertEqual(len(line), size + 1)
        return took

    def test_a_long_line_costs_time_in_proportion_to_its_length(self):
        small = min(self.feed(8_000_000) for _ in range(2))
        large = min(self.feed(32_000_000) for _ in range(2))
        # 4x the data: linear is ~4x, the old rescan was ~16x
        self.assertLess(large, max(small, 0.02) * 9,
                        "8 MB: %.3f s, 32 MB: %.3f s" % (small, large))

    def test_readline_with_a_limit_hands_out_pieces_of_a_long_line(self):
        r, w = os.pipe()
        os.write(w, b"abcdefghij\nxyz\n")
        os.close(w)
        reader = jail_mod._FdLineReader(r)
        self.assertEqual(reader.readline(4), b"abcd")
        self.assertEqual(reader.readline(4), b"efgh")
        self.assertEqual(reader.readline(4), b"ij\n")
        self.assertEqual(reader.readline(4), b"xyz\n")
        self.assertEqual(reader.readline(4), b"")
        os.close(r)

    def test_a_limit_never_makes_the_buffer_grow_past_it(self):
        r, w = os.pipe()

        def push():
            with os.fdopen(w, "wb") as f:
                f.write(b"y" * 3_000_000 + b"\n")
        threading.Thread(target=push, daemon=True).start()
        reader = jail_mod._FdLineReader(r)
        biggest = 0
        while True:
            piece = reader.readline(65536)
            biggest = max(biggest, len(reader._buf))
            if piece.endswith(b"\n") or not piece:
                break
        os.close(r)
        self.assertLessEqual(biggest, 65536 + 65536)


class TestAReaderRefusesALineOverTheLimit(unittest.TestCase):
    def pump(self, data, limit):
        q = queue.Queue()
        stream = io.BytesIO(data)
        seen = []
        real = stream.readline

        def spy(n=-1):
            got = real(n)
            seen.append(len(got))
            return got
        stream.readline = spy
        reader = jail_mod._Reader(stream, "server", q, limit)
        reader.run()
        items = []
        while not q.empty():
            items.append(q.get())
        return items, seen

    def test_a_line_at_the_limit_passes_and_one_byte_more_does_not(self):
        ok = b"a" * 99 + b"\n"           # 100 bytes with its newline
        items, _ = self.pump(ok, 100)
        self.assertEqual(items[0], ("server", ok))
        big = b"a" * 100 + b"\n"         # 101
        items, _ = self.pump(big, 100)
        self.assertIsInstance(items[0][1], jail_mod._Oversize)
        self.assertEqual(items[0][1].size, 101)

    def test_the_rest_of_the_line_is_dropped_and_the_next_one_is_read(self):
        data = b'{"id":3,"pad":"' + b"z" * 300_000 + b'"}\n{"id":4}\n'
        items, seen = self.pump(data, 1000)
        self.assertIsInstance(items[0][1], jail_mod._Oversize)
        self.assertEqual(items[0][1].size, len(data) - len(b'{"id":4}\n'))
        self.assertEqual(items[0][1].head, data[:1001])   # limit + 1
        self.assertEqual(items[1], ("server", b'{"id":4}\n'))
        self.assertEqual(items[2], ("server", None))
        # no single read handed over more than the limit (+1) or a chunk
        self.assertLessEqual(max(seen), 65536)

    def test_an_id_at_the_start_is_recovered(self):
        h = jail_mod._head_id
        self.assertEqual(h(b'{"jsonrpc":"2.0","id":7,"result":{"pad":"aaa'), 7)
        self.assertEqual(h(b'{"id": "abc" , "x":1'), "abc")
        self.assertIs(h(b'{"jsonrpc":"2.0","result":{"id":9,"pad":"aaa'),
                      jail_mod._NO_ID)
        self.assertIs(h(b'{"id":true,"x"'), jail_mod._NO_ID)
        self.assertIs(h(b'not json'), jail_mod._NO_ID)


class TestTheProxyEnforcesTheLimit(Base):
    LIMIT = 4096

    def test_a_client_message_over_the_limit_is_refused_under_its_id(self):
        code, replies, _ = self.drive(
            [request(1, "ping"), request(2, "ping", pad=50000),
             request(3, "ping")], self.LIMIT)
        self.assertEqual(code, 0)
        by_id = {r["id"]: r for r in replies}
        self.assertEqual(by_id[2]["error"]["code"], -32600)
        self.assertIn("too large", by_id[2]["error"]["message"])
        self.assertIn("result", by_id[1])
        self.assertIn("result", by_id[3])
        rejected = [r for r in self.records() if r.get("rejected") == "client"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["decision"], "deny")

    def test_a_server_response_over_the_limit_fails_that_request(self):
        started = time.monotonic()
        code, replies, _ = self.drive(
            [request(1, "ping"), request(2, "big"), request(3, "ping")],
            self.LIMIT)
        self.assertLess(time.monotonic() - started, 8)   # not a timeout
        by_id = {r["id"]: r for r in replies}
        self.assertEqual(by_id[2]["error"]["code"], -32603)
        self.assertIn("too large", by_id[2]["error"]["message"])
        self.assertIn("result", by_id[1])
        self.assertIn("result", by_id[3])
        rejected = [r for r in self.records() if r.get("rejected") == "server"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["decision"], "deny")
        self.assertIn("too large", rejected[0]["reason"])

    def test_nothing_over_the_limit_reaches_the_client(self):
        code, replies, _ = self.drive([request(2, "big")], self.LIMIT)
        for r in replies:
            self.assertLess(len(json.dumps(r)), 1000)

    def test_a_response_whose_id_is_not_at_the_start_times_out_instead(self):
        code, replies, err = self.drive([request(5, "bigtail")], self.LIMIT,
                                        timeout=1.0)
        self.assertEqual(code, jail_mod.EXIT_SERVER)
        by_id = {r["id"]: r for r in replies}
        self.assertIn("error", by_id[5])

    def test_the_default_is_sixteen_mebibytes(self):
        self.assertEqual(jail_mod.DEFAULT_MAX_MESSAGE, 16 * 1024 * 1024)

    def test_the_command_line_option(self):
        parser = cli_mod.build_parser()
        self.assertEqual(parser.parse_args(["--", "x"]).max_message_bytes,
                         16 * 1024 * 1024)
        self.assertEqual(parser.parse_args(
            ["--max-message-bytes", "2048", "--", "x"]).max_message_bytes,
            2048)
        for bad in ("10", "0", "-5", "abc", "1e6"):
            with redirect_stderr(io.StringIO()), self.assertRaises(
                    SystemExit) as stop:
                parser.parse_args(["--max-message-bytes", bad, "--", "x"])
            self.assertEqual(stop.exception.code, 2, bad)

    def test_run_refuses_a_limit_that_is_too_small(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = jail_mod.run(self.policy, [sys.executable, self.server],
                                stdin=io.BytesIO(b""), stdout=io.BytesIO(),
                                max_message=10)
        self.assertEqual(code, 2)
        self.assertIn("--max-message-bytes", err.getvalue())


class TestTheStarterPolicy(Base):
    def init(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_mod.main(["--init-policy", *argv])
        return code, out.getvalue(), err.getvalue()

    def test_it_says_it_blocks_nothing_and_points_to_learn(self):
        target = os.path.join(self.tmp, "p.json")
        code, out, err = self.init("--path", target)
        self.assertEqual(code, 0)
        self.assertIn("wrote", out)
        self.assertIn("allows EVERY tool", err)
        self.assertIn("mcp-jail learn", err)

    def test_the_file_holds_stricter_examples_and_still_loads(self):
        target = os.path.join(self.tmp, "p.json")
        self.init("--path", target)
        with open(target, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertIn("STARTER", doc["_comment"])
        self.assertIn("blocks nothing", doc["_comment"])
        self.assertGreaterEqual(len(doc["_examples"]), 3)
        pol = jail_mod.load_policy(target)       # the notes are never read
        self.assertEqual(pol["allow_tools"], ["*"])
        # and each example is a policy that loads on its own
        for name, example in doc["_examples"].items():
            jail_mod.compile_policy(json.loads(json.dumps(example)))

    def test_an_untouched_starter_warns_each_time_it_runs(self):
        target = os.path.join(self.tmp, "p.json")
        self.init("--path", target)
        self.policy = target
        code, replies, err = self.drive([request(1, "ping")], 65536)
        self.assertEqual(code, 0)
        self.assertIn("starter policy", err)

    def test_a_tightened_one_does_not_warn(self):
        target = os.path.join(self.tmp, "p.json")
        self.init("--path", target)
        with open(target, encoding="utf-8") as f:
            doc = json.load(f)
        doc["allow_tools"] = ["read_file"]
        with open(target, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        self.policy = target
        code, replies, err = self.drive([request(1, "ping")], 65536)
        self.assertNotIn("starter policy", err)

    def test_a_hand_written_allow_all_is_not_nagged(self):
        code, replies, err = self.drive([request(1, "ping")], 65536)
        self.assertNotIn("starter policy", err)

    def test_an_unwritable_path_is_one_line_and_exit_2(self):
        blocker = os.path.join(self.tmp, "afile")
        with open(blocker, "w") as f:
            f.write("x")
        for target in (os.path.join(blocker, "sub", "p.json"),   # not a dir
                       self.tmp,                                  # a directory
                       os.path.join(self.tmp, "a\0b.json")):      # invalid
            code, out, err = self.init("--path", target, "--force")
            self.assertEqual(code, 2, target)
            self.assertEqual(len(err.strip().splitlines()), 1, err)
            self.assertIn("cannot write the policy", err)
            self.assertNotIn("Traceback", err)

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid")
                                         and os.geteuid() == 0),
                     "permission bits do not bind here")
    def test_a_read_only_folder_is_one_line_and_exit_2(self):
        ro = os.path.join(self.tmp, "ro")
        os.mkdir(ro)
        os.chmod(ro, 0o500)
        self.addCleanup(os.chmod, ro, 0o700)
        code, out, err = self.init("--path", os.path.join(ro, "p.json"))
        self.assertEqual(code, 2)
        self.assertEqual(len(err.strip().splitlines()), 1, err)


class TestTheAuditLogIsBounded(Base):
    def test_it_is_rotated_past_the_limit(self):
        with mock.patch.dict(os.environ, {"MCP_JAIL_AUDIT_MAX_MB": "0.002"}):
            for i in range(200):
                jail_mod.audit({"decision": "allow", "tool": "t%d" % i,
                                "reason": "x" * 50})
        self.assertTrue(os.path.exists(self.log + ".1"))
        limit = int(0.002 * 1024 * 1024)
        self.assertLessEqual(os.path.getsize(self.log), limit + 400)
        self.assertLessEqual(os.path.getsize(self.log + ".1"), limit + 400)
        # nothing lost between the two files: the newest record is in the log
        self.assertEqual(self.records()[-1]["tool"], "t199")
        with open(self.log + ".1", encoding="utf-8") as old:
            total = len(self.records()) + sum(1 for _ in old)
        self.assertGreater(total, 10)      # about two files' worth are kept
        self.assertLess(total, 100)        # and the oldest are gone

    def test_zero_means_never(self):
        with mock.patch.dict(os.environ, {"MCP_JAIL_AUDIT_MAX_MB": "0"}):
            for i in range(100):
                jail_mod.audit({"decision": "allow", "tool": "t",
                                "reason": "x" * 100})
        self.assertFalse(os.path.exists(self.log + ".1"))
        self.assertEqual(len(self.records()), 100)

    def test_bad_values_fall_back_to_the_default(self):
        for bad in ("abc", "-1", "nan", "inf", ""):
            with mock.patch.dict(os.environ, {"MCP_JAIL_AUDIT_MAX_MB": bad}):
                self.assertEqual(jail_mod.audit_log_limit(),
                                 jail_mod.AUDIT_LOG_MAX_BYTES, bad)

    def test_the_log_stays_private(self):
        if os.name == "nt":
            self.skipTest("mode bits")
        with mock.patch.dict(os.environ, {"MCP_JAIL_AUDIT_MAX_MB": "0.0005"}):
            for i in range(60):
                jail_mod.audit({"decision": "allow", "tool": "t",
                                "reason": "x" * 50})
        self.assertEqual(os.stat(self.log).st_mode & 0o077, 0)


class TestTheReadmeAndThePackage(unittest.TestCase):
    def readme(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            return f.read()

    def test_install_line_and_the_other_project(self):
        text = self.readme()
        self.assertIn("pip install mcp-jail", text)
        self.assertNotIn("pip install git+", text)
        self.assertIn("`mcpjail`", text)

    def test_the_new_behaviour_is_documented(self):
        text = self.readme()
        for word in ("--max-message-bytes", "audit.jsonl.1",
                     "MCP_JAIL_AUDIT_MAX_MB", "_examples",
                     "allows every tool and blocks nothing",
                     "Tool names in `allow_tools` are folded too"):
            self.assertIn(word, text, word)

    def test_the_metadata(self):
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
            meta = tomllib.load(f)
        project = meta["project"]
        self.assertTrue(project["keywords"])
        self.assertEqual(project["authors"][0]["name"],
                         "Calas Automations Inc.")
        self.assertIn("Homepage", project["urls"])
        self.assertIn("Issues", project["urls"])
        self.assertIn("Topic :: Security", project["classifiers"])
        self.assertEqual(project["version"], cli_mod.VERSION)


if __name__ == "__main__":
    unittest.main()

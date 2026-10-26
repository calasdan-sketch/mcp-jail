"""Round 10c: loud starter warning, the strict starter and policy packs, the
optional audit hash chain, audit redaction, --env-allow, the rotation warning
and the 1 GiB message ceiling. Hermetic: temp HOME and log, no timing."""

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

from mcp_jail import auditchain, packs, policytest
from mcp_jail import cli as cli_mod
from mcp_jail import jail as jail_mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ECHO_SERVER = r"""
import json, sys, os
for raw in sys.stdin.buffer:
    req = json.loads(raw)
    rid, m = req.get("id"), req.get("method")
    if rid is None:
        continue
    if m == "tools/call":
        out = {"jsonrpc": "2.0", "id": rid, "result": {"content": [
            {"type": "text", "text": json.dumps(sorted(os.environ))}]}}
    else:
        out = {"jsonrpc": "2.0", "id": rid, "result": {"ok": True}}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
"""


def req(rid, method, params=None):
    return (json.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                        "params": params or {}}) + "\n").encode()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mj10c-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patch = mock.patch.dict(os.environ, {"HOME": self.tmp,
                                             "USERPROFILE": self.tmp})
        patch.start()
        self.addCleanup(patch.stop)
        os.environ.pop("MCP_JAIL_AUDIT_CHAIN", None)
        self.log = os.path.join(self.tmp, "audit.jsonl")
        old = jail_mod.AUDIT_LOG
        jail_mod.AUDIT_LOG = self.log
        self.addCleanup(setattr, jail_mod, "AUDIT_LOG", old)
        self.addCleanup(jail_mod.set_audit_chain, False)
        self.server = os.path.join(self.tmp, "srv.py")
        with open(self.server, "w", encoding="utf-8") as f:
            f.write(ECHO_SERVER)
        self.policy = os.path.join(self.tmp, "policy.json")

    def write_policy(self, pol):
        with open(self.policy, "w", encoding="utf-8") as f:
            json.dump(pol, f)

    def records(self):
        try:
            with open(self.log, encoding="utf-8") as f:
                return [json.loads(x) for x in f if x.strip()]
        except FileNotFoundError:
            return []

    def drive(self, lines, **kw):
        inp, out = io.BytesIO(b"".join(lines)), io.BytesIO()
        code, errs = [], io.StringIO()

        def target():
            code.append(jail_mod.run(
                self.policy, [sys.executable, self.server], timeout=10.0,
                stdin=inp, stdout=out, **kw))
        with redirect_stderr(errs):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            t.join(60)
        self.assertFalse(t.is_alive(), "the jail did not finish")
        replies = [json.loads(x) for x in out.getvalue().split(b"\n")
                   if x.strip()]
        return code[0], replies, errs.getvalue()

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_mod.main(list(argv))
        return code, out.getvalue(), err.getvalue()


class TestLoudStarter(Base):
    def test_every_start_with_the_starter_warns_and_names_learn(self):
        self.write_policy(jail_mod.default_policy())
        for _ in range(2):
            code, replies, err = self.drive([req(1, "ping")])
            self.assertEqual(code, 0, err)
            self.assertIn("allows every tool and blocks nothing", err)
            self.assertIn("mcp-jail learn", err)
            self.assertGreaterEqual(err.count("WARNING"), 3)   # not one line
            self.assertIn("First step", err)

    def test_a_policy_that_blocks_something_does_not_warn(self):
        pol = jail_mod.default_policy()
        pol["deny_tools"] = ["rm"]
        self.write_policy(pol)
        code, replies, err = self.drive([req(1, "ping")])
        self.assertNotIn("blocks nothing", err)

    def test_init_policy_names_learn_as_the_first_step(self):
        path = os.path.join(self.tmp, "p.json")
        code, out, err = self.cli("--init-policy", "--path", path)
        self.assertEqual(code, 0)
        self.assertIn("First step", err)
        self.assertIn("mcp-jail learn", err)


class TestStrictStarter(Base):
    def test_it_blocks_and_refuses_resources_and_prompts(self):
        path = os.path.join(self.tmp, "s.json")
        code, out, err = self.cli("--init-policy", "--strict", "--path", path)
        self.assertEqual(code, 0, err)
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(doc["allow_tools"], [])
        self.assertEqual(doc["deny_methods"], ["resources/*", "prompts/*"])
        self.assertTrue(doc["strict_args"])
        pol = jail_mod.load_policy(path)
        self.assertFalse(jail_mod._blocks_nothing(pol))
        self.assertFalse(jail_mod._is_unedited_starter(pol))
        for method in ("resources/list", "resources/read", "prompts/get"):
            self.assertTrue(jail_mod.method_denied(pol, method), method)
        ok = policytest.decide(pol, {"key": "tool", "name": "anything",
                                     "arguments": {}, "params": None})[0]
        self.assertFalse(ok)

    def test_the_session_it_gives_is_not_called_a_blank_check(self):
        self.write_policy(jail_mod.default_policy(strict=True))
        code, replies, err = self.drive([req(1, "ping")])
        self.assertNotIn("blocks nothing", err)

    def test_pack_and_strict_together_are_refused(self):
        code, out, err = self.cli("--init-policy", "--strict", "--pack",
                                  "git", "--path",
                                  os.path.join(self.tmp, "x.json"))
        self.assertEqual(code, 2)

    def test_strict_without_init_policy_is_refused(self):
        code, out, err = self.cli("--strict", "--", "x")
        self.assertEqual(code, 2)
        self.assertIn("--init-policy", err)


class TestPacks(Base):
    def decide(self, pol, tool, args=None):
        return policytest.decide(pol, {"key": "tool", "name": tool,
                                       "arguments": args or {},
                                       "params": None})[0]

    def pol(self, name):
        path = os.path.join(self.tmp, name + ".json")
        code, out, err = self.cli("--init-policy", "--pack", name, "--path",
                                  path)
        self.assertEqual(code, 0, err)
        return jail_mod.load_policy(path)

    def test_every_pack_compiles_and_writes_through_the_command(self):
        for name in packs.names():
            pol = self.pol(name)
            self.assertFalse(jail_mod._blocks_nothing(pol), name)
            self.assertTrue(jail_mod.method_denied(pol, "resources/read"))

    def test_filesystem_reads_and_does_not_write_or_reach_secrets(self):
        pol = self.pol("filesystem")
        self.assertTrue(self.decide(pol, "read_file", {"path": "/p/a.txt"}))
        self.assertTrue(self.decide(pol, "list_directory", {"path": "/p"}))
        self.assertFalse(self.decide(pol, "write_file",
                                     {"path": "/p/a", "content": "x"}))
        self.assertFalse(self.decide(pol, "move_file", {}))
        self.assertFalse(self.decide(pol, "read_file",
                                     {"path": "/p/../etc/passwd"}))
        self.assertFalse(self.decide(pol, "read_file",
                                     {"path": "/home/me/.ssh/id_rsa"}))
        self.assertFalse(self.decide(pol, "read_text_file",
                                     {"path": "C:\\Users\\me\\.aws\\credentials"}))
        self.assertFalse(self.decide(pol, "read_file", {"path": "/p/.env"}))
        self.assertFalse(self.decide(pol, "read_file",
                                     {"path": "/p/server.pem"}))
        self.assertFalse(self.decide(pol, "unknown_tool", {}))

    def test_git_is_read_only(self):
        pol = self.pol("git")
        for tool in ("git_status", "git_diff", "git_log", "git_show"):
            self.assertTrue(self.decide(pol, tool, {"repo_path": "/r"}), tool)
        for tool in ("git_commit", "git_reset", "git_add", "git_checkout",
                     "git_init", "git_create_branch"):
            self.assertFalse(self.decide(pol, tool, {"repo_path": "/r"}), tool)
        self.assertFalse(self.decide(pol, "git_log", {"max_count": "5; rm"}))
        self.assertTrue(self.decide(pol, "git_log", {"repo_path": "/r",
                                                     "max_count": 5}))

    def test_shell_allows_a_short_list_and_no_chaining(self):
        pol = self.pol("shell")
        for cmd in ("ls -la /tmp", "pwd", "git status", "cat README.md"):
            self.assertTrue(self.decide(pol, "run_command", {"command": cmd}),
                            cmd)
        for cmd in ("rm -rf /", "ls; rm x", "ls | sh", "cat a > b",
                    "ls `id`", "ls $(id)", "cat ../../etc/passwd",
                    "ls\nrm x", "curl http://x.example"):
            self.assertFalse(self.decide(pol, "run_command", {"command": cmd}),
                             cmd)
        self.assertFalse(self.decide(pol, "bash", {"command": "ls"}))

    def test_an_unknown_pack_is_refused_by_the_parser(self):
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit):
            cli_mod.build_parser().parse_args(["--init-policy", "--pack",
                                               "nope"])

    def test_policy_returns_a_copy(self):
        a = packs.policy("git")
        a["allow_tools"].append("x")
        self.assertNotIn("x", packs.policy("git")["allow_tools"])


class TestAuditChain(Base):
    def setUp(self):
        super().setUp()
        self.write_policy({"allow_tools": ["*"], "hide_denied": False,
                           "deny_tools": ["bad"]})

    def run_calls(self, n=3):
        lines = [req(i, "tools/call", {"name": "good" if i % 2 else "bad",
                                       "arguments": {}}) for i in range(1, n + 1)]
        return self.drive(lines, audit_chain=True)

    def test_each_record_carries_the_hash_of_the_line_before(self):
        code, replies, err = self.run_calls(4)
        self.assertEqual(code, 0, err)
        with open(self.log, "rb") as f:
            lines = [l.rstrip(b"\n") for l in f if l.strip()]
        self.assertGreaterEqual(len(lines), 4)
        recs = [json.loads(l) for l in lines]
        self.assertEqual(recs[0]["prev"], auditchain.GENESIS)
        for i in range(1, len(lines)):
            self.assertEqual(recs[i]["prev"], auditchain.line_hash(lines[i - 1]))
        res = auditchain.verify(self.log)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["head"], auditchain.line_hash(lines[-1]))

    def test_a_changed_removed_or_inserted_record_breaks_it(self):
        self.run_calls(5)
        with open(self.log, encoding="utf-8") as f:
            original = f.read().splitlines()

        def verify(lines):
            with open(self.log, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
            return auditchain.verify(self.log)

        changed = list(original)
        rec = json.loads(changed[1])
        rec["decision"] = "allow"
        rec["reason"] = "edited"
        changed[1] = json.dumps(rec)
        self.assertFalse(verify(changed)["ok"])
        self.assertFalse(verify(original[:1] + original[2:])["ok"])
        forged = original[:2] + [json.dumps({"decision": "allow"})] + original[2:]
        self.assertFalse(verify(forged)["ok"])
        self.assertTrue(verify(original)["ok"])

    def test_truncating_the_end_is_not_detected_and_that_is_documented(self):
        self.run_calls(4)
        with open(self.log, encoding="utf-8") as f:
            lines = f.read().splitlines()
        with open(self.log, "w", encoding="utf-8") as f:
            f.write("\n".join(lines[:-1]) + "\n")
        self.assertTrue(auditchain.verify(self.log)["ok"])
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("cut records off the end", text)
        self.assertIn("same user", auditchain.__doc__)

    def test_the_chain_survives_a_rotation(self):
        self.run_calls(2)
        os.replace(self.log, self.log + ".1")
        self.run_calls(2)
        recs = self.records()
        with open(self.log + ".1", "rb") as f:
            last = [l for l in f if l.strip()][-1]
        self.assertEqual(recs[0]["prev"], auditchain.line_hash(last))
        self.assertTrue(auditchain.verify(self.log)["ok"])

    def test_off_by_default_and_the_environment_turns_it_on(self):
        self.drive([req(1, "tools/call", {"name": "good", "arguments": {}})])
        self.assertTrue(all("prev" not in r for r in self.records()))
        with mock.patch.dict(os.environ, {"MCP_JAIL_AUDIT_CHAIN": "1"}):
            self.assertTrue(jail_mod.audit_chain_enabled())

    def test_a_log_without_a_chain_is_reported_as_such(self):
        self.drive([req(1, "tools/call", {"name": "good", "arguments": {}})])
        code, out, err = self.cli("--verify-audit")
        self.assertEqual(code, 1)
        self.assertIn("none chained", out)

    def test_verify_audit_command_ok_and_broken(self):
        self.run_calls(3)
        code, out, err = self.cli("--verify-audit")
        self.assertEqual(code, 0, out)
        self.assertIn("chain ok", out)
        self.assertIn("head", out)
        with open(self.log, encoding="utf-8") as f:
            lines = f.read().splitlines()
        rec = json.loads(lines[0])
        rec["reason"] = "x"
        lines[0] = json.dumps(rec)
        with open(self.log, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        code, out, err = self.cli("--verify-audit")
        self.assertEqual(code, 1)
        self.assertIn("BROKEN", out)

    def test_no_log_yet(self):
        code, out, err = self.cli("--verify-audit")
        self.assertEqual(code, 0)
        self.assertIn("no audit log", out)

    def test_last_line_reads_a_line_longer_than_a_chunk(self):
        big = json.dumps({"x": "y" * (auditchain._CHUNK * 3)})
        with open(self.log, "w", encoding="utf-8") as f:
            f.write('{"a": 1}\n' + big + "\n")
        self.assertEqual(auditchain.last_line(self.log), big.encode())
        self.assertIsNone(auditchain.last_line(self.log + ".none"))


class TestAuditRedaction(Base):
    KEY = "sk-" + "A" * 24

    def test_matches_are_replaced_in_values_and_keys(self):
        rx = jail_mod.compile_redactions([r"hunter\d+", "@defaults"])
        view = jail_mod.audit_args_view(
            {"note": "pw hunter42 ok", f"k-{self.KEY}": [self.KEY, "plain"]},
            0, rx)
        text = json.dumps(view)
        self.assertNotIn("hunter42", text)
        self.assertNotIn(self.KEY, text)
        self.assertIn("plain", text)
        self.assertIn("[redacted]", text)

    def test_a_secret_at_the_cut_is_still_found_whole(self):
        rx = jail_mod.compile_redactions([r"SECRET[a-z]{30}"])
        value = "x" * 190 + "SECRET" + "a" * 30 + "tail"
        out = jail_mod.audit_args_view(value, 0, rx)
        self.assertNotIn("SECRET", out)

    def test_the_policy_validates_the_list(self):
        for bad in ("x", [1], [""], ["("], ["a*"], ["x"] * 51):
            with self.assertRaises(ValueError, msg=str(bad)):
                jail_mod.compile_policy({"audit_redact": bad})
        pol = jail_mod.compile_policy({"audit_redact": ["a+b"]})
        self.assertEqual(len(pol["_audit_redact"]), 1)

    def test_internal_key_cannot_be_forged_in_a_file(self):
        path = os.path.join(self.tmp, "p.json")
        with open(path, "w") as f:
            json.dump({"_audit_redact": []}, f)
        with self.assertRaises(ValueError):
            jail_mod.load_policy(path)

    def test_the_audit_log_end_to_end(self):
        self.write_policy({"allow_tools": ["*"], "audit_args": "all",
                           "audit_redact": ["@defaults", r"hunter\d+"]})
        code, replies, err = self.drive([req(1, "tools/call", {
            "name": "t", "arguments": {"token": self.KEY,
                                       "pw": "hunter99", "ok": "fine"}})])
        with open(self.log, encoding="utf-8") as f:
            raw = f.read()
        self.assertNotIn(self.KEY, raw)
        self.assertNotIn("hunter99", raw)
        self.assertIn("fine", raw)

    def test_rejected_messages_are_redacted_too(self):
        self.write_policy({"allow_tools": ["*"], "audit_redact": [r"hunter\d+"]})
        code, replies, err = self.drive([b'{"jsonrpc":"2.0","id":1,"method":'
                                         b'"x","params":{"pw":"hunter7"}'
                                         b'  garbage\n'])
        with open(self.log, encoding="utf-8") as f:
            raw = f.read()
        self.assertIn("rejected", raw)
        self.assertNotIn("hunter7", raw)

    def test_without_the_option_nothing_changes(self):
        self.assertEqual(jail_mod.audit_args_view({"a": "b"}), {"a": "b"})
        self.assertEqual(jail_mod.compile_redactions(None), [])


class TestEnvAllow(Base):
    def env_names(self, **kw):
        self.write_policy({"allow_tools": ["*"]})
        code, replies, err = self.drive([req(1, "tools/call", {
            "name": "t", "arguments": {}})], **kw)
        self.assertEqual(code, 0, err)
        text = replies[0]["result"]["content"][0]["text"]
        return set(json.loads(text))

    def test_default_passes_everything(self):
        with mock.patch.dict(os.environ, {"MJ_SECRET_TOKEN": "v"}):
            self.assertIn("MJ_SECRET_TOKEN", self.env_names())

    def test_only_the_baseline_and_the_named_variables_get_through(self):
        with mock.patch.dict(os.environ, {
                "MJ_SECRET_TOKEN": "v", "MJ_KEEP": "1", "MYAPP_A": "1",
                "MYAPP_B": "2", "OTHER_THING": "3"}):
            names = self.env_names(env_allow=["MJ_KEEP", "MYAPP_*"])
        self.assertNotIn("MJ_SECRET_TOKEN", names)
        self.assertNotIn("OTHER_THING", names)
        self.assertTrue({"MJ_KEEP", "MYAPP_A", "MYAPP_B"} <= names)
        self.assertIn("PATH", names)

    def test_child_env_is_a_pure_function(self):
        env = {"PATH": "p", "Home": "h", "SECRET": "s", "LC_ALL": "C",
               "LCX": "x", "KEEP_1": "1"}
        with mock.patch.object(jail_mod, "_WINDOWS", False):
            got = jail_mod.child_env(["KEEP_*"], env)
        self.assertEqual(set(got), {"PATH", "LC_ALL", "KEEP_1"})
        with mock.patch.object(jail_mod, "_WINDOWS", True):
            got = jail_mod.child_env([], env)
        self.assertIn("Home", got)          # names compare case-insensitively
        self.assertNotIn("SECRET", got)

    def test_bad_names_are_refused(self):
        for bad in (["A=B"], ["*"], ["A*B"], [""], ["  "]):
            self.assertIsNotNone(jail_mod.env_allow_problem(bad), bad)
        self.assertIsNone(jail_mod.env_allow_problem(["A", "B_*"]))
        self.write_policy({"allow_tools": ["*"]})
        code, replies, err = self.drive([req(1, "ping")], env_allow=["A=B"])
        self.assertEqual(code, 2)
        self.assertIn("--env-allow", err)

    def test_the_option_is_repeatable_and_comma_separated(self):
        self.assertEqual(cli_mod._env_names(["A,B", " C ", ""]),
                         ["A", "B", "C"])
        args = cli_mod.build_parser().parse_args(
            ["--env-allow", "A,B", "--env-allow", "C", "--", "x"])
        self.assertEqual(cli_mod._env_names(args.env_allow), ["A", "B", "C"])


class TestRotationWarning(Base):
    def test_a_skipped_rotation_is_said_once(self):
        with open(self.log, "w", encoding="utf-8") as f:
            f.write("x" * 5000 + "\n")
        err = io.StringIO()
        jail_mod._rotation_warned = False
        self.addCleanup(setattr, jail_mod, "_rotation_warned", False)

        class Nope:
            def __enter__(self):
                return False

            def __exit__(self, *a):
                return False

        with mock.patch.dict(os.environ, {"MCP_JAIL_AUDIT_MAX_MB": "0.001"}), \
                mock.patch.object(jail_mod, "_exclusive", lambda p: Nope()), \
                redirect_stderr(err):
            jail_mod.audit({"decision": "allow"})
            jail_mod.audit({"decision": "allow"})
        text = err.getvalue()
        self.assertEqual(text.count("could not be rotated"), 1)
        self.assertTrue(os.path.exists(self.log))
        self.assertFalse(os.path.exists(self.log + ".1"))


class TestMessageCeiling(unittest.TestCase):
    def test_the_ceiling_is_one_gibibyte(self):
        self.assertEqual(jail_mod.MAX_MAX_MESSAGE, 2 ** 30)
        self.assertIsNone(jail_mod.max_message_problem(2 ** 30))
        self.assertIn("1 GiB", jail_mod.max_message_problem(2 ** 30 + 1))
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli_mod.build_parser().parse_args(
                ["--max-message-bytes", str(2 ** 30 + 1), "--", "x"])


class TestOnDriftBlockAlreadyExists(unittest.TestCase):
    def test_block_is_a_mode_and_the_default(self):
        args = cli_mod.build_parser().parse_args(["--lockfile", "l", "--", "x"])
        self.assertEqual(args.on_drift, "block")
        self.assertIn("block", jail_mod.lockguard.MODES)


class TestCiAndDocs(unittest.TestCase):
    def read(self, *p):
        with open(os.path.join(REPO, *p), encoding="utf-8") as f:
            return f.read()

    def test_the_wheel_is_installed_on_windows_and_macos(self):
        if not os.path.exists(os.path.join(REPO, ".github", "workflows",
                                           "ci.yml")):
            self.skipTest("workflows are not shipped in the sdist")
        text = self.read(".github", "workflows", "ci.yml")
        self.assertIn("windows-latest, macos-latest", text)
        self.assertIn("Scripts", text)

    def test_the_readme_documents_the_new_options(self):
        if not os.path.exists(os.path.join(REPO, "README.md")):
            self.skipTest("not a source checkout")
        text = self.read("README.md")
        for needle in ("--strict", "--pack", "--audit-chain", "--verify-audit",
                       "--env-allow", "audit_redact", "1 GiB",
                       "cut records off the end"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()

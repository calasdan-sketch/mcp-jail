"""mcp-jail: runtime permission firewall for MCP servers.

A stdio proxy that enforces a JSON policy on every tool call. mcp-audit
finds the problems; mcp-jail enforces least-privilege at runtime.

  mcp-jail --policy policy.json -- npx -y some-mcp-server
  mcp-jail --init-policy                # write an annotated starter policy
  mcp-jail --audit                      # show the audit log
  mcp-jail learn --script calls.json --out policy.json -- <server cmd>
  mcp-jail --policy p.json --lockfile mcp.lock -- <server cmd>
  mcp-jail verify-policy --policy p.json --session session.json
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import sys

from . import VERSION
from . import jail as jail_mod


# Tests patch this to exercise the Windows branch on any OS.
_WINDOWS = os.name == "nt"


def _pipe_gone(exc: BaseException) -> bool:
    """Did the reader of our stdout go away?

    POSIX raises BrokenPipeError (EPIPE). Windows reports the same thing as
    a plain OSError with errno EINVAL and no file name (measured on Windows
    11 / Python 3.11: errno 22, winerror None), raised by the FLUSH rather
    than by the print, and it fails a second time at interpreter exit
    (status 120) unless fd 1 is pointed at the null device first."""
    if isinstance(exc, BrokenPipeError):
        return True
    if not isinstance(exc, OSError):
        return False
    if exc.errno == errno.EPIPE:
        return True
    return (_WINDOWS and exc.errno == errno.EINVAL
            and getattr(exc, "filename", None) is None)


def _broken_pipe() -> int:
    """stdout's reader went away (`mcp-jail --audit | head`): leave
    quietly. stdout is pointed at the null device first so the
    interpreter's exit-time flush cannot raise the same error again."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass
    return 0


def _harden_streams() -> None:
    """Never crash on a console that cannot encode a tool name or reason.

    The proxy itself writes protocol bytes (UTF-8) straight to the binary
    stdout; this only affects the human-facing text output (--audit,
    learn summaries, errors) on e.g. a cp1252 Windows console.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        # Both handlers raise UnicodeEncodeError on a character the code
        # page lacks: "strict" (the default) and "surrogateescape" (what a
        # piped stdout reports on Windows 11 / Python 3.11, with cp1252).
        if reconfigure is None or getattr(stream, "errors", None) not in (
                "strict", "surrogateescape"):
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


class _Parser(argparse.ArgumentParser):
    """argparse with nowhere to complain. error() prints the usage with
    print_usage(sys.stderr), and print_usage(None) means standard OUTPUT -
    which is where a process started with stderr closed would put it. It
    exits 2 without a word then."""

    def error(self, message):
        if sys.stderr is None:
            self.exit(2)
        super().error(message)


def _seconds(text: str) -> float:
    """argparse type for --timeout: a finite number of seconds, 0 or more.
    float() alone takes "nan" and "inf" and a minus sign."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a number of seconds") from None
    why = jail_mod.seconds_problem(value)
    if why is not None:
        raise argparse.ArgumentTypeError(f"{text!r} {why}")
    return value


def _positive_count(text: str) -> int:
    """argparse type for --limit: a whole number, 1 or more. int() alone takes
    0 (which showed the whole log) and negatives (which dropped lines): the
    log is cut with a slice that counts from the end."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a whole number") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"{text!r} is not 1 or more")
    return value


def _message_bytes(text: str) -> int:
    """argparse type for --max-message-bytes: a whole number, 1024 to 2**40."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a whole number") from None
    why = jail_mod.max_message_problem(value)
    if why is not None:
        if value > jail_mod.MAX_MAX_MESSAGE:
            raise argparse.ArgumentTypeError(
                f"{text!r} is above the maximum of {jail_mod.MAX_MAX_MESSAGE} "
                f"(1 TiB)")
        raise argparse.ArgumentTypeError(
            f"{text!r} is below the minimum of {jail_mod.MIN_MAX_MESSAGE}")
    return value


def cmd_init_policy(args) -> int:
    try:
        path = jail_mod.expand_path(args.path)
        if os.path.exists(path) and not args.force:
            jail_mod._say(f"exists: {path} (use --force to overwrite)")
            return 2
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(jail_mod.default_policy(), f, indent=2)
            f.write("\n")
    except (OSError, ValueError) as e:     # unwritable, a directory, a NUL ...
        why = getattr(e, "strerror", None) or str(e)
        jail_mod._say(f"mcp-jail: cannot write the policy {args.path}: {why}")
        return 2
    print(f"wrote {path}")
    jail_mod._say("mcp-jail: warning: this starter policy allows EVERY tool "
                  "and blocks nothing. Run `mcp-jail learn -- <server "
                  "command>` to write a tight one from a real session, or "
                  "edit it (see _examples in the file).")
    return 0


def _plain(value) -> str:
    """A field of an audit record as one line of printable text. The log is
    JSON, so a newline, a terminal escape or a bidi override inside a reason
    (or a tool name: the client chooses it) is harmless there; printed as it
    is, it would forge lines in the report and drive the terminal. Whatever is
    not printable is shown as its escape: \\n, \\x1b, \\u202e."""
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value)
        except (TypeError, ValueError):
            value = repr(value)
    return "".join(ch if ch.isprintable()
                   else ch.encode("unicode_escape").decode("ascii")
                   for ch in value)


def cmd_audit(args) -> int:
    path = jail_mod.audit_log_path()
    if not os.path.exists(path):
        print("no audit log yet.")
        return 0
    denies = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()[-args.limit:]
    for ln in lines:
        try:
            e = json.loads(ln)
        except (ValueError, RecursionError):
            continue
        if not isinstance(e, dict):
            continue
        denied = e.get("decision") == "deny"
        denies += denied
        mark = ("DENY " if denied else
                "SHADOW" if e.get("decision") == "would-deny" else "allow")
        what = e.get("tool")
        if what is None:
            if e.get("rejected") is not None:  # a message the jail would not relay
                what = f"{_plain(e['rejected'])} message"
            else:  # a whole method refused by deny_methods
                what = f"method {_plain(e.get('method'))}"
        drift = e.get("drift")
        tag = ("" if drift is None else " [lockfile]" if drift == "lockfile"
               else f" [lockfile: {_plain(drift)}]")
        print(f"{mark} {_plain(what)}{tag} {_plain(e.get('reason', ''))}")
    print(f"\n{denies} denied in last {len(lines)} calls")
    return 0


def cmd_learn(argv: list[str]) -> int:
    p = _Parser(
        prog="mcp-jail learn",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Observe a server session and generate a tight-fit "
                    "allowlist policy: only the tools actually called, with "
                    "per-argument allow patterns derived from the values "
                    "seen.\n\n--script drives canned calls against the "
                    "server (no client needed); without it, learn proxies "
                    "stdin/stdout until stdin EOF or Ctrl-C.")
    p.add_argument("--script",
                   help="JSON array of {\"tool\": name, "
                        "\"arguments\": {...}} to drive against the server")
    p.add_argument("--out", help="write the policy here (default: stdout)")
    p.add_argument("--timeout", type=_seconds, default=30.0,
                   help="seconds to wait for each server response "
                        "(default: 30; 0 waits for ever)")
    p.add_argument("--grace", type=_seconds, default=jail_mod.DEFAULT_GRACE,
                   help="live mode: seconds to give the server to exit on "
                        "its own once stdin has ended, before it is sent "
                        "SIGTERM (default: 5; 0 stops it at once)")
    p.add_argument("--max-message-bytes", type=_message_bytes,
                   default=jail_mod.DEFAULT_MAX_MESSAGE, metavar="N",
                   help="the longest message, one line, accepted from the "
                        "client or the server (default: 16777216, 16 MiB; "
                        "1024 to 1099511627776). A longer server message "
                        "is skipped")
    p.add_argument("--record", metavar="FILE",
                   help="also write the calls seen as a session file for "
                        "`mcp-jail verify-policy`")
    p.add_argument("server", nargs=argparse.REMAINDER,
                   help="server command after -- : "
                        "mcp-jail learn --script c.json -- <cmd>")
    args = p.parse_args(argv)
    cmd = list(args.server)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        jail_mod._say("error: no server command: "
                      "mcp-jail learn [--script c.json] [--out p.json] "
                      "-- <cmd>")
        return 2
    return jail_mod.learn(cmd, script=args.script, out=args.out,
                          timeout=args.timeout, grace=args.grace,
                          max_message=args.max_message_bytes,
                          record=args.record)


def cmd_verify_policy(argv: list[str]) -> int:
    from . import policytest
    p = _Parser(
        prog="mcp-jail verify-policy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Replay a recorded session against a policy and check "
                    "each call is allowed or refused as expected. No server "
                    "is started. Exit 0 all as expected, 1 some not, 2 the "
                    "policy or session is unusable.\n\n"
                    "Write a session with `mcp-jail learn --record FILE`, "
                    "or by hand (see the README).")
    p.add_argument("--policy", default=jail_mod.default_policy_path(),
                   metavar="FILE", help="policy file (default: the usual one)")
    p.add_argument("--session", required=True, metavar="FILE",
                   help="the recorded session")
    p.add_argument("--format", choices=("text", "json"), default="text")
    args = p.parse_args(argv)
    return policytest.verify_policy(args.policy, args.session,
                                    as_json=args.format == "json")


def build_parser() -> argparse.ArgumentParser:
    default_policy = jail_mod.default_policy_path()
    p = _Parser(
        prog="mcp-jail", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="subcommands: mcp-jail learn --help, mcp-jail verify-policy --help\n\n"
               "exit status: 0 a clean session; 2 an unusable policy or "
               "command; 3 the server failed (it exited or closed its pipes, "
               "stopped reading its input, or did not answer a request "
               "within --timeout); 128+N (143, 129) stopped by SIGTERM or "
               "SIGHUP after closing the server's input and waiting --grace")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--policy", default=default_policy, metavar="FILE",
                   help=f"policy file; ~ and environment variables are "
                        f"expanded (default: {default_policy})")
    p.add_argument("--init-policy", action="store_true",
                   help="write an annotated starter policy to --path and "
                        "exit (allows every tool: edit it)")
    p.add_argument("--path", default=default_policy, metavar="FILE",
                   help=f"where --init-policy writes "
                        f"(default: {default_policy})")
    p.add_argument("--force", action="store_true",
                   help="let --init-policy overwrite an existing file")
    p.add_argument("--audit", action="store_true",
                   help="print the last --limit audit-log entries "
                        "(allow/deny per tool call) and exit")
    p.add_argument("--limit", type=_positive_count, default=50, metavar="N",
                   help="how many audit entries --audit shows: the last N, "
                        "a whole number, 1 or more (default: 50)")
    p.add_argument("--timeout", type=_seconds, default=30.0, metavar="SECS",
                   help="seconds to wait for each server response, and for "
                        "the server to take each message off its stdin "
                        "(default: 30; 0 waits for ever)")
    p.add_argument("--grace", type=_seconds, default=jail_mod.DEFAULT_GRACE,
                   metavar="SECS",
                   help="seconds to give the server to finish and exit on "
                        "its own once the client's input has ended and every "
                        "request is answered; then it is sent SIGTERM, and "
                        "killed if it ignores that (default: 5; 0 stops it "
                        "at once)")
    p.add_argument("--max-message-bytes", type=_message_bytes,
                   default=jail_mod.DEFAULT_MAX_MESSAGE, metavar="N",
                   help="the longest message, one line, accepted from the "
                        "client or the server (default: 16777216, 16 MiB; "
                        "1024 to 1099511627776). A longer client message is "
                        "refused "
                        "with -32600, a longer server response with -32603 "
                        "and an audit record; neither is held in memory")
    p.add_argument("--lockfile", metavar="FILE",
                   help="compare every tools/list answer with this mcp.lock "
                        "(made by `mcp-audit lock`) and act on a change. "
                        "See docs/LOCKFILE.md")
    p.add_argument("--lock-server", metavar="NAME",
                   help="the server's name in the lockfile (default: the "
                        "one started with this command)")
    p.add_argument("--on-drift", choices=("block", "strip", "ask", "warn"),
                   default="block", metavar="MODE",
                   help="MODE is block, strip, ask or warn. What to do when "
                        "a tool is new or changed: block "
                        "(default: refuse the list and the calls), strip "
                        "(hide the changed tools, refuse their calls), ask "
                        "(ask on the terminal; no answer means block), warn "
                        "(pass it on and say so)")
    p.add_argument("--shadow", action="store_true",
                   help="evaluate the policy and the lockfile but enforce "
                        "nothing: every call and list goes through, and a "
                        "report says what would have been refused. Denied "
                        "calls DO reach the server")
    p.add_argument("--shadow-report", metavar="FILE",
                   help="with --shadow, also write the report as JSON")
    p.add_argument("server", nargs=argparse.REMAINDER,
                   help="server command after -- : "
                        "mcp-jail --policy p.json -- npx -y srv")
    return p


def _main(argv: list[str]) -> int:
    if argv[:1] == ["learn"]:
        return cmd_learn(argv[1:])
    if argv[:1] == ["verify-policy"]:
        return cmd_verify_policy(argv[1:])
    args = build_parser().parse_args(argv)
    if args.init_policy:
        return cmd_init_policy(args)
    if args.audit:
        return cmd_audit(args)
    cmd = list(args.server)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        jail_mod._say("error: no server command: "
                      "mcp-jail --policy p.json -- <cmd>")
        return 2
    if args.shadow_report and not args.shadow:
        jail_mod._say("error: --shadow-report needs --shadow")
        return 2
    return jail_mod.run(args.policy, cmd, timeout=args.timeout,
                        grace=args.grace, max_message=args.max_message_bytes,
                        lockfile=args.lockfile, lock_server=args.lock_server,
                        on_drift=args.on_drift, shadow=args.shadow,
                        shadow_report=args.shadow_report)


def main(argv=None) -> int:
    _harden_streams()
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        rc = _main(argv)
        if sys.stdout is not None:
            sys.stdout.flush()  # a closed pipe surfaces here, not at interpreter exit
        return rc
    except OSError as e:
        if _pipe_gone(e):
            return _broken_pipe()
        raise


if __name__ == "__main__":
    sys.exit(main())

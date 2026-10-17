"""mcp-jail: runtime permission firewall for MCP servers.

A stdio proxy that enforces a JSON policy on every tool call. mcp-audit
finds the problems; mcp-jail enforces least-privilege at runtime.

  mcp-jail --policy policy.json -- npx -y some-mcp-server
  mcp-jail --init-policy                # write an annotated starter policy
  mcp-jail --audit                      # show the audit log
  mcp-jail learn --script calls.json --out policy.json -- <server cmd>
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import jail as jail_mod

VERSION = "0.4.0"


def _harden_streams() -> None:
    """Never crash on a console that cannot encode a tool name or reason.

    The proxy itself writes protocol bytes (UTF-8) straight to the binary
    stdout; this only affects the human-facing text output (--audit,
    learn summaries, errors) on e.g. a cp1252 Windows console.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None or getattr(stream, "errors", None) != "strict":
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def cmd_init_policy(args) -> int:
    path = jail_mod.expand_path(args.path)
    if os.path.exists(path) and not args.force:
        print(f"exists: {path} (use --force to overwrite)", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(jail_mod.default_policy(), f, indent=2)
        f.write("\n")
    print(f"wrote {path}")
    return 0


def cmd_audit(args) -> int:
    path = jail_mod.audit_log_path()
    if not os.path.exists(path):
        print("no audit log yet.")
        return 0
    denies = 0
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()[-args.limit:]
    for ln in lines:
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        mark = "DENY " if e.get("decision") == "deny" else "allow"
        if e.get("decision") == "deny":
            denies += 1
        print(f"{mark} {e.get('tool')} {e.get('reason', '')}")
    print(f"\n{denies} denied in last {len(lines)} calls")
    return 0


def cmd_learn(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
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
    p.add_argument("--timeout", type=float, default=30.0,
                   help="seconds to wait for each server response "
                        "(default: 30)")
    p.add_argument("server", nargs=argparse.REMAINDER,
                   help="server command after -- : "
                        "mcp-jail learn --script c.json -- <cmd>")
    args = p.parse_args(argv)
    cmd = list(args.server)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("error: no server command: "
              "mcp-jail learn [--script c.json] [--out p.json] -- <cmd>",
              file=sys.stderr)
        return 2
    return jail_mod.learn(cmd, script=args.script, out=args.out,
                          timeout=args.timeout)


def build_parser() -> argparse.ArgumentParser:
    default_policy = jail_mod.default_policy_path()
    p = argparse.ArgumentParser(
        prog="mcp-jail", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="subcommand: mcp-jail learn --help")
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
    p.add_argument("--limit", type=int, default=50, metavar="N",
                   help="how many audit entries --audit shows "
                        "(default: 50)")
    p.add_argument("--timeout", type=float, default=30.0, metavar="SECS",
                   help="seconds to wait for each server response "
                        "(default: 30)")
    p.add_argument("server", nargs=argparse.REMAINDER,
                   help="server command after -- : "
                        "mcp-jail --policy p.json -- npx -y srv")
    return p


def main(argv=None) -> int:
    _harden_streams()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["learn"]:
        return cmd_learn(argv[1:])
    args = build_parser().parse_args(argv)
    if args.init_policy:
        return cmd_init_policy(args)
    if args.audit:
        return cmd_audit(args)
    cmd = list(args.server)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("error: no server command: mcp-jail --policy p.json -- <cmd>",
              file=sys.stderr)
        return 2
    return jail_mod.run(args.policy, cmd, timeout=args.timeout)


if __name__ == "__main__":
    sys.exit(main())

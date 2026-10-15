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

VERSION = "0.2.0"


def cmd_init_policy(args) -> int:
    path = os.path.expanduser(args.path)
    if os.path.exists(path) and not args.force:
        print(f"exists: {path} (use --force to overwrite)", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(jail_mod.default_policy(), f, indent=2)
    print(f"wrote {path}")
    return 0


def cmd_audit(args) -> int:
    path = jail_mod.AUDIT_LOG
    if not os.path.exists(path):
        print("no audit log yet.")
        return 0
    denies = 0
    with open(path) as f:
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
        description="Observe a server session and generate a tight-fit "
                    "allowlist policy. --script drives canned calls against "
                    "the server (no client needed); without it, learn "
                    "proxies stdin/stdout until stdin EOF or Ctrl-C.")
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
    p = argparse.ArgumentParser(prog="mcp-jail", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--policy", default=jail_mod.DEFAULT_POLICY_PATH)
    p.add_argument("--init-policy", action="store_true")
    p.add_argument("--path", default=jail_mod.DEFAULT_POLICY_PATH)
    p.add_argument("--force", action="store_true")
    p.add_argument("--audit", action="store_true")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--timeout", type=float, default=30.0,
                   help="seconds to wait for each server response "
                        "(default: 30)")
    p.add_argument("server", nargs=argparse.REMAINDER,
                   help="server command after -- : mcp-jail --policy p.json -- npx -y srv")
    return p


def main(argv=None) -> int:
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

"""Ready-made starter policies for the servers most people run: `mcp-jail
--init-policy --pack NAME`. Each is a tight starting point that allows a
read-only part of the server and refuses the rest, written with the tool
names of the reference servers. Check them against `tools/list` of the
server you run (a tool this file does not know is denied, which is the safe
mistake), then tighten with `mcp-jail learn`."""

from __future__ import annotations

import copy

_SECRET_PATH = (r"(?i)(^|[\\/])(\.ssh|\.aws|\.gnupg|\.kube|\.docker)"
                r"([\\/]|$)")
_SECRET_FILE = r"(?i)(^|[\\/])(\.env(\..*)?|id_(rsa|dsa|ecdsa|ed25519)|" \
               r".*\.(pem|key|p12|pfx))$"

PACKS = {
    "filesystem": {
        "_comment": "mcp-jail pack: filesystem. Read-only: it can list and "
                    "read files, not write, move or create them, and not "
                    "reach '..', ~/.ssh, ~/.aws, key files or .env files. "
                    "Add the folder you serve to arg_rules.*.allow (a "
                    "pattern such as \"^/home/me/project/\") to confine it. "
                    "Resources and prompts are refused.",
        "allow_tools": ["read_file", "read_text_file", "read_multiple_files",
                        "list_directory", "list_directory_with_sizes",
                        "directory_tree", "search_files", "get_file_info",
                        "list_allowed_directories"],
        "deny_tools": ["write_file", "edit_file", "create_directory",
                       "move_file", "read_media_file"],
        "arg_rules": {tool: {"deny": {"**": [r"\.\.", _SECRET_PATH,
                                             _SECRET_FILE]}}
                      for tool in ("read_file", "read_text_file",
                                   "read_multiple_files", "list_directory",
                                   "list_directory_with_sizes",
                                   "directory_tree", "search_files",
                                   "get_file_info")},
        "policed_methods": ["tools/call"],
        "deny_methods": ["resources/*", "prompts/*"],
        "strict_args": False,
        "audit_args": "denied",
        "hide_denied": True,
    },
    "git": {
        "_comment": "mcp-jail pack: git. Read-only: status, diffs, log, "
                    "show and branch listing. Staging, committing, "
                    "resetting, checking out, creating branches and init "
                    "are refused. Resources and prompts are refused.",
        "allow_tools": ["git_status", "git_diff", "git_diff_staged",
                        "git_diff_unstaged", "git_log", "git_show",
                        "git_branch"],
        "deny_tools": ["git_add", "git_commit", "git_reset", "git_checkout",
                       "git_create_branch", "git_init"],
        "arg_rules": {"git_log": {"deny": {"max_count": [r"\D"]}}},
        "policed_methods": ["tools/call"],
        "deny_methods": ["resources/*", "prompts/*"],
        "strict_args": False,
        "audit_args": "denied",
        "hide_denied": True,
    },
    "shell": {
        "_comment": "mcp-jail pack: shell. A shell tool can do anything the "
                    "user can, so this allows only a short list of "
                    "read-only commands (ls, pwd, cat, head, tail, wc, "
                    "grep, git status/diff/log) and refuses a command "
                    "that chains, redirects or substitutes (; & | ` $ < > "
                    "or a line break). The tool is called run_command here: "
                    "rename it to what your server calls it. Everything "
                    "else is denied.",
        "allow_tools": ["run_command"],
        "deny_tools": ["execute_command", "run_shell_command", "shell",
                       "bash", "exec", "run_script"],
        "arg_rules": {"run_command": {
            "allow": {"command": [
                r"\A(ls|pwd|cat|head|tail|wc|grep|git status|git diff|"
                r"git log)( [A-Za-z0-9_./=:@%+,-]+)*\Z"]},
            "deny": {"**": [r"[;&|`$<>\n\r]", r"\.\."]}}},
        "policed_methods": ["tools/call"],
        "deny_methods": ["resources/*", "prompts/*"],
        "strict_args": True,
        "audit_args": "all",
        "hide_denied": True,
    },
}


def names() -> "tuple[str, ...]":
    return tuple(PACKS)


def policy(name: str) -> dict:
    """A copy of the pack's policy (ValueError for a name it does not
    have)."""
    if name not in PACKS:
        raise ValueError(f"unknown pack {name!r}; choose from "
                         f"{', '.join(PACKS)}")
    return copy.deepcopy(PACKS[name])

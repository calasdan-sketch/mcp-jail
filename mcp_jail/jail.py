"""Stdio proxy: MCP permission firewall.

Sits between your MCP client and a real MCP server. Every tools/call is
checked against a JSON policy before forwarding; denied calls get a
JSON-RPC error and an audit-log line instead of execution.

Zero client changes: swap the server command for the jail wrapper.

  "my-server": {
    "command": "mcp-jail",
    "args": ["--policy", "~/.mcp-jail/policy.json", "--",
             "npx", "-y", "some-mcp-server"]
  }

Transport: newline-delimited JSON-RPC over stdio (the MCP stdio
transport), UTF-8 on the wire regardless of the console code page.
Both pipes are pumped by reader threads into one queue, so the proxy
runs the same way on Windows as on POSIX (no select() on pipes).
"""

from __future__ import annotations

import collections
import contextlib
import difflib
import fnmatch
import heapq
import io
import itertools
import json
import math
import os
import queue
import re
import shutil
import signal
import stat
import string
import subprocess
import sys
import threading
import time
import unicodedata

from . import VERSION

# The MCP revision learn offers in its initialize handshake. The server
# answers with the revision it will speak; stdio has nowhere else to put
# it, so learn only reports it.
PROTOCOL_VERSION = "2025-06-18"

# Tests patch this to exercise the Windows branches on any OS.
_WINDOWS = os.name == "nt"

# Exit codes: 0 a clean session, 2 unusable policy / script / command (or a
# learn session that ended early), 3 the server failed while the jail was
# relaying: it exited or closed its pipes, stopped reading its input, or did
# not answer a request within --timeout. 128 plus the signal number (143,
# 129): the jail was told to stop by SIGTERM / SIGHUP (see _StopSignals).
EXIT_SERVER = 3

# The longest one wait on the queue may last. A wait that never ends cannot be
# interrupted on Windows (a lock is not alerted by a console event, so the
# handler for Ctrl-C only runs when the call returns), and one that is too
# long is refused outright by threading (OverflowError, a traceback). The loop
# looks at its deadlines again on every pass, so nothing is lost by waking up
# twice a second, and idle that costs next to nothing.
_IDLE_WAKE = 0.5

# Once the client has gone and nothing is owed, the server is given this many
# seconds to finish and exit on its own (--grace; 0 stops it at once). One that
# is still there is sent SIGTERM (terminate(): TerminateProcess on Windows) and,
# if it ignores that for _TERM_WAIT seconds, killed.
DEFAULT_GRACE = 5.0
_TERM_WAIT = 5.0


def seconds_problem(value) -> "str | None":
    """Why `value` cannot be a number of seconds for --timeout or --grace
    (None: it can). float() takes "nan" and "inf" and a minus sign: nan and a
    negative value quietly meant "no timeout", and inf died in the first
    wait."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "is not a number"
    if not math.isfinite(value):
        return "must be a finite number of seconds"
    if value < 0:
        return "must not be negative"
    return None


def _refuse_seconds(**options) -> "str | None":
    """The message for the first of `options` (name=value) that is not a
    usable number of seconds, else None. The command line refuses such a
    value before this; this is for whoever calls run() or learn()."""
    for name, value in options.items():
        why = seconds_problem(value)
        if why is not None:
            return f"--{name} {value!r} {why}"
    return None


def _missing_streams(client_in, client_out) -> "str | None":
    """Why the jail cannot talk to its client when a standard stream it is to
    use is not there (None: both are). A process started with its stdin or
    stdout closed - by a supervisor that forgot a pipe, or pythonw on
    Windows - has None for it."""
    shut = [name for name, stream in (("input", client_in),
                                      ("output", client_out))
            if stream is None]
    if len(shut) == 2:
        return ("standard input and output are closed (the client talks to "
                "mcp-jail over them)")
    if shut == ["input"]:
        return "standard input is closed (the client's messages arrive on it)"
    if shut == ["output"]:
        return "standard output is closed (the server's answers go out on it)"
    return None


def _say(line: str) -> None:
    """One line on stderr. A process without one (started with it closed:
    `2>&-`, or pythonw; sys.stderr is None) has nothing to say it on, and
    print(file=None) would say it on standard OUTPUT, which carries the
    protocol (and the policy `learn` writes); one whose stderr cannot be
    written to (its reader went away) is no worse off. Neither is an error:
    a notice must not end a session, or turn exit status 2 into 1."""
    err = sys.stderr
    if err is None:
        return
    try:
        err.write(line + "\n")
    except (OSError, ValueError):
        pass


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------


def jail_dir() -> str:
    """~/.mcp-jail, resolved at call time (so HOME/USERPROFILE overrides
    in tests and launchers are honoured)."""
    return os.path.join(os.path.expanduser("~"), ".mcp-jail")


def default_policy_path() -> str:
    return os.path.join(jail_dir(), "policy.json")


def expand_path(path: str) -> str:
    """~ and environment variables, as a shell would have done it. MCP
    clients pass our arguments straight from a JSON config file - there
    is no shell in between to expand `~/.mcp-jail/policy.json`."""
    # normpath: expanduser keeps the forward slash of "~/x" on Windows
    return os.path.normpath(os.path.expandvars(os.path.expanduser(path)))


# Tests (and embedders) may point this at another file; None = default.
AUDIT_LOG: str | None = None


def audit_log_path() -> str:
    return AUDIT_LOG or os.path.join(jail_dir(), "audit.jsonl")


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------

# One compiled argument rule: where it applies (path segments), the
# regex, the JSON type it is restricted to (None = any scalar, matched
# by text) and whether it explicitly spells out `\.\.` (opt-in to `..`).
Rule = collections.namedtuple("Rule", "path pattern vtype dotdot_ok")

# JSON type names a typed rule ({"type": ..., "pattern": ...}) may carry.
# object/array only ever describe EMPTY containers: a non-empty one is
# structure, and its values are matched one by one.
VALUE_TYPES = ("string", "number", "boolean", "null", "object", "array")

# Arguments nested deeper than this are denied outright. Real tool calls
# are a handful of levels deep; thousands of levels is an attack on the
# proxy's stack (json.loads and the argument walk both recurse).
MAX_ARG_DEPTH = 100

AUDIT_ARGS_MODES = ("denied", "all", "none")
AUDIT_VALUE_MAX = 200  # chars of any one string value kept in the audit log

# A value containing a `..` path segment (`/../`, leading `../`,
# trailing `/..`, or just `..`), with either separator.
_TRAVERSAL = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")

# Prepended by `learn` to every class-based pattern: a prefix like
# /srv/data/ plus a class that admits `.` and `/` would otherwise match
# /srv/data/../../etc/passwd -- or, with a Windows prefix,
# C:\proj\../.ssh/id_rsa, hence both separators. The matcher refuses `..`
# segments too; the guard keeps the policy file honest on its own.
_TRAVERSAL_GUARD = r"(?!.*(?:^|[/\\])\.\.(?:[/\\]|$))"
# What mcp-jail < 0.5 emitted (forward slash only). Still recognised as a
# guard, so a policy learned back then does not count as opting in to `..`.
_OLD_TRAVERSAL_GUARD = r"(?!.*(?:^|/)\.\.(?:/|$))"

# Tool names are compared after NFKC normalisation and case folding, with
# invisible characters removed: format (zero-width space, soft hyphen,
# BOM), control, surrogate and combining marks. `Delete_All`,
# `delete_all ` and `delete_all\u200b` are all `delete_all`.
_IGNORED_NAME_CATEGORIES = frozenset({"Cf", "Cc", "Cs", "Mn", "Me"})


def normalize_tool_name(name: str) -> str:
    text = unicodedata.normalize("NFKC", name).casefold()
    text = "".join(ch for ch in text
                   if unicodedata.category(ch) not in _IGNORED_NAME_CATEGORIES)
    return text.strip()


# The members a JSON-RPC message is made of, and the fields of a policed
# method's params that the jail reads (see _key_clash).
_ENVELOPE_KEYS = ("jsonrpc", "id", "method", "params", "result", "error")
_PARAM_KEYS = ("name", "arguments", "uri", "ref")


def _key_clash(obj: dict, keys) -> "str | None":
    """A key of `obj` that is not one of `keys` but reads as one of them: a
    different case (METHOD), a Unicode fold (U+017F, the long s, reads as
    `s`, so "param" + U+017F is `params`), invisible characters, a
    compatibility form. Go's encoding/json, C#'s System.Text.Json (when told
    to) and Jackson (when told to) match member names without regard to case
    and let the last duplicate win, so such a key beside the real one - or in
    its place - makes the jail and that server disagree about what the
    message says. The jail refuses it rather than guess which of the
    spellings its peer would read. None if no key clashes."""
    for key in obj:
        if key not in keys and normalize_tool_name(key) in keys:
            return key
    return None


def _clash_text(key: str) -> str:
    return (f"key {ascii(key)} is another spelling of "
            f"{ascii(normalize_tool_name(key))}; a parser that ignores case "
            f"would read it as that key")


def _strict_end_anchors(pattern: str) -> str:
    """Rewrite every `$` of an allow pattern (outside character classes,
    not escaped) to `\\Z`. In `re`, `$` also matches just before a
    trailing newline, so `^ls$` would admit "ls\\n"; an allow pattern
    must pin the whole value."""
    out: list[str] = []
    i, n, in_class = 0, len(pattern), False
    while i < n:
        c = pattern[i]
        if c == "\\":
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            out.append(c)
            i += 1
            # `]` right after `[` or `[^` is a literal, not the class end
            if i < n and pattern[i] == "^":
                out.append("^")
                i += 1
            if i < n and pattern[i] == "]":
                out.append("]")
                i += 1
            continue
        elif c == "$":
            out.append(r"\Z")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _opts_into_dotdot(pattern: str) -> bool:
    """A pattern spells out `\\.\\.` itself (outside the traversal guard):
    the author means it, so the matcher's `..` veto is skipped."""
    for guard in (_TRAVERSAL_GUARD, _OLD_TRAVERSAL_GUARD):
        pattern = pattern.replace(guard, "")
    return r"\.\." in pattern


def _parse_path(path: str) -> tuple[str, ...]:
    """'args.*.path' -> ('args', '*', 'path'). '' and '**' mean any path."""
    if not isinstance(path, str):
        raise ValueError(f"arg_rules path must be a string, got {path!r}")
    path = path.strip()
    if path in ("", "**"):
        return ("**",)
    segs = tuple(s.strip() for s in path.split("."))
    if any(not s for s in segs):
        raise ValueError(f"arg_rules path {path!r} has an empty segment")
    return segs


def _path_matches(rule: tuple[str, ...], path: tuple[str, ...],
                  fold: bool = False) -> bool:
    """Glob match: '*' = exactly one segment, '**' = zero or more.
    `fold` compares key names case-insensitively (deny rules: `path`
    also catches `Path` and `PATH`)."""
    if not rule:
        return not path
    head, rest = rule[0], rule[1:]
    if head == "**":
        return any(_path_matches(rest, path[i:], fold)
                   for i in range(len(path) + 1))
    if not path:
        return False
    if head == "*" or head == path[0] or (
            fold and head.lower() == path[0].lower()):
        return _path_matches(rest, path[1:], fold)
    return False


def _is_typed_rule(pat) -> bool:
    return isinstance(pat, dict) and ("type" in pat or "pattern" in pat)


def _compile_rule(segs, pat, where: str, allow: bool) -> Rule:
    """One pattern spec -> Rule. A spec is a regex string, a compiled
    pattern, or a typed rule {"type": T, "pattern": P} (either key may
    be omitted: a type alone admits any value of that type, a pattern
    alone is matched by text whatever the type)."""
    vtype = None
    if isinstance(pat, dict):
        extra = set(pat) - {"type", "pattern"}
        if extra or not pat:
            raise ValueError(f"{where}: a typed rule has only 'type' and "
                             f"'pattern', got {sorted(pat)}")
        vtype = pat.get("type")
        if vtype is not None and vtype not in VALUE_TYPES:
            raise ValueError(f"{where}: type must be one of {VALUE_TYPES}, "
                             f"got {vtype!r}")
        pat = pat.get("pattern", "")
    if isinstance(pat, re.Pattern):
        flags, pat = pat.flags, pat.pattern
    elif isinstance(pat, str):
        flags = 0
    else:
        raise ValueError(f"{where}: a pattern is a regex string or a "
                         f"{{\"type\": ..., \"pattern\": ...}} rule, "
                         f"got {pat!r}")
    dotdot_ok = _opts_into_dotdot(pat)
    if allow:
        pat = _strict_end_anchors(pat)
    return Rule(segs, re.compile(pat, flags), vtype, dotdot_ok)


def _compile_rule_set(spec, where: str = "arg_rules",
                      allow: bool = False) -> list[Rule]:
    """Normalise one allow/deny spec into a list of Rule.

    Accepts the documented object form {"path": ["regex", ...]} and the
    shorthand list form ["regex", ...] (== {"**": [...]}: every value at
    any depth). Called exactly once per policy, by compile_policy().
    """
    if spec is None:
        return []
    if isinstance(spec, (list, tuple)):
        spec = {"**": list(spec)}
    if isinstance(spec, (str, re.Pattern)) or _is_typed_rule(spec):
        spec = {"**": [spec]}
    if not isinstance(spec, dict):
        raise ValueError(f"{where}: expected a list of patterns or an "
                         f"object of {{path: [patterns]}}, got {spec!r}")
    rules: list[Rule] = []
    for path, pats in spec.items():
        segs = _parse_path(path)
        if isinstance(pats, (str, re.Pattern)) or _is_typed_rule(pats):
            pats = [pats]
        if not isinstance(pats, (list, tuple)):
            raise ValueError(f"{where}.{path}: expected a list of patterns")
        for pat in pats:
            rules.append(_compile_rule(segs, pat, f"{where}.{path}", allow))
    return rules


# The keys a policy may carry. Anything else is refused at load: a mistyped
# `alow_tools` used to be skipped silently, and a policy that ignores its own
# allowlist allows every tool.
POLICY_KEYS = ("allow_tools", "deny_tools", "arg_rules", "policed_methods",
               "deny_methods", "strict_args", "audit_args", "hide_denied")
# Notes: written by --init-policy and by `learn`, never read.
NOTE_KEYS = ("_comment", "_not_called")
RULE_KEYS = ("allow", "deny")  # the keys of one arg_rules.<tool> entry
# compile_policy() marks the dict it has compiled with these; a policy
# file must not be able to carry them (a forged marker skips validation).
_INTERNAL_KEYS = ("_compiled", "_rules_by_norm")


def _check_keys(obj: dict, allowed, where: str) -> None:
    """Refuse a key that is not in `allowed`, with a did-you-mean."""
    for key in obj:
        if key in allowed:
            continue
        close = difflib.get_close_matches(str(key), allowed, n=1, cutoff=0.6)
        hint = f" (did you mean {close[0]!r}?)" if close else ""
        raise ValueError(f"{where + ': ' if where else ''}unknown key "
                         f"{key!r}{hint}; allowed keys: {', '.join(allowed)}")


def _method_list(pol: dict, key: str) -> list[str]:
    val = pol.get(key)
    if val is None:
        return []
    if not isinstance(val, (list, tuple)) or not all(
            isinstance(m, str) and m for m in val):
        raise ValueError(f"{key} must be a list of JSON-RPC method names")
    return list(val)


def method_denied(pol: dict, method: str) -> bool:
    """deny_methods: exact names or fnmatch globs (`resources/*`). A method
    is matched as written, and as a router that ignores case and invisible
    characters would read it (`RESOURCES/LIST`; "resource" + U+017F +
    "/list"), against the pattern as written and likewise normalised."""
    folded = normalize_tool_name(method)
    return any(fnmatch.fnmatchcase(method, pat)
               or fnmatch.fnmatchcase(folded, normalize_tool_name(pat))
               for pat in (pol.get("deny_methods") or []))


def method_policed(pol: dict, method: str) -> bool:
    """tools/call is always policed; policed_methods adds more (their
    params.name -- or params.uri -- is the tool name, params.arguments the
    arguments). Spelling does not matter: `Tools/Call` is policed as
    tools/call."""
    folded = normalize_tool_name(method)
    return folded == "tools/call" or any(
        folded == normalize_tool_name(m)
        for m in (pol.get("policed_methods") or []))


# What a policed method's params are judged by: the field that really
# selects what the call touches. allow_tools / deny_tools are compared with
# that field and with nothing else, and a second selector beside it is
# refused rather than preferred - a server need not make the jail's choice.
_SELECTORS = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
    "resources/subscribe": "uri",
    "resources/unsubscribe": "uri",
    "completion/complete": "ref",   # {"type": "ref/prompt", "name": ...} or
                                    # {"type": "ref/resource", "uri": ...}
}
_REF_KEYS = ("type", "name", "uri")


def _selected(method_key: str, params: dict) -> tuple:
    """What the policy is to judge for a policed method: (name, None), or
    (None, why) when `params` do not say unambiguously what the call is for.
    `method_key` is the normalised method. A method added through
    policed_methods that this table does not know takes exactly one of `name`
    and `uri`."""
    field = _SELECTORS.get(method_key)
    if field is None:
        present = [k for k in ("name", "uri") if k in params]
        if len(present) != 1:
            return None, (f"{method_key}: params must carry exactly one of "
                          f"'name' and 'uri', got "
                          f"{' and '.join(map(repr, present)) or 'neither'}")
        field = present[0]
    competing = [k for k in ("name", "uri") if k != field and k in params]
    if competing:
        return None, (f"{method_key} selects by '{field}', but params also "
                      f"carries '{competing[0]}'")
    if field == "ref":
        return _ref_selected(method_key, params.get("ref"))
    value = params.get(field)
    if not isinstance(value, str) or not value:
        return None, (f"{method_key} selects by '{field}': params.{field} "
                      f"must be a non-empty string")
    return value, None


def _ref_selected(method_key: str, ref) -> tuple:
    """The prompt name or resource uri that a completion/complete `ref`
    names. A ref that says it is a prompt may not also carry a uri, nor a
    resource ref a name: a server that picks by which field is present would
    pick the other one."""
    if not isinstance(ref, dict):
        return None, (f"{method_key} selects by 'ref': params.ref must be an "
                      f"object")
    clash = _key_clash(ref, _REF_KEYS)
    if clash is not None:
        return None, "params.ref: " + _clash_text(clash)
    kind = ref.get("type")
    if kind == "ref/prompt":
        field, other = "name", "uri"
    elif kind == "ref/resource":
        field, other = "uri", "name"
    else:
        return None, (f"params.ref.type must be ref/prompt or ref/resource, "
                      f"got {_clip(kind, 40)}")
    if other in ref:
        return None, (f"params.ref is a {kind} but also carries '{other}'")
    value = ref.get(field)
    if not isinstance(value, str) or not value:
        return None, (f"params.ref ({kind}) must carry a non-empty string "
                      f"'{field}'")
    return value, None


def compile_policy(pol: dict) -> dict:
    """Validate + compile every arg rule in place, once. Raises
    ValueError / re.error on a malformed policy so run() can fail closed
    at startup. A compiled policy is marked and never recompiled."""
    if not isinstance(pol, dict):
        raise ValueError("policy must be a JSON object")
    if pol.get("_compiled") and "_rules_by_norm" in pol:
        return pol
    _check_keys(pol, POLICY_KEYS + NOTE_KEYS, "")
    rules_by_tool = pol.get("arg_rules") or {}
    if not isinstance(rules_by_tool, dict):
        raise ValueError("arg_rules must be an object keyed by tool name")
    by_norm: dict[str, dict] = {}
    for tool, rules in rules_by_tool.items():
        if not isinstance(rules, dict):
            raise ValueError(f"arg_rules.{tool} must be an object with "
                             f"'allow' and/or 'deny'")
        _check_keys(rules, RULE_KEYS, f"arg_rules.{tool}")
        if "*" in normalize_tool_name(tool):
            raise ValueError(f"arg_rules: {tool!r} is not a tool name - '*' "
                             f"is not a wildcard in arg_rules keys, each key "
                             f"names one tool (write a rule for each)")
        allow = rules.get("allow")
        if allow == "*":
            pass  # explicit: any arguments (deny rules still apply)
        else:
            rules["allow"] = _compile_rule_set(allow,
                                               f"arg_rules.{tool}.allow",
                                               allow=True)
        rules["deny"] = _compile_rule_set(rules.get("deny"),
                                          f"arg_rules.{tool}.deny")
        norm = normalize_tool_name(tool)
        if norm in by_norm:
            raise ValueError(f"arg_rules: {tool!r} is the same tool name as "
                             f"another entry once normalised")
        by_norm[norm] = rules
    pol["_rules_by_norm"] = by_norm
    for key in ("allow_tools", "deny_tools"):
        val = pol.get(key)
        if isinstance(val, dict):
            # iterating one gives its keys alone: whatever is nested under a
            # name (a path pattern meant as an argument rule) would be dropped
            # and the tool allowed without it
            raise ValueError(f"{key} must be a list of tool names, not an "
                             f"object (only its keys would count and what is "
                             f"nested in it would be dropped; argument rules "
                             f"go under arg_rules.<tool>.allow / .deny)")
        if val is not None and not isinstance(val, (list, tuple)):
            raise ValueError(f"{key} must be a list of tool names")
        for entry in (val or ()):
            # a nested list or a number would be skipped by every match
            if not isinstance(entry, str) or not entry:
                raise ValueError(f"{key} must hold tool name strings, "
                                 f"got {entry!r}")
            if key == "deny_tools" and _star_inside(entry):
                raise ValueError(f"deny_tools: {entry!r} is not a pattern - "
                                 f"'*' means every tool only on its own, any "
                                 f"other entry is an exact name (list each "
                                 f"tool)")
    for key in ("policed_methods", "deny_methods"):
        methods = _method_list(pol, key)
        if key == "policed_methods":
            for m in methods:
                if "*" in normalize_tool_name(m):
                    raise ValueError(f"policed_methods: {m!r} is not a method "
                                     f"name - '*' is not a wildcard here, "
                                     f"list the methods (\"prompts/get\", "
                                     f"\"resources/read\")")
    mode = pol.get("audit_args", "denied")
    if mode not in AUDIT_ARGS_MODES:
        raise ValueError(f"audit_args must be one of {AUDIT_ARGS_MODES}, "
                         f"got {mode!r}")
    if not isinstance(pol.get("strict_args", False), bool):
        raise ValueError("strict_args must be true or false")
    if not isinstance(pol.get("hide_denied", True), bool):
        raise ValueError("hide_denied must be true or false")
    pol["_compiled"] = True
    return pol


def load_policy(path: str) -> dict:
    """Read and compile a policy file. Refused (ValueError, JSONDecodeError
    or re.error): invalid JSON, a duplicate key anywhere (the reader would
    keep only the last one: `deny_tools` twice is `deny_tools` once, and the
    wrong one), the internal markers, an unknown key, a bad rule."""
    with open(path, encoding="utf-8") as f:
        try:
            pol = json.load(f, object_pairs_hook=_no_duplicate_keys,
                            parse_constant=_no_constants)
        except _DuplicateKey as e:
            raise ValueError(f"{e} (a key may appear once)") from None
    if isinstance(pol, dict):
        for key in _INTERNAL_KEYS:
            if key in pol:
                raise ValueError(f"{key!r} is reserved for mcp-jail's own use")
    return compile_policy(pol)


def default_policy() -> dict:
    return {
        "_comment": "mcp-jail policy. Unknown keys are refused at startup. "
                    "allow_tools/deny_tools are tool names "
                    "('*' = all; deny wins; names are compared normalised: "
                    "NFKC, case-folded, trimmed, invisible characters "
                    "removed). arg_rules.<tool>.allow/deny map argument "
                    "paths ('path', 'args.*.path', '**') to regexes checked "
                    "against every value at that path, however deeply "
                    "nested; a rule may be {\"type\": \"number\", "
                    "\"pattern\": ...} to pin the JSON type; deny paths "
                    "match key names case-insensitively. strict_args: a "
                    "tool without allow patterns accepts only empty "
                    "arguments, {} (set its allow to \"*\" to accept any). "
                    "audit_args: log argument values for 'denied' "
                    "(default), 'all' or 'none' calls. hide_denied strips "
                    "tools denied by name from tools/list so agents don't "
                    "see them. Only tools/call (plus policed_methods, e.g. "
                    "prompts/get, resources/read) is checked; deny_methods "
                    "refuses whole JSON-RPC methods ('resources/*').",
        "allow_tools": ["*"],
        "deny_tools": [],
        "arg_rules": {},
        "policed_methods": ["tools/call"],
        "deny_methods": [],
        "strict_args": False,
        "audit_args": "denied",
        "hide_denied": True,
    }


def _leaf_text(v) -> str:
    if isinstance(v, str):
        return v
    return json.dumps(v)  # true/false/null/numbers/{}/[] as JSON text


def _type_tag(v) -> str:
    """JSON type name of a value (what a typed rule's "type" names)."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, dict):
        return "object"
    if isinstance(v, list):
        return "array"
    return "string"


def _nodes(value, max_depth: int = MAX_ARG_DEPTH):
    """Pre-order (path, node) for every node under `value`, iteratively
    (no recursion to exhaust). Raises ValueError past `max_depth`."""
    stack = [((), value)]
    while stack:
        path, node = stack.pop()
        if len(path) > max_depth:
            raise ValueError(f"arguments nested deeper than {max_depth} "
                             f"levels")
        yield path, node
        if isinstance(node, dict):
            items = [(path + (str(k),), v) for k, v in node.items()]
        elif isinstance(node, list):
            items = [(path + (str(i),), v) for i, v in enumerate(node)]
        else:
            continue
        stack.extend(reversed(items))


def _walk(value):
    """Yield (path, text, is_leaf, vtype) for every value under `value`:
    scalars, and empty objects/arrays (a value too -- text `{}` / `[]`,
    type object/array; the root is never one). Plus one joined-text
    entry (is_leaf False, vtype None) per array of scalars, so
    ["rm", "-rf", "/"] is also seen as "rm -rf /"."""
    for path, node in _nodes(value):
        if isinstance(node, dict):
            if not node and path:
                yield (path, "{}", True, "object")
            continue
        if isinstance(node, list):
            if not node:
                if path:
                    yield (path, "[]", True, "array")
            elif all(not isinstance(v, (dict, list)) for v in node):
                yield (path, " ".join(_leaf_text(v) for v in node), False, None)
            continue
        yield (path, _leaf_text(node), True, _type_tag(node))


def _fmt_path(path: tuple[str, ...]) -> str:
    return ".".join(path) if path else "(arguments)"


def _name_listed(name_norm: str, names) -> bool:
    return any(isinstance(t, str) and normalize_tool_name(t) == name_norm
               for t in names)


def _denied_by_name(name_norm: str, deny) -> bool:
    """Does deny_tools name this tool? An entry that is a lone `*` names
    every tool - entries are read the way tool names are, so a fullwidth
    asterisk, or one with a space or a zero-width character beside it, is
    that `*` too. (It used to name a tool called `*` and nothing else.)"""
    return any(isinstance(t, str) and normalize_tool_name(t) in ("*", name_norm)
               for t in deny)


def _star_inside(name: str) -> bool:
    """A `*` in the middle of a name (`delete_*`), as names are compared. A
    lone `*` is the wildcard and does not count; nothing else here is a
    pattern, so such an entry would name a tool that does not exist."""
    norm = normalize_tool_name(name)
    return "*" in norm and norm != "*"


def tool_visible(pol: dict, name) -> tuple[bool, str]:
    """Name-level decision: deny_tools / allow_tools only. This is what
    hide_denied uses for tools/list — argument rules are per-call and
    must not hide a tool that is callable with the right arguments.
    Names are compared normalised (see normalize_tool_name)."""
    if not isinstance(name, str) or not name:
        return False, "tool name must be a non-empty string"
    norm = normalize_tool_name(name)
    if not norm:
        return False, "tool name must be a non-empty string"
    deny = pol.get("deny_tools") or []
    allow = pol.get("allow_tools")
    if allow is None:
        allow = ["*"]
    if _denied_by_name(norm, deny):
        return False, f"tool '{name}' is denied by policy"
    if "*" not in allow and not _name_listed(norm, allow):
        return False, f"tool '{name}' is not in allow_tools"
    return True, ""


def _allow_admits(allow: list[Rule], path, text, vtype) -> tuple[bool, bool]:
    """Does some allow rule admit this leaf? A typed rule admits only its
    type. A value holding a `..` path segment is never admitted unless
    the pattern itself spells out `\\.\\.` (explicit opt-in): an
    allowlist on paths must not be a door to `/srv/data/../../etc/passwd`.
    Returns (admitted, traversal_veto)."""
    path_hit = False
    for rule in allow:
        if not _path_matches(rule.path, path):
            continue
        path_hit = True
        if rule.vtype is not None and rule.vtype != vtype:
            continue
        if not rule.pattern.search(text):
            continue
        if _TRAVERSAL.search(text) and not rule.dotdot_ok:
            continue  # vetoed
        return True, False
    return False, bool(path_hit and _TRAVERSAL.search(text))


def tool_allowed(pol: dict, name, args) -> tuple[bool, str]:
    """Full per-call decision: tool name, then argument rules. Any
    failure inside the evaluation denies (fail closed).

    Argument rules are matched over objects and arrays. A *value* is a
    scalar or an empty object/array (text `{}` / `[]`); a non-empty
    container is structure, and its values are matched one by one.

    - deny: a rule for path P is checked (re.search) against every value
      at P *and below it* — wrapping a value in an object or array never
      hides it. Key names in deny paths match case-insensitively. Arrays
      of scalars are also checked as one space-joined string.
    - allow: when a tool has allow rules, EVERY value in the arguments
      must match an allow rule whose path matches the value's path
      exactly ('*' = one segment, '**' = any segments). Unknown paths are
      denied — default-deny, which is what `learn` generates. A typed
      rule admits only values of its JSON type. A value containing a
      `..` path segment is never admitted unless the pattern mentions
      `\\.\\.`. `"allow": "*"` admits any arguments.
    - strict_args (policy-level): a tool with no allow rules accepts
      only empty arguments ({}), instead of anything.
    """
    try:
        return _tool_allowed(pol, name, args)
    except Exception as e:  # never fail open on a surprise
        return False, f"tool '{name}': arguments rejected ({e})"


def _tool_allowed(pol: dict, name, args) -> tuple[bool, str]:
    ok, reason = tool_visible(pol, name)
    if not ok:
        return False, reason
    if not pol.get("_compiled"):
        compile_policy(pol)  # once, in place
    rules = pol["_rules_by_norm"].get(normalize_tool_name(name)) or {}
    deny = rules.get("deny") or []
    allow = rules.get("allow")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return False, (f"tool '{name}': arguments must be a JSON object, "
                       f"got {type(args).__name__}")
    entries = list(_walk(args))
    for path, text, _leaf, vtype in entries:
        for rule in deny:
            if (_path_matches(rule.path + ("**",), path, fold=True)
                    and (rule.vtype is None or rule.vtype == vtype)
                    and rule.pattern.search(text)):
                return False, (f"tool '{name}': argument {_fmt_path(path)} "
                               f"matches deny pattern "
                               f"'{rule.pattern.pattern}'")
    if allow == "*":
        return True, ""
    if allow:
        for path, text, leaf, vtype in entries:
            if not leaf:
                continue
            admitted, vetoed = _allow_admits(allow, path, text, vtype)
            if admitted:
                continue
            if vetoed:
                return False, (f"tool '{name}': argument {_fmt_path(path)} "
                               f"contains a '..' path segment")
            return False, (f"tool '{name}': argument {_fmt_path(path)} "
                           f"matches no allow pattern")
    elif pol.get("strict_args"):
        for path, text, leaf, _vtype in entries:
            if leaf:
                return False, (f"tool '{name}': argument {_fmt_path(path)} "
                               f"is not allowed (strict_args: this tool has "
                               f"no allow patterns; set its allow to \"*\" "
                               f"to accept any arguments)")
    return True, ""


def filter_tools_list(pol: dict, result) -> None:
    """hide_denied: drop tools denied by name from one tools/list page,
    in place. Keeps nextCursor and every other field. Entries that are
    not {"name": str, ...} are dropped too (never fail open)."""
    if not isinstance(result, dict):
        return
    tools = result.get("tools")
    if not isinstance(tools, list):
        return
    result["tools"] = [t for t in tools
                       if isinstance(t, dict)
                       and _key_clash(t, ("name",)) is None
                       and tool_visible(pol, t.get("name"))[0]]


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def audit_args_view(value, depth: int = 0):
    """Copy of call arguments fit for the log: every string cut to
    AUDIT_VALUE_MAX chars, nesting cut at the depth the policy denies
    anyway. Secrets are still secrets - prefer audit_args 'denied'."""
    if depth > MAX_ARG_DEPTH:
        return "...(nested too deep)"
    if isinstance(value, str):
        if len(value) <= AUDIT_VALUE_MAX:
            return value
        return value[:AUDIT_VALUE_MAX] + f"...(+{len(value) - AUDIT_VALUE_MAX})"
    if isinstance(value, dict):
        return {str(k)[:AUDIT_VALUE_MAX]: audit_args_view(v, depth + 1)
                for k, v in value.items()}
    if isinstance(value, list):
        return [audit_args_view(v, depth + 1) for v in value]
    return value


def _open_private_append(path: str):
    """Append handle created 0600: the log can hold argument values.
    Best effort on Windows (mode bits beyond read-only do not exist
    there; the per-user profile directory is the protection)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_BINARY", 0)
    existed = os.path.exists(path)
    fd = os.open(path, flags, 0o600)
    if existed and os.name != "nt":
        try:  # a log created by an older mcp-jail was 0644: tighten it
            if stat.S_IMODE(os.stat(path).st_mode) & 0o077:
                os.chmod(path, 0o600)
        except OSError:
            pass
    return os.fdopen(fd, "a", encoding="utf-8")


def audit(event: dict) -> None:
    """Append one JSON line to the audit log. An unwritable log is
    reported on stderr but never takes the firewall down: the decision
    has already been enforced."""
    path = audit_log_path()
    event["at"] = int(time.time())
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with _open_private_append(path) as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        _say(f"mcp-jail: cannot write audit log {path}: {e}")


# ---------------------------------------------------------------------------
# transport: newline-delimited JSON over binary pipes, reader threads
# ---------------------------------------------------------------------------

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND = -32700, -32600, -32601
INVALID_PARAMS, INTERNAL_ERROR = -32602, -32603

_NO_ID = object()


def _int_or_none(text: str):
    """parse_int hook for the lookups of an id in a line _parse refused: an
    integer too long for Python to read (another reason to refuse the line)
    becomes None, which is no id, and does not hide the id beside it."""
    try:
        return int(text)
    except ValueError:
        return None


def _lenient_id(line: bytes):
    """The id of a server document that _parse refused only for its
    duplicate keys (or a number it cannot carry), so the request it answers
    can be failed closed by id rather than by guesswork. _NO_ID when there
    is none."""
    try:
        obj = json.loads(line.decode("utf-8"), parse_int=_int_or_none)
    except (ValueError, RecursionError):
        return _NO_ID
    if isinstance(obj, dict) and "id" in obj:
        return obj["id"]
    return _NO_ID


def _preview(line: bytes, limit: int = 200) -> str:
    text = line.decode("utf-8", "replace").strip()
    return repr(text[:limit] + ("..." if len(text) > limit else ""))


def _clip(value, limit: int = AUDIT_VALUE_MAX) -> str:
    """A message (the wire line, or the parsed object) cut down for the
    audit record."""
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace").strip()
    else:
        try:
            text = json.dumps(value)
        except (ValueError, RecursionError):
            text = f"<{type(value).__name__}>"
    if len(text) <= limit:
        return text
    return text[:limit] + f"...(+{len(text) - limit})"


def _salvage_id(line: bytes):
    """The id of a client line that was refused, when there is one to
    trust: it parses, has exactly one "id" key and that holds a string or
    an integer. Otherwise _NO_ID (the refusal then carries a null id)."""
    try:
        obj = json.loads(line.decode("utf-8"),
                         object_pairs_hook=_no_duplicate_keys,
                         parse_int=_int_or_none)
    except (ValueError, RecursionError):
        return _NO_ID
    rid = obj.get("id") if isinstance(obj, dict) else None
    if isinstance(rid, bool) or not isinstance(rid, (str, int)):
        return _NO_ID
    return rid


def _rpc_error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": message}}


def _id_key(req_id) -> str:
    """Exact-type identity for a JSON-RPC id: 1, "1" and 1.0 differ."""
    return json.dumps(req_id, sort_keys=True)


def _encode(obj) -> bytes:
    """The one wire form of every message the jail writes, to either side:
    compact JSON, pure ASCII (every non-ASCII character an escape, so no
    raw U+2028 or NEL for a line-splitting reader to trip over), finite
    numbers only, one trailing newline. It is built from the object the jail
    parsed and checked - never from the peer's bytes - so the jail and
    whatever reads the line cannot disagree about what it says."""
    return (json.dumps(obj, ensure_ascii=True, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("ascii")


class _FdLineReader:
    """readline() over raw os.read() on a file descriptor.

    The client's stdin is read this way so the reader thread never holds
    the BufferedReader lock of sys.stdin: a daemon thread blocked inside
    sys.stdin.buffer.readline() at interpreter shutdown is a fatal
    `_enter_buffered_busy` abort (exit -6) whenever the server exits
    while the client still holds our stdin open.
    """

    def __init__(self, fd: int):
        self._fd = fd
        self._buf = bytearray()
        self._eof = False

    def readline(self) -> bytes:
        while True:
            i = self._buf.find(b"\n")
            if i >= 0:
                line = bytes(self._buf[:i + 1])
                del self._buf[:i + 1]
                return line
            if self._eof:
                line = bytes(self._buf)
                self._buf.clear()
                return line
            chunk = os.read(self._fd, 65536)
            if not chunk:
                self._eof = True
            else:
                self._buf += chunk


def _binary_in(stream):
    """Bytes line reader for the client side: raw fd reads for a real
    file (see _FdLineReader), else the binary stream itself (BytesIO in
    tests)."""
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
        fd = None
    if fd is not None:
        return _FdLineReader(fd)
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        return buf
    if isinstance(stream, (io.RawIOBase, io.BufferedIOBase)):
        return stream
    raise TypeError("mcp-jail needs a binary stream for stdin")


class _Writer:
    """Single-owner writer of protocol bytes to a binary stream (the
    .buffer of a text stream, or a BytesIO/pipe directly)."""

    def __init__(self, stream):
        self._binary = getattr(stream, "buffer", None)
        if self._binary is None:
            if not isinstance(stream, (io.RawIOBase, io.BufferedIOBase)):
                raise TypeError("mcp-jail needs a binary stream for stdout")
            self._binary = stream

    def write(self, data: bytes) -> None:
        self._binary.write(data)
        self._binary.flush()

    def send(self, obj) -> None:
        self.write(_encode(obj))


class _ServerInput:
    """Everything the jail sends to the server goes through here: queued by
    the proxy, written by a thread of its own.

    A write to a pipe blocks while the pipe is full, and a server that has
    stopped reading (hung, deadlocked, busy for good) leaves it full. Done on
    the thread that also answers the client, that write froze the whole proxy
    and kept --timeout from ever firing. So the proxy only queues, and asks
    stalled(): has the oldest message waited longer than --timeout to be
    taken?

    The thread writes with os.write() to a duplicate of the descriptor. No
    buffered stream is involved, so there is no lock for another thread to
    wedge on and nothing for interpreter shutdown to wait for. The thread
    closes that descriptor itself, and nothing else does: a descriptor closed
    under a blocked write can be handed to the next open() and written to by
    mistake. A write that is stuck can only be ended from the other side, so
    a stalled server is killed (see _Proxy.serve); if the thread is still
    stuck after that (a grandchild holds the pipe open) it is a daemon and
    dies with the process.

    `notify` is called from the thread: with None after each message that
    went out, with the exception when writing failed (the server's stdin is
    gone). `timeout` None means a message may wait for ever.
    """

    def __init__(self, stream, timeout: "float | None", notify):
        self._timeout = timeout
        self._notify = notify
        self._cv = threading.Condition()
        self._items: "collections.deque" = collections.deque()  # (bytes, when queued)
        self._closing = False   # no more messages: finish these, then stop
        self._aborted = False   # stop now
        self._ended = False     # the thread has finished
        self._stream = None
        self._fd = None
        try:
            fd = stream.fileno()
        except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
            self._stream = stream   # not a descriptor (tests): write + flush
        else:
            self._fd = os.dup(fd)
            if _WINDOWS:
                # a C runtime descriptor may be in text mode, which would turn
                # every "\n" into "\r\n": the wire is bytes
                try:
                    import msvcrt
                    msvcrt.setmode(self._fd, getattr(os, "O_BINARY", 0))
                except BaseException:
                    os.close(self._fd)
                    raise
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="mcp-jail-server-writer")

    def start(self) -> None:
        self._thread.start()

    def put(self, data: bytes) -> bool:
        """Queue one message. False when the server can no longer be written
        to (its stdin broke, or the input was closed or aborted)."""
        with self._cv:
            if self._ended or self._closing or self._aborted:
                return False
            self._items.append((data, time.monotonic()))
            self._cv.notify()
        return True

    def busy(self) -> bool:
        """Is some queued message not yet fully written?"""
        with self._cv:
            return bool(self._items)

    def stall_deadline(self) -> "float | None":
        """When the oldest message not yet taken has waited --timeout."""
        with self._cv:
            if self._timeout and self._items:
                return self._items[0][1] + self._timeout
        return None

    def stalled(self, now: float) -> bool:
        deadline = self.stall_deadline()
        return deadline is not None and deadline <= now

    def close(self) -> None:
        """No more messages: write what is queued, then close the pipe."""
        with self._cv:
            self._closing = True
            self._cv.notify_all()

    def abort(self) -> None:
        """Stop at the next chance. A write already blocked in the pipe only
        ends when the server's end goes away."""
        with self._cv:
            self._aborted = True
            self._cv.notify_all()

    def alive(self) -> bool:
        return self._thread.is_alive()

    def join(self, timeout: float) -> None:
        if self._thread.ident is not None:
            self._thread.join(timeout)

    def _write_all(self, data: bytes) -> None:
        if self._fd is None:
            self._stream.write(data)
            self._stream.flush()
            return
        view = memoryview(data)
        while len(view):
            if self._aborted:
                raise BrokenPipeError("input aborted")
            written = os.write(self._fd, view)
            if written <= 0:
                raise BrokenPipeError("short write to the server")
            view = view[written:]

    def _run(self) -> None:
        failure = None
        try:
            while True:
                with self._cv:
                    while (not self._items and not self._closing
                           and not self._aborted):
                        self._cv.wait()
                    if self._aborted or not self._items:
                        break           # told to stop, or closed and drained
                    data = self._items[0][0]
                self._write_all(data)
                with self._cv:
                    self._items.popleft()
                self._notify(None)
        except Exception as e:
            failure = e
        finally:
            with self._cv:
                self._ended = True
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
        if failure is not None and not self._aborted:
            self._notify(failure)


class _Reader(threading.Thread):
    """Pump lines from a binary stream into a queue as (tag, line);
    (tag, None) marks EOF or a broken pipe."""

    def __init__(self, stream, tag: str, q: "queue.Queue"):
        super().__init__(name=f"mcp-jail-{tag}-reader", daemon=True)
        self._stream, self._tag, self._q = stream, tag, q

    def run(self) -> None:
        try:
            while True:
                line = self._stream.readline()
                if not line:
                    break
                # Frames are newline-delimited; a Windows text-mode peer
                # ends them with CRLF. Normalise the terminator only --
                # the JSON bytes themselves are never touched.
                self._q.put((self._tag, line.rstrip(b"\r\n") + b"\n"))
        except (OSError, ValueError):
            pass
        finally:
            self._q.put((self._tag, None))


class ServerNotFound(Exception):
    """The server command cannot be run. str() is the command. With no `why`
    the lookup found nothing to run: it is not on PATH, or it is a directory,
    or a file without the execute permission (shutil.which says None to all
    three). With one, it is what the system answered when it was started."""

    def __init__(self, command: str, why: "str | None" = None):
        super().__init__(command)
        self.why = why


def _server_problem(e: ServerNotFound) -> str:
    if e.why:
        return f"cannot start the server command {e}: {e.why}"
    return f"server command not found or not executable: {e}"


def _spawn(server_cmd: list[str]):
    # Resolve the executable ourselves: a clean error instead of a
    # FileNotFoundError traceback, and on Windows `npx` is `npx.cmd`,
    # which only PATHEXT-aware lookup (shutil.which) finds.
    exe = shutil.which(server_cmd[0]) if server_cmd else None
    if exe is None:
        raise ServerNotFound(server_cmd[0] if server_cmd else "")
    # sys.stderr may be a redirected StringIO (no fileno) in tests;
    # fall back to inherited stderr then.
    err = sys.stderr
    try:
        err.fileno()
    except (io.UnsupportedOperation, AttributeError, OSError, ValueError):
        err = None
    try:
        proc = subprocess.Popen(
            [exe] + list(server_cmd[1:]), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=err)
    except OSError as e:    # no #! line (Exec format error), permission, ...
        raise ServerNotFound(server_cmd[0], e.strerror or str(e)) from None
    assert proc.stdin and proc.stdout
    return proc


def _kill(proc) -> None:
    """End the server now, without asking: a server that has stopped reading
    is not going to act on a polite request, and only its death ends a write
    that is blocked on its pipe."""
    try:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _stop(proc) -> None:
    """Stop the server and reap it (no zombies, no ResourceWarning).

    Portable: terminate()/kill() only - no killpg, no SIGKILL. Our end of
    its stdin is closed first; a session that ended well has given the server
    its --grace to leave on its own before it gets here (_Proxy._wind_down),
    so a server still running now is sent SIGTERM and, if that is ignored for
    _TERM_WAIT seconds, killed. Its stdout is closed last, after the process
    is gone, so a reader thread still blocked in readline() sees EOF instead
    of a close() that waits on the buffer lock.
    """
    try:
        if proc.stdin:
            proc.stdin.close()
    except OSError:
        pass
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=_TERM_WAIT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    except OSError:
        pass
    try:
        if proc.stdout:
            proc.stdout.close()
    except OSError:
        pass


class _DuplicateKey(ValueError):
    pass


def _no_duplicate_keys(pairs):
    """object_pairs_hook: the policy is evaluated on the parsed object,
    so a document whose meaning depends on which duplicate the reader
    keeps ({"name":"delete_all","name":"read_file"}) is refused."""
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise _DuplicateKey(f"duplicate key {k!r}")
        obj[k] = v
    return obj


def _no_constants(name):
    raise ValueError(f"{name} is not valid JSON")


# A message is ONE compact line. JSON allows a control character outside a
# string only as whitespace, and a bare CR (or TAB, VT, FF...) there is how
# a line smuggles a second message past a reader that ends lines on CR
# (Java's BufferedReader.readLine, Python's universal newlines).
_CONTROL = re.compile(r"[\x00-\x1f]")


class _Unrepresentable(ValueError):
    pass


def _finite_float(text: str) -> float:
    """parse_float hook: 1e999 would become inf, which JSON cannot carry
    and the jail could neither check nor forward faithfully."""
    value = float(text)
    if not math.isfinite(value):
        raise _Unrepresentable(f"number out of range: {text[:30]}")
    return value


# Python 3.10.7 and later refuse to turn more than 4300 digits into an int (a
# ValueError, which _parse took for bad JSON); older ones read any length, at a
# cost that grows with its square. The jail's limit is the same on every
# version, and a longer integer is a number it cannot carry, like 1e999.
_MAX_INT_DIGITS = 4300


def _bounded_int(text: str) -> int:
    """parse_int hook: see _MAX_INT_DIGITS."""
    digits = len(text) - (text[:1] == "-")
    if digits > _MAX_INT_DIGITS:
        raise _Unrepresentable(
            f"integer of more than {_MAX_INT_DIGITS} digits")
    try:
        return int(text)
    except ValueError:      # a lower limit has been set for this Python
        raise _Unrepresentable(
            f"integer of {digits} digits (more than this Python reads)"
        ) from None


def _parse(line: bytes):
    """Decode one wire line. Returns (obj, None, "") on success,
    (None, None, "") for a blank line, else (None, rpc_code, text)."""
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as e:
        return None, PARSE_ERROR, f"invalid UTF-8: {e.reason}"
    # the reader ended the line with exactly one "\n"; the rest is the message
    body = text[:-1] if text.endswith("\n") else text
    if not body.strip(" "):
        return None, None, ""  # blank line: protocol noise
    try:
        obj = json.loads(body, object_pairs_hook=_no_duplicate_keys,
                         parse_constant=_no_constants,
                         parse_float=_finite_float, parse_int=_bounded_int)
    except (_DuplicateKey, _Unrepresentable) as e:
        # well-formed JSON that the jail will not carry: its id is known
        return None, INVALID_REQUEST, str(e)
    except RecursionError:
        return None, PARSE_ERROR, "invalid JSON: nesting too deep"
    except ValueError as e:
        return None, PARSE_ERROR, f"invalid JSON: {e}"
    bad = _CONTROL.search(body)
    if bad:
        return None, INVALID_REQUEST, (
            f"raw control character U+{ord(bad.group()):04X} in the message "
            f"line (a message is one compact JSON line)")
    return obj, None, ""


def _stop_signals() -> list:
    """The signals that mean "stop now, tidily": SIGTERM wherever it can be
    sent, SIGHUP when the terminal goes away (POSIX), SIGBREAK, Ctrl-Break,
    on Windows - which has no other. Ctrl-C (SIGINT) stays Python's
    KeyboardInterrupt: it stops the server at once."""
    return [getattr(signal, name) for name in ("SIGTERM", "SIGHUP", "SIGBREAK")
            if hasattr(signal, name)]


def _signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except ValueError:
        return f"signal {signum}"


class _StopSignals:
    """While active, the signals of _stop_signals() do not kill the jail: the
    first is put on the proxy's queue, where the loop ends the session the
    way the client leaving does (_Proxy.serve); the second is no longer
    waited for: the server is killed and the jail ends at once. The handler
    does nothing else, since it runs between two statements of the loop: the
    queue is a SimpleQueue because its put() may be called from there. Only
    the main thread can take a signal, so on any other this does nothing; a
    signal that was being ignored (nohup) still is."""

    def __init__(self):
        self.signum = None
        self._q = None
        self._proc = None
        self._saved: dict = {}

    def __enter__(self):
        if threading.current_thread() is threading.main_thread():
            for sig in _stop_signals():
                try:
                    if signal.getsignal(sig) == signal.SIG_IGN:
                        continue
                    self._saved[sig] = signal.signal(sig, self._on_signal)
                except (OSError, ValueError):
                    pass
        return self

    def __exit__(self, *exc) -> None:
        for sig, old in self._saved.items():
            try:
                signal.signal(sig, signal.SIG_DFL if old is None else old)
            except (OSError, ValueError):
                pass
        self._saved.clear()

    def attach(self, q, proc) -> None:
        """The proxy's queue and the server, once there are any; a signal
        that came before is told now."""
        self._q, self._proc = q, proc
        if self.signum is not None:
            q.put(("signal", self.signum))

    def _on_signal(self, signum, frame) -> None:
        if self.signum is not None:
            self._hard_exit(signum)
            return
        self.signum = signum
        if self._q is not None:
            self._q.put(("signal", signum))

    def _hard_exit(self, signum: int) -> None:
        if self._proc is not None:
            try:
                self._proc.kill()
            except OSError:
                pass
        os._exit(128 + signum)


class _Pending:
    """Requests forwarded to the server that still owe a response, keyed
    by exact-type id. Duplicate ids queue up FIFO.

    The loop asks how many are owed and when the next falls due on every
    message, so neither is worked out by walking them all (with thousands in
    flight that was quadratic): a count is kept, and the deadlines sit in a
    heap. A request answered before its deadline is not searched for in the
    heap - it is flagged, and its entry is dropped when it comes to the top,
    or sooner, when the dead entries outnumber the live ones."""

    def __init__(self):
        self._by_key: dict[str, collections.deque] = {}
        self._count = 0
        self._heap: list = []           # (deadline, serial, key, entry)
        self._serial = itertools.count()

    def add(self, req_id, method: str, deadline: float | None,
            call=None) -> None:
        key = _id_key(req_id)
        entry = {"id": req_id, "method": method, "deadline": deadline,
                 "call": call, "gone": False}
        self._by_key.setdefault(key, collections.deque()).append(entry)
        self._count += 1
        if deadline is not None:
            heapq.heappush(self._heap,
                           (deadline, next(self._serial), key, entry))

    def peek(self, req_id) -> dict | None:
        """The entry pop() would return, left where it is."""
        dq = self._by_key.get(_id_key(req_id))
        return dq[0] if dq else None

    def pop(self, req_id) -> dict | None:
        key = _id_key(req_id)
        dq = self._by_key.get(key)
        if not dq:
            return None
        entry = dq[0]
        self._remove(key, entry)
        return entry

    def _remove(self, key: str, entry: dict) -> None:
        """Take one entry out (it is answered, or timed out, or expired)."""
        dq = self._by_key[key]
        if dq[0] is entry:
            dq.popleft()
        else:                           # not the oldest of its id: rare
            for i, e in enumerate(dq):
                if e is entry:
                    del dq[i]
                    break
        if not dq:
            del self._by_key[key]
        entry["gone"] = True
        self._count -= 1
        if len(self._heap) > 2 * self._count + 64:
            self._heap = [h for h in self._heap if not h[3]["gone"]]
            heapq.heapify(self._heap)

    def __len__(self) -> int:
        return self._count

    def _soonest(self):
        """The heap's first live item, dead ones dropped on the way."""
        heap = self._heap
        while heap and heap[0][3]["gone"]:
            heapq.heappop(heap)
        return heap[0] if heap else None

    def expired(self, now: float) -> list[dict]:
        """Take out, and return in the order they fell due, the requests
        whose deadline has passed."""
        out = []
        while True:
            item = self._soonest()
            if item is None or item[0] > now:
                return out
            heapq.heappop(self._heap)
            self._remove(item[2], item[3])
            out.append(item[3])

    def drain(self) -> list[dict]:
        out = [e for dq in self._by_key.values() for e in dq]
        for e in out:
            e["gone"] = True
        self._by_key.clear()
        self._heap = []
        self._count = 0
        return out

    def next_deadline(self) -> float | None:
        item = self._soonest()
        return item[0] if item is not None else None


class _Cancelled:
    """The ids of requests the client has cancelled, each kept until the one
    reply a server may still send for it: MCP lets the receiver of a
    cancellation answer anyway, and the answer is to be ignored. Bounded, the
    oldest forgotten first, so a server that never answers a cancelled
    request cannot make it grow."""

    def __init__(self, limit: int = 1024):
        self._limit = limit
        self._keys: "collections.OrderedDict[str, None]" = (
            collections.OrderedDict())

    def add(self, key: str) -> None:
        self._keys.pop(key, None)
        self._keys[key] = None
        while len(self._keys) > self._limit:
            self._keys.popitem(last=False)

    def discard(self, key: str) -> None:
        self._keys.pop(key, None)

    def __contains__(self, key) -> bool:
        return key in self._keys

    def __len__(self) -> int:
        return len(self._keys)


def _call_succeeded(msg: dict) -> bool:
    """A tools/call response that means the server accepted and ran the
    call: a result that is not an MCP tool error (isError)."""
    if "result" not in msg:
        return False
    result = msg["result"]
    return not (isinstance(result, dict) and result.get("isError"))


class _Proxy:
    """The proxy loop. One consumer thread (this one) reads both pumps
    from a single queue and is the only writer to either side."""

    def __init__(self, proc, client_in, client_out, timeout: float | None,
                 pol: dict | None, observer=None, grace: float = DEFAULT_GRACE,
                 stop: "_StopSignals | None" = None):
        self.proc = proc
        self.grace = grace
        self.q: "queue.SimpleQueue" = queue.SimpleQueue()
        self.client = _Writer(client_out)
        self.timeout = timeout if timeout and timeout > 0 else None
        self.server = _ServerInput(proc.stdin, self.timeout,
                                   lambda payload: self.q.put(("input", payload)))
        self.pol = pol
        self.observer = observer
        self.pending = _Pending()
        self._cancelled = _Cancelled()
        self._client_in = _binary_in(client_in)
        # why the server is lost (it exited, closed its input, stopped
        # reading it), and how many requests it left unanswered past --timeout
        self.lost: "str | None" = None
        self.timed_out = 0
        # the signal that told the jail to stop, once one has
        self.signalled: "int | None" = None
        if stop is not None:
            stop.attach(self.q, proc)

    # -- helpers ----------------------------------------------------------

    def _log(self, msg: str) -> None:
        _say(f"mcp-jail: {msg}")

    def _deadline(self) -> float | None:
        return (time.monotonic() + self.timeout) if self.timeout else None

    def _forward(self, msg: dict, req_id=None, has_id: bool = False) -> bool:
        """Send `msg` to the server in its canonical encoding (see _encode).
        False, after telling the client, when it cannot be encoded."""
        try:
            data = _encode(msg)
        except (RecursionError, ValueError):
            if has_id:
                self.client.send(_rpc_error(req_id, INVALID_REQUEST,
                                            "Invalid Request: nesting too "
                                            "deep"))
            self._audit_rejected("client", "nesting too deep", msg)
            return False
        if not self.server.put(data):
            # its stdin is gone (the writer has ended): nothing more can be
            # sent, so everything still owed is answered now
            if has_id:
                self.client.send(_rpc_error(req_id, INTERNAL_ERROR,
                                            "server closed"))
            self._lose("closed its input", "server closed")
            return False
        return True

    def _audit(self, name, args, ok: bool, reason: str,
               method: str = "tools/call") -> None:
        event = {"decision": "allow" if ok else "deny", "reason": reason}
        if name is not None:  # None: nothing in params said what it was for
            event["tool"] = name if isinstance(name, str) else repr(name)
        if method != "tools/call" or name is None:
            event["method"] = method
        mode = self.pol.get("audit_args", "denied")
        if mode == "all" or (mode == "denied" and not ok):
            event["args"] = audit_args_view(args)
        audit(event)

    # -- client -> server ---------------------------------------------------

    def _audit_rejected(self, side: str, why: str, subject=None,
                        method=None) -> None:
        """The record of a message the jail would not relay, from `side`
        ("client" or "server"): whatever it was, it is on the record."""
        event = {"decision": "deny", "rejected": side, "reason": why}
        if isinstance(method, str):
            event["method"] = method
        mode = (self.pol or {}).get("audit_args", "denied")
        if subject is not None and mode != "none":
            event["message"] = _clip(subject)
        audit(event)

    def _refuse(self, why: str, code: int = INVALID_REQUEST, req_id=None,
                reply: bool = True, subject=None, method=None) -> None:
        """Turn one client message away: an error under its id (null when
        there is none to trust) unless it was a notification, and an audit
        record either way. `subject` is the wire line (bytes), from which
        an id is recovered when it has one, or the parsed object."""
        if reply:
            if req_id is None and isinstance(subject, bytes):
                salvaged = _salvage_id(subject)
                req_id = None if salvaged is _NO_ID else salvaged
            prefix = "Parse error" if code == PARSE_ERROR else "Invalid Request"
            self.client.send(_rpc_error(req_id, code, f"{prefix}: {why}"))
        self._audit_rejected("client", why, subject, method)

    def _on_client_line(self, line: bytes) -> None:
        msg, code, err = _parse(line)
        if code is not None:
            self._refuse(err, code, subject=line)
            return
        if msg is None:
            return  # blank line
        if isinstance(msg, list):
            # JSON-RPC batch: split it. Each element is handled on its
            # own; the server answers forwarded elements individually.
            if not msg:
                self._refuse("empty batch", subject=line)
                return
            for item in msg:
                self._on_client_message(item)
            return
        self._on_client_message(msg)

    def _on_client_message(self, msg) -> None:
        if not isinstance(msg, dict):
            self._refuse("not an object", subject=msg)
            return
        bad = _key_clash(msg, _ENVELOPE_KEYS)
        if bad is not None:
            self._refuse(_clash_text(bad), req_id=msg.get("id"), subject=msg)
            return
        if "method" not in msg:
            # The client's answer to a request the server made of it
            # (sampling, roots, elicitation): relayed when it is one, an
            # id and exactly one of result / error.
            if "id" not in msg or ("result" in msg) == ("error" in msg):
                self._refuse("a response needs an id and exactly one of "
                             "result and error", req_id=msg.get("id"),
                             subject=msg)
                return
            self._forward(msg, msg["id"], True)
            return
        method = msg.get("method")
        has_id = "id" in msg
        req_id = msg.get("id")
        if "result" in msg or "error" in msg:
            self._refuse("a message with a method must not carry a result "
                         "or an error", req_id=req_id, reply=has_id,
                         subject=msg)
            return
        if has_id and req_id is None:
            # MCP: "the request ID MUST NOT be null". Answer, don't drop.
            self._refuse("id must not be null", subject=msg)
            return
        if not isinstance(method, str):
            self._refuse("method must be a string", req_id=req_id,
                         reply=has_id, subject=msg)
            return
        call = None
        # the method as a parser that ignores case would route it: what the
        # rest of the proxy goes by (tools/list responses, learn's observer)
        mkey = normalize_tool_name(method)
        if self.pol is not None and method_denied(self.pol, method):
            reason = f"method '{method}' is denied by policy"
            audit({"method": method, "decision": "deny", "reason": reason})
            if has_id:
                self.client.send(_rpc_error(req_id, METHOD_NOT_FOUND,
                                            f"mcp-jail denied: {reason}"))
            return
        if (mkey == "tools/call" if self.pol is None
                else method_policed(self.pol, method)):
            params = msg.get("params")
            params = params if isinstance(params, dict) else {}
            targs = params.get("arguments")
            if targs is None:
                targs = {}
            clash = _key_clash(params, _PARAM_KEYS)
            if clash is not None:
                name, why = None, "params: " + _clash_text(clash)
            else:
                name, why = _selected(mkey, params)
            if why is not None:
                ok, reason = False, why
            elif self.pol is None:
                ok, reason = True, ""
            else:
                ok, reason = tool_allowed(self.pol, name, targs)
            if self.pol is not None:
                self._audit(name, targs, ok, reason, method)
            if not ok:
                # Same id, same type, as the request. A notification
                # (no id) never gets a response — it is just dropped.
                if has_id:
                    self.client.send(_rpc_error(req_id, INVALID_PARAMS,
                                                f"mcp-jail denied: {reason}"))
                return
            if self.observer is not None and has_id and mkey == "tools/call":
                call = (name, targs)  # recorded once the server succeeds
        if (mkey == "notifications/cancelled" and not has_id
                and self._cancels_initialize(msg)):
            # MCP: a client must not cancel initialize. Not passed on, so the
            # handshake completes as it would have.
            self._refuse("initialize cannot be cancelled", reply=False,
                         subject=msg, method=method)
            return
        if not self._forward(msg, req_id, has_id):
            return
        if has_id:
            self.pending.add(req_id, mkey, self._deadline(), call=call)
            self._cancelled.discard(_id_key(req_id))    # the id is in use again
        elif mkey == "notifications/cancelled":
            self._stop_waiting_for(msg)

    @staticmethod
    def _cancelled_id(msg: dict):
        """The request id a notifications/cancelled names, or _NO_ID when it
        names none the jail could be waiting for (no params, no requestId, or
        one that is not a string or a number)."""
        params = msg.get("params")
        rid = params.get("requestId") if isinstance(params, dict) else None
        if isinstance(rid, bool) or not isinstance(rid, (str, int, float)):
            return _NO_ID
        return rid

    def _cancels_initialize(self, msg: dict) -> bool:
        rid = self._cancelled_id(msg)
        entry = None if rid is _NO_ID else self.pending.peek(rid)
        return entry is not None and entry["method"] == "initialize"

    def _stop_waiting_for(self, msg: dict) -> None:
        """The cancel has gone to the server. The receiver need not answer a
        cancelled request (the TypeScript and Python SDK servers do not), so
        the jail stops timing it: it is no longer owed, and a reply that comes
        anyway is dropped (see _on_server_message). A cancel that names no
        request pending here - unknown, already answered, odd - is just passed
        on."""
        rid = self._cancelled_id(msg)
        if rid is not _NO_ID and self.pending.pop(rid) is not None:
            self._cancelled.add(_id_key(rid))

    # -- server -> client ---------------------------------------------------

    def _refuse_server(self, why: str, rid=_NO_ID, subject=None) -> None:
        """A message from the server the jail will not relay. When it
        answers a request we know of (`rid`), that request fails closed;
        either way it is logged and on the audit record."""
        entry = self.pending.pop(rid) if rid is not _NO_ID else None
        if entry is not None:
            self.client.send(_rpc_error(entry["id"], INTERNAL_ERROR,
                                        f"bad response from server: {why}"))
        else:
            self._log(f"dropping a message from the server: {why}")
        self._audit_rejected("server", why, subject)

    def _on_server_line(self, line: bytes) -> None:
        msg, code, err = _parse(line)
        if code is not None:
            if code == INVALID_REQUEST:
                # JSON the jail will not relay (duplicate keys, a raw
                # control character): a request it answers fails closed by
                # its id instead of waiting for --timeout.
                self._refuse_server(err, _lenient_id(line), line)
            else:
                # Not a JSON-RPC frame. npm servers console.log() banners
                # and progress onto stdout; such a line answers nothing, so
                # it is logged and skipped -- never charged to a pending
                # request, whose real answer would then be dropped. A
                # request the server never answers is still caught by
                # --timeout.
                self._log(f"ignoring non-JSON line from server: "
                          f"{_preview(line)}")
            return
        if msg is None:
            return
        if isinstance(msg, list):
            # A batch response: deliver it once, as one array, keeping
            # the elements that survive (filtered tools/list pages and
            # all).
            kept = [m for m in msg if self._on_server_message(m)]
            if kept:
                self._deliver(kept)
            return
        if self._on_server_message(msg):
            self._deliver(msg)

    def _deliver(self, obj) -> None:
        """Write one server message (or batch) to the client, re-encoded."""
        try:
            data = _encode(obj)
        except (RecursionError, ValueError):
            rid = obj.get("id") if isinstance(obj, dict) else None
            self.client.send(_rpc_error(rid, INTERNAL_ERROR,
                                        "bad response from server"))
            return
        self.client.write(data)

    def _on_server_message(self, msg) -> bool:
        """Decide one server message: False = drop, True = deliver the
        object (modified in place when a tools/list page was filtered)."""
        if not isinstance(msg, dict):
            return False
        bad = _key_clash(msg, _ENVELOPE_KEYS)
        if bad is not None:
            self._refuse_server(_clash_text(bad), msg.get("id", _NO_ID), msg)
            return False
        if "method" in msg:
            if "result" in msg or "error" in msg:
                self._refuse_server("a message with a method also carries a "
                                    "result or an error", msg.get("id", _NO_ID),
                                    msg)
                return False
            # Server-originated request or notification: pass through.
            return True
        if "id" not in msg:
            self._log("ignoring server message with neither method nor id")
            return False
        if ("result" in msg) == ("error" in msg):
            self._refuse_server("a response needs exactly one of result and "
                                "error", msg["id"], msg)
            return False
        entry = self.pending.pop(msg.get("id"))
        if entry is None:
            key = _id_key(msg.get("id"))
            if key in self._cancelled:
                # the reply a cancelled request was allowed to get: the client
                # was to ignore it, so it is not passed on and not remarked on
                self._cancelled.discard(key)
                return False
            # Late (already timed out) or unsolicited: the client already
            # has its answer for this id, a second one would confuse it.
            self._log(f"dropping response with unknown id {msg.get('id')!r}")
            return False
        if entry["method"] == "tools/call" and entry.get("call") is not None:
            if self.observer is not None and _call_succeeded(msg):
                self.observer.on_call(*entry["call"])
        if entry["method"] == "tools/list" and "result" in msg:
            if self.observer is not None:
                self.observer.on_tools(msg["result"])
            if self.pol is not None and self.pol.get("hide_denied", True):
                result = msg["result"]
                bad = (_key_clash(result, ("tools", "nextCursor"))
                       if isinstance(result, dict) else None)
                if bad is not None:
                    # a second spelling of `tools` is a list this filter
                    # never saw: the request fails instead
                    why = _clash_text(bad)
                    self.client.send(_rpc_error(
                        entry["id"], INTERNAL_ERROR,
                        f"bad response from server: {why}"))
                    self._audit_rejected("server", why, msg)
                    return False
                filter_tools_list(self.pol, result)
        return True

    # -- loop ---------------------------------------------------------------

    def _fail_pending(self, entries, message: str) -> None:
        for e in entries:
            self.client.send(_rpc_error(e["id"], INTERNAL_ERROR, message))

    def _lose(self, why: str, message: str) -> None:
        """The server is gone or no use any more: answer everything it owes
        and remember why (the loop ends, the exit code says so)."""
        if self.lost is None:
            self.lost = why
        self._fail_pending(self.pending.drain(), message)

    def _check_deadlines(self) -> "float | None":
        """Act on whatever is overdue; seconds until the next deadline (None:
        nothing is due, wait for traffic). Looked at on every pass, not only
        when the queue happens to be idle, so a server that keeps the queue
        busy cannot keep --timeout from firing."""
        now = time.monotonic()
        if self.server.stalled(now):
            self._lose(f"stopped reading its input (no message taken within "
                       f"{self.timeout:g}s)",
                       f"server stopped reading its input (timed out after "
                       f"{self.timeout:g}s)")
            return None
        expired = self.pending.expired(now)
        if expired:
            self.timed_out += len(expired)
            self._fail_pending(expired, "server timed out")
        due = [d for d in (self.pending.next_deadline(),
                           self.server.stall_deadline()) if d is not None]
        return max(0.0, min(due) - now) if due else None

    def _handle(self, handler, line: bytes) -> None:
        """One line through its handler. A pipe going away ends the loop
        (re-raised); anything else is a bug in one message, logged, and
        the firewall stays up."""
        try:
            handler(line)
        except (OSError, ValueError):
            raise
        except Exception as e:
            self._log(f"internal error on one message, dropped: {e!r}")

    def _server_status(self) -> str:
        """" (exit status N)" for a server that has just closed its output,
        given a moment to finish exiting; "" if it is still running."""
        try:
            code = self.proc.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return f" (exit status {code})"

    def _end_input(self) -> None:
        """Stop the writer thread. A server that is lost is killed first:
        that is what ends a write blocked on its full pipe."""
        if self.lost is not None:
            _kill(self.proc)
            self.server.abort()
        else:
            self.server.close()
        self.server.join(2.0)

    def _wind_down(self) -> None:
        """The client has gone and nothing is owed. Do what the MCP stdio
        transport asks of a client that is leaving: close the server's input
        (it reads end of file), then give it --grace seconds to finish what
        it was sent and exit. Whatever it says meanwhile - a last answer, a
        goodbye notification - goes through the same checks as ever. A server
        still there at the end is stopped by _stop(): SIGTERM, then a kill."""
        self.server.close()
        self.server.join(2.0)       # nothing is queued: this is the thread leaving
        try:
            self.proc.stdin.close()     # the thread has closed its own descriptor
        except OSError:
            pass
        deadline = time.monotonic() + self.grace
        out_open = True
        while True:
            now = time.monotonic()
            if now >= deadline:
                if self.proc.poll() is None:
                    self._log(f"server did not exit within {self.grace:g}s of "
                              f"its input closing; stopping it")
                else:
                    # gone, but a process it started still has its output
                    # open, and _stop() cannot close the pipe under a reader
                    self._log("server has exited, but something it started "
                              "still has its output open; waiting for that "
                              "to let go")
                return
            if not out_open:
                # everything it wrote has been relayed: only its exit is left
                try:
                    self.proc.wait(timeout=min(deadline - now, 0.05))
                    return
                except subprocess.TimeoutExpired:
                    continue
                except OSError:
                    return
            try:
                tag, line = self.q.get(timeout=min(deadline - now, 0.05))
            except queue.Empty:
                continue
            if tag == "signal":     # told to stop while leaving: no more waiting
                self._note_signal(line)
                return
            if tag == "server":     # not the writer's receipts
                if line is None:
                    out_open = False
                else:
                    self._handle(self._on_server_line, line)

    def _note_signal(self, signum: int) -> None:
        self.signalled = signum
        self._log(f"{_signal_name(signum)} received: ending the session")

    def serve(self) -> int:
        """Relay until the client is done and everything is answered, then
        wind the server down (see _wind_down), or until the server is lost,
        or the jail is told to stop (SIGTERM, SIGHUP, Ctrl-Break): the client
        is not read from any more and the server is wound down the same way.
        Returns 0 for a clean session, EXIT_SERVER when the server exited or
        closed its pipes while the client was still talking to it, stopped
        reading its input, or left a request unanswered past --timeout, and
        128 plus the number of the signal that stopped it."""
        _Reader(self._client_in, "client", self.q).start()
        _Reader(self.proc.stdout, "server", self.q).start()
        self.server.start()
        client_open = True
        try:
            while True:
                wait = self._check_deadlines()
                if self.lost is not None:
                    break
                if (not client_open and not len(self.pending)
                        and not self.server.busy()):
                    if not self.timed_out and self.grace > 0:
                        self._wind_down()
                    break
                try:
                    tag, line = self.q.get(
                        timeout=_IDLE_WAKE if wait is None
                        else min(wait, _IDLE_WAKE))
                except queue.Empty:
                    continue
                if tag == "client":
                    if line is None:
                        client_open = False
                        continue
                    self._handle(self._on_client_line, line)
                elif tag == "input":
                    if line is not None:    # writing failed: its stdin is gone
                        self._lose(f"closed its input ({line})", "server closed")
                        break
                elif tag == "signal":
                    self._note_signal(line)
                    if not self.timed_out and self.grace > 0:
                        self._wind_down()
                    break
                else:
                    if line is None:
                        # the server's stdout closed: it exited, or shut its
                        # pipes. A session whose client had finished and
                        # was owed nothing never gets here.
                        self._lose("exited or closed its output"
                                   + self._server_status(), "server closed")
                        break
                    self._handle(self._on_server_line, line)
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        except (OSError, ValueError) as e:  # a pipe went away under us
            self._log(f"transport closed: {e}")
        finally:
            if self.timed_out:
                s = "" if self.timed_out == 1 else "s"
                self._log(f"server did not answer {self.timed_out} "
                          f"request{s} within {self.timeout:g}s")
            if self.lost is not None:
                self._log(f"server {self.lost}")
            self._end_input()
        if self.signalled is not None:
            return 128 + self.signalled
        return EXIT_SERVER if (self.lost is not None or self.timed_out) else 0


def run(policy_path: str, server_cmd: list[str], timeout: float = 30.0,
        stdin=None, stdout=None, grace: float = DEFAULT_GRACE) -> int:
    """Run the jail: policy-check stdin -> server, pass server -> stdout.

    `stdin`/`stdout` default to the process's own (binary) streams; tests
    pass in-memory streams. `grace` is how long the server is given to leave
    on its own once the client has gone (0: not at all).
    """
    problem = _refuse_seconds(timeout=timeout, grace=grace)
    if problem:
        _say(f"mcp-jail: {problem}")
        return 2
    policy_path = expand_path(policy_path)
    try:
        pol = load_policy(policy_path)
    except FileNotFoundError:
        _say(f"mcp-jail: no policy at {policy_path}\n"
             f"mcp-jail: create one - see README")
        return 2
    except OSError as e:        # a directory, no permission, ...
        _say(f"mcp-jail: cannot read the policy {policy_path}: {e}")
        return 2
    except RecursionError:
        _say("mcp-jail: bad policy: nested too deeply")
        return 2
    except (json.JSONDecodeError, re.error, ValueError) as e:
        _say(f"mcp-jail: bad policy: {e}")
        return 2
    client_in, client_out = stdin or sys.stdin, stdout or sys.stdout
    closed = _missing_streams(client_in, client_out)
    if closed:
        _say(f"mcp-jail: {closed}")
        return 2
    with _StopSignals() as stop:
        try:
            proc = _spawn(server_cmd)
        except ServerNotFound as e:
            _say(f"mcp-jail: {_server_problem(e)}")
            return 2
        try:
            return _Proxy(proc, client_in, client_out, timeout, pol,
                          grace=grace, stop=stop).serve()
        finally:
            _stop(proc)


# ---------------------------------------------------------------------------
# learn: observe a server session and generate a tight-fit allowlist policy
# ---------------------------------------------------------------------------

# Fixed menu of character classes, smallest first. Generated string
# patterns are literal-longest-common-prefix + the smallest class here
# covering every observed char. Never `.*`.
_CHAR_CLASSES = [
    ("[0-9]", set(string.digits)),
    ("[a-z]", set(string.ascii_lowercase)),
    ("[a-zA-Z0-9_.-]", set(string.ascii_letters + string.digits + "_.-")),
    ("[a-zA-Z0-9_/.-]", set(string.ascii_letters + string.digits + "_/.-")),
]

_MIN_USEFUL_PREFIX = 2  # shorter shared prefixes fall back to alternation

# JSON number text, exponent notation included (1e-05 is how json.dumps
# spells 0.00001)
_NUMBER_PATTERN = r"\A-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?\Z"


def _string_core(bodies: list[str]) -> str:
    """Tightest value-pattern for observed string values."""
    if len(set(bodies)) == 1:
        return re.escape(bodies[0])  # single distinct value: exact
    lcp = os.path.commonprefix(bodies)
    suffix_chars = set("".join(b[len(lcp):] for b in bodies))
    chosen = None
    for cls, chars in _CHAR_CLASSES:
        if suffix_chars <= chars:
            chosen = cls
            break
    if len(lcp) >= _MIN_USEFUL_PREFIX and chosen is not None:
        if not suffix_chars:
            return re.escape(lcp)  # single distinct value: exact
        return _TRAVERSAL_GUARD + re.escape(lcp) + chosen + "*"
    # no useful shared prefix, or chars outside the menu:
    # exact alternation of observed literals
    return "(?:" + "|".join(re.escape(b) for b in sorted(set(bodies))) + ")"


def _value_pattern(values: list) -> str:
    """One anchored pattern for same-typed values seen at a path.

    Anchored \\A...\\Z (not ^...$: `$` would also admit a value with a
    trailing newline), so the regex pins the whole value for any
    consumer of the policy file, not only mcp-jail's matcher.
    """
    tag = _type_tag(values[0])
    if tag == "null":
        return r"\Anull\Z"
    if tag == "boolean":
        return r"\A(?:true|false)\Z"
    if tag == "number":
        return _NUMBER_PATTERN
    if tag == "object":
        return r"\A\{\}\Z"  # only an empty object is ever a value
    if tag == "array":
        return r"\A\[\]\Z"
    return r"\A" + _string_core([str(v) for v in values]) + r"\Z"


def _value_rules(values: list) -> list[dict]:
    """Typed allow rules for the values seen at one path: one
    {"type": T, "pattern": P} per JSON type seen, so a learned number
    admits 3 but never the string "3"."""
    by_type: dict[str, list] = {}
    for v in values:
        by_type.setdefault(_type_tag(v), []).append(v)
    return [{"type": tag, "pattern": _value_pattern(by_type[tag])}
            for tag in sorted(by_type)]


def _observed_paths(args) -> list[tuple[str, object]]:
    """Flatten call arguments to (path, value) -- scalars and empty
    containers -- with numeric segments (array indices) generalised to
    '*', so tags.0/tags.1 become tags.*."""
    out = []
    for path, value in _nodes(args):
        if isinstance(value, (dict, list)) and (value or not path):
            continue  # structure (or the root object): not a value
        segs = tuple("*" if s.isdigit() else s for s in path)
        out.append((".".join(segs) if segs else "**", value))
    return out


def _unlearnable(called) -> dict[str, str]:
    """The called tool names that a policy cannot hold, each with why: a name
    with a `*` in it (arg_rules keys name one tool each, and `*` alone in
    allow_tools is every tool), and names that are one name once normalised
    (Read and read: the policy compares names that way, so it could not tell
    them apart). The loader refuses a policy that has either."""
    names = sorted(set(called))
    by_norm: dict[str, list[str]] = {}
    for name in names:
        by_norm.setdefault(normalize_tool_name(name), []).append(name)
    why: dict[str, str] = {}
    for name in names:
        norm = normalize_tool_name(name)
        if "*" in norm:
            why[name] = "a policy cannot hold a '*' in a tool name"
        elif len(by_norm[norm]) > 1:
            twins = ", ".join(repr(n) for n in by_norm[norm] if n != name)
            why[name] = (f"it is the same tool name as {twins} once "
                         f"normalised, and a policy cannot tell them apart")
    return why


def generate_policy(observed_tools: list[str],
                    observed_calls: list[tuple[str, dict]]) -> dict:
    """Build the tightest-fit allowlist policy from observations.

    Only tools that were actually CALLED (and answered) are allowed;
    tools the server merely listed are reported under `_not_called` for
    the reviewer, and denied. Every allowed tool gets an arg_rules entry,
    so with strict_args a tool that was only ever called with empty
    arguments accepts only empty arguments. A called tool whose name a
    policy cannot hold (see _unlearnable) is left out, so denied, and named
    in the `_comment`: the loader would refuse the policy otherwise.
    """
    called = sorted({t for t, _ in observed_calls if isinstance(t, str)})
    left_out = _unlearnable(called)
    called = [t for t in called if t not in left_out]
    listed = {t for t in observed_tools if isinstance(t, str)}
    by_path: dict[tuple[str, str], list] = {}
    for tool, args in observed_calls:
        if not isinstance(tool, str) or tool in left_out:
            continue
        try:
            paths = _observed_paths(args)
        except ValueError:
            continue  # absurdly deep arguments: nothing to learn from
        for gen_path, value in paths:
            by_path.setdefault((tool, gen_path), []).append(value)
    arg_rules: dict[str, dict] = {t: {"allow": {}, "deny": {}}
                                  for t in called}
    for (tool, gen_path), values in sorted(by_path.items()):
        arg_rules[tool]["allow"][gen_path] = _value_rules(values)
    policy: dict = {
        "_comment": "generated by `mcp-jail learn` - tightest-fit "
                    "allowlist from observed traffic. Review before use: "
                    "it permits exactly what was seen, nothing more. "
                    "Only tools that were called are allowed; every "
                    "argument value must match the typed allow rule for "
                    "its path; unseen paths are denied; a tool with no "
                    "allow patterns accepts only empty arguments, {} "
                    "(strict_args) - set its allow to \"*\" to accept any. "
                    "Only tools/call is checked (policed_methods).",
        "allow_tools": called,
    }
    if left_out:
        policy["_comment"] += (" Left out, so denied, because a policy "
                               "cannot hold them: " + "; ".join(
                                   f"{name!r} ({why})"
                                   for name, why in left_out.items()) + ".")
    not_called = sorted(listed - set(called) - set(left_out))
    if not_called:
        policy["_not_called"] = not_called  # listed by the server, denied
    policy.update({
        "deny_tools": [],
        "arg_rules": arg_rules,
        "policed_methods": ["tools/call"],
        "deny_methods": [],
        "strict_args": True,
        "audit_args": "denied",
        "hide_denied": True,
    })
    return policy


class _Recorder:
    """Observer for learn: collects listed tool names and the (tool, args)
    of calls the server answered successfully."""

    def __init__(self):
        self.tools: list[str] = []
        self.calls: list[tuple[str, dict]] = []
        self.protocol_version: str | None = None  # what the server answered

    def on_call(self, name, args) -> None:
        if not isinstance(args, dict):
            return  # can never be allowed (arguments must be an object)
        self.calls.append((name, args))

    def on_tools(self, result) -> None:
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            for t in result["tools"]:
                if isinstance(t, dict) and isinstance(t.get("name"), str):
                    self.tools.append(t["name"])


class _Session:
    """Synchronous request/response client for a server subprocess,
    built on the same reader-thread transport (used by learn --script).

    request() returns a discriminated tuple:
      ("ok", obj)   -- the response with the matching id arrived
      ("closed",)   -- server closed stdout, or its stdin is gone
      ("timeout",)  -- nothing matching arrived within `timeout` seconds
    Non-JSON lines on the server's stdout (banners) are logged and
    skipped. Notifications are ignored; server-originated requests get a
    -32601 error so the server never waits on a client that isn't there.
    """

    def __init__(self, proc):
        self.proc = proc
        self.q: "queue.Queue" = queue.Queue()
        # no stall timer of its own: request() waits with its own deadline
        self.out = _ServerInput(proc.stdin, None,
                                lambda payload: self.q.put(("input", payload)))
        self.out.start()
        self.closed = False
        _Reader(proc.stdout, "server", self.q).start()

    def notify(self, msg: dict) -> bool:
        """Send a notification (or any message) without waiting. False
        when the server has gone (its stdin pipe is closed)."""
        if self.closed:
            return False
        if not self.out.put(_encode(msg)):
            self.closed = True
            return False
        return True

    def close(self) -> None:
        """Stop the writer thread (a blocked write ends when the server is
        stopped)."""
        self.out.abort()

    def request(self, msg: dict, timeout: float):
        if not self.notify(msg):
            return ("closed",)
        want = _id_key(msg.get("id"))
        deadline = time.monotonic() + timeout if timeout else None  # 0: no limit
        while True:
            if self.closed:
                return ("closed",)
            remaining = _IDLE_WAKE
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return ("timeout",)
            try:
                tag, line = self.q.get(timeout=min(remaining, _IDLE_WAKE))
            except queue.Empty:
                continue            # the deadline, if any, is checked above
            if tag == "input":
                if line is not None:    # writing failed: its stdin is gone
                    self.closed = True
                    return ("closed",)
                continue                # a message went out
            if line is None:
                self.closed = True
                return ("closed",)
            obj, code, _err = _parse(line)
            if code is not None:
                _say(f"learn: ignoring non-JSON line from server: "
                     f"{_preview(line)}")
                continue
            if not isinstance(obj, dict):
                continue
            if "method" in obj:
                if obj.get("id") is not None:
                    self.notify(_rpc_error(obj["id"], METHOD_NOT_FOUND,
                                           "mcp-jail learn: client requests "
                                           "are not supported"))
                continue
            if "id" in obj and _id_key(obj["id"]) == want:
                return ("ok", obj)


def load_script(path: str) -> list[dict]:
    """Read and validate a learn --script file: a JSON array of
    {"tool": "<name>", "arguments": {...}} ("arguments" optional).
    Raises ValueError (or OSError) with a message fit for the user."""
    with open(path, encoding="utf-8") as f:
        try:
            calls = json.load(f)
        except ValueError as e:
            raise ValueError(f"not valid JSON ({e})") from None
    if not isinstance(calls, list):
        raise ValueError('must be a JSON array of {"tool": ..., '
                         '"arguments": {...}}')
    for i, call in enumerate(calls):
        if not isinstance(call, dict):
            raise ValueError(f"entry {i} is not an object")
        if not isinstance(call.get("tool"), str) or not call["tool"]:
            raise ValueError(f'entry {i} needs a "tool" name (string)')
        if "arguments" in call and call["arguments"] is not None and not (
                isinstance(call["arguments"], dict)):
            raise ValueError(f'entry {i}: "arguments" must be a JSON object')
    return calls


def _learn_from_script(proc, calls: list[dict], timeout: float,
                       rec: _Recorder) -> str | None:
    """Drive canned calls against the server; no client needed. A call
    is recorded only once the server answered it successfully. Returns
    None when the script ran through, else why the session ended early
    (the server refused initialize, or went away)."""
    session = _Session(proc)
    try:
        return _drive_script(session, calls, timeout, rec)
    finally:
        session.close()


def _drive_script(session: _Session, calls: list[dict], timeout: float,
                  rec: _Recorder) -> str | None:
    status = session.request(
        {"jsonrpc": "2.0", "id": "learn-init", "method": "initialize",
         "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": {"name": "mcp-jail", "version": VERSION}}},
        timeout)
    if status[0] != "ok":
        return (f"server did not answer initialize ({status[0]})"
                if status[0] == "timeout" else
                "server closed before answering initialize")
    reply = status[1]
    if "error" in reply:
        err = reply["error"] if isinstance(reply["error"], dict) else {}
        return (f"server refused initialize: {err.get('message', '?')} "
                f"(code {err.get('code', '?')})")
    result = reply.get("result")
    version = result.get("protocolVersion") if isinstance(result, dict) else None
    if isinstance(version, str):
        rec.protocol_version = version
        if version != PROTOCOL_VERSION:
            _say(f"learn: server speaks MCP {version} (offered "
                 f"{PROTOCOL_VERSION}); continuing with the server's version")
    # MCP: the client confirms the handshake before any other request;
    # an SDK server answers everything else with -32602 until it does.
    if not session.notify({"jsonrpc": "2.0",
                           "method": "notifications/initialized"}):
        return "server closed during the handshake"
    status = session.request({"jsonrpc": "2.0", "id": "learn-list",
                              "method": "tools/list"}, timeout)
    if status[0] == "ok":
        rec.on_tools(status[1].get("result"))
    elif status[0] == "timeout":
        _say("learn: tools/list timed out")
    else:
        return "server closed before answering tools/list"

    for i, call in enumerate(calls):
        name = call["tool"]
        args = call.get("arguments")
        if args is None:
            args = {}
        status = session.request(
            {"jsonrpc": "2.0", "id": f"learn-{i}", "method": "tools/call",
             "params": {"name": name, "arguments": args}}, timeout)
        if status[0] == "ok":
            if _call_succeeded(status[1]):
                rec.on_call(name, args)
            else:
                _say(f"learn: call {i} ({name!r}) failed on the server; "
                     f"not learned")
        elif status[0] == "timeout":
            _say(f"learn: call {i} ({name!r}) timed out after {timeout}s")
        else:
            return (f"server closed during call {i} ({name!r}); "
                    f"{len(calls) - i} call(s) not driven")
    return None


def learn(server_cmd: list[str], script: str | None = None,
          out: str | None = None, timeout: float = 30.0,
          stdin=None, stdout=None, grace: float = DEFAULT_GRACE) -> int:
    """Observe a server and emit a tight-fit allowlist policy.

    --script mode drives canned calls against the server (no client).
    Live mode proxies stdin/stdout (everything allowed, nothing hidden)
    until stdin EOF or Ctrl-C.  Policy goes to stdout or --out; a summary
    goes to stderr.

    Exit 2 without touching --out when the script or --out is unusable,
    the server command cannot be run, or the session ended early (refused
    handshake, server gone): whatever was learned by then goes to stdout
    for review instead, so a failed run never overwrites a good policy.
    """
    problem = _refuse_seconds(timeout=timeout, grace=grace)
    if problem:
        _say(f"mcp-jail learn: {problem}")
        return 2
    calls: list[dict] = []
    if script is not None:
        script = expand_path(script)
        if not os.path.exists(script):
            _say(f"mcp-jail learn: no script at {script}")
            return 2
        try:
            calls = load_script(script)
        except (OSError, ValueError) as e:
            _say(f"mcp-jail learn: bad --script {script}: {e}")
            return 2
    if out:
        out = expand_path(out)
        if os.path.isdir(out):
            _say(f"mcp-jail learn: --out {out} is a directory")
            return 2
        try:
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        except OSError as e:
            _say(f"mcp-jail learn: cannot create the directory for "
                 f"--out {out}: {e}")
            return 2
    client_in, client_out = stdin or sys.stdin, stdout or sys.stdout
    if script is None:
        closed = _missing_streams(client_in, client_out)
    elif not out and client_out is None:
        closed = ("standard output is closed and no --out was given (the "
                  "policy has nowhere to go)")
    else:
        closed = None
    if closed:
        _say(f"mcp-jail learn: {closed}")
        return 2
    rec = _Recorder()
    # a live session ends on SIGTERM / SIGHUP as it does on Ctrl-C, with the
    # policy; a script is driven by this thread alone and has no loop to tell
    with (_StopSignals() if script is None else contextlib.nullcontext()) as stop:
        try:
            proc = _spawn(server_cmd)
        except ServerNotFound as e:
            _say(f"mcp-jail learn: {_server_problem(e)}")
            return 2
        failure: str | None = None
        try:
            if script is not None:
                failure = _learn_from_script(proc, calls, timeout, rec)
            else:
                proxy = _Proxy(proc, client_in, client_out, timeout, None,
                               observer=rec, grace=grace, stop=stop)
                try:
                    proxy.serve()
                except KeyboardInterrupt:
                    pass
                if proxy.lost is not None:
                    failure = f"the server {proxy.lost} during the session"
        finally:
            _stop(proc)
    policy = generate_policy(rec.tools, rec.calls)
    for name, why in _unlearnable(
            t for t, _ in rec.calls if isinstance(t, str)).items():
        _say(f"learn: left {name!r} out of the policy ({why}); "
             f"it stays denied")
    text = json.dumps(policy, indent=2)
    code = 0
    if failure:
        code = 2
        _say(f"learn: {failure}")
        if rec.calls:
            _say("learn: partial policy follows on stdout (--out not "
                 "written); review before use")
            print(text)
        else:
            _say("learn: nothing learned; no policy written")
    elif out:
        try:
            with open(out, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            _say(f"learn: wrote {out}")
        except OSError as e:
            code = 2
            _say(f"learn: cannot write {out}: {e}; policy follows on stdout")
            print(text)
    else:
        print(text)
    n_listed = len(set(rec.tools))
    n_called = len({t for t, _ in rec.calls})
    n_left = n_called - len(policy["allow_tools"])
    left = f" ({n_left} left out)" if n_left else ""
    spoke = (f" (server speaks MCP {rec.protocol_version})"
             if rec.protocol_version else "")
    _say(f"learn: {n_listed} tool(s) listed by the server, "
         f"{n_called} tool(s) called in {len(rec.calls)} successful "
         f"call(s); allowlisted the {len(policy['allow_tools'])} "
         f"called{left}{spoke}")
    return code

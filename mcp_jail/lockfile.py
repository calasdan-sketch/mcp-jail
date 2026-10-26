"""The tool-definition lockfile (`mcp.lock`), format version 1.

This file is the reference implementation of docs/LOCKFILE.md. mcp-audit and
mcp-jail each ship an identical copy, so a lock written by one is checked by
the other with the same hashes. It uses the standard library only and imports
nothing from either package.

What it is for: an MCP server can change its tool descriptions after you have
approved it (a "rug pull"). The lock keeps a SHA-256 of every tool's name,
description and input schema, taken when you approved the server; a later
tools/list that hashes differently is drift.
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import re
import unicodedata

FORMAT_VERSION = 1

#: Nesting deeper than this is refused (a hostile schema must not crash the
#: hasher; real schemas are a handful of levels deep).
MAX_DEPTH = 100
#: ...and a lock file larger than this is not read.
MAX_LOCK_BYTES = 64 * 1024 * 1024

NEW_TOOL = "new_tool"
REMOVED_TOOL = "removed_tool"
DESCRIPTION_CHANGED = "description_changed"
SCHEMA_CHANGED = "schema_changed"
DEFINITION_CHANGED = "definition_changed"
ANNOTATIONS_CHANGED = "annotations_changed"
INVALID_TOOL = "invalid_tool"
COMMAND_CHANGED = "command_changed"
NEW_SERVER = "new_server"
REMOVED_SERVER = "removed_server"

#: What each kind says, in plain words.
KIND_TEXT = {
    NEW_TOOL: "new tool",
    REMOVED_TOOL: "removed tool",
    DESCRIPTION_CHANGED: "description changed",
    SCHEMA_CHANGED: "schema changed",
    DEFINITION_CHANGED: "definition changed",
    ANNOTATIONS_CHANGED: "annotations changed (hint)",
    INVALID_TOOL: "invalid tool definition",
    COMMAND_CHANGED: "command changed",
    NEW_SERVER: "new server",
    REMOVED_SERVER: "removed server",
}
#: These are reported but are not drift by themselves: a removed tool cannot
#: do more than it could, and annotations are hints the server gives about
#: itself.
HINT_KINDS = frozenset({REMOVED_TOOL, ANNOTATIONS_CHANGED, REMOVED_SERVER})

Drift = collections.namedtuple("Drift", "kind tool detail")

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_KIND_ORDER = {k: i for i, k in enumerate((
    INVALID_TOOL, NEW_TOOL, DEFINITION_CHANGED, DESCRIPTION_CHANGED,
    SCHEMA_CHANGED, ANNOTATIONS_CHANGED, REMOVED_TOOL))}


class LockError(ValueError):
    """A value that cannot be hashed, or a lock file that is not valid."""


# -- canonical form -----------------------------------------------------------


def _norm(value, depth: int):
    """`value` with every string (and key) in NFC, numbers in their canonical
    form, and anything that is not JSON refused."""
    if depth > MAX_DEPTH:
        raise LockError("nested too deeply")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = unicodedata.normalize("NFC", value)
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise LockError("a string is not valid Unicode (lone surrogate)") \
                from None
        return text
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise LockError("a number is not finite")
        if value == int(value) and abs(value) < 2 ** 53:
            return int(value)           # 1.0 and 1 are the same number
        return value
    if isinstance(value, (list, tuple)):
        return [_norm(v, depth + 1) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise LockError("an object key is not a string")
            key = _norm(k, depth + 1)
            if key in out:
                raise LockError("two object keys are the same after "
                                "normalisation")
            out[key] = _norm(v, depth + 1)
        return out
    raise LockError(f"{type(value).__name__} is not a JSON value")


def canonical(value) -> bytes:
    """The canonical bytes of a JSON value: strings in NFC, keys sorted by
    code point, no whitespace, non-ASCII written as it is, UTF-8."""
    try:
        text = json.dumps(_norm(value, 0), sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False)
        return text.encode("utf-8")
    except RecursionError:
        raise LockError("nested too deeply") from None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_value(value) -> str:
    """SHA-256 (hex) of the canonical form of `value`."""
    return sha256_hex(canonical(value))


# -- tools --------------------------------------------------------------------


def tool_hashes(tool) -> dict:
    """The hashes the lock keeps for one tool definition (a tools/list
    entry): `sha256` over name, description and inputSchema together,
    `description_sha256`, `schema_sha256`, and `annotations_sha256` (a hint:
    it is kept apart and does not enter `sha256`). A missing description,
    schema or annotations hashes as JSON null. Raises LockError for an entry
    that is not an object with a non-empty string `name`."""
    if not isinstance(tool, dict):
        raise LockError("a tool is not an object")
    name = tool.get("name")
    if not isinstance(name, str) or not name:
        raise LockError("a tool has no name")
    description = tool.get("description")
    schema = tool.get("inputSchema")
    return {
        "sha256": hash_value({"name": name, "description": description,
                              "inputSchema": schema}),
        "description_sha256": hash_value(description),
        "schema_sha256": hash_value(schema),
        "annotations_sha256": hash_value(tool.get("annotations")),
    }


def tools_entries(tools) -> "tuple[dict, list[Drift]]":
    """({name: hashes}, problems) for a list of tools/list entries. An entry
    that cannot be hashed, or a name that comes twice, is a problem (an
    INVALID_TOOL Drift) and has no entry."""
    entries: dict = {}
    problems: "list[Drift]" = []
    seen = set()
    for i, tool in enumerate(tools):
        label = tool.get("name") if isinstance(tool, dict) and isinstance(
            tool.get("name"), str) else f"#{i}"
        try:
            hashes = tool_hashes(tool)
        except LockError as e:
            problems.append(Drift(INVALID_TOOL, label, str(e)))
            continue
        if tool["name"] in seen:
            problems.append(Drift(INVALID_TOOL, tool["name"],
                                  "the name is listed twice"))
            entries.pop(tool["name"], None)
            continue
        seen.add(tool["name"])
        entries[tool["name"]] = hashes
    return entries, problems


def _short(h) -> str:
    return h[:12] if isinstance(h, str) else "?"


def diff_entry(name: str, locked: dict, now: dict) -> "list[Drift]":
    """How one tool's current hashes differ from its locked entry."""
    out = []
    if locked["description_sha256"] != now["description_sha256"]:
        out.append(Drift(DESCRIPTION_CHANGED, name, "was %s, now %s" % (
            _short(locked["description_sha256"]),
            _short(now["description_sha256"]))))
    if locked["schema_sha256"] != now["schema_sha256"]:
        out.append(Drift(SCHEMA_CHANGED, name, "was %s, now %s" % (
            _short(locked["schema_sha256"]), _short(now["schema_sha256"]))))
    if not out and locked["sha256"] != now["sha256"]:
        out.append(Drift(DEFINITION_CHANGED, name, "was %s, now %s" % (
            _short(locked["sha256"]), _short(now["sha256"]))))
    ann = locked.get("annotations_sha256")
    if ann is not None and ann != now["annotations_sha256"]:
        out.append(Drift(ANNOTATIONS_CHANGED, name, "was %s, now %s" % (
            _short(ann), _short(now["annotations_sha256"]))))
    return out


def diff_tools(locked: dict, tools, complete: bool = True) -> "list[Drift]":
    """Everything that differs between the locked tools ({name: entry}) and a
    list of tools/list entries, in a fixed order (by tool name, then kind).
    `complete`: the list is the whole list, so a locked tool that is missing
    from it is REMOVED_TOOL; pass False for one page of a paged list."""
    now, problems = tools_entries(tools)
    out = list(problems)
    for name, hashes in now.items():
        if name not in locked:
            out.append(Drift(NEW_TOOL, name, "not in the lockfile"))
        else:
            out.extend(diff_entry(name, locked[name], hashes))
    if complete:
        listed = {t.get("name") for t in tools if isinstance(t, dict)}
        for name in locked:
            if name not in listed:
                out.append(Drift(REMOVED_TOOL, name, "no longer listed"))
    out.sort(key=lambda d: (d.tool, _KIND_ORDER.get(d.kind, 99)))
    return out


# -- commands -----------------------------------------------------------------


def command_fingerprint(command=None, args=None, url=None) -> str:
    """SHA-256 (hex) of how a server is started: its command and arguments,
    or its URL. Environment values are never part of it."""
    if url is not None:
        return hash_value({"url": url})
    if not isinstance(command, str):
        raise LockError("a server has neither a command nor a URL")
    args = [] if args is None else list(args)
    if not all(isinstance(a, str) for a in args):
        raise LockError("an argument is not a string")
    return hash_value({"command": command, "args": args})


# -- the file -----------------------------------------------------------------


def new_lock(generated_by: str) -> dict:
    return {"version": FORMAT_VERSION, "generated_by": generated_by,
            "servers": {}}


def server_entry(fingerprint: str, tools: dict) -> dict:
    """A lock entry for one server: `tools` is {name: hashes}."""
    return {"command_fingerprint": fingerprint,
            "tools": {n: dict(h) for n, h in sorted(tools.items())}}


def dump_lock(lock: dict) -> str:
    """The lock as text: sorted keys, two-space indent, a final newline. The
    same lock is the same bytes, so a diff of the file is a diff of the
    approvals."""
    return json.dumps(lock, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise LockError(f"the key {k!r} appears twice")
        out[k] = v
    return out


def _check_keys(obj, required, optional, where):
    if not isinstance(obj, dict):
        raise LockError(f"{where} is not an object")
    for key in required:
        if key not in obj:
            raise LockError(f"{where} has no {key!r}")
    for key in obj:
        if key not in required and key not in optional:
            raise LockError(f"{where} has an unknown key {key!r}")


def parse_lock(text) -> dict:
    """The lock in `text` (str or bytes), checked in full. Raises LockError
    with a message fit to show for anything that is not a valid version-1
    lock; unknown keys are refused, not ignored."""
    if isinstance(text, (bytes, bytearray)):
        if len(text) > MAX_LOCK_BYTES:
            raise LockError("the lockfile is too large")
        try:
            text = bytes(text).decode("utf-8-sig")
        except UnicodeDecodeError:
            raise LockError("the lockfile is not UTF-8") from None
    try:
        lock = json.loads(text, object_pairs_hook=_no_duplicates)
    except LockError:
        raise
    except (ValueError, RecursionError):
        raise LockError("the lockfile is not valid JSON") from None
    _check_keys(lock, ("version", "servers"), ("generated_by",), "the lockfile")
    version = lock["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise LockError("'version' is not a whole number")
    if version != FORMAT_VERSION:
        raise LockError(f"the lockfile is version {version}; this program "
                        f"reads version {FORMAT_VERSION} (upgrade it)")
    if "generated_by" in lock and not isinstance(lock["generated_by"], str):
        raise LockError("'generated_by' is not a string")
    if not isinstance(lock["servers"], dict):
        raise LockError("'servers' is not an object")
    for key, server in lock["servers"].items():
        where = f"server {key!r}"
        _check_keys(server, ("command_fingerprint", "tools"), (), where)
        if not isinstance(server["command_fingerprint"], str) \
                or not _HEX64.match(server["command_fingerprint"]):
            raise LockError(f"{where}: 'command_fingerprint' is not a "
                            "SHA-256 in lower-case hex")
        if not isinstance(server["tools"], dict):
            raise LockError(f"{where}: 'tools' is not an object")
        for name, entry in server["tools"].items():
            twhere = f"{where}, tool {name!r}"
            _check_keys(entry, ("sha256", "description_sha256",
                                "schema_sha256"), ("annotations_sha256",),
                        twhere)
            for field, value in entry.items():
                if not isinstance(value, str) or not _HEX64.match(value):
                    raise LockError(f"{twhere}: {field!r} is not a SHA-256 "
                                    "in lower-case hex")
    return lock


def find_server(lock: dict, key=None, fingerprint=None):
    """(key, entry) of the server in `lock` that is named `key`, or else the
    one whose command_fingerprint is `fingerprint`; (None, None) when there
    is none. Raises LockError when a fingerprint matches several servers
    (name the one you mean)."""
    servers = lock["servers"]
    if key is not None:
        return (key, servers[key]) if key in servers else (None, None)
    hits = [(k, s) for k, s in servers.items()
            if s["command_fingerprint"] == fingerprint]
    if len(hits) > 1:
        raise LockError("several servers in the lockfile are started the "
                        "same way (" + ", ".join(repr(k) for k, _ in hits)
                        + "); say which one")
    return hits[0] if hits else (None, None)

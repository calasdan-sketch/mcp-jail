"""An optional hash chain over the audit log (--audit-chain).

Each record then carries "prev": the SHA-256 of the previous line of the log
exactly as it was written. Deleting, changing or inserting a record in the
middle of the log breaks the chain at that point, and `mcp-jail
--verify-audit` says where.

What it does NOT do: the log is a file the same user can write, and so can
whoever runs as that user. Someone who can edit the log can also recompute
every hash after the edit, and one who cuts records off the END leaves a
chain that is still valid. It catches accident and careless tampering, not an
attacker with the user's rights. To get more, copy the head hash that
--verify-audit prints somewhere the user cannot write (a ticket, a remote
log) and compare later: an older head must still be in the chain."""

from __future__ import annotations

import hashlib
import json
import os

GENESIS = "0" * 64
_CHUNK = 64 * 1024


def line_hash(line: bytes) -> str:
    """The hash a record's successor carries: of the line without its
    newline."""
    return hashlib.sha256(line.rstrip(b"\r\n")).hexdigest()


def last_line(path: str) -> "bytes | None":
    """The last complete line of the file at `path` (None: no file, or
    nothing in it). Read from the end, so a big log costs one chunk."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return None
            data = b""
            pos = size
            while pos > 0:
                step = min(_CHUNK, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
                body = data.rstrip(b"\r\n")
                cut = body.rfind(b"\n")
                if cut >= 0 or pos == 0:
                    line = body[cut + 1:]
                    return line or None
            return None
    except OSError:
        return None


def head(path: str) -> str:
    """The hash the next record of the log at `path` must carry: that of
    its last line; if it has none (a new log after a rotation), that of the
    last line of `<path>.1`; for a first log, GENESIS."""
    for p in (path, path + ".1"):
        line = last_line(p)
        if line is not None:
            return line_hash(line)
    return GENESIS


def verify(path: str) -> dict:
    """Check the chain of the log at `path` (with `<path>.1` before it).
    Returns {"ok", "records", "chained", "head", "problems": [text]}. The
    first chained record is taken as given (what it follows may have been
    rotated away); every one after it must carry the hash of the line before
    it, and an unchained or unreadable line after the chain began is a
    problem."""
    files = [p for p in (path + ".1", path) if os.path.exists(p)]
    out = {"ok": True, "records": 0, "chained": 0, "head": None,
           "problems": []}
    prev_hash = None
    started = False
    n = 0
    for p in files:
        try:
            f = open(p, "rb")
        except OSError as e:
            out["problems"].append(f"cannot read {p}: {e.strerror or e}")
            continue
        with f:
            for raw in f:
                line = raw.rstrip(b"\r\n")
                if not line:
                    continue
                n += 1
                try:
                    rec = json.loads(line.decode("utf-8"))
                except (ValueError, RecursionError):
                    rec = None
                prev = rec.get("prev") if isinstance(rec, dict) else None
                if isinstance(prev, str):
                    out["chained"] += 1
                    if started and prev != prev_hash:
                        out["problems"].append(
                            f"record {n} ({os.path.basename(p)}) does not "
                            "follow the record before it: one was changed, "
                            "removed or inserted")
                    started = True
                elif started:
                    out["problems"].append(
                        f"record {n} ({os.path.basename(p)}) has no 'prev' "
                        "after the chain began (unreadable, inserted, or "
                        "written with --audit-chain off)")
                prev_hash = line_hash(line)
    out["records"] = n
    out["head"] = prev_hash
    out["ok"] = not out["problems"]
    return out

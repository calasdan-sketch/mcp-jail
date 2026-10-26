"""Check a server's tools/list answers against a lockfile (mcp.lock, see
docs/LOCKFILE.md) while the jail relays them, and refuse calls to tools that
have changed.

The jail does not decide whether a tool is good. It remembers what you
approved (mcp-audit lock) and notices when the server says something else: a
new tool, a description or schema that is not the one in the lock. What it
does about that is --on-drift:

  block  (default) the tools/list answer is replaced by an error, and calls
         to the tools that changed, or are not in the lock, are refused
  strip  the changed and new tools are removed from the answer, calls to them
         are refused, the rest is passed on
  ask    ask on the terminal (/dev/tty, CONIN$) whether to allow what changed
         for this session; no terminal, no answer, or "no" means block
  warn   pass everything on and say so (audit log and stderr)

Deterministic: hashes and set differences, nothing scored or guessed.
"""

from __future__ import annotations

import os
import threading

from . import lockfile as lf

MODES = ("block", "strip", "ask", "warn")
#: Seconds the terminal is waited on before the answer is "no".
ASK_TIMEOUT = 60.0

_WINDOWS = os.name == "nt"


class Verdict:
    """What to do with one tools/list result."""

    def __init__(self):
        #: "pass", "error" (answer with an error) or "strip"
        self.action = "pass"
        self.message = ""
        self.drift: "list[lf.Drift]" = []    # what differs (hard drift)
        self.hints: "list[lf.Drift]" = []    # removed tools, annotations
        #: the names to remove from the list when action is "strip"
        self.strip: "set[str]" = set()
        #: what enforcing would have done, whatever mode runs (for --shadow)
        self.would: str = "pass"
        self.approved = False


def _terminal_streams():
    """(input, output) of the controlling terminal, or raise OSError."""
    if _WINDOWS:
        return open("CONIN$", "r"), open("CONOUT$", "w")
    tty = open("/dev/tty", "r+")
    return tty, tty


def ask_on_terminal(question: str, timeout: float = ASK_TIMEOUT,
                    opener=_terminal_streams) -> bool:
    """Ask a yes/no question on the terminal (not on the pipes the protocol
    uses). False when there is no terminal, no answer within `timeout`
    seconds, or the answer is not yes."""
    try:
        tin, tout = opener()
    except OSError:
        return False
    answer: "list[str]" = []

    def read():
        try:
            answer.append(tin.readline())
        except (OSError, ValueError):
            pass
    try:
        tout.write(question + " [y/N] (no answer in %d s means no) "
                   % int(timeout))
        tout.flush()
        t = threading.Thread(target=read, daemon=True)
        t.start()
        t.join(timeout)
    except (OSError, ValueError):
        return False
    finally:
        # a thread blocked in readline() is left to die with the process
        pass
    return bool(answer) and answer[0].strip().lower() in ("y", "yes")


def _safe(name, limit: int = 80) -> str:
    """A tool name (the server chooses it) as one short line of printable
    text: it goes to the terminal, to stderr and into error messages."""
    text = "".join(ch if ch.isprintable()
                   else ch.encode("unicode_escape").decode("ascii")
                   for ch in str(name)[:limit * 4])
    return text if len(text) <= limit else text[:limit] + "..."


class LockGuard:
    def __init__(self, key: str, entry: dict, mode: str = "block", ask=None):
        if mode not in MODES:
            raise ValueError(f"on-drift must be one of {', '.join(MODES)}")
        self.key = key
        self.locked = entry["tools"]
        self.mode = mode
        self._ask = ask or ask_on_terminal
        #: tool name -> the drift kinds it was flagged for this session
        self.flagged: "dict[str, list[str]]" = {}
        #: (name, sha256) the operator allowed this session (ask)
        self.approved: "set[tuple[str, str]]" = set()
        #: tools whose current definition matches the lock, seen this session
        self.listed_ok: "set[str]" = set()
        self._current: "dict[str, str]" = {}   # name -> sha256, last listed

    # -- tools/list --------------------------------------------------------

    def review(self, result, complete: bool) -> Verdict:
        """Compare one tools/list result with the lock. `complete`: it is the
        whole list (no cursor was sent and none came back), so a locked tool
        that is missing is noted as removed."""
        v = Verdict()
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            v.drift = [lf.Drift(lf.INVALID_TOOL, "",
                                "the answer has no list of tools")]
            return self._decide(v, [], {})
        now, problems = lf.tools_entries(tools)
        drift = lf.diff_tools(self.locked, tools, complete=complete)
        v.drift = [d for d in drift if d.kind not in lf.HINT_KINDS]
        v.hints = [d for d in drift if d.kind in lf.HINT_KINDS]
        return self._decide(v, tools, now)

    def _decide(self, v: Verdict, tools, now: dict) -> Verdict:
        names_bad = {d.tool for d in v.drift if d.tool}
        unnamed = [d for d in v.drift if not d.tool]
        # tools that match the lock again are no longer flagged
        for name in list(self.flagged):
            if name in now and name not in names_bad:
                del self.flagged[name]
        self._current.update({n: h["sha256"] for n, h in now.items()})
        for name in now:
            if name not in names_bad:
                self.listed_ok.add(name)
        if not v.drift:
            return v
        # what has been allowed already (ask) is not asked again
        pending = [d for d in v.drift if d.tool and (
            d.tool, now.get(d.tool, {}).get("sha256")) not in self.approved]
        if not pending and not unnamed:
            v.approved = True
            return v
        v.would = ("pass" if self.mode == "warn" else
                   "strip" if self.mode == "strip" and not unnamed
                   else "error")
        for d in pending:
            self.flagged.setdefault(d.tool, [])
            if d.kind not in self.flagged[d.tool]:
                self.flagged[d.tool].append(d.kind)
        mode = self.mode
        if mode == "ask":
            allowed = self._ask(self.question(v, pending, unnamed))
            if allowed:
                for d in pending:
                    self.approved.add((d.tool, now.get(d.tool, {})
                                       .get("sha256")))
                    self.flagged.pop(d.tool, None)
                v.approved = True
                return v
            mode = "block"
        if mode == "warn":
            v.action = "pass"
            return v
        if mode == "strip" and not unnamed:
            v.action = "strip"
            v.strip = {d.tool for d in pending}
            return v
        v.action = "error"
        v.message = ("the server's tool definitions are not the ones in the "
                     "lockfile: " + self.summary(v.drift))
        return v

    @staticmethod
    def summary(drift, limit: int = 5) -> str:
        parts = []
        for d in drift[:limit]:
            what = lf.KIND_TEXT[d.kind]
            parts.append(f"'{_safe(d.tool)}' {what}" if d.tool else what)
        more = len(drift) - limit
        return "; ".join(parts) + (f"; and {more} more" if more > 0 else "")

    def question(self, v: Verdict, pending, unnamed) -> str:
        return (f"mcp-jail: server '{self.key}' changed since it was locked: "
                + self.summary(pending + unnamed)
                + ". Allow this for the rest of this session?")

    # -- tools/call --------------------------------------------------------

    def check_call(self, name) -> "tuple[bool, str]":
        """May a call to tool `name` go through? (ok, reason). In warn mode
        always."""
        if self.mode == "warn":
            return True, ""
        return self.refusal(name)

    def refusal(self, name) -> "tuple[bool, str]":
        """Would a call to `name` be refused, whatever the mode runs (for
        --shadow)? (ok, reason)"""
        if not isinstance(name, str):
            return True, ""         # the policy's own checks refuse that
        sha = self._current.get(name)
        if sha is not None and (name, sha) in self.approved:
            return True, ""
        if name in self.flagged:
            kinds = ", ".join(lf.KIND_TEXT[k] for k in self.flagged[name])
            return False, (f"tool '{_safe(name)}' is not the one in the lockfile "
                           f"({kinds})")
        if name not in self.locked:
            return False, f"tool '{_safe(name)}' is not in the lockfile"
        return True, ""

    @staticmethod
    def strip_tools(result: dict, names) -> None:
        """Remove the named tools from a tools/list result, in place, and
        every entry that is not an object with a string name."""
        result["tools"] = [t for t in result["tools"]
                           if isinstance(t, dict)
                           and isinstance(t.get("name"), str)
                           and t["name"] not in names]

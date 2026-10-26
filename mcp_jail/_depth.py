"""A depth limit of our own for untrusted JSON.

How deep json.loads can go before it raises RecursionError depends on the
Python version and on the stack the process was given (Python 3.14 follows the
real stack, so a big stack parses 100000 levels without an error). Relying on
that exception means the same input is refused on one machine and accepted on
another, so the depth is counted here, in linear time, before parsing."""

import json
import re

#: Real JSON documents are a handful of levels deep.
MAX_DEPTH = 400

_TOKENS = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[\[\]{}]', re.DOTALL)


def check(text: str, limit: int = MAX_DEPTH) -> None:
    """Raise RecursionError when [ / { nesting (outside strings) is deeper than
    `limit`. RecursionError is what callers already handle for deep input."""
    if text.count("[") + text.count("{") <= limit:
        return                                  # cannot be that deep
    depth = 0
    for m in _TOKENS.finditer(text):
        c = m.group()
        if c in "[{":
            depth += 1
            if depth > limit:
                raise RecursionError("nested too deeply")
        elif c in "]}":
            depth -= 1


def loads(text, **kw):
    """json.loads with the depth limit; `text` may be str or bytes."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8")
    check(text)
    return json.loads(text, **kw)

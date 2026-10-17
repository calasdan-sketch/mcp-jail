"""A piped stdout on Windows reports errors="surrogateescape" (measured on
Windows 11 / Python 3.11, encoding cp1252), not "strict". The hardening that
keeps a report from dying on a mark such as the cross or the arrow must treat
both alike -- it used to skip anything that was not "strict"."""
from __future__ import annotations

import io
import sys
import unittest
from unittest import mock

from mcp_jail import cli as cli_mod


class TestHardenStreams(unittest.TestCase):
    def _text_stream(self, errors: str):
        raw = io.BytesIO()
        return raw, io.TextIOWrapper(raw, encoding="cp1252", errors=errors,
                                     newline="")

    def test_strict_and_surrogateescape_streams_stop_raising(self):
        for errors in ("strict", "surrogateescape"):
            raw, stream = self._text_stream(errors)
            with mock.patch.object(sys, "stdout", stream), \
                    mock.patch.object(sys, "stderr", io.StringIO()):
                cli_mod._harden_streams()
            stream.write("\u2717 mark \u2192 arrow")
            stream.flush()
            self.assertEqual(raw.getvalue(), b"? mark ? arrow", errors)

    def test_a_lenient_handler_chosen_by_the_user_is_left_alone(self):
        raw, stream = self._text_stream("backslashreplace")
        with mock.patch.object(sys, "stdout", stream), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            cli_mod._harden_streams()
        self.assertEqual(stream.errors, "backslashreplace")


if __name__ == "__main__":
    unittest.main()

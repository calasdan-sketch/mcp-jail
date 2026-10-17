"""Windows reports a reader that has gone away as OSError(EINVAL) out of the
flush -- not as BrokenPipeError -- and fails a second time at interpreter
exit (status 120) unless fd 1 was pointed at the null device first. These
tests reproduce that on any OS. The real-pipe subprocess tests elsewhere in
this suite are the proof on a real Windows machine."""
from __future__ import annotations

import errno
import io
import sys
import unittest
from unittest import mock

from mcp_jail import cli as cli_mod


class _DeadPipe(io.StringIO):
    """Writes are buffered fine; the flush says what Windows says once the
    reader of the pipe is gone."""

    def __init__(self, exc: BaseException):
        super().__init__()
        self._exc = exc

    def flush(self):
        raise self._exc


def _einval(*extra) -> OSError:
    return OSError(errno.EINVAL, "Invalid argument", *extra)


class TestPipeGoneHelper(unittest.TestCase):
    def test_which_errors_mean_the_reader_is_gone(self):
        with mock.patch.object(cli_mod, "_WINDOWS", True):
            self.assertTrue(cli_mod._pipe_gone(BrokenPipeError()))
            self.assertTrue(cli_mod._pipe_gone(OSError(errno.EPIPE, "Broken pipe")))
            self.assertTrue(cli_mod._pipe_gone(_einval()))
            # an EINVAL that names a file is an open()/stat() problem, not a pipe
            self.assertFalse(cli_mod._pipe_gone(_einval("somefile.txt")))
            self.assertFalse(cli_mod._pipe_gone(OSError(errno.ENOSPC, "No space")))
            self.assertFalse(cli_mod._pipe_gone(ValueError("x")))
        with mock.patch.object(cli_mod, "_WINDOWS", False):
            self.assertTrue(cli_mod._pipe_gone(BrokenPipeError()))
            self.assertTrue(cli_mod._pipe_gone(OSError(errno.EPIPE, "Broken pipe")))
            # EINVAL is a Windows-only way of saying "pipe closed"
            self.assertFalse(cli_mod._pipe_gone(_einval()))


class TestWindowsClosedPipe(unittest.TestCase):
    def _call(self, windows: bool, exc: BaseException):
        gone: list[int] = []
        with mock.patch.object(cli_mod, "_WINDOWS", windows), \
                mock.patch.object(cli_mod, "_broken_pipe", lambda: (gone.append(1), 0)[1]), \
                mock.patch.object(sys, "stdout", _DeadPipe(exc)):
            with mock.patch.object(cli_mod, "_main", lambda argv: print("hello") or 0):
                rc = cli_mod.main([])
        return rc, gone

    def test_einval_out_of_the_flush_is_a_quiet_exit_on_windows(self):
        rc, gone = self._call(True, _einval())
        self.assertEqual(rc, 0)
        self.assertEqual(gone, [1], "fd 1 must be pointed at the null device")

    def test_broken_pipe_and_epipe_are_quiet_everywhere(self):
        for windows in (False, True):
            for exc in (BrokenPipeError(errno.EPIPE, "Broken pipe"),
                        OSError(errno.EPIPE, "Broken pipe")):
                rc, gone = self._call(windows, exc)
                self.assertEqual((rc, gone), (0, [1]))

    def test_einval_off_windows_is_still_an_error(self):
        gone: list[int] = []
        with self.assertRaises(OSError):
            self._call_raising(False, _einval(), gone)
        self.assertEqual(gone, [])

    def test_einval_naming_a_file_is_not_a_pipe(self):
        gone: list[int] = []
        with self.assertRaises(OSError):
            self._call_raising(True, _einval("somefile.txt"), gone)
        self.assertEqual(gone, [])

    def _call_raising(self, windows, exc, gone):
        with mock.patch.object(cli_mod, "_WINDOWS", windows), \
                mock.patch.object(cli_mod, "_broken_pipe", lambda: (gone.append(1), 0)[1]), \
                mock.patch.object(sys, "stdout", _DeadPipe(exc)):
            with mock.patch.object(cli_mod, "_main", lambda argv: print("hello") or 0):
                rc = cli_mod.main([])


if __name__ == "__main__":
    unittest.main()

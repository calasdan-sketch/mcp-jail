"""Deeply nested JSON is refused by a limit of our own, not by whatever
RecursionError the Python version and stack size happen to give (3.14 parses
100000 levels when the stack is big)."""

import time
import unittest

from mcp_jail import _depth


class TestDepthGuard(unittest.TestCase):
    def test_deep_input_is_refused_on_every_python(self):
        deep = "[" * 100000 + "]" * 100000
        with self.assertRaises(RecursionError):
            _depth.loads(deep)
        with self.assertRaises(RecursionError):
            _depth.check('{"a":' * (_depth.MAX_DEPTH + 1))

    def test_ordinary_input_and_brackets_inside_strings_are_fine(self):
        self.assertEqual(_depth.loads('{"a": [1, {"b": "[[[[{{{{"}]}'), {"a": [1, {"b": "[[[[{{{{"}]})
        self.assertEqual(_depth.loads(b'[1]'), [1])
        ok = "[" * 300 + "]" * 300
        _depth.check(ok)
        with self.assertRaises(ValueError):
            _depth.loads("[1,")

    def test_a_lot_of_brackets_in_strings_costs_little_time(self):
        text = '["' + "[" * 2_000_000 + '"]'
        started = time.perf_counter()
        _depth.check(text)
        self.assertLess(time.perf_counter() - started, 5.0)


if __name__ == "__main__":
    unittest.main()

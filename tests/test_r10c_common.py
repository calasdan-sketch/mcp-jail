"""Common release hygiene (round 10c): one version, typed marker, a security
policy, and a release that tests before it publishes."""

import os
import re
import unittest

import mcp_jail

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HAVE_ROOT = os.path.exists(os.path.join(ROOT, "pyproject.toml"))


def _read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


@unittest.skipUnless(HAVE_ROOT, "not a source checkout")
class TestReleaseHygiene(unittest.TestCase):
    def test_the_version_is_written_once_and_matches_pyproject(self):
        found = re.search(r'(?m)^version\s*=\s*"([^"]+)"', _read("pyproject.toml"))
        self.assertEqual(mcp_jail.__version__, found.group(1))

    def test_the_package_is_marked_typed_and_ships_the_marker(self):
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "mcp_jail", "py.typed")))
        self.assertIn("py.typed", _read("pyproject.toml"))

    def test_there_is_a_security_policy_with_a_contact(self):
        text = _read("SECURITY.md")
        self.assertIn("calasdan@gmail.com", text)
        self.assertIn("Report a vulnerability", text)

    def test_publishing_waits_for_the_tests(self):
        path = os.path.join(ROOT, ".github", "workflows", "release.yml")
        if not os.path.exists(path):
            self.skipTest("workflows are not shipped in the sdist")
        text = _read(".github", "workflows", "release.yml")
        self.assertIn("needs: [test, build]", text)
        self.assertIn("python -m unittest discover -s tests", text)


if __name__ == "__main__":
    unittest.main()

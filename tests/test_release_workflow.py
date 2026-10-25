"""The release workflow must be valid YAML that means what it says, and its
checks must work when run for real (round 10).

0.6.3 shipped `run: python - <<'PY'` followed by an indented script. In YAML
that is a plain scalar: the lines fold into ONE line, the heredoc never ends
and every release fails. These tests read the workflow files with the
standard library only (no YAML package), run the shell steps with a faked
GITHUB_REF_NAME / GITHUB_SHA, and check the CI file builds the sdist and
runs its tests."""

import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")
POSIX = os.name == "posix" and shutil.which("bash") and shutil.which("git")

_RUN_RE = re.compile(r"^(?P<indent> *)(?:- )?run:(?: +(?P<value>.*))?$")
_NAME_RE = re.compile(r"^ *- name: *(?P<name>.*)$")


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def project():
    text = read("pyproject.toml")
    name = re.search(r'(?m)^name = "([^"]+)"', text).group(1)
    version = re.search(r'(?m)^version = "([^"]+)"', text).group(1)
    return name, version


def run_steps(text):
    """[(name or None, script)] for every `run:` of a workflow. A block scalar
    (`run: |`) is returned dedented; a plain one-line value as it is. A plain
    value that CONTINUES on the next, more indented lines is the bug and
    raises."""
    lines = text.split("\n")
    out = []
    name = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("- "):
            name = None             # a new step
        m = _NAME_RE.match(line)
        if m:
            name = m.group("name")
        m = _RUN_RE.match(line)
        if not m:
            i += 1
            continue
        indent = len(m.group("indent"))
        value = (m.group("value") or "").strip()
        j = i + 1
        body = []
        while j < len(lines) and (not lines[j].strip()
                                  or len(lines[j]) - len(lines[j].lstrip())
                                  > indent):
            body.append(lines[j])
            j += 1
        if value[:1] in ("|", ">"):
            pad = min((len(b) - len(b.lstrip()) for b in body if b.strip()),
                      default=0)
            out.append((name, "\n".join(b[pad:] for b in body).rstrip() + "\n"))
        else:
            if any(b.strip() for b in body):
                raise ValueError(
                    "line %d: `run: %s` is a plain value that continues on "
                    "the next lines; YAML folds it into one line (use `run: "
                    "|`)" % (i + 1, value))
            out.append((name, value))
        i = j
    return out


class TestWorkflowSyntax(unittest.TestCase):
    def test_no_run_value_folds_into_one_line(self):
        files = sorted(glob.glob(os.path.join(WORKFLOWS, "*.yml")))
        self.assertTrue(files)
        for path in files:
            with open(path, encoding="utf-8") as f:
                run_steps(f.read())     # raises on a folded run

    def test_the_detector_catches_the_0_2_4_bug(self):
        bad = ("steps:\n"
               "      - name: tag must equal package version\n"
               "        run: python - <<'PY'\n"
               "          import os\n"
               "          PY\n")
        with self.assertRaises(ValueError):
            run_steps(bad)

    def test_a_block_scalar_is_read_as_a_script(self):
        good = ("steps:\n  - run: |\n      python - <<'PY'\n"
                "      print(1)\n      PY\n")
        (name, script), = run_steps(good)
        self.assertEqual(script, "python - <<'PY'\nprint(1)\nPY\n")

    def test_no_tabs_in_workflows(self):
        for path in glob.glob(os.path.join(WORKFLOWS, "*.yml")):
            with open(path, encoding="utf-8") as f:
                self.assertNotIn("\t", f.read(), path)


class TestCiBuildsAndTestsTheSdist(unittest.TestCase):
    def setUp(self):
        self.ci = read(".github", "workflows", "ci.yml")

    def test_ci_builds_and_extracts_the_sdist_and_runs_its_tests(self):
        scripts = [s for _, s in run_steps(self.ci)]
        self.assertTrue(any("tar -xzf dist/*.tar.gz" in s
                            and "unittest discover -s tests" in s
                            for s in scripts), scripts)

    def test_ci_covers_python_3_10_to_3_14(self):
        for v in ("3.10", "3.11", "3.12", "3.13", "3.14"):
            self.assertIn('"%s"' % v, self.ci)

    def test_release_runs_the_sdist_tests_before_publishing(self):
        release = read(".github", "workflows", "release.yml")
        scripts = [s for _, s in run_steps(release)]
        self.assertTrue(any("tar -xzf dist/*.tar.gz" in s for s in scripts))


@unittest.skipUnless(POSIX, "needs bash and git")
class TestReleaseStepsRunForReal(unittest.TestCase):
    def setUp(self):
        self.release = read(".github", "workflows", "release.yml")
        self.steps = dict(run_steps(self.release))
        self.tmp = tempfile.mkdtemp(prefix="wf-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def sh(self, script, cwd, **env):
        full = dict(os.environ, PATH=os.path.dirname(sys.executable)
                    + os.pathsep + os.environ["PATH"], **env)
        full["PYTHONPATH"] = ""
        return subprocess.run(["bash", "-eo", "pipefail", "-c", script],
                              cwd=cwd, env=full, capture_output=True,
                              text=True, timeout=60)

    def test_tag_check_passes_for_the_matching_tag(self):
        name, version = project()
        stem = name.replace("-", "_") + "-" + version
        os.makedirs(os.path.join(self.tmp, "dist"))
        for fname in (stem + ".tar.gz", stem + "-py3-none-any.whl"):
            open(os.path.join(self.tmp, "dist", fname), "wb").close()
        script = self.steps["tag must equal package version"]
        ok = self.sh(script, self.tmp, GITHUB_REF_NAME="v" + version)
        self.assertEqual(ok.returncode, 0, ok.stderr)

    def test_tag_check_fails_for_another_tag(self):
        name, version = project()
        stem = name.replace("-", "_") + "-" + version
        os.makedirs(os.path.join(self.tmp, "dist"))
        open(os.path.join(self.tmp, "dist", stem + ".tar.gz"), "wb").close()
        script = self.steps["tag must equal package version"]
        bad = self.sh(script, self.tmp, GITHUB_REF_NAME="v9.9.9")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("AssertionError", bad.stderr)

    def git(self, cwd, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        r = subprocess.run(["git", *args], cwd=cwd, env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def clone_with_main(self):
        origin = os.path.join(self.tmp, "origin.git")
        work = os.path.join(self.tmp, "work")
        self.git(self.tmp, "init", "-q", "--bare", "-b", "main", origin)
        self.git(self.tmp, "clone", "-q", origin, work)
        self.git(work, "checkout", "-q", "-b", "main")
        open(os.path.join(work, "a"), "w").close()
        self.git(work, "add", "a")
        self.git(work, "commit", "-qm", "one")
        self.git(work, "push", "-q", "origin", "main")
        return work

    def test_a_commit_on_main_is_released(self):
        work = self.clone_with_main()
        sha = self.git(work, "rev-parse", "HEAD")
        script = self.steps["tagged commit must be on main"]
        r = self.sh(script, work, GITHUB_SHA=sha, GITHUB_REF_NAME="v1")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_commit_that_is_not_on_main_is_refused(self):
        work = self.clone_with_main()
        self.git(work, "checkout", "-q", "-b", "feature")
        open(os.path.join(work, "b"), "w").close()
        self.git(work, "add", "b")
        self.git(work, "commit", "-qm", "two")
        self.git(work, "push", "-q", "origin", "feature")
        sha = self.git(work, "rev-parse", "HEAD")
        script = self.steps["tagged commit must be on main"]
        r = self.sh(script, work, GITHUB_SHA=sha, GITHUB_REF_NAME="v1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not on main", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()

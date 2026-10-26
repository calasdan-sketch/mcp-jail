# Changelog

## 0.7.0

- Tests only: the linear-time reader test repeats a noisy timing attempt (three tries) so a busy CI runner cannot fail it; a quadratic reader still fails all three.

- **New: `--lockfile mcp.lock`.** Compares every `tools/list` answer with the
  lockfile `mcp-audit lock` writes (format in `docs/LOCKFILE.md`, shared with
  mcp-audit and covered by the same test vectors). `--on-drift` says what
  happens to a new or changed tool: `block` (default), `strip`, `ask` or
  `warn`. Every finding goes to the audit log. A different server command
  than the locked one stops the start. `--lock-server NAME` picks the entry.
  Hashes only: nothing is scored or guessed.
- **New: `--shadow`** (and `--shadow-report FILE`). Checks the policy and the
  lockfile, enforces nothing, and reports what would have been blocked.
  Denied calls do reach the server in this mode.
- **New: `mcp-jail verify-policy --policy P --session S`.** Replays a recorded
  session against a policy and checks each decision. Exit 0, 1 or 2.
  `mcp-jail learn --record FILE` writes such a session.
- `--audit` shows lockfile findings and `SHADOW` records.
- Waiting for an `--on-drift ask` answer no longer counts against `--timeout`.

## 0.6.4

- **Fixed: every release failed.** The release workflow's version check was a
  YAML plain value that folds into one line, so the script never ran. It is a
  block (`run: |`) now, and a test reads the workflow, runs the checks with a
  faked tag and commit, and fails if a `run:` ever folds again. The workflow
  also refuses a tag whose commit is not on `main` and runs the tests from the
  built sdist; CI does the same on every change and also runs Python 3.14.
- **Fixed: several jails could erase the audit history.** Jails that share
  `~/.mcp-jail/audit.jsonl` could all see the log over its limit; the second
  rename then moved the new, nearly empty log over `audit.jsonl.1`. The size is
  now checked again, and the file moved, under a lock (`audit.jsonl.lock`).
- **Fixed: an oversize server response could leave its request waiting.** The
  `id` was only looked for at the start of the message. The last 4 KB are kept
  too, so `{"result":...,"id":7}` fails request 7 at once. An `id` inside a
  nested object or a string is still not trusted.
- `--max-message-bytes` above 2^40 (1 TiB) is refused; larger numbers used to
  end in an `OverflowError` traceback and a dead session.
- The starter-policy warning ("allows every tool and blocks nothing") is no
  longer shown for a policy with `strict_args` on, which does block.
- `mcp-jail learn` takes `--max-message-bytes` and uses it (it was fixed at the
  default).

## 0.6.3

- **Memory and time:** a message from the client or the server is read in
  linear time and is never held past `--max-message-bytes` (default 16 MiB,
  at least 1024). Before, the client reader rescanned its whole buffer after
  every 64 KB chunk (a 200 MB line took 17 s) and the server reader had no
  limit at all (a 400 MB response used 1.6 GB). A longer client message is
  refused with `-32600` (under its id when the first bytes show one), a longer
  server response fails the request it answers with `-32603`, both with an
  audit record (`rejected`); the rest of the line is discarded unread.
- `--init-policy` says that the starter policy allows every tool and blocks
  nothing and points to `mcp-jail learn`; the file carries a `_examples` note
  with stricter policies; an untouched starter warns each time `mcp-jail`
  starts with it. A `--path` it cannot write is one line and exit 2, not a
  traceback.
- The audit log is rotated to `audit.jsonl.1` past 10 MiB
  (`MCP_JAIL_AUDIT_MAX_MB`; `0` never rotates).
- README: `pip install mcp-jail`; allow lists fold case and NFKC like deny
  lists (stated under Limitations); the unrelated PyPI project `mcpjail` is
  named so the two are not confused.
- Package metadata (authors, keywords, classifiers, URLs), `MANIFEST.in` so the
  sdist carries the tests, GitHub Actions CI and a trusted-publishing release
  workflow.

## 0.6.2 and earlier

See the git history.

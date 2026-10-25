# Changelog

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

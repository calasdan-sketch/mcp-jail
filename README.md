# mcp-jail (`mcp-jail`)

Runtime permission firewall for MCP servers. mcp-audit *finds* the
problems; mcp-jail *enforces* least-privilege at the moment a tool call
fires. It's a stdio proxy: it sits between your MCP client and the real
server, checks every `tools/call` against a JSON policy, and forwards or
denies. Denied calls get a JSON-RPC error plus an append-only audit-log
line — never execution.

Zero client changes: swap the server command for the jail wrapper.

```json
"my-server": {
  "command": "mcp-jail",
  "args": ["--policy", "~/.mcp-jail/policy.json",
           "--", "npx", "-y", "some-mcp-server"]
}
```

`~` and environment variables in `--policy` are expanded by mcp-jail
itself (the client passes these arguments straight from its JSON config,
no shell in between). The server command is looked up on `PATH` the way
the OS does — on Windows `npx` resolves to `npx.cmd` — and a command
that is not there is a clean `exit 2`, not a traceback.

## Install

Zero dependencies — Python 3.10+ stdlib only.

```bash
pip install git+https://github.com/calasdan-sketch/mcp-jail
mcp-jail --version
```

## Usage

```bash
mcp-jail --init-policy                       # annotated starter policy
mcp-jail --policy policy.json -- npx -y some-mcp-server
mcp-jail --policy policy.json --timeout 10 -- npx -y some-mcp-server
mcp-jail --audit                             # who got denied lately
mcp-jail learn --script calls.json --out policy.json -- npx -y some-mcp-server
mcp-jail --help                              # every flag, explained
```

Policy (`policy.json`):

```json
{
  "allow_tools": ["*"],
  "deny_tools": ["delete_all", "run_cmd"],
  "arg_rules": {
    "read_file": {"deny": {"**.path": ["^/etc/", "\\.\\."]}, "allow": {}},
    "run_cmd":   {"deny": ["rm -rf"], "allow": {"cmd": ["^(?:ls|cat) "]}}
  },
  "strict_args": false,
  "audit_args": "denied",
  "hide_denied": true
}
```

- `allow_tools` / `deny_tools`: tool names (`*` = all). Deny wins.
- `arg_rules`: per-tool regexes keyed by **argument path**, matched
  against every value in the arguments however deeply it is nested
  (see *Argument paths* below) — block `rm -rf` in a shell tool while
  allowing `ls`. A tool's `"allow"` may also be the string `"*"`: any
  arguments (deny rules still apply).
- `strict_args` (default `false`): when `true`, a tool with no allow
  patterns accepts only *empty* arguments instead of anything. `learn`
  generates `true` so a tool that was only ever called bare stays bare.
- `audit_args`: which calls get their argument values written to the
  audit log — `"denied"` (default), `"all"` or `"none"`.
- `hide_denied`: strip tools that are denied *by name* (`deny_tools`, or
  missing from an explicit `allow_tools`) from every `tools/list` page
  so the agent never sees them. A hidden tool's `tools/call` is denied
  too. Argument rules never hide a tool — they are decided per call.

Every allowed/denied call lands in `~/.mcp-jail/audit.jsonl`
(`%USERPROFILE%\.mcp-jail\audit.jsonl` on Windows): tool, decision,
reason, timestamp. The file is created with mode `0600` (owner only;
best effort on Windows, where the per-user profile is the fence) and,
by default, carries argument values **only for denied calls** — the
arguments of allowed calls are routinely tokens, file contents and
prompts, and a log of them is a second copy of your secrets. Logged
string values are cut to 200 characters. `audit_args: "all"` turns full
logging on if you want it.

`--timeout N` (default 30): seconds to wait for each server response
before the jail fails closed with a JSON-RPC timeout error. A silent
or wedged server can never hang your client.

## Argument paths

An argument path names where a value sits in the call's `arguments`:
segments are separated by `.`, array elements are addressed by index,
`*` matches exactly one segment (any key or index) and `**` matches any
number of segments, including none.

| path            | matches                                                |
|-----------------|--------------------------------------------------------|
| `path`          | the top-level `path` argument                          |
| `files.*.path`  | `path` inside every element of `files`                 |
| `**.path`       | every `path` key at any depth                          |
| `**` (or `""`)  | every value anywhere                                   |

A plain list of patterns (`"deny": ["rm -rf"]`) is shorthand for
`{"**": ["rm -rf"]}`.

What a pattern is matched against (always with `re.search`): the value
itself for strings; `true`/`false`/`null`/the number as JSON text for
other scalars. Object keys are not matched. `arguments` must be a JSON
object — a string or array in its place is denied outright (`-32602`),
since path rules cannot be applied to it. Arguments nested more than
100 levels deep are denied too.

- **deny**: a rule at path `P` is checked against every value at `P`
  *and below it*. Wrapping a value in an object or array hides nothing:
  `{"path": {"$ref": "/etc/passwd"}}` is caught by a `path` rule, and
  `{"path": ["..", "secret"]}` by `\.\.`. Arrays of scalars are also
  checked as one space-joined string, so `["rm", "-rf", "/"]` is seen
  as `rm -rf /`. Key names in deny paths are **case-insensitive**:
  a `path` rule also catches `Path` and `PATH`. Prefer `**.path` over
  `path` for file arguments, so `{"files": [{"path": ...}]}` is covered.
- **allow**: when a tool has any allow rules, **every** value in the
  call must match an allow rule whose path matches the value's path
  exactly (`*`/`**` in the rule, not the value; key names exact — an
  allowlist admits the shape it learned). Allow patterns are not OR'd
  across arguments, a value smuggled in at an unlisted path is denied,
  and a nested object where a string was expected is denied. Empty
  objects/arrays carry no values and pass. Anchor allow patterns
  (`^...$`) — `learn` does.
- **`..` is never allowed in by accident**: a value containing a `..`
  path segment (`/srv/data/../../etc/passwd`, `..\x`, a bare `..`) is
  not admitted by any allow pattern unless that pattern itself spells
  out `\.\.`. An allowlist on paths must not be a door to the whole
  filesystem.

## Policy authoring

Policies are JSON. `allow_tools` / `deny_tools` are tool names
(`*` = all, deny wins). `arg_rules` map argument paths to regexes, as
above.

**Honest limitation — read this before writing deny patterns.**
Deny patterns are *syntactic*: they match the argument text, not what
the argument will *do*. A deny pattern like `rm -rf` is bypassed by

```json
{"cmd": "rm${IFS}-rf /"}
```

because the *shell* expands `${IFS}` to a space at execution time —
the pattern never sees the real command. Same story for `$(...)`
indirection, quote games, and every other shell obfuscation. A regex
cannot parse shell, so deny-patterns are a speed bump, never a wall.

The recommended posture is the inverse: **default-deny allowlists**,
generated by `learn` (below) — permit exactly the tools and argument
shapes you observed, nothing more. An attacker who can't get their
tool or their argument shape past the allowlist never reaches the
shell at all. One more caveat, same honesty:

- `learn` can only allowlist what it saw. Traffic you didn't exercise
  during learning stays denied — that's the point, but budget a
  re-learn pass when your agent's usage grows.

## learn: generate a policy from observed traffic

Instead of hand-writing regexes, watch the server and let mcp-jail
write the tightest-fit allowlist: only the tools actually **called and
answered successfully** (no `*`; tools the server merely listed are
reported under `_not_called` and denied), and per-argument `allow`
patterns derived conservatively from observed values — literal
longest-common-prefix plus the smallest character class covering what
was seen (`[0-9]`, `[a-z]`, `[a-zA-Z0-9_.-]`, `[a-zA-Z0-9_/.-]`), never
`.*`, each class pattern guarded against `..` segments. Values with no
useful shared prefix fall back to exact alternation of observed
literals; numbers (exponent notation included), bools, nulls, and
nested structures get exact-shape patterns. A tool only ever called
with empty arguments accepts only empty arguments (`strict_args`).

Two modes:

```bash
# (a) scripted: drive canned calls against the server, no client needed
mcp-jail learn --script calls.json --out policy.json -- npx -y some-mcp-server

# (b) live: proxy a real session until stdin EOF or Ctrl-C, then emit
mcp-jail learn --out policy.json -- npx -y some-mcp-server
```

`calls.json`:

```json
[
  {"tool": "read_file", "arguments": {"path": "/tmp/a.txt"}},
  {"tool": "read_file", "arguments": {"path": "/tmp/b.txt"}},
  {"tool": "run_cmd",   "arguments": {"cmd": "ls", "count": 3}}
]
```

Generated `policy.json` (abridged):

```json
{
  "allow_tools": ["read_file", "run_cmd"],
  "_not_called": ["delete_all"],
  "deny_tools": [],
  "arg_rules": {
    "read_file": {"allow": {"path": ["^(?!.*(?:^|/)\\.\\.(?:/|$))/tmp/[a-zA-Z0-9_.-]*$"]}, "deny": {}},
    "run_cmd":   {"allow": {"cmd": ["^ls$"],
                            "count": ["^-?\\d+(?:\\.\\d+)?(?:[eE][-+]?\\d+)?$"]}, "deny": {}}
  },
  "strict_args": true,
  "audit_args": "denied",
  "hide_denied": true
}
```

Nested arguments become nested paths (`cfg.a`), array elements collapse
to `*` (`tags.*`), and every value in a call must match the pattern for
its path — an unseen argument, or a seen one with an unseen shape, is
denied. A call the server answered with an error (or an MCP `isError`
result) is not learned; neither is a call whose `arguments` is not an
object.

The policy goes to stdout or `--out`; a short summary (tools listed,
tools called, successful calls) goes to stderr. Review the generated
file before enforcing it — it permits exactly what was seen, nothing
more; to let one tool take any arguments, set its `"allow"` to `"*"`.
A server that hangs during `learn` times out per `--timeout` instead
of wedging the session.

## Protocol handling

The jail is a transparent JSON-RPC relay apart from the policy check:

- Requests and responses are matched by **id, exactly** (`1`, `"1"` and
  `1.0` are three different ids). A denied request gets an error with
  the same id and type as the request. A denied *notification* (no id)
  is audited and dropped — notifications never get a response. A
  request with `"id": null` (forbidden by MCP) gets `-32600`.
- A `tools/call` is forwarded **re-serialised from the object the
  policy checked**, never as the client's bytes; every other message
  passes through byte-for-byte. A document with duplicate keys
  anywhere (`{"name":"delete_all","name":"read_file"}` — which tool
  that names depends on who parses it) is refused with `-32600`,
  from either side.
- Upstream responses are passed through byte-for-byte; only
  `tools/list` results are re-serialised when `hide_denied` filters
  them. Server notifications (`notifications/message`, progress,
  `tools/list_changed`) and server-to-client requests (sampling,
  roots, elicitation) pass straight through, and the client's answers
  go straight back. A batch response from the server is delivered
  once, as one array.
- JSON-RPC batch arrays from the client are split and handled element
  by element.
- A request the server never answers within `--timeout` gets a
  `-32603 server timed out` error; a response that arrives later for
  that id is dropped, so the client never sees two answers. A non-JSON
  line on the server's stdout fails the longest-waiting request with
  `-32603 bad response from server`; the proxy stays up. Malformed
  input from the client gets `-32700` / `-32600` as the spec says —
  including JSON nested a hundred thousand levels deep, which is an
  attack on the proxy's stack, not a reason for it to exit.
- When the server exits, pending requests fail with `-32603 server
  closed` and the proxy exits cleanly, even while the client still
  holds its stdin open.
- Wire format: newline-delimited JSON, UTF-8 regardless of console
  code page. Both pipes are pumped by reader threads into one queue —
  no `select()` on pipes — so it runs the same on Windows 11 as on
  Linux/macOS.

## Why not just audit?

Audit is point-in-time. The ecosystem installs MCP servers recklessly and
a poisoned tool description fires at *use* time — exactly when no scanner
is watching. The jail is the enforcement half of the story.

## Tests

```bash
python3 -m unittest discover -s tests   # 82 tests, fake stdio servers
python3 -m pytest -q                    # same suite
```

Tests spawn fake MCP servers as subprocesses and point `HOME`,
`USERPROFILE` and `APPDATA` at a throwaway directory, so they never
touch your real `~/.mcp-jail`.

## License

MIT — see `LICENSE`.

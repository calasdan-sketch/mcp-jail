# mcp-jail (`mcp-jail`)

Runtime permission firewall for MCP servers. mcp-audit *finds* the
problems; mcp-jail *enforces* least-privilege at the moment a tool call
fires. It's a stdio proxy: it sits between your MCP client and the real
server, checks every `tools/call` against a JSON policy, and forwards or
denies. Denied calls get a JSON-RPC error plus an append-only audit-log
line — never execution.

**Scope, plainly:** the tool policy is applied to `tools/call` (and to
any other method you list in `policed_methods`, such as `prompts/get`
or `resources/read`). Whole JSON-RPC methods can be refused with
`deny_methods`. Everything else — resources, prompts, completions,
notifications, server-to-client requests — is relayed unchecked (though
re-serialised, see *Protocol handling*).

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
mcp-jail --policy policy.json --grace 10 -- npx -y some-mcp-server
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
    "run_cmd":   {"deny": ["rm -rf"], "allow": {"cmd": ["^(?:ls|cat) "],
                                                 "count": [{"type": "number"}]}}
  },
  "policed_methods": ["tools/call"],
  "deny_methods": ["resources/*"],
  "strict_args": false,
  "audit_args": "denied",
  "hide_denied": true
}
```

The policy is checked when mcp-jail starts, and anything it cannot read
unambiguously is refused (exit `2`, the server is never started): an
**unknown key** at any level — the top level, or inside an `arg_rules`
entry, which takes only `allow` and `deny` — with a suggestion
(`unknown key 'alow_tools' (did you mean 'allow_tools'?)`); a
**duplicate key** (a JSON reader keeps only the last one, so a second
`deny_tools` would silently replace the first); a tool list that holds
anything but non-empty strings; a bad regex. `_comment` (and
`_not_called`, which `learn` writes) are notes and are never read.
Leaving `allow_tools` out is allowed and means "every tool that
`deny_tools` does not name"; write `"allow_tools": []` to allow nothing.
A policy path that is a directory, or cannot be read, is the same exit
`2`, not a traceback.

- `allow_tools` / `deny_tools`: tool names (`*` = all). Deny wins.
  Names are compared **normalised** — Unicode NFKC, case-folded,
  trimmed, invisible characters (zero-width space, soft hyphen, BOM,
  control and combining marks) removed — so `Delete_All`,
  `delete_all ` and `delete_all` plus a U+200B are all `delete_all`. The same
  normalised name selects a tool's `arg_rules`.
- `arg_rules`: per-tool regexes keyed by **argument path**, matched
  against every value in the arguments however deeply it is nested
  (see *Argument paths* below) — block `rm -rf` in a shell tool while
  allowing `ls`. A rule is a regex string, or a **typed rule**
  `{"type": "number", "pattern": "..."}` that admits only values of
  that JSON type (`string`, `number`, `boolean`, `null`, `object`,
  `array`; either key may be omitted). A tool's `"allow"` may also be
  the string `"*"`: any arguments (deny rules still apply).
- `policed_methods` (default `["tools/call"]`): the JSON-RPC methods
  whose parameters go through the tool policy (`allow_tools` /
  `deny_tools` / `arg_rules`). `tools/call` is always policed. Each
  method is judged by the field that really selects what the call
  touches, and by nothing else: `tools/call` and `prompts/get` by
  `params.name` (with `params.arguments` as the arguments);
  `resources/read`, `resources/subscribe` and `resources/unsubscribe` by
  `params.uri`; `completion/complete` by its `params.ref`, the `name` of
  a `ref/prompt` or the `uri` of a `ref/resource`; any other method you
  list, by whichever of `name` and `uri` it carries (exactly one). A
  second selector beside the right one
  (`{"uri": "file:///etc/passwd", "name": "harmless"}`), a `ref` that is
  both kinds, or a selector that is missing or not a string is refused
  with `-32602`: a server need not make the choice the jail would. The
  selector is compared the way a tool name is, with case ignored (see
  *Limitations*). `hide_denied` only filters `tools/list`.
- `deny_methods` (default `[]`): methods refused outright with `-32601`
  and an audit line — exact names or globs (`resources/*`,
  `prompts/get`), matched as written and ignoring case. Notifications
  matching it are dropped.
- `strict_args` (default `false`): when `true`, a tool with no allow
  patterns accepts only *empty* arguments — `{}` and nothing else; an
  empty object or array inside (`{"q": {}}`) is a value and is refused.
  `learn` generates `true` so a tool that was only ever called bare
  stays bare.
- `audit_args`: which calls get their argument values written to the
  audit log — `"denied"` (default), `"all"` or `"none"`.
- `hide_denied`: strip tools that are denied *by name* (`deny_tools`, or
  missing from an explicit `allow_tools`) from every `tools/list` page
  so the agent never sees them. A hidden tool's `tools/call` is denied
  too. Argument rules never hide a tool — they are decided per call.

Every allowed/denied call lands in `~/.mcp-jail/audit.jsonl`
(`%USERPROFILE%\.mcp-jail\audit.jsonl` on Windows): tool, decision,
reason, timestamp. A message the jail would not relay at all (see
*Protocol handling*) is a `deny` record too, with `rejected` set to
`client` or `server` and no tool. The file is created with mode `0600`
(owner only; best effort on Windows, where the per-user profile is the
fence) and, by default, carries argument values **only for denied
calls** — the arguments of allowed calls are routinely tokens, file
contents and prompts, and a log of them is a second copy of your
secrets. Logged string values are cut to 200 characters. `audit_args: "all"` turns full
logging on if you want it.

`--timeout N` (default 30; `0` waits for ever): seconds to wait for each
server response before the jail fails closed with a JSON-RPC timeout
error, and for the server to take each message off its stdin. N is a
finite number, 0 or more: `nan`, `inf` and negative values are refused
(exit `2`, nothing started). A silent
or wedged server can never hang your client: messages for the server
are queued and written by a thread of their own, so a server that has
stopped reading (its pipe is full: it hung, deadlocked, or is busy for
good) cannot freeze the jail. A message that has waited longer than N
seconds to be taken is a stall: every request still waiting gets
`-32603 server stopped reading its input`, the server is killed, and
mcp-jail exits `3`.

`--grace N` (default 5; `0` stops the server at once): when the client
closes its input and every request has been answered, mcp-jail does what
the MCP stdio transport asks of a client that is leaving. It finishes
writing what is queued, closes the server's stdin, and waits up to N
seconds for the server to finish and exit, relaying (and checking, and
auditing) whatever the server still says meanwhile, a last notification
for one. A server still running after N seconds is sent SIGTERM (on
Windows `terminate()`, which ends it outright) and, if it ignores that
for five more seconds, is killed; mcp-jail says so on stderr and still
exits `0`. A session that failed (exit `3`) does not wait. So a burst of
notifications sent just before the client went away reaches the server in
full, which `--grace 0` (stop the server as soon as the jail's own work is
done, the way mcp-jail used to) can lose. `learn` without `--script` ends
its session the same way and takes `--grace` too.

`mcp-jail --audit` shows every field of a record as printable text on
one line: a newline, a terminal escape sequence or a bidi override in a
reason or a tool name (the client chooses it) is shown as an escape
(`\n`, `\x1b`, `\u202e`), so it cannot forge a line of the report or
drive your terminal.

## Exit codes

| code | meaning |
|------|---------|
| `0`  | a clean session: the client finished and every request it sent was answered (a denied call is the jail doing its job, not a failure); or `--audit` / `--init-policy` / `learn` succeeded |
| `2`  | unusable input: a policy that is missing or refused (the server is never started), a server command that is not on `PATH`, an option value that is not a finite number of seconds, a `learn` session that ended early |
| `3`  | the server failed while the jail was relaying: it exited or closed its pipes while the client was still talking to it, stopped reading its input, or left a request unanswered past `--timeout` |

A wrapper (a CI job, a supervisor) can tell a server that died on
start-up from a session that ran.

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

A **value** is a scalar or an *empty* object/array; a non-empty object
or array is structure, and the values inside it are matched one by one.
What a pattern is matched against (always with `re.search`): the value
itself for strings; `true`/`false`/`null`/the number as JSON text for
other scalars; `{}` / `[]` for an empty container. A plain pattern
admits any value whose text matches, whatever its type — `^3$` admits
the number `3` and the string `"3"`; a typed rule
(`{"type": "number", "pattern": "^3$"}`) admits only its type. Object
keys are not matched. `arguments` must be a JSON object — a string or
array in its place is denied outright (`-32602`), since path rules
cannot be applied to it. Arguments nested more than 100 levels deep are
denied too.

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
  a nested object where a string was expected is denied, and so is an
  empty object or array at a path without a rule (`{"type": "array"}`
  admits an empty array; `learn` writes such a rule when it saw one).
  Anchor allow patterns: in an allow pattern `$` always means *end of
  the value* — mcp-jail compiles it as `\Z`, because Python's `$` also
  matches just before a trailing newline, and `^ls$` must not admit
  `"ls\n"`. (`learn` writes `\A...\Z` outright.)
- **`..` is never allowed in by accident**: a value containing a `..`
  path segment (`/srv/data/../../etc/passwd`, `C:\proj\..\.ssh`, `..\x`,
  a bare `..`) is not admitted by any allow pattern unless that pattern
  itself spells out `\.\.` — outside the `(?!...)` traversal guard that
  `learn` prepends, which does not count. An allowlist on paths must
  not be a door to the whole filesystem, on either separator.

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
reported under `_not_called` and denied), and per-argument **typed**
`allow` rules derived conservatively from observed values. Strings get
the literal longest-common-prefix plus the smallest character class
covering what was seen (`[0-9]`, `[a-z]`, `[a-zA-Z0-9_.-]`,
`[a-zA-Z0-9_/.-]`), never `.*`, each class pattern guarded against `..`
segments with either separator; values with no useful shared prefix
fall back to exact alternation of observed literals. Numbers (exponent
notation included), booleans and nulls get a rule for their type — a
learned `count` admits `3` and never the string `"3"`; a path seen with
two types gets one rule per type. Nested arguments become nested paths
(`cfg.a`), array elements collapse to `*` (`tags.*`), and an empty
object or array that was passed gets a rule of its own (`{}` / `[]`
only). Every pattern is anchored `\A...\Z`. A tool only ever called
with empty arguments accepts only empty arguments (`strict_args`).

Two modes:

```bash
# (a) scripted: drive canned calls against the server, no client needed
mcp-jail learn --script calls.json --out policy.json -- npx -y some-mcp-server

# (b) live: proxy a real session until stdin EOF or Ctrl-C, then emit
mcp-jail learn --out policy.json -- npx -y some-mcp-server
```

In scripted mode mcp-jail is the MCP client: it performs the real
handshake (`initialize` with `protocolVersion`, `capabilities` and
`clientInfo`, then `notifications/initialized`) before `tools/list` and
the calls — servers built on the official SDKs answer `-32602` to
everything until that handshake is complete. The server's protocol
revision is reported in the summary; a server that refuses
`initialize` stops `learn` with its error message and `exit 2`.

`calls.json` — a JSON array of `{"tool": name, "arguments": {...}}`
(`arguments` optional); it is validated before the server is started:

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
    "read_file": {"allow": {"path": [{"type": "string",
                                      "pattern": "\\A(?!.*(?:^|[/\\\\])\\.\\.(?:[/\\\\]|$))/tmp/[a-zA-Z0-9_.-]*\\Z"}]},
                  "deny": {}},
    "run_cmd":   {"allow": {"cmd":   [{"type": "string", "pattern": "\\Als\\Z"}],
                            "count": [{"type": "number",
                                       "pattern": "\\A-?\\d+(?:\\.\\d+)?(?:[eE][-+]?\\d+)?\\Z"}]},
                  "deny": {}}
  },
  "policed_methods": ["tools/call"],
  "deny_methods": [],
  "strict_args": true,
  "audit_args": "denied",
  "hide_denied": true
}
```

Every value in a call must match a rule for its path — an unseen
argument, or a seen one with an unseen shape or type, is denied. A call
the server answered with an error (or an MCP `isError` result) is not
learned; neither is a call whose `arguments` is not an object.

The policy goes to stdout or `--out`; a short summary (tools listed,
tools called, successful calls, the server's MCP revision) goes to
stderr. Review the generated file before enforcing it — it permits
exactly what was seen, nothing more; to let one tool take any
arguments, set its `"allow"` to `"*"`. A server that hangs during
`learn` times out per `--timeout` (`0` waits for ever) instead of wedging
the session.
Banner or log lines the server prints to stdout are reported and
skipped.

`learn` never ends in a traceback and never destroys a good policy: the
directory of `--out` is created (or refused) before the server starts;
if the server goes away mid-session (scripted or live) — refuses the
handshake, exits, closes its pipes, stops reading its input — `learn`
says so and exits `2` **without writing `--out`**, printing whatever
partial policy it had to stdout for review; if the final write to `--out` fails, the policy is printed to
stdout instead of being lost.

## Protocol handling

The jail is a transparent JSON-RPC relay apart from the policy check:

- Requests and responses are matched by **id, exactly** (`1`, `"1"` and
  `1.0` are three different ids). A denied request gets an error with
  the same id and type as the request. A denied *notification* (no id)
  is audited and dropped — notifications never get a response. A
  request with `"id": null` (forbidden by MCP) gets `-32600`.
- **Both directions carry the jail's own encoding, never the peer's
  bytes.** Every message, from the client and from the server, is
  parsed strictly and, once checked, **re-serialised** as compact,
  pure-ASCII JSON (every non-ASCII character an escape; no `NaN`,
  `Infinity` or whitespace padding). What the jail checked is then
  exactly what the other side parses. Two parsers reading the same
  bytes differently is how a filter gets bypassed: a Java server that
  ends a line at a bare CR runs a second, unchecked `tools/call`
  smuggled into the first, and a document with a key twice
  (`{"name":"delete_all","name":"read_file"}`) names whichever tool the
  reader keeps. So a message that is not one clean JSON line is
  **refused**, not repaired: a raw control character anywhere in the
  line (CR, TAB, NUL, ...; JSON has `\r` and `\t` for text), a
  duplicate key at any depth, `NaN` / `Infinity` / a number a double
  cannot hold (`1e999`), invalid UTF-8, a request without a string
  `method`, a response that is not exactly one of `result` and `error`
  (or that also names a `method`). A refused client message gets
  `-32700` / `-32600` under its own id (null when it has none, or none
  that can be trusted), a refused server message fails the request it
  answers (`-32603 bad response from server: ...`) or is dropped with a
  line on stderr, and each lands in the audit log as a `deny` record
  with `rejected` set to `client` or `server` (the offending line, cut
  to 200 characters, is kept unless `audit_args` is `none`).
  Integers of any size are exact; a decimal with more digits than an
  IEEE double holds is rounded to the nearest double, as every
  double-based parser would (see *Limitations*).
- **Member names are exact.** Some JSON readers (Go's `encoding/json`,
  C#'s `System.Text.Json` and Jackson when so configured) match member
  names without regard to case and let the last duplicate win, so
  `{"method":"ping","METHOD":"tools/call"}` is a ping to the jail and a
  tool call to such a server. A message with a member that is another
  spelling of `jsonrpc`, `id`, `method`, `params`, `result` or `error`
  (another case, a Unicode fold such as U+017F for `s`, invisible
  characters), or, in the `params` of a policed method, of `name`,
  `arguments`, `uri` or `ref`, is refused (`-32600`; `-32602` for
  `params`) and never normalised. The same goes for what the server
  sends: the envelope, `result.tools` / `nextCursor` of a `tools/list`
  page (the request fails closed), and each tool's `name` (an entry whose
  `name` has a second spelling is hidden, since `hide_denied` cannot tell
  which tool it names). Method *values* are read the way a
  case-insensitive router would: `Tools/Call` is policed as `tools/call`
  and `RESOURCES/LIST` is denied by `resources/*`.
- A method in `deny_methods` gets `-32601` and an audit line.
  Server notifications (`notifications/message`, progress,
  `tools/list_changed`) and server-to-client requests (sampling,
  roots, elicitation) are relayed, and the client's answers go back to
  the server, all re-serialised as above. `tools/list` results are
  filtered in place when `hide_denied` is on. A batch response from the
  server is delivered once, as one array.
- JSON-RPC batch arrays from the client are split and handled element
  by element.
- A request the server never answers within `--timeout` gets a
  `-32603 server timed out` error (and the session ends with exit status
  `3`); a response that arrives later for that id is dropped, so the
  client never sees two answers. A non-JSON
  line on the server's stdout (npm servers `console.log()` banners and
  progress there) answers nothing: it is reported on stderr and
  skipped, never charged to a pending request, whose real answer still
  gets through; a wedged server is caught by `--timeout`. Malformed
  input from the client gets `-32700` / `-32600` as the spec says —
  including JSON nested a hundred thousand levels deep, which is an
  attack on the proxy's stack, not a reason for it to exit.
- When the server exits, pending requests fail with `-32603 server
  closed` and the proxy ends the session without a crash, even while
  the client still holds its stdin open - with exit status `3`. When
  *our* stdout's reader goes away (`mcp-jail --audit | head`),
  mcp-jail exits quietly.
- Wire format: newline-delimited JSON, UTF-8 regardless of console
  code page. Both pipes are pumped by reader threads into one queue —
  no `select()` on pipes — so it runs the same on Windows 11 as on
  Linux/macOS.

## Limitations

What mcp-jail does not do, in plain words (the two caveats on deny
patterns and on `learn` above apply as well):

- **A URI in `allow_tools` is compared like a tool name**: NFKC-normalised
  and case-folded. A policy that allows `file:///srv/Public` also allows
  `file:///srv/public`, which on a case-sensitive file system is a
  different file. Deny entries want that folding; allow entries would
  rather not have it. Prefer `deny_tools` / `deny_methods` for resources,
  or keep to lowercase URIs.
- **A stalled server is stopped by killing the process mcp-jail
  started.** A grandchild that still holds the server's stdin open
  (`npx` starting node) is not, and a write stuck on it can outlive the
  stop; mcp-jail does not wait for it and exits regardless. One that
  holds the server's *output* open is waited for, whether the server was
  killed or left on its own: the pipe cannot be closed under the thread
  that is reading it, so mcp-jail exits when that grandchild lets go or
  ends.
- **Numbers are re-written as an IEEE double would write them.** Integers
  of any size are exact; a decimal with more significant digits than a
  double holds (about 17) is rounded to the nearest double, and `1E2`
  arrives as `100.0`. The jail cannot forward the original digits without
  forwarding the original bytes.

## Why not just audit?

Audit is point-in-time. The ecosystem installs MCP servers recklessly and
a poisoned tool description fires at *use* time — exactly when no scanner
is watching. The jail is the enforcement half of the story.

## Tests

```bash
python3 -m unittest discover -s tests   # fake stdio servers (+ the official MCP SDK when installed)
python3 -m pytest -q                    # same suite
```

Tests spawn fake MCP servers as subprocesses and point `HOME`,
`USERPROFILE` and `APPDATA` at a throwaway directory, so they never
touch your real `~/.mcp-jail`.

## License

MIT — see `LICENSE`.

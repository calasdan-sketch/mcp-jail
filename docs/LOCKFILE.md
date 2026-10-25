# mcp.lock: the tool-definition lockfile (format version 1)

An MCP server decides what its tools are called, what they say they do and
what arguments they take, and it can change all of that after you have
approved it. A "rug pull" is a server that behaves while you look and then
swaps in a new description that tells the model to do something else (the
Deadbugz campaign described by Pillar Security in August 2026 is one). The
defence is the one package managers use: write down what you approved, and
compare against it every time.

`mcp.lock` is that record. It holds a SHA-256 of every tool a server listed
when you approved it. It does not hold the descriptions, so it is safe to
commit and to read in a code review.

Two programs use this one format, and this document is identical in both
repositories:

* **mcp-audit** writes the lock (`mcp-audit lock`) and checks it
  (`mcp-audit verify`).
* **mcp-jail** checks it live (`mcp-jail --lockfile mcp.lock`): every
  `tools/list` answer from the server is compared against it.

A lock written by one is accepted by the other, because both hash the same
bytes (see "Test vectors").

## The file

UTF-8 JSON, written with sorted keys and a two-space indent (the same lock is
the same bytes, so a diff of the file is a diff of the approvals).

```json
{
  "version": 1,
  "generated_by": "mcp-audit 0.3.0",
  "servers": {
    "files": {
      "command_fingerprint": "<64 hex>",
      "tools": {
        "read_file": {
          "sha256": "<64 hex>",
          "description_sha256": "<64 hex>",
          "schema_sha256": "<64 hex>",
          "annotations_sha256": "<64 hex>"
        }
      }
    }
  }
}
```

* `version`: the whole number `1`. A reader that finds another number stops.
* `generated_by`: free text, for people. Not read.
* `servers`: one entry per server, named by its **server key**: the name the
  server has in the client's config (`github`, `files`). If one name appears
  in two configs with different commands, the key is `name@client`.
* `command_fingerprint`: how the server is started (below).
* `tools`: one entry per tool, named by the tool's exact `name` (no
  normalisation: the server compares names exactly, so the lock does too).
* `annotations_sha256` is optional; the other three hashes are required.
* Unknown keys anywhere, duplicate keys, and any hash that is not 64
  lower-case hex digits make the file invalid. A reader refuses an invalid
  lock; it never guesses.

## Canonical form

Every hash is a SHA-256 over the **canonical bytes** of a JSON value:

1. Every string, and every object key, is converted to Unicode normalisation
   form **NFC**. Two keys that become the same after this make the value
   invalid.
2. Numbers: an integer is written in decimal. A float with no fractional part
   and an absolute value below 2^53 is written as the integer (`1.0` is
   `1`). Any other float is written the way Python's `repr` writes it. `NaN`
   and infinities make the value invalid.
3. Objects are written with their keys sorted by Unicode code point, no
   whitespace at all (`{"a":1,"b":[2,3]}`), arrays in their own order.
4. Strings are written between double quotes. Only `"` and `\` get a
   backslash; U+0008, U+0009, U+000A, U+000C, U+000D are `\b \t \n \f \r`;
   every other character below U+0020 is `\u00xx` with lower-case hex.
   Everything else, non-ASCII included, is written as itself (not `\uXXXX`).
5. The text is encoded as UTF-8. A string with a lone surrogate cannot be
   encoded, so the value is invalid.
6. Nesting deeper than 100 levels makes the value invalid.

An invalid value is never silently hashed. A program that meets one in a
server's `tools/list` treats that tool as changed.

## What is hashed

For a tool definition (one entry of `tools/list`):

| field | hash of |
|---|---|
| `sha256` | the canonical form of `{"name": <name>, "description": <description>, "inputSchema": <inputSchema>}` |
| `description_sha256` | the canonical form of the description |
| `schema_sha256` | the canonical form of `inputSchema` |
| `annotations_sha256` | the canonical form of `annotations` |

A description, schema or annotations that the tool does not have is JSON
`null` (so a missing description and `"description": null` are the same).
`name` must be a non-empty string.

`annotations` are the hints a server gives about itself (`readOnlyHint`,
`destructiveHint`, ...). They are kept apart and are **not** part of `sha256`:
a change to them is reported as a hint, not as drift. Other fields of a tool
(`title`, `outputSchema`, `icons`, `_meta`) are not covered by version 1.

## The command fingerprint

`command_fingerprint` is the SHA-256 of the canonical form of

* `{"command": <command>, "args": [<arg>, ...]}` for a server started with a
  command, or
* `{"url": <url>}` for a remote server.

Environment variables and headers are **not** part of it (they hold
credentials and change between machines). When a config starts a server
through `mcp-jail ... -- <command> <args>`, the fingerprint is of the part
after `--`, so the same server has the same fingerprint with or without the
jail around it.

## Drift

Comparing a server's current `tools/list` with its entry gives these, in this
order for one tool:

| kind | meaning |
|---|---|
| `invalid_tool` | the entry cannot be hashed (no name, a lone surrogate, listed twice) |
| `new_tool` | listed, but not in the lock |
| `definition_changed` | `sha256` differs but neither part does (a hand-edited lock) |
| `description_changed` | `description_sha256` differs |
| `schema_changed` | `schema_sha256` differs |
| `annotations_changed` | `annotations_sha256` differs (a hint) |
| `removed_tool` | in the lock, no longer listed (only for a complete list; a hint) |

Between servers: `command_changed` (the fingerprint differs), `new_server`
(configured, not in the lock) and `removed_server` (in the lock, no longer
configured; a hint).

Hints are reported. They are not drift: a removed tool can do nothing it
could not do before, and annotations are the server's own opinion.

## Test vectors

`tests/vectors/lockfile_v1.json` in both repositories is the same file. It
lists values with their canonical text and hash, tools with their four
hashes, commands with their fingerprints, values that must be refused, and
one whole lock with the tools it was made from. Both programs run it. The
hashes in it were computed with a separate script that builds each canonical
string by hand and calls `hashlib` directly, not with the implementation under
test.

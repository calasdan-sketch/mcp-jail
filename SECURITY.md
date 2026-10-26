# Security

## Reporting a vulnerability

Please report it privately: on GitHub use the repository's **Security** tab >
**Report a vulnerability** (a private advisory). If you cannot, email
calasdan@gmail.com. Please do not open a public issue for a vulnerability.
You will get an answer within a few days.

## Scope

In scope: a way for untrusted input (a repository, a config file, a model
reply, a tool description) to make mcp-jail run code, write or read outside what
it is documented to touch, hide a finding, or leak a secret.

Out of scope: results that depend on an attacker who already controls your
account or the machine you run mcp-jail on, and findings the README lists under
its limits.

## Supported versions

Only the latest release on PyPI receives fixes.

# tvault

**Scoped, revocable API-key access for AI agents. Your keys stay on your own webhook.**

[Token Vault](https://tokenvault.uk) gives your AI agents scoped, revocable, audited access
to your API keys — and never holds them. Your credentials live on a webhook you deploy in ten
minutes; Token Vault holds identities, grants, ABAC policies and audit metadata, and brokers
access without ever seeing a credential.

`tvault` is the terminal interface to it. Manage credentials, agents, grants and the vault
lock from your shell — with a browser-based login and kubectl-style contexts for switching
between admin and agent personas.

## Install

With the Go toolchain:

```bash
go install github.com/c-lgrant/tvault@latest
```

Or grab a prebuilt binary (Linux/macOS, amd64/arm64) — the installer detects
your OS/arch, downloads the matching release, and verifies its SHA256:

```bash
curl -fsSL https://raw.githubusercontent.com/c-lgrant/tvault/main/install.sh | bash
```

## Quick start

```bash
tvault login              # browser-based admin login
tvault ls                 # list tokens
tvault get github         # print a credential (stdout only — safe for $(...))
tvault add stripe                       # create a token; the value is a hidden prompt. A name that exists is refused
tvault set stripe                       # rotate it: the only command that replaces a value (it goes straight to your webhook)
printf %s "$SECRET" | tvault add stripe # or pipe the value in
tvault add stripe --for my-agent        # store, then grant it to my-agent (created if missing)
tvault connect my-agent github stripe   # grant existing credentials and set up Claude Code
```

Secret values never need to be on the command line: with no `--value`, `add`
and `set` read a hidden prompt on a terminal, or stdin when it is piped (or with
`--value-stdin`; one trailing newline is trimmed). `--value` still works but
prints a warning, since it lands in your shell history. A pipe is waited on
without a timeout (a password manager may take a while to answer); empty input
is an error. To create a credential with no value on purpose, pass `--empty`.

The most common token verbs are also available at the top level: `get`, `set`,
`show`, `rm`, `add`, `ls`. They're shortcuts for the equivalent `tokens …`
commands; see [Top-level shortcuts](#top-level-shortcuts) below.

## Contexts: admin, agent, key

`tvault` stores one or more *contexts*, each holding one of:

- **admin** — a browser login (Firebase identity, full console access).
- **agent** — a `tvagent_*` key, limited to its grants (or, for a scoped agent, its scopes).
- **key** — a `tvkey_*` scoped key (see [Keys](#keys--tvault-keys)), limited to the scopes it was minted with.

Agent and key contexts authenticate with the key itself as a bearer token (no
Firebase session, nothing to refresh). The CLI does **not** pre-check what a
context may do: every command sends its request and the server is the sole
enforcer, answering `SCOPE_DENIED` / `HUMAN_ONLY` (see [Exit codes](#exit-codes)).
The one local exception is `tvault auth print-token`, which prints a Firebase ID
token and so only works in an admin context.

Commands resolve the active context automatically; override it
per-invocation with `--context <name>`.

### Pin a shell to one context: `TVAULT_CONTEXT`

Set `TVAULT_CONTEXT=<name>` and every command in that shell uses that context,
with no flag. Use it to make an agent's shell act as that agent and nothing
else, for example in the environment a coding agent's harness sets.

While it is set:

- `--context` with another name is refused (exit 1).
- `tvault login`, `logout`, `use`, `context use`, `context rm` and `connect`
  are refused, so the shell cannot change what is stored for other shells.
- `tvault context current` prints the pinned name.

The pin stops mistakes. It is not a wall: a process that can unset the variable
or read the stored contexts is not held by it. Keep an admin sign-in off a
machine where agents run.

### The host label: `TVAULT_CLIENT_LABEL`

Each request to Token Vault carries a short host label, so the Activity page
can say which machine made a read ("Program: tvault/0.16.0 macmini"). The
default is the machine's short host name. Set `TVAULT_CLIENT_LABEL=<label>` to
choose the text (letters, digits and `. _ @ : -`, up to 48 characters), or
`TVAULT_CLIENT_LABEL=-` to send no label. The label goes to the Token Vault
API only, never to a webhook. Token Vault shows it and makes no decision from
it.

| Command | Purpose |
|---------|---------|
| `tvault login` | Browser-based admin login. `--as <name>` names the context; `--key-stdin` reads a `tvagent_*`/`tvkey_*` key from a pipe for a non-interactive login (agent or key context, detected from the prefix; needs `--as`) — `printf %s "$TVAULT_KEY" \| tvault login --key-stdin --as ci`. `--key <key>` does the same but leaves the key in your shell history and process list, so prefer `--key-stdin`; `--no-launch-browser` uses the manual code-paste flow for SSH/headless sessions. |
| `tvault logout` | Remove the stored credentials for a context. |
| `tvault whoami` (`who`) | Show the active context and the server's view of it: principal type/name, kind (classic/scoped), scopes, and key expiry. `--format json` for machine output. |
| `tvault context` (`ctx`) | `list`/`ls`, `use <name>`, `current`, `rm <name>` — manage stored contexts. |

## Commands

Most groups have a short alias (shown in parentheses). Every command can be
run from any context type; whether it succeeds depends on the principal's
scopes, enforced by the server (`SCOPE_DENIED` → exit 8, `HUMAN_ONLY` → exit 9).

### Tokens — `tvault tokens` (`tk`)

| Command | Purpose |
|---------|---------|
| `tk list` (`ls`) | List tokens. |
| `tk get <service>` | Print a credential value to stdout — safe for `$(...)`. `--check` exits 0/6 without printing (presence probe). |
| `tk show <service>` (`info`) | Show token metadata (no secret). |
| `tk create` (`new`) | Create a token — interactive type-picker wizard, or fully flag-driven with `--type`/`--service`. The value comes from a hidden prompt, stdin (`--value-stdin`, or any piped stdin), or `--value` (warns: shell history); `--empty` creates it with no value. The secret goes straight to your webhook with a store ticket; Token Vault never receives it. |
| `tk set <service>` (`up`) | Rotate a credential value: hidden prompt, stdin / `--value-stdin`, or `--value`. The new value goes straight to your webhook with a store ticket. An empty value is an error. |
| `tk edit <service>` | Edit metadata: `--name`, `--notes`, `--tags`. |
| `tk rm <service>...` (`del`, `d`) | Delete one or more tokens. |
| `tk refresh <service>` (`ref`) | Force an OAuth token refresh. |
| `tk history <service>` (`hist`) | Show a token's usage history. |
| `tk store-ticket <service>` | Webhook-mode escape hatch: store a secret on the user's webhook via a signed ticket. `set`/`create` use this automatically — call directly for power-user scripts or to print the raw ticket envelope. |

Token types offered by the `tk new` type picker map to the real backend
`tokenType` values: **JWT** (OAuth · JWT), **PlainText** (API key / PAT),
**Certificate** (X.509), **SSHKey**, **RawCredential** (raw blob), and
**TOTP** (2FA).

### Agents — `tvault agents` (`ag`)

Agent references (`<name-or-id>`) accept either the human-readable name *or*
the backend-assigned ID — the CLI resolves names through `agents list`.

| Command | Purpose |
|---------|---------|
| `ag list` (`ls`) | List agents. |
| `ag show <name-or-id>` (`info`) | Show agent details and grants. |
| `ag create` (`new`) | Create an agent — interactive name + grants wizard, or `--name`/`--grants`. `--kind scoped --scopes a,b` creates a scoped agent. The API key is shown once. There is no per-agent MCP switch: MCP access is what lets an agent use an MCP server. If Token Vault asks for a fresh sign-in (`REAUTH_REQUIRED`), an interactive admin context runs the browser login and retries once. |
| `ag rotate-key <name-or-id>` | Replace an agent's API key. The new key is printed once, on stdout (status goes to stderr). |
| `ag rm <name-or-id>...` (`del`, `d`) | Delete one or more agents. |
| `ag suspend <name-or-id>` (`off`) | Suspend an agent. |
| `ag resume <name-or-id>` (`on`) | Resume a suspended agent. |
| `ag mcp-on <name-or-id>` | Clear a leftover MCP off-switch (the web app's "Turn MCP on" button on the Connect tab), so Claude Code can use the agent. |

### Keys — `tvault keys`

Scoped keys (`tvkey_*`) carry an explicit scope list and an expiry. The secret
is printed **once, on stdout only**; all metadata goes to stderr, so
`KEY=$(tvault keys create ...)` captures just the secret.

| Command | Purpose |
|---------|---------|
| `keys create` (`new`) | `--name <n> --scopes a,b,c [--expires 30d\|90d\|365d\|YYYY-MM-DD\|never]`. Default expiry is `90d`; a date expires at 23:59:59 UTC that day. |
| `keys ls` (`list`) | List keys: id, name, status, scopes, expiry, last use. The secret is never shown. |
| `keys show <id-or-name>` (`info`) | Key details plus its grants (service, source, expiry). |
| `keys grant <key> <service>` | Grant a service to a key. `--expires-in-hours N` makes the grant temporary. |
| `keys ungrant <key> <service>` | Remove a service grant from a key. |
| `keys rotate <id-or-name>` | Replace the secret; the new key is printed once on stdout and the old one stops working. |
| `keys revoke <id-or-name>` (`rm`) | Permanently revoke a key. Asks for confirmation; `--yes` skips it, and a non-interactive shell refuses without `--yes`. |

Scopes: `credentials:read`, `mcp:use`, `tokens:list`, `tokens:create`,
`tokens:create-read`, `tokens:update`, `tokens:delete`, `agents:read`,
`agents:create`, `agents:manage`, `grants:write`, `proxies:read`,
`proxies:write`, `policies:read`, `policies:write`, `keys:manage`.

```bash
KEY=$(tvault keys create --name ci --scopes credentials:read,tokens:list --expires 30d)
printf %s "$KEY" | tvault login --key-stdin --as ci   # tvkey_ prefix → a key context
tvault --context ci whoami             # principal, kind, scopes, expiry
```

Token writes from a key or agent context still use the store-ticket flow: the
metadata goes to Token Vault, and the value is POSTed straight to your webhook.

### Grants — `tvault grants` (`gr`)

| Command | Purpose |
|---------|---------|
| `gr list <agent>` (`ls`) | List an agent's grants. |
| `gr add <agent> <service>[=<uses>[:<server>,...]]...` | Grant services to an agent. |
| `gr rm <agent> <service>...` | Revoke grants from an agent. |

The top-level `tvault grant <agent> <service>...` is a flat-verb shortcut for
`gr add`.

A plain `<service>` grants the value. Append `=<uses>` to say what the grant is
for: `value` (the agent may read the credential) and/or `mcp` (the agent may
call the credential's [MCP servers](#mcp-servers--tvault-mcp-servers-mcp)
through Token Vault and is never handed the value; `tools`, the API's word for it,
is accepted too). After a colon, name the
MCP servers an `mcp` grant covers; without it, every MCP server of the credential.
A [Token Vault sign-in](#token-vault-sign-in--tvault-add---sign-in) credential
can only be granted `mcp`.

```bash
tvault grant claude-code github            # value (today's meaning)
tvault grant claude-code github=mcp        # MCP access only, every server
tvault grant claude-code github=value,mcp:github
```

### MCP servers — `tvault mcp-servers` (`mcp`)

A credential can have up to five MCP servers attached. An agent given MCP access
to it calls them through Token Vault; your webhook puts the credential into the
upstream request, so neither the agent nor Token Vault holds the value. The CLI
sends only the MCP server's name, URL and header *templates*.

| Command | Purpose |
|---------|---------|
| `mcp-servers ls <service>` | List the credential's MCP servers and the endpoint each is served at (`--format json` for the full shape). |
| `mcp-servers add <service> --preset <id>` | Attach a preset MCP server (`github`, `linear`, `sentry`; `name` defaults to the preset id). |
| `mcp-servers add <service> --name <n> --url <u> --header 'Name: value'...` | Attach your own MCP server. `--header` is repeatable. |
| `mcp-servers rm <service> <name>` | Detach an MCP server (`--force` skips the prompt). Grants naming it are not edited. |
| `mcp-servers templates` | List the presets. |

`add` needs your own login (an admin context): a key or agent cannot add an MCP
server or change its URL or headers (`HUMAN_ONLY`, exit 9), because the server
would keep getting the credential after that key had expired.

`add` and `rm` read the current list and write the whole list back (the API is a
full replace). Credentials go into a header with the literal text `${TOKEN}`;
**single-quote it** so your shell does not expand it, and never put a real
secret in a header value:

```bash
tvault mcp-servers add github --preset github
tvault mcp-servers add github --name docs --url https://mcp.example.com/mcp \
    --header 'Authorization: Bearer ${TOKEN}' --header 'Accept: application/json, text/event-stream'
```

Adding an MCP server (or changing a URL or headers) needs a recent sign-in. In an
interactive admin context the CLI opens the browser login and retries once. A
key or agent context sees MCP servers redacted (URL origin only, no headers), so it
may add to an empty list but will not rewrite an existing one.

### Token Vault sign-in — `tvault add --sign-in`

A credential with no value, for an MCP server that signs the agent in itself.
Token Vault gives each calling agent a short pass (15 minutes) that only that
MCP server accepts, in the header `Authorization: Bearer ${AGENT_SESSION}`. The
agent never holds the pass, and Token Vault never holds a credential.

```bash
tvault add notes --sign-in https://mcp.example.com/mcp --for my-agent=mcp --yes
tvault add notes --sign-in https://mcp.example.com/mcp --server docs   # name the MCP server (default "mcp")
```

`add --sign-in` creates the credential, attaches the MCP server, then grants
each `--for` agent. A sign-in credential can only be granted `mcp`: a plain
`--for my-agent` means mcp, and `--for my-agent=value` is refused before
anything is created. `--value`, `--type` and `--mcp` do not apply to it.
`tvault ls` and `tvault show` list its type as "Token Vault sign-in".
`tvault get`, `set` and the other value commands refuse it with `SIGNIN_NO_VALUE`
(exit 6, nothing on stdout). To change its MCP server later, use
`tvault mcp-servers add <name> --name <mcp-server> --url <url> --header 'Authorization: Bearer ${AGENT_SESSION}'`
(a sign-in credential's headers use `${AGENT_SESSION}`; ordinary credentials use `${TOKEN}`).

### Vault — `tvault vault`

| Command | Purpose |
|---------|---------|
| `vault status` (`stat`) | Show the vault lock state. |
| `vault lock` | Lock the vault — blocks all mutating operations. |
| `vault unlock` | Unlock the vault. |

### Webhook — `tvault webhook` (`wh`)

Connect your own [Webhook Mode](https://docs.tokenvault.uk/vault-modes/webhook)
vault. Deploy the reference webhook in [`examples/webhook`](examples/webhook)
(Deploy to Workers, or `docker compose up -d --build`); the CLI then binds it to
your vault **without a browser**, reusing your admin context's session.

| Command | Purpose |
|---------|---------|
| `wh bind --url <webhook-url>` | Fetch the one-time code from the running webhook and bind it to your vault — no browser. |
| `wh status` (`stat`) | Show the control plane's view of the webhook (mode, URL, last health check, capabilities) plus a direct health probe from this machine. |

Typical first run:

```bash
cd examples/webhook && docker compose up -d --build
tvault webhook bind --url https://my-webhook.example.com
```

### Upgrading

- **`tvault webhook init`, `up` and `down` were removed**, along with the
  published `ghcr.io/c-lgrant/tvault-webhook` image (it was the old Python
  webhook). Run the reference webhook with `docker compose up -d --build` in
  `examples/webhook`, or use Deploy to Workers. `webhook bind` now takes the
  webhook's URL with `--url` instead of reading a generated project.
- **Webhook 0.13 or earlier, upgrading:** `tv-refresh` is now opt-in. See
  [Upgrading from 0.13 or earlier](examples/webhook/README.md#upgrading-from-013-or-earlier).

## Top-level shortcuts

The most common verbs are also available at the root, so you don't have to
type `tokens` / `context` / `agents grants` for every operation.

| Shortcut | Equivalent |
|----------|------------|
| `tvault ls` | `tvault tokens list` |
| `tvault credentials` (`creds`) | `tvault tokens list` |
| `tvault history <svc>` | `tvault tokens history <svc>` |
| `tvault get <svc>` | `tvault tokens get <svc>` |
| `tvault add <svc>` | `tvault tokens create --service <svc>` (defaults `--type PlainText`). `--for` is repeatable (`--for claude-code=mcp --for cursor=mcp`), one agent per value. `--labels work,ai` labels the credential after storing it (if that fails the value stays stored and the retry command is printed). `--for <agent>` also grants it to that agent, creating the agent first if missing (asks `Create agent "<name>"? [y/N]` on a terminal; `--yes` skips, and a non-interactive shell needs it). `--for <agent>=<uses>[:<server>,...]` sets what the grant is for (`--for my-agent=mcp`). `--mcp <preset>` then attaches that MCP server preset; if that fails the value stays stored and the retry command is printed. `--sign-in <url>` makes a [Token Vault sign-in](#token-vault-sign-in--tvault-add---sign-in) credential instead (no value; `--server <name>` names its MCP server; grants are tools only). |
| `tvault connect <agent> [<svc>[=<uses>]...]` | Grant existing credentials to an agent (created if missing; `--yes`), then register Token Vault in Claude Code if `claude` is on PATH and has no `tokenvault` MCP server (`claude mcp add --transport http --scope user tokenvault <api>/api/agents/mcp`; a registration for a different control plane is left alone and the switch commands are printed). `--print` only prints that command; `--no-claude` skips it. `--server <svc>/<server>` registers that one credential MCP server instead, as its own entry (`claude mcp add --transport http --scope user tv-<svc>-<server> <api>/api/mcp/<svc>/<server>`; `--name` renames the entry), and notes if the agent still needs `tvault grant <agent> <svc>=mcp:<server>`. Finish in Claude Code: `/mcp`, sign in, pick the agent. |
| `tvault set <svc>` | `tvault tokens set <svc>` |
| `tvault show <svc>` | `tvault tokens show <svc>` |
| `tvault rm <svc>...` | `tvault tokens rm <svc>...` |
| `tvault use <ctx>` | `tvault ctx use <ctx>` |
| `tvault grant <agent> <svc>...` | `tvault agents grants add <agent> <svc>...` |

### Labels and policies — `tvault label`, `tvault policy`

Labels are short tags (1-32 lowercase letters, digits or hyphens) on
credentials, agents and keys. A policy attached to a label applies to every
object carrying it. A label never grants access. `<kind>` is `credential`,
`agent` or `key`; agents and keys may be named by name or ID.

| Command | Purpose |
|---------|---------|
| `label ls` | Every label with how many credentials, agents and keys carry it, and its policy IDs. `--json` prints the raw response. |
| `label set <kind> <id> <label>...` | Replace the object's labels with exactly these. |
| `label add <kind> <id> <label>...` | Add labels, keeping the existing ones. |
| `label rm <kind> <id> <label>...` | Remove labels. Removing one that has policies loosens them, so it needs `policies:write` (`SCOPE_DENIED` → exit 8). |
| `policy attach <policyId>` | Attach a policy: `--label`, `--credential`, `--agent`, `--key` (each repeatable). |
| `policy detach <policyId>` | Detach it from the same kinds of target. |

The bare `tvault <service>` form is still the back-compat shim (see below).

## Back-compat shim

For drop-in compatibility with the legacy bash script, a bare invocation works:

```bash
$(tvault github)    # print the github credential inline
tvault              # with no args, lists tokens (or nudges you to log in)
```

`tvault <service> [more words]` joins its args into a service name and prints
that credential — equivalent to `tvault tk get <service>`.

## Global flags

| Flag | Effect |
|------|--------|
| `--context <name>` (alias: `--ctx`) | Override the active context for this command. |
| `--format json\|table\|wide\|name` | Output format. `name` prints just the primary key (e.g. service name) — convenient for piping. |
| `--no-color` | Disable colored output. |
| `--debug` | Print HTTP request/response diagnostics to stderr. |
| `--dry-run` | On write commands, print the request that would be sent without sending it. |

## Exit codes

Every failure maps to a distinct exit code, so scripts can branch without
parsing text.

| Code | Meaning |
|------|---------|
| 0 | Success. |
| 1 | User error — bad arguments, validation, not found, other 4xx. |
| 2 | Auth — no context, session expired, bad credentials (401). |
| 3 | Network — could not reach the API. |
| 4 | Server error (5xx). |
| 5 | Vault locked (`VAULT_LOCKED`). |
| 6 | Token exists but has no credential value, or is a Token Vault sign-in credential (`SIGNIN_NO_VALUE`: it never has one). |
| 7 | Rate limited (429). |
| 8 | `SCOPE_DENIED` — the key lacks a required scope; the message names it. |
| 9 | `HUMAN_ONLY` — the operation needs a signed-in human, not an API key. |
| 10 | `KEY_EXPIRED` — the API key is past its expiry. |
| 11 | `KEY_SUSPENDED` — the API key is suspended. |
| 12 | `INVALID_KEY` — the API key is unknown, malformed, or revoked. |
| 13 | `POLICY_DENIED` — a policy refused the call (hours, rate, IP, usage); the message says which. |
| 14 | No grant for this use — `NO_GRANT`, `GRANT_EXPIRED` or `GRANT_TOOLS_ONLY`. |

Other server codes keep the code of their HTTP class and add a hint to the
message (see `tvault explain <code>`):

| Server code | Exit | Notes |
|-------------|------|-------|
| `VAULT_LOCKED` (423) | 5 | Same as the locked-vault code above. |
| `REAUTH_REQUIRED` (401) | 2 | Creating a key as a human needs a fresh sign-in: run `tvault login` again. |
| `NOT_OWNER`, `GRANT_REQUIRED` (403) | 1 | User errors; hints say what to do. |
| `UNKNOWN_SCOPE`, `INVALID_EXPIRY` (400/422) | 1 | Bad `--scopes` / `--expires`. |

## Other commands

- `tvault explain <error-code>` — explain a Token Vault error code (e.g.
  `VAULT_LOCKED`, `POLICY_DENIED`, `GRANT_EXPIRED`) and how to fix it.
- `tvault completion <shell>` — generate a shell completion script. Service,
  agent, and context names complete dynamically.
- `tvault completion install <shell>` — write the script to a tvault-managed
  file under XDG paths (e.g. `~/.local/share/bash-completion/completions/tvault`,
  `~/.config/fish/completions/tvault.fish`). Bash and fish auto-discover it on
  next shell start; for zsh the command prints the exact `fpath=` line you can
  paste into `~/.zshrc`. Never edits any rc file. `--print-only` shows the path
  without writing. `tvault completion uninstall <shell>` removes the file.
- `tvault version` — print version, commit, and build date.

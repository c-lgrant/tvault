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
tvault add stripe --value sk_test_...   # create a token
tvault set stripe --value sk_test_new   # rotate it (auto-routes around webhook mode)
```

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

| Command | Purpose |
|---------|---------|
| `tvault login` | Browser-based admin login. `--as <name>` names the context; `--key <tvagent_*|tvkey_*>` does a non-interactive login (agent or key context, detected from the prefix; needs `--as`); `--no-launch-browser` uses the manual code-paste flow for SSH/headless sessions. |
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
| `tk create` (`new`) | Create a token — interactive type-picker wizard, or fully flag-driven with `--type`/`--service`/`--value`. In webhook-mode vaults the secret auto-routes to the user's webhook (TV never sees it). |
| `tk set <service>` (`up`) | Rotate a credential value (`--value`). Auto-routes through the store-ticket flow in webhook-mode vaults. |
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
| `ag create` (`new`) | Create an agent — interactive name + grants wizard, or `--name`/`--grants`. `--kind scoped --scopes a,b` creates a scoped agent. The API key is shown once. |
| `ag rotate-key <name-or-id>` | Replace an agent's API key. The new key is printed once, on stdout (status goes to stderr). |
| `ag rm <name-or-id>...` (`del`, `d`) | Delete one or more agents. |
| `ag suspend <name-or-id>` (`off`) | Suspend an agent. |
| `ag resume <name-or-id>` (`on`) | Resume a suspended agent. |

### Keys — `tvault keys`

Scoped keys (`tvkey_*`) carry an explicit scope list and an expiry. The secret
is printed **once, on stdout only**; all metadata goes to stderr, so
`KEY=$(tvault keys create ...)` captures just the secret.

| Command | Purpose |
|---------|---------|
| `keys create` (`new`) | `--name <n> --scopes a,b,c [--expires 30d\|90d\|365d\|YYYY-MM-DD\|never]`. Default expiry is `90d`; a date expires at 23:59:59 UTC that day. |
| `keys ls` (`list`) | List keys: id, name, status, scopes, expiry, last use. The secret is never shown. |
| `keys rotate <id-or-name>` | Replace the secret; the new key is printed once on stdout and the old one stops working. |
| `keys revoke <id-or-name>` (`rm`) | Permanently revoke a key. Asks for confirmation; `--yes` skips it, and a non-interactive shell refuses without `--yes`. |

Scopes: `credentials:read`, `mcp:use`, `tokens:list`, `tokens:create`,
`tokens:create-read`, `tokens:update`, `tokens:delete`, `agents:read`,
`agents:create`, `agents:manage`, `grants:write`, `proxies:read`,
`proxies:write`, `policies:read`, `policies:write`, `keys:manage`.

```bash
KEY=$(tvault keys create --name ci --scopes credentials:read,tokens:list --expires 30d)
tvault login --key "$KEY" --as ci      # tvkey_ prefix → a key context
tvault --context ci whoami             # principal, kind, scopes, expiry
```

Token writes from a key or agent context still use the store-ticket flow: the
metadata goes to Token Vault, and the value is POSTed straight to your webhook.

### Grants — `tvault grants` (`gr`)

| Command | Purpose |
|---------|---------|
| `gr list <agent>` (`ls`) | List an agent's grants. |
| `gr add <agent> <service>...` | Grant services to an agent. |
| `gr rm <agent> <service>...` | Revoke grants from an agent. |

The top-level `tvault grant <agent> <service>...` is a flat-verb shortcut for
`gr add`.

### Vault — `tvault vault`

| Command | Purpose |
|---------|---------|
| `vault status` (`stat`) | Show the vault lock state. |
| `vault lock` | Lock the vault — blocks all mutating operations. |
| `vault unlock` | Unlock the vault. |

### Webhook — `tvault webhook` (`wh`)

Deploy and connect your own [Webhook Mode](https://docs.tokenvault.uk/vault-modes/webhook)
vault. The CLI generates the Docker Compose project and binds the webhook to your
vault **without a browser**, reusing your admin context's session.

| Command | Purpose |
|---------|---------|
| `wh init` | Generate a `docker-compose.yml` + `.env` for a webhook deployment. Interactive method picker, or `--method` + `--set KEY=VALUE`. Methods: `ngrok`, `cloudflare`, `tailscale`, `custom`. `--dir` sets the target (default `./tvault-webhook`); `--image` overrides the webhook image. |
| `wh up` | `docker compose up -d`, then wait for the webhook to report healthy. |
| `wh bind` | Fetch the one-time code from the running webhook and bind it to your vault — no browser. |
| `wh status` (`stat`) | Show local container state next to the backend's view of the webhook. |
| `wh down` | `docker compose down`. |

Typical first run:

```bash
tvault webhook init          # pick a method, answer the prompts
cd tvault-webhook
tvault webhook up            # start it
tvault webhook bind          # connect it to your vault
```

`up`/`down`/`bind`/`status` look for the project in the current directory, or
`--dir <path>`.

## Top-level shortcuts

The most common verbs are also available at the root, so you don't have to
type `tokens` / `context` / `agents grants` for every operation.

| Shortcut | Equivalent |
|----------|------------|
| `tvault ls` | `tvault tokens list` |
| `tvault get <svc>` | `tvault tokens get <svc>` |
| `tvault add <svc>` | `tvault tokens create --service <svc>` (defaults `--type PlainText`) |
| `tvault set <svc>` | `tvault tokens set <svc>` |
| `tvault show <svc>` | `tvault tokens show <svc>` |
| `tvault rm <svc>...` | `tvault tokens rm <svc>...` |
| `tvault use <ctx>` | `tvault ctx use <ctx>` |
| `tvault grant <agent> <svc>...` | `tvault agents grants add <agent> <svc>...` |

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
| 6 | Token exists but has no credential value. |
| 7 | Rate limited (429). |
| 8 | `SCOPE_DENIED` — the key lacks a required scope; the message names it. |
| 9 | `HUMAN_ONLY` — the operation needs a signed-in human, not an API key. |
| 10 | `KEY_EXPIRED` — the API key is past its expiry. |

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

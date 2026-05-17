# tvault

The Token Vault command-line interface. Manage credentials, agents, grants, and
the vault lock from your terminal — with a browser-based login and
kubectl-style contexts for switching between admin and agent personas.

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

> **Trying the `preview` branch?** The `install.sh` route does **not** work
> yet on `preview` — it pulls from GitHub Releases and there are no Go
> releases on this repo until `preview` is merged to `main`. Use one of:
>
> ```bash
> # Build straight from the branch (requires Go)
> go install github.com/c-lgrant/tvault@preview
>
> # Or download the CI-built preview binary (requires gh CLI, no Go)
> # Pick the run id from: gh run list --repo c-lgrant/tvault --branch preview --workflow ci.yml
> gh run download <run-id> --repo c-lgrant/tvault -n tvault-preview-darwin-arm64
> # asset name: tvault-preview-{linux|darwin}-{amd64|arm64}
> chmod +x tvault-darwin-arm64
> xattr -d com.apple.quarantine tvault-darwin-arm64 2>/dev/null  # macOS
> sudo install -m 0755 tvault-darwin-arm64 /usr/local/bin/tvault
> ```
>
> `tvault version` will print `preview-<sha>` so you can tell preview builds
> from real releases.

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

## Contexts: admin vs. agent

`tvault` stores one or more *contexts*, each holding either an admin login
(Firebase identity, full console access) or an agent login (a `tvagent_*` key,
scoped to its grants). Commands resolve the active context automatically;
override it per-invocation with `--context <name>`.

| Command | Purpose |
|---------|---------|
| `tvault login` | Browser-based admin login. `--as <name>` names the context; `--key <tvagent_*>` does a non-interactive agent login; `--no-launch-browser` uses the manual code-paste flow for SSH/headless sessions. |
| `tvault logout` | Remove the stored credentials for a context. |
| `tvault whoami` (`who`) | Show the active context's identity. |
| `tvault context` (`ctx`) | `list`/`ls`, `use <name>`, `current`, `rm <name>` — manage stored contexts. |

## Commands

Most groups have a short alias (shown in parentheses). Admin-only commands
require an admin context.

### Tokens — `tvault tokens` (`tk`)

| Command | Purpose |
|---------|---------|
| `tk list` (`ls`) | List tokens. |
| `tk get <service>` | Print a credential value to stdout — safe for `$(...)`. `--check` exits 0/6 without printing (presence probe). |
| `tk show <service>` (`info`) | Show token metadata (no secret). |
| `tk create` (`new`) | Create a token — interactive type-picker wizard, or fully flag-driven with `--type`/`--service`/`--value`. In webhook-mode vaults the secret auto-routes to the user's webhook (TV never sees it). |
| `tk set <service>` (`up`) | Rotate a credential value (`--value`). Admin only. Auto-routes through the store-ticket flow in webhook-mode vaults. |
| `tk edit <service>` | Edit metadata: `--name`, `--notes`, `--tags`. Admin only. |
| `tk rm <service>...` (`del`, `d`) | Delete one or more tokens. Admin only. |
| `tk refresh <service>` (`ref`) | Force an OAuth token refresh. Admin only. |
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
| `ag create` (`new`) | Create an agent — interactive name + grants wizard, or `--name`/`--grants`. The API key is shown once. |
| `ag rm <name-or-id>...` (`del`, `d`) | Delete one or more agents. |
| `ag suspend <name-or-id>` (`off`) | Suspend an agent. |
| `ag resume <name-or-id>` (`on`) | Resume a suspended agent. |

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
| `vault unlock` | Unlock the vault. Admin only. |

### Webhook — `tvault webhook` (`wh`)

Deploy and connect your own [Webhook Mode](https://docs.tokenvault.uk/vault-modes/webhook)
vault. The CLI generates the Docker Compose project and binds the webhook to your
vault **without a browser**, reusing your admin context's session.

| Command | Purpose |
|---------|---------|
| `wh init` | Generate a `docker-compose.yml` + `.env` for a webhook deployment. Interactive method picker, or `--method` + `--set KEY=VALUE`. Methods: `ngrok`, `cloudflare`, `tailscale`, `custom`. `--dir` sets the target (default `./tvault-webhook`); `--image` overrides the webhook image. |
| `wh up` | `docker compose up -d`, then wait for the webhook to report healthy. |
| `wh bind` | Fetch the one-time code from the running webhook and bind it to your vault — no browser. Admin only. |
| `wh status` (`stat`) | Show local container state next to the backend's view of the webhook. Admin only. |
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

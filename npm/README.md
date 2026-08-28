# tvault

Scoped, revocable API-key access for AI agents. Your keys stay on your own webhook.

This package installs the [Token Vault](https://tokenvault.uk) command-line interface.

## What Token Vault is

Token Vault gives your AI agents scoped, revocable, audited access to your API keys — and never holds them. Your credentials live on a webhook you deploy in ten minutes; Token Vault holds identities, grants, ABAC policies and audit metadata, and brokers access without ever seeing a credential.

`tvault` is the terminal interface to it: manage credentials, agents, grants and the vault lock, with a browser-based login and kubectl-style contexts for switching between admin and agent personas.

## Install

```bash
npm install -g tvault
```

Or run it without installing:

```bash
npx tvault --help
```

The postinstall step downloads the release binary matching this package's version from [GitHub Releases](https://github.com/c-lgrant/tvault/releases) and verifies its SHA256 against the published `checksums.txt`.

Prebuilt binaries exist for **linux** and **darwin** on **x64** and **arm64**. On any other platform the install fails with instructions rather than silently producing a broken command.

### Other install routes

```bash
# Go toolchain
go install github.com/c-lgrant/tvault@latest

# Shell installer
curl -fsSL https://raw.githubusercontent.com/c-lgrant/tvault/main/install.sh | bash
```

## Quick start

```bash
tvault login              # browser-based admin login
tvault ls                 # list tokens
tvault get github         # print a credential (stdout only — safe for $(...))
tvault add stripe --value sk_test_...
```

`tvault get` writes the value to stdout and nothing else, so it composes:

```bash
curl -H "Authorization: Bearer $(tvault get github)" https://api.github.com/user
```

That keeps the credential out of files, environment variables and shell history.

## Environment variables

| Variable | Effect |
|---|---|
| `TVAULT_VERSION` | Install a specific release tag instead of the one matching this package |
| `TVAULT_SKIP_DOWNLOAD` | Skip the binary download (for CI images that supply their own) |

## Links

- Docs — https://docs.tokenvault.uk
- CLI reference — https://docs.tokenvault.uk/agents/tvault-cli
- Source — https://github.com/c-lgrant/tvault

## Licence

MIT

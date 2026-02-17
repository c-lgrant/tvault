# tvault — Token Vault CLI

A single-file CLI for [Token Vault](https://tokenvault.uk). Retrieve API keys, access tokens, and secrets from your vault in scripts, pipelines, and AI agents.

```
tvault github          # prints your GitHub token to stdout
tvault anthropic       # prints your Anthropic key
tvault                 # lists all granted services
```

Zero dependencies. Single bash script. Works anywhere `curl` and `bash` are available.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/c-lgrant/tvault/main/tvault \
  -o /usr/local/bin/tvault && chmod +x /usr/local/bin/tvault
```

Or with Homebrew-style local install:

```bash
mkdir -p ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/c-lgrant/tvault/main/tvault \
  -o ~/.local/bin/tvault && chmod +x ~/.local/bin/tvault
```

Make sure `~/.local/bin` is in your `PATH`.

## Setup

```bash
tvault init
```

You'll need an agent API key (`tvagent_...`) from the [Token Vault dashboard](https://tokenvault.uk). Create an agent, grant it access to the tokens it needs, then copy the key.

```
$ tvault init
Token Vault CLI Setup

Agent key (tvagent_...): tvagent_abc123...
Verifying key... ok

Saved to /home/you/.config/tv/config

Available tokens:
  github
  anthropic
  openai

Usage: tvault github
```

The key is saved to `~/.config/tv/config` (chmod 600). You can also set it via the `TV_AGENT_KEY` environment variable instead of running `tvault init`.

## Usage

```bash
tvault <service>                   # print the access token for a service
tvault                             # list all granted services
tvault init                        # configure your agent key
tvault install-skill               # install Claude Code /tvault skill
tvault update                      # self-update to the latest version
tvault version                     # print version
tvault --help                      # show help
```

### Flags

```bash
tvault --key <key> <service>       # override agent key for one call
```

### Environment variables

These override the config file:

| Variable | Purpose |
|----------|---------|
| `TV_AGENT_KEY` | Agent key (overrides config file) |
| `TV_CONFIG_DIR` | Config directory (default: `~/.config/tv`) |

## Examples

### Use tokens in API calls

```bash
# GitHub
curl -H "Authorization: token $(tvault github)" https://api.github.com/user

# GitHub CLI
gh auth login --with-token <<< "$(tvault github)"

# Anthropic Claude
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $(tvault anthropic)" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}'

# OpenAI
curl https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $(tvault openai)" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'

# Google Gemini
curl "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=$(tvault gemini)" \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
```

### Export as environment variables

```bash
export GITHUB_TOKEN=$(tvault github)
export ANTHROPIC_API_KEY=$(tvault anthropic)
export OPENAI_API_KEY=$(tvault openai)
```

### Pipe to clipboard

```bash
tvault github | pbcopy          # macOS
tvault github | xclip -sel c    # Linux
```

### Use in CI/CD

```yaml
# GitHub Actions
- name: Deploy
  env:
    API_KEY: ${{ secrets.TV_AGENT_KEY }}
  run: |
    export DEPLOY_TOKEN=$(TV_AGENT_KEY=$API_KEY tvault deploy-service)
    ./deploy.sh
```

### Use in Docker

```dockerfile
RUN curl -fsSL https://raw.githubusercontent.com/c-lgrant/tvault/main/tvault \
    -o /usr/local/bin/tvault && chmod +x /usr/local/bin/tvault
```

```bash
docker run -e TV_AGENT_KEY=tvagent_... myimage tvault github
```

## Claude Code Integration

The CLI includes built-in support for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) via a `/tvault` slash command.

### Quick setup

```bash
tvault install-skill
```

This prompts for install location and fetches the skill definition from GitHub:

```
Token Vault — Claude Code Integration

Where should the /tvault skill be installed?

  1) user   ~/.claude/skills/tvault/       (available in all projects)
  2) repo   .claude/skills/tvault/          (committed to this repo)

Choice [1]: 1

Installing to user: ~/.claude/
Fetching skill definition... ok

Installed:
  Skill: /home/you/.claude/skills/tvault/SKILL.md

Available in Claude Code:
  /tvault github    Retrieve a token via slash command
  /tvault           List available grants
```

Skip the prompt with flags:

```bash
tvault install-skill --user    # install to ~/.claude/
tvault install-skill --repo    # install to .claude/ in current repo
```

### What gets installed

| File | Purpose |
|------|---------|
| `skills/tvault/SKILL.md` | `/tvault` slash command definition |

### /tvault slash command

Once installed, use `/tvault` in any Claude Code session:

```
> /tvault github          # retrieves your GitHub token
> /tvault anthropic       # retrieves your Anthropic key
> /tvault                 # lists available grants
```

The skill invokes the `tvault` CLI under the hood. Claude uses safe patterns (env vars, subshells) and never prints raw tokens.

## Updating

Self-update to the latest version:

```bash
tvault update
```

```
Checking for updates... v0.2.0 -> v0.3.0
Updated to v0.3.0
```

If the CLI is installed in a system directory:

```bash
sudo tvault update
```

## Repository Structure

```
tvault              Bash CLI (single file, no dependencies)
SKILL.md            Claude Code /tvault slash command definition
README.md           This file
```

The `tvault install-skill` command fetches `SKILL.md` from this repo and installs it into the user's `~/.claude/skills/tvault/` or the current repo's `.claude/skills/tvault/` directory.

## How it works

1. You create an agent in the [Token Vault dashboard](https://tokenvault.uk) and get an API key (`tvagent_...`)
2. You grant specific vault tokens to the agent (GitHub, Anthropic, etc.)
3. The CLI calls `GET /api/agents/credentials?service=<name>` with the agent key
4. Token Vault returns the access token; the CLI prints it to stdout
5. Grants expire automatically or can be revoked from the dashboard

The agent key only has access to tokens you explicitly grant. Grants are time-limited and revocable. Every access is logged in your vault's audit trail.

## Config file format

`~/.config/tv/config`:

```bash
# Token Vault CLI config — generated by tvault init
tv_agent_key="tvagent_abc123..."
tv_api_url="https://api.tokenvault.uk"
```

## Requirements

- `bash` (4.0+)
- `curl`
- `python3` or `jq` (for JSON parsing — tries python3 first, falls back to jq)

## License

MIT

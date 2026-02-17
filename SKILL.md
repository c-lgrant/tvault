---
name: tvault
description: Retrieve credentials from Token Vault. Use when the user needs an API key, access token, or secret from their vault — for example "get my GitHub token" or "use my Anthropic key".
argument-hint: [service]
allowed-tools: Bash
---

# Token Vault Credential Retrieval

Retrieve credentials from the user's Token Vault using the `tvault` CLI.

## Prerequisites

The `tvault` CLI must be installed and configured:
```bash
# Install
curl -fsSL https://raw.githubusercontent.com/c-lgrant/tvault/main/tvault -o /usr/local/bin/tvault && chmod +x /usr/local/bin/tvault

# Configure (one-time)
tvault init
```

## Instructions

1. If `$ARGUMENTS` is provided, retrieve that specific service token:
   ```bash
   tvault $ARGUMENTS
   ```

2. If no arguments, list all available grants:
   ```bash
   tvault
   ```

3. **Never print raw tokens to the user.** Instead:
   - Set them as environment variables: `export GITHUB_TOKEN=$(tvault github)`
   - Use them inline in commands: `curl -H "Authorization: token $(tvault github)" ...`
   - Store in a variable for the session: `TOKEN=$(tvault github)`

4. If `tvault` is not installed or not configured, show the install/init commands above.

5. If the user asks to use a token with a specific API, construct the appropriate curl or SDK call with the token injected via `$(tvault <service>)` subshell — never paste the raw value.

## Common patterns

```bash
# GitHub API
curl -H "Authorization: token $(tvault github)" https://api.github.com/user

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

# Export for SDK use
export GITHUB_TOKEN=$(tvault github)
export ANTHROPIC_API_KEY=$(tvault anthropic)
export OPENAI_API_KEY=$(tvault openai)
```

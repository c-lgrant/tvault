#!/bin/sh
# Secret scan gate for the tvault PUBLIC repo.
# Run before any push: sh scripts/secret-scan.sh
# Wired as a git pre-push hook — see .git/hooks/pre-push.
set -eu

TARGET="${1:-.}"
FAIL=0

check() {
  local pattern="$1"
  local label="$2"
  # Search staged+tracked files; exclude git dir and node_modules
  if git grep -I -l -E "$pattern" -- ':!node_modules' ':!*.lock' ':!dist' 2>/dev/null | grep -q .; then
    echo "SECRET-SCAN FAIL [$label]: pattern '$pattern' found in:" >&2
    git grep -I -l -E "$pattern" -- ':!node_modules' ':!*.lock' ':!dist' >&2
    FAIL=1
  fi
}

echo "Running secret scan on tracked files..."

# Private key blocks
check '-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY' "private-key"

# Token Vault tokens
check 'tvagent_[A-Za-z0-9_-]{16,}' "tvagent-token"
check 'mcp_[A-Za-z0-9_-]{16,}' "mcp-token"

# OpenAI / Anthropic / generic sk_ keys
check 'sk-[A-Za-z0-9]{20,}' "sk-key"
check 'sk-ant-[A-Za-z0-9_-]{20,}' "anthropic-key"

# AWS
check 'AKIA[0-9A-Z]{16}' "aws-access-key"
check 'aws_secret_access_key\s*=\s*[^\s]+' "aws-secret"

# Generic high-entropy assignments that look like secrets
check '(password|secret|token|api_key)\s*[:=]\s*["\x27][A-Za-z0-9+/]{20,}' "generic-secret"

# Actual secret values in .dev.vars / env assignments (require 20+ char value)
check 'TV_WEBHOOK_SEED\s*=\s*[A-Za-z0-9+/=_-]{20,}' "wrangler-seed"
check 'NGROK_AUTHTOKEN\s*=\s*[A-Za-z0-9_-]{20,}' "ngrok-token"
check 'CF_TUNNEL_TOKEN\s*=\s*[A-Za-z0-9._-]{20,}' "cf-tunnel-token"

if [ "$FAIL" -eq 1 ]; then
  echo "" >&2
  echo "Push BLOCKED — remove secrets before pushing to the public repo." >&2
  exit 1
fi

echo "Secret scan clean."

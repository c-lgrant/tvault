# Token Vault Webhook (ngrok)

Reference [Token Vault](https://tokenvault.uk) webhook implementation that runs locally and exposes itself via [ngrok](https://ngrok.com). Implements all seven webhook endpoints for the webhook-sovereign (zero-knowledge) architecture — Token Vault never sees your credentials.

Full documentation: [docs.tokenvault.uk/webhook-protocol](https://docs.tokenvault.uk/webhook-protocol)

## Architecture

Your webhook owns its own AES-256-GCM encryption key. Token Vault is a metadata, policy, and authorization layer only — it never holds key material or plaintext credentials.

- **Storing tokens** — the browser sends credentials directly to `/v1/store` with a signed ticket. Token Vault issues the ticket but never sees the credential.
- **Agent access** — Token Vault validates the agent's API key and policies, then returns a **307 redirect** to `/v1/credential`. The agent follows the redirect and gets the credential directly from your webhook.
- **MCP proxy** — Token Vault forwards the request to `/v1/proxy` with a signed ticket. Your webhook decrypts the credential, injects it into the upstream request, and returns the response.
- **Token refresh** — Token Vault notifies your webhook via `/v1/refresh-notify` with provider hints. Your webhook handles the OAuth refresh independently.

## Prerequisites

- Docker
- [ngrok](https://ngrok.com) account with a static domain
- `NGROK_AUTHTOKEN` from your ngrok dashboard

## Quick start

```bash
docker build -t tv-webhook .

docker run -d \
  -e NGROK_AUTHTOKEN=your_ngrok_token \
  -e NGROK_URL=your-domain.ngrok-free.app \
  -v tv-webhook-data:/data \
  tv-webhook
```

The container starts the webhook server on port 8080 and an ngrok tunnel that exposes it at your static domain.

### Connect to Token Vault

1. Open `https://your-domain.ngrok-free.app/bind` in your browser
2. Click **Connect to TokenVault** — this redirects you to the Token Vault dashboard
3. Token Vault exchanges a one-time code with your webhook to establish the HMAC secret
4. Your vault is now connected — add tokens from the dashboard

## Run locally (without Docker)

```bash
pip install -r requirements.txt
PORT=8080 python main.py
```

Then run ngrok separately:

```bash
ngrok http 8080 --url=your-domain.ngrok-free.app
```

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NGROK_AUTHTOKEN` | Yes (Docker) | ngrok authentication token |
| `NGROK_URL` | Yes (Docker) | Your ngrok static domain |
| `PORT` | No | Server port (default: 8080) |
| `WEBHOOK_EXTERNAL_URL` | No | Public URL (auto-detected from ngrok headers) |
| `TOKENVAULT_FRONTEND_URL` | No | Token Vault frontend URL (default: `https://tokenvault.uk`) |
| `TOKENVAULT_STORE_PATH` | No | Path to persist webhook config (default: `/data/tokenvault_store.json`) |
| `TOKENVAULT_KV_STORE_PATH` | No | Path to persist token data (default: `/data/tokenvault_kv_store.json`) |
| `LOG_LEVEL` | No | Logging level (default: `DEBUG`) |

## Endpoints

### Token Vault → Webhook (HMAC-signed)

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/v1/exchange` | POST | One-time code | Establish HMAC secret during webhook-bind |
| `/v1/health` | GET/POST | HMAC (POST) | Health check and status |
| `/v1/storage` | POST | HMAC | Metadata CRUD — token listings, proxy configs, audit events |
| `/v1/proxy` | POST | HMAC + ticket | MCP proxy — decrypt credential, inject into upstream request |
| `/v1/refresh-notify` | POST | HMAC | Token refresh notification — webhook handles the OAuth refresh |

### Direct Access (agents & browsers — NOT called by Token Vault)

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/v1/credential` | GET/POST | Signed ticket | Agent 307 redirect — decrypt and return credential |
| `/v1/store` | POST | Signed ticket | Browser-direct — encrypt and store credential |

### Registration

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/bind` | GET | Browser landing page — one-click webhook-bind flow |
| `/v1/register-url` | GET | Generate registration URL with one-time code |

## Persistent storage

The webhook persists two JSON files (in `/data/` by default):

- **`tokenvault_store.json`** — HMAC secret, encryption key, webhook ID
- **`tokenvault_kv_store.json`** — Encrypted tokens, proxy configs, audit events, vault settings

Mount a Docker volume (`-v tv-webhook-data:/data`) to persist data across container restarts.

## Generate your own webhook

Token Vault publishes a machine-readable specification at [`tokenvault.uk/llm.txt`](https://tokenvault.uk/llm.txt). Feed it to an LLM along with your language and framework of choice:

```bash
curl -s https://tokenvault.uk/llm.txt | pbcopy
```

> Generate a Token Vault webhook server in Go using Gin. Include all seven endpoints, HMAC verification, ticket verification, AES-256-GCM encryption, a SQLite storage backend, and inline comments.

# Token Vault Webhook (ngrok)

Example [Token Vault](https://tokenvault.uk) webhook service that runs locally and exposes itself via [ngrok](https://ngrok.com). Implements the full Token Vault webhook protocol (setup, health, decrypt, refresh, storage).

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
  tv-webhook
```

The container starts the webhook server on port 8080 and an ngrok tunnel that exposes it at your static domain. Use that URL as the webhook URL in the Token Vault dashboard.

## Run locally (without Docker)

```bash
pip install -r requirements.txt
PORT=8080 python main.py
```

Then run ngrok separately:

```bash
ngrok http 8080 --url=your-domain.ngrok-free.app
```

## Endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/setup` | Receives Shamir share + HMAC secret |
| `GET/POST /v1/health` | Returns health status |
| `POST /v1/decrypt` | Reconstructs key, decrypts token |
| `POST /v1/refresh` | Reconstructs key, refreshes OAuth token |
| `POST /v1/get_share` | Returns the webhook's share for auto-unlock |
| `POST /v1/storage` | KV storage operations |

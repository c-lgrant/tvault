# Cloudflare Workers Deploy

This directory contains configuration and instructions for deploying the webhook to Cloudflare Workers.

## Quick deploy

Click the button in the top-level `examples/webhook/README.md` to deploy directly to your Cloudflare account via the Workers dashboard.

## Manual deploy

```bash
# 1. Authenticate
wrangler login

# 2. Create KV namespaces
wrangler kv namespace create TOKENS
wrangler kv namespace create REPLAY

# 3. Update wrangler.toml with the returned namespace IDs

# 4. Set secrets
wrangler secret put TV_WEBHOOK_SEED
wrangler secret put TV_BASE_URL
wrangler secret put TV_TOKEN

# 5. Deploy
npm run deploy
```

## Post-deploy

Register the Workers URL with your Token Vault instance:

```
TV_BASE_URL/v1/register-url?url=https://<your-worker>.workers.dev
```

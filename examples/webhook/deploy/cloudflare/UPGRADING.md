# Upgrading your Token Vault webhook

Upgrading is an **in-place redeploy** — there is no migration, no re-keying, and
no URL change. Your credentials (D1) and your seed (`TV_WEBHOOK_SEED`) are
preserved across every deploy, and the webhook upconverts its own storage schema
on boot.

## The easy path (recommended)

1. Open your webhook repo on GitHub → **Actions** → **Update webhook** → **Run
   workflow**.
2. It opens a PR titled `chore: update webhook to <version>`. Review the diff.
3. **Merge** it. Cloudflare Workers Builds redeploys automatically against your
   existing D1 database and seed.

That's it. Same URL, same identity, same data — newer code.

> The Action never touches your `wrangler.toml`, `.dev.vars`, or secrets. If a
> release adds a new `wrangler.toml` variable, the PR won't include it — check
> the release notes and add it manually.

## Manual path (if you prefer the CLI)

```bash
# from a clone of YOUR webhook repo
curl -fsSL https://codeload.github.com/c-lgrant/tvault/tar.gz/refs/tags/<tag> -o up.tgz
mkdir up && tar -xzf up.tgz -C up --strip-components=1
node scripts/apply-update.mjs up/examples/webhook .
git checkout -b chore/update-webhook && git add -A && git commit -m "chore: update webhook to <tag>"
git push origin chore/update-webhook   # open a PR, review, merge → auto-deploy
```

## What is preserved

| Thing | Preserved? | Why |
|---|---|---|
| Credentials (D1) | ✅ | Same auto-provisioned `tv-webhook` D1, reused every deploy |
| Seed / keys | ✅ | `TV_WEBHOOK_SEED` is a Workers Secret, untouched by deploys |
| Webhook URL + TV binding | ✅ | Identity is HKDF-derived from the seed; nothing re-registers |
| `wrangler.toml` / secrets | ✅ | The update Action skips operator config |

> **Auto-seal on upgrade.** If you bound your webhook before the bind-seal
> mechanism shipped and never set `TV_ADMIN_SECRET`, the webhook will
> auto-seal its setup endpoints on the next boot. To re-run `/v1/exchange`
> afterwards, set `TV_ADMIN_SECRET` as a Workers Secret and redeploy.

## Re-hosting (different account, region, or runtime)

That's a different operation — moving the *data* to *new infrastructure* — not an
upgrade. It is not covered here; reach for a future `tvault migrate` flow.

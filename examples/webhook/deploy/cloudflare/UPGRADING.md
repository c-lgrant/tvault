# Upgrading your Token Vault webhook

Upgrading is an **in-place redeploy** — there is no migration, no re-keying, and
no URL change. Your credentials (D1) and your seed (`TV_WEBHOOK_SEED`) are
preserved across every deploy, and the webhook upconverts its own storage schema
on boot.

## One-time prerequisite

GitHub blocks Actions from opening pull requests on new repos by default, so the
**first** run of the update workflow fails with:

```
GitHub Actions is not permitted to create or approve pull requests.
```

Enable it once, in **your** webhook repo — Settings → Actions → General →
Workflow permissions → tick **Allow GitHub Actions to create and approve pull
requests** → Save. Or with the CLI:

```bash
gh api -X PUT repos/<you>/<your-webhook-repo>/actions/permissions/workflow \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true
```

The workflow requests `pull-requests: write` itself, so leaving the default
workflow permission at `read` is fine — this repo-level switch is the only thing
that needs changing.

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
# Stage the download OUTSIDE the repo — `git add -A` below would otherwise
# commit the tarball and the whole extracted tree into your PR.
up=$(mktemp -d)
curl -fsSL https://codeload.github.com/c-lgrant/tvault/tar.gz/refs/tags/<tag> -o "$up/up.tgz"
tar -xzf "$up/up.tgz" -C "$up" --strip-components=1
node scripts/apply-update.mjs "$up/examples/webhook" .
git checkout -b chore/update-webhook && git add -A && git commit -m "chore: update webhook to <tag>"
git push origin chore/update-webhook   # open a PR, review, merge → auto-deploy
rm -rf "$up"
```

## What is preserved

| Thing | Preserved? | Why |
|---|---|---|
| Credentials (D1) | ✅ | Same auto-provisioned `tv-webhook` D1, reused every deploy |
| Seed / keys | ✅ | `TV_WEBHOOK_SEED` is a Workers Secret, untouched by deploys |
| Webhook URL + TV binding | ✅ | Identity is HKDF-derived from the seed; nothing re-registers |
| `wrangler.toml` / secrets | ✅ | The update Action skips operator config |
| `.github/workflows/` | ✅ | Skipped — see below; changes are reported, not applied |

> **Workflow files are never auto-updated.** GitHub refuses to let an Actions
> token write under `.github/workflows/`, and that permission cannot be granted
> to `GITHUB_TOKEN` at all. So the update skips those files rather than building
> a commit that could never be pushed. When upstream changes one, the run's
> summary and the PR body both name it — copy it in by hand.

> **Auto-seal on upgrade.** If you bound your webhook before the bind-seal
> mechanism shipped and never set `TV_ADMIN_SECRET`, the webhook will
> auto-seal its setup endpoints on the next boot. To re-run `/v1/exchange`
> afterwards, set `TV_ADMIN_SECRET` as a Workers Secret and redeploy.

## Re-hosting (different account, region, or runtime)

That's a different operation — moving the *data* to *new infrastructure* — not an
upgrade. It is not covered here; reach for a future `tvault migrate` flow.

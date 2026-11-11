# Releasing tvault

Development follows gitflow, and releases are automated with
[release-please](https://github.com/googleapis/release-please).

## The happy path

1. Branch from `develop`. Use conventional-commit subjects (`feat: add foo`,
   `fix: bar`).
2. Open a PR into `develop` with a conventional title. CI must pass before it
   merges. **Squash-merge it**: GitHub puts the PR title in a merge commit, so
   a merge commit makes release-please list the change twice.
3. To ship, open a PR from `develop` into `main` and merge it with a merge
   commit (not a squash), so the `feat`/`fix` commits reach release-please.
   `examples/webhook/wrangler.toml` differs between the branches, so this PR
   needs one extra commit; see [wrangler.toml values](#wranglertoml-values).
4. The `release-please` workflow opens (or updates) a PR titled
   `chore(main): release X.Y.Z`. Its body is the generated `CHANGELOG.md`
   diff. The workflow also starts CI on that PR.
5. Review the changelog and merge the release PR.
6. release-please tags `vX.Y.Z` and publishes the GitHub Release. The same
   workflow then builds the binaries (goreleaser) and publishes `@tvault/cli`
   to npm.
7. Merge `main` back into `develop` (a PR), so `develop` has the release
   commit, `CHANGELOG.md` and the version bumps. This PR must restore the dev
   `wrangler.toml` values; see below.

## wrangler.toml values

`examples/webhook/wrangler.toml` carries three environment-specific values:

| Key                        | `develop` (dev control plane) | `main` (production)          |
|----------------------------|-------------------------------|------------------------------|
| `name`                     | `tv-webhook-dev`              | `tv-webhook`                 |
| `TOKENVAULT_FRONTEND_URL`  | `https://tokenvault.one`      | `https://tokenvault.uk`      |
| `database_name`            | `tv-webhook-dev`              | `tv-webhook`                 |

The `wrangler-env` CI job (`scripts/check-wrangler-env.mjs`) fails a PR whose
base is `main` while the file has dev values, and a PR or push to `develop`
while it has prod values. Because `develop` merges into `main` at each release:

1. **Release PR (develop into main).** Branch `release/prod-values` from
   `develop`, change the three values to the prod column in
   `examples/webhook/wrangler.toml` (keep the rest of the file as is), commit
   it as `chore(webhook): production wrangler defaults`, and open the PR from
   that branch into `main`. It carries every commit of `develop` plus the flip.
   Merge it with a merge commit. Do not put the flip on `develop` itself.
2. **Back-merge (main into develop).** Branch `chore/back-merge` from `main`,
   change the three values back to the dev column, commit it as
   `chore(webhook): restore dev wrangler defaults`, and open the PR into
   `develop`. Merge it with a merge commit. Until this lands, `develop` would
   pick up prod values from the next `main` merge.
3. Run `node scripts/check-wrangler-env.mjs main` on the first branch and
   `node scripts/check-wrangler-env.mjs develop` on the second before pushing.

The release-please PR (`release-please--branches--main`) only edits
`CHANGELOG.md` and version files, so it needs nothing.

## Triggers at a glance

| Event                              | Workflow             | What it does |
|------------------------------------|----------------------|--------------|
| PR, or push to `develop`/`main`    | `ci.yml`             | gofmt, vet, build, test (ubuntu + macOS); wrangler.toml env-values check; webhook typecheck + tests; goreleaser dry-run; install.sh smoke on `main` |
| Push to `main`                     | `release-please.yml` | Open or update the release PR and dispatch its CI; no-op if nothing is releasable |
| Merge of the release PR            | `release-please.yml` | Tag + GitHub Release, then call `release.yml` (binaries), then `npm publish` |

Everything runs on `GITHUB_TOKEN`; there are no release secrets. Events that
`GITHUB_TOKEN` causes never start other workflows, which is why the release
jobs are called from `release-please.yml` and the release PR's CI is
dispatched explicitly.

## npm

`@tvault/cli` is published with npm trusted publishing: npmjs.com trusts
`release-please.yml` in `c-lgrant/tvault`, so no npm token exists and every
version carries provenance. The package version moves with each release
(release-please bumps `npm/package.json`). The npm job runs after the binaries
upload, because `npm/install.js` downloads the tag's release assets.

## Versioning notes

The `version` package var in `cmd/root.go` (default `"dev"`) is **not**
auto-patched by release-please. The version users see comes from one of two
places:

- **Released binaries:** goreleaser injects the real version via
  `-ldflags -X .../cmd.version={{.Version}}` at build time. `tvault version`
  prints e.g. `tvault v0.5.0 (commit abc123, built ...)`.
- **`go install` builds:** `cmd/version.go` falls back to
  `runtime/debug.ReadBuildInfo()` and prints the module version + VCS metadata
  Go records in the binary. No source patching needed.

If you `go run .` from a working tree, you'll always see `tvault dev (commit
unknown, built unknown)` — that's expected and not a regression.

Never move or delete a published tag: the Go checksum database has recorded
its content, and `go install …@vX.Y.Z` fails for everyone if it changes.

## Forcing a release

If you need to ship even though no `feat:`/`fix:` commits have landed (e.g. a
docs-only release), include a footer in any commit:

```
docs: clarify webhook setup

Release-As: 0.5.1
```

Or land an empty `feat:` commit:

```bash
git commit --allow-empty -m "feat: bump for documentation refresh"
```

Either nudges release-please into opening / updating the release PR.

## Recovering from a failed release

**Anything after the tag failed (binaries or npm):** run
`release-please` by hand on `main` with the tag:

```bash
gh workflow run release-please.yml --ref main -f tag=vX.Y.Z
```

That publishes the existing release again: goreleaser replaces assets a failed
run already uploaded (`replace_existing_artifacts`), and the npm job runs from the same workflow file npm trusts. If
that version is already on npm, `npm publish` fails without harm. Run
`release.yml` alone (with the tag) to rebuild only the binaries.

**release-please isn't opening a PR:** Check that the most recent commit
subjects use conventional-commit prefixes (`feat:`, `fix:`, etc.). The bot
ignores commits whose type is marked `hidden` in `release-please-config.json`
(`test:`, `chore:`, `ci:`) — a release of only those produces no PR.

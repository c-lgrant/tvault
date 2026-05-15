# Releasing tvault

Releases are automated via [release-please](https://github.com/googleapis/release-please).
You almost never need to do anything manual.

## The happy path

1. Land conventional-commit work on `main` (e.g. `feat: add foo`, `fix: bar`).
2. The `release-please` workflow opens (or updates) a PR titled
   `chore(main): release tvault X.Y.Z`. The PR body is the auto-generated
   `CHANGELOG.md` diff.
3. Review the changelog. Merge the PR.
4. release-please creates the `vX.Y.Z` tag and publishes a GitHub Release. That
   triggers `release.yml` (binaries via goreleaser) and `build-webhook.yml`
   (multi-arch image to `ghcr.io/c-lgrant/tvault-webhook`).

That's the whole thing.

## Triggers at a glance

| Event                                | Workflow            | What it does                                        |
|--------------------------------------|---------------------|-----------------------------------------------------|
| Push to `main` (any commit)          | `ci.yml`            | gofmt, vet, build, test (ubuntu + macOS); goreleaser dry-run; install.sh smoke (when a release exists and the repo is public) |
| PR open / update                     | `ci.yml`            | Same minus the install.sh smoke job                 |
| Push to `main` (any commit)          | `release-please.yml`| Open or update the release PR; no-op if nothing releasable |
| Merge of release PR                  | (release-please)    | Create `vX.Y.Z` tag + published GitHub Release      |
| GitHub Release published             | `release.yml`       | `goreleaser release --clean` → binaries + checksums |
| GitHub Release published             | `build-webhook.yml` | Build + push `ghcr.io/c-lgrant/tvault-webhook` tags |

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

## First-release bootstrap (one-time)

The GHCR `tvault-webhook` package is created on the first push and defaults to
**private** because the source repo is private. After the first release lands,
flip its visibility once:

```bash
gh api -X PATCH /user/packages/container/tvault-webhook/visibility \
  -f visibility=public
```

After this, anonymous `docker pull ghcr.io/c-lgrant/tvault-webhook:latest`
works — which is what `tvault webhook init`/`up` rely on.

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

**`release.yml` failed (binaries didn't publish):** Re-run the workflow from
the Actions tab. goreleaser is idempotent against GitHub Release assets — it
overwrites them. Re-running is safe.

**`build-webhook.yml` failed (image didn't push):** Same — re-run the
workflow from the Actions tab. The metadata-action regenerates the same tag
list from the release event.

**Tag is wrong / changelog is wrong:** Delete the GitHub Release (UI: Releases
→ … → Delete release) AND the corresponding `vX.Y.Z` git tag
(`git push origin :refs/tags/vX.Y.Z`). release-please will reopen the release
PR on the next push to `main` so you can fix the commits/changelog and merge
again.

**release-please isn't opening a PR:** Check that the most recent commit
subjects use conventional-commit prefixes (`feat:`, `fix:`, etc.). The bot
ignores commits whose type is marked `hidden` in `release-please-config.json`
(`test:`, `chore:`, `ci:`) — a release of only those produces no PR.

## Private repo vs public repo

While `c-lgrant/tvault` is private:

- `go install github.com/c-lgrant/tvault@latest` returns 404 — Go's module
  proxy can't see private repos without auth.
- `curl … install.sh | bash` returns 404 on the API call — same reason.
- CI's `install-sh-smoke` job self-skips (it checks `gh repo view --json visibility`).
- All other workflows run normally; goreleaser publishes binaries to the
  GitHub Release just fine, but only authenticated users can download them.

When the repo flips to public, all of the above start working automatically —
no code changes needed at flip time.

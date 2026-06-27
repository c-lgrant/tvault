// examples/webhook/scripts/apply-update.mjs
// Overlays a freshly-fetched upstream webhook tree onto the operator's repo,
// preserving their config. Used by .github/workflows/update-webhook.yml. Pure
// helpers are exported for tests; the CLI tail runs the overlay.

import { readdir, mkdir, copyFile, stat, lstat } from "node:fs/promises";
import { join, dirname, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";

// Paths (relative to the webhook root) that belong to the operator and must
// never be overwritten by an upstream overlay.
const SKIP_PREFIXES = ["wrangler.toml", ".dev.vars", ".git", "node_modules", ".wrangler"];

function isSkipped(rel) {
  const norm = rel.split(sep).join("/");
  return SKIP_PREFIXES.some((p) => norm === p || norm.startsWith(p + "/"));
}

export function planOverlay(files) {
  const copy = [];
  const skipped = [];
  for (const f of files) (isSkipped(f) ? skipped : copy).push(f);
  return { copy, skipped };
}

/**
 * Recursively collect regular files under `dir`, relative to `base`.
 * Only regular files are emitted in `files`. Symlinks (never followed) and
 * non-regular special files (FIFO/socket/device, which copyFile() can't copy)
 * are returned separately in `skipped` so callers can report them.
 */
async function walk(dir, base = dir) {
  const files = [];
  const skipped = [];
  for (const ent of await readdir(dir, { withFileTypes: true })) {
    const abs = join(dir, ent.name);
    let isSymlink = ent.isSymbolicLink();
    let isDir = ent.isDirectory();
    let isFile = ent.isFile();
    // On some filesystems readdir() returns Dirents with an unknown type
    // (d_type unknown) — every isX() is false. Fall back to lstat(), which does
    // NOT follow symlinks, so the symlink guard can't be bypassed into the
    // plain-file branch (which would copyFile() the link target).
    if (!isSymlink && !isDir && !isFile) {
      const st = await lstat(abs);
      isSymlink = st.isSymbolicLink();
      isDir = st.isDirectory();
      isFile = st.isFile();
    }
    if (isSymlink) {
      // Refuse to follow symlinks: they could point anywhere on the runner
      // filesystem and copyFile() would silently exfiltrate the target.
      skipped.push(relative(base, abs));
    } else if (isDir) {
      const sub = await walk(abs, base);
      files.push(...sub.files);
      skipped.push(...sub.skipped);
    } else if (isFile) {
      files.push(relative(base, abs));
    } else {
      // Non-regular file (FIFO/socket/device): copyFile() only supports regular
      // files, so skip it and report it alongside symlinks rather than failing.
      skipped.push(relative(base, abs));
    }
  }
  return { files, skipped };
}

export async function applyOverlay(upstreamDir, targetDir) {
  const { files, skipped: walkSkipped } = await walk(upstreamDir);
  const { copy, skipped } = planOverlay(files);
  // Symlinks and other non-regular files are always skipped — append them.
  const allSkipped = [...skipped, ...walkSkipped];
  for (const rel of copy) {
    const dest = join(targetDir, rel);
    await mkdir(dirname(dest), { recursive: true });
    await copyFile(join(upstreamDir, rel), dest);
  }
  return { copied: copy, skipped: allSkipped };
}

// CLI: node apply-update.mjs <upstreamDir> <targetDir>
// Compare against pathToFileURL(argv[1]).href rather than a hand-built
// `file://${argv[1]}` string: import.meta.url is URL-encoded (spaces → %20,
// platform-correct separators), so a raw concatenation mismatches whenever the
// script path contains spaces or runs on Windows, silently skipping the CLI.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [, , upstreamDir, targetDir] = process.argv;
  if (!upstreamDir || !targetDir) {
    console.error("usage: apply-update.mjs <upstreamWebhookDir> <targetRepoDir>");
    process.exit(2);
  }
  await stat(upstreamDir); // throws if missing
  const r = await applyOverlay(upstreamDir, targetDir);
  console.log(`overlay: ${r.copied.length} copied, ${r.skipped.length} skipped`);
}

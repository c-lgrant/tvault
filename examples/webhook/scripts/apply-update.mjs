// examples/webhook/scripts/apply-update.mjs
// Overlays a freshly-fetched upstream webhook tree onto the operator's repo,
// preserving their config. Used by .github/workflows/update-webhook.yml. Pure
// helpers are exported for tests; the CLI tail runs the overlay.

import { readdir, mkdir, copyFile, stat } from "node:fs/promises";
import { join, dirname, relative, sep } from "node:path";

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

async function walk(dir, base = dir) {
  const out = [];
  for (const ent of await readdir(dir, { withFileTypes: true })) {
    const abs = join(dir, ent.name);
    if (ent.isDirectory()) out.push(...(await walk(abs, base)));
    else out.push(relative(base, abs));
  }
  return out;
}

export async function applyOverlay(upstreamDir, targetDir) {
  const all = await walk(upstreamDir);
  const { copy, skipped } = planOverlay(all);
  for (const rel of copy) {
    const dest = join(targetDir, rel);
    await mkdir(dirname(dest), { recursive: true });
    await copyFile(join(upstreamDir, rel), dest);
  }
  return { copied: copy, skipped };
}

// CLI: node apply-update.mjs <upstreamDir> <targetDir>
if (import.meta.url === `file://${process.argv[1]}`) {
  const [, , upstreamDir, targetDir] = process.argv;
  if (!upstreamDir || !targetDir) {
    console.error("usage: apply-update.mjs <upstreamWebhookDir> <targetRepoDir>");
    process.exit(2);
  }
  await stat(upstreamDir); // throws if missing
  const r = await applyOverlay(upstreamDir, targetDir);
  console.log(`overlay: ${r.copied.length} copied, ${r.skipped.length} skipped`);
}

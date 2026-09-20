// Shared <head> for this webhook's small set of inline HTML pages (bind,
// setup, landing) — one small stylesheet, no external assets, so the visual
// language can't drift between them. Title defaults to the bind flow's
// original copy since that's still the most common page an operator sees.

export function pageHead(title = "Connect to Token Vault"): string {
  return `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
  body{font:16px system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1.5rem;color:#0f172a;line-height:1.5}
  h1{font-size:1.4rem}
  h2{font-size:1.1rem}
  .btn{display:inline-block;margin-top:1.5rem;padding:.7rem 1.25rem;border-radius:.5rem;
       background:#059669;color:#fff;text-decoration:none;font-weight:600}
  button.btn{border:0;cursor:pointer;font:inherit}
  .btn.secondary{background:#475569}
  .btn.disabled{background:#94a3b8;pointer-events:none}
  code{background:#f1f5f9;padding:.15rem .35rem;border-radius:.25rem;font-size:.85em}
  pre{background:#0f172a;color:#e2e8f0;padding:.9rem 1rem;border-radius:.5rem;overflow-x:auto;font-size:.85em}
  .dest{margin-top:1rem;padding:.75rem 1rem;border:1px solid #e2e8f0;border-radius:.5rem;background:#f8fafc}
  .warn{margin-top:1rem;padding:.75rem 1rem;border:1px solid #fcd34d;border-radius:.5rem;background:#fffbeb}
  .tip{margin-top:1rem;padding:.75rem 1rem;border:1px solid #bbf7d0;border-radius:.5rem;background:#f0fdf4}
  .muted{color:#475569;font-size:.9em}
  hr{margin:1.75rem 0;border:0;border-top:1px solid #e2e8f0}
  ol{padding-left:1.2rem}
  .status{list-style:none;padding:0;margin:1.25rem 0}
  .status li{padding:.4rem 0;border-bottom:1px solid #e2e8f0}
  .status li:last-child{border-bottom:0}
  .ok{color:#059669;font-weight:700}
  .bad{color:#b45309;font-weight:700}
</style>`;
}

/** Escape a string for safe interpolation into HTML text or attribute values. */
export function escapeHtml(v: string): string {
  return v
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

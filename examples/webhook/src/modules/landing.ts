// Root landing page (`GET /`) — the first URL a new user opens after the
// Deploy-to-Cloudflare button finishes. Reports this worker's own state (seed
// present? bound to a Token Vault instance?) instead of leaving `/` a 404, and
// is now the only place the "seed missing" fix is shown — Token Vault's own
// console no longer needs to pre-emptively explain that failure; it can just
// point here.
//
// "Bound to <frontend>" reads the currently configured TOKENVAULT_FRONTEND_URL,
// not a value recorded at bind time — bindState.ts only persists a boolean.
// That's fine: once bound, /bind is sealed (guardBound in exchange.ts), so the
// configured default IS the instance this webhook is bound to.

import { WEBHOOK_VERSION } from "../core/protocol/types.ts";
import { isBound } from "./bindState.ts";
import { pageHead, escapeHtml } from "./pageChrome.ts";
import { resolveExternalUrl, resolveFrontend, seedFix } from "./webhookLinks.ts";
import type { FeatureModule } from "../core/registry.ts";

function statusRow(ok: boolean, label: string, detail: string): string {
  return `<li><span class="${ok ? "ok" : "bad"}">${ok ? "✓" : "✗"}</span> ${label} — ${detail}</li>`;
}

const LANDING_PAGE = (opts: {
  externalUrl: string;
  frontend: string;
  seedConfigured: boolean;
  bound: boolean;
  adminSecretConfigured: boolean;
  bindHref: string;
}) => {
  const { externalUrl, frontend, seedConfigured, bound, adminSecretConfigured, bindHref } = opts;
  const fix = seedConfigured ? null : seedFix(externalUrl);
  // Build-time ensure-seed greps for this to tell an EMPTY secret from a set one.
  const marker = seedConfigured ? "" : "<!-- tv-seed:unset -->";

  // Disconnecting in Token Vault only forgets the webhook on TV's side — it
  // never calls back here to clear bind state (vault.py's delete_vault leaves
  // "the user's webhook ... entirely out of scope"). Re-binding this webhook
  // to a different TV instance is gated purely by guardBound in exchange.ts:
  // the correct x-tv-admin-secret header re-opens /bind, or — with no
  // TV_ADMIN_SECRET configured — the webhook is permanently sealed.
  const rebindNote = adminSecretConfigured
    ? "To bind this webhook to a different Token Vault instance, call /bind with a valid x-tv-admin-secret header (this page can't send one) — disconnecting in Token Vault does not unbind this webhook."
    : "This webhook is permanently sealed: no TV_ADMIN_SECRET is configured, so it can't be re-bound to a different Token Vault instance without redeploying with one set. Disconnecting in Token Vault does not unbind this webhook.";

  const action = bound
    ? `<a class="btn" href="${escapeHtml(frontend)}">Open Token Vault →</a>
<p class="muted">Already connected. ${rebindNote}</p>`
    : seedConfigured
      ? `<a class="btn" href="${bindHref}">Connect to Token Vault →</a>
<p class="muted">Binding to: <code>${escapeHtml(frontend)}</code></p>`
      : `<span class="btn disabled" aria-disabled="true">Connect to Token Vault →</span>
<p class="muted">Set the seed below first. Binding to: <code>${escapeHtml(frontend)}</code></p>`;

  return `${marker}<!doctype html>
<html lang="en"><head>${pageHead("Token Vault webhook")}</head><body>
<h1>Token Vault webhook</h1>
<p><code>${escapeHtml(externalUrl)}</code> · v${WEBHOOK_VERSION}</p>
<ul class="status">
${statusRow(true, "Deployed", "yes")}
${statusRow(seedConfigured, "Seed", seedConfigured ? "set" : "not set")}
${statusRow(bound, "Connected to Token Vault", bound ? `bound to <code>${escapeHtml(frontend)}</code>` : "not yet")}
</ul>
${action}
${fix
  ? `<hr>
<h2>Set <code>TV_WEBHOOK_SEED</code></h2>
<p>Required before this webhook can bind. Set it as a Workers Secret, then reload.</p>
<a class="btn secondary" href="${fix.settingsUrl}" target="_blank" rel="noopener">Open this Worker's Settings →</a>
<pre>${fix.command}</pre>`
  : ""}
</body></html>`;
};

export function landingModule(): FeatureModule {
  return {
    name: "landing",
    register(app, ctx) {
      app.get("/", async (c) => {
        const externalUrl = resolveExternalUrl(c, ctx.config);
        if (!externalUrl) {
          return c.html("<h1>Webhook misconfigured</h1><p>EXTERNAL_URL is not set.</p>", 500);
        }
        const frontend = resolveFrontend(c, ctx.config);
        const seedConfigured = await ctx.secrets.isConfigured();
        const bound = await isBound(ctx.storage);
        // Always spell the destination out in the link itself, exactly as the
        // console's guided flow does, so the URL a user hovers/copies says
        // where the bind will land. `frontend` already honours a ?tv= override.
        const bindHref = `/bind?tv=${encodeURIComponent(frontend)}`;
        const adminSecretConfigured = !!ctx.config.adminSecret;
        const html = LANDING_PAGE({
          externalUrl,
          frontend,
          seedConfigured,
          bound,
          adminSecretConfigured,
          bindHref,
        });
        return c.html(html, 200, { "Cache-Control": "no-store" });
      });
    },
  };
}

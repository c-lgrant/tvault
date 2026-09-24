// examples/webhook/test/scripts/apply-update.test.ts
import { describe, expect, it } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from "node:fs/promises";
import { createServer } from "node:net";
import { planOverlay, applyOverlay, isDriftWatched } from "../../scripts/apply-update.mjs";

describe("planOverlay", () => {
  it("copies code, skips operator config", () => {
    const r = planOverlay([
      "src/core/app.ts",
      "package.json",
      "wrangler.toml",
      ".dev.vars",
      ".git/config",
      "node_modules/x/index.js",
    ]);
    expect(r.copy).toContain("src/core/app.ts");
    expect(r.copy).toContain("package.json");
    expect(r.skipped).toEqual(expect.arrayContaining([
      "wrangler.toml", ".dev.vars", ".git/config", "node_modules/x/index.js",
    ]));
    expect(r.copy).not.toContain("wrangler.toml");
  });

  it("skips .github/workflows — GITHUB_TOKEN cannot push workflow files", () => {
    const r = planOverlay([".github/workflows/update-webhook.yml", "src/app.ts"]);
    expect(r.skipped).toContain(".github/workflows/update-webhook.yml");
    expect(r.copy).toEqual(["src/app.ts"]);
  });

  it("does not let the .git prefix swallow .github, nor skip non-workflow .github files", () => {
    const r = planOverlay([".github/dependabot.yml", ".github/ISSUE_TEMPLATE/bug.md"]);
    expect(r.copy).toEqual([".github/dependabot.yml", ".github/ISSUE_TEMPLATE/bug.md"]);
    expect(r.skipped).toEqual([]);
  });

  it("watches only workflow paths for drift", () => {
    expect(isDriftWatched(".github/workflows/update-webhook.yml")).toBe(true);
    expect(isDriftWatched("wrangler.toml")).toBe(false);
  });
});

describe("applyOverlay", () => {
  it("skips symlinks in the upstream tree and reports them in result.skipped (Copilot review: refuse symlink overlay)", async () => {
    const up = await mkdtemp(join(tmpdir(), "up-sym-"));
    const tgt = await mkdtemp(join(tmpdir(), "tgt-sym-"));
    const outside = await mkdtemp(join(tmpdir(), "outside-"));
    try {
      // A real file that should be copied
      await writeFile(join(up, "real.ts"), "REAL");
      // A symlink in the upstream tree pointing at an outside file
      await writeFile(join(outside, "secret.txt"), "SECRET");
      await symlink(join(outside, "secret.txt"), join(up, "link.ts"));

      const r = await applyOverlay(up, tgt);

      // Real file was copied
      expect(await readFile(join(tgt, "real.ts"), "utf-8")).toBe("REAL");
      // Symlink was NOT copied into target (file must not exist)
      await expect(readFile(join(tgt, "link.ts"), "utf-8")).rejects.toThrow();
      // Symlink path appears in skipped
      expect(r.skipped).toContain("link.ts");
    } finally {
      await rm(up, { recursive: true, force: true });
      await rm(tgt, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("skips non-regular files (unix socket) and reports them in result.skipped (Copilot review: copyFile only supports regular files)", async () => {
    const up = await mkdtemp(join(tmpdir(), "up-sock-"));
    const tgt = await mkdtemp(join(tmpdir(), "tgt-sock-"));
    const server = createServer();
    try {
      // A real file that should be copied.
      await writeFile(join(up, "real.ts"), "REAL");
      // A unix-domain socket — a non-regular file copyFile() cannot copy.
      const sockPath = join(up, "daemon.sock");
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(sockPath, resolve);
      });

      const r = await applyOverlay(up, tgt);

      // Real file copied; socket neither copied nor allowed to crash the overlay.
      expect(await readFile(join(tgt, "real.ts"), "utf-8")).toBe("REAL");
      await expect(readFile(join(tgt, "daemon.sock"), "utf-8")).rejects.toThrow();
      expect(r.skipped).toContain("daemon.sock");
      expect(r.copied).not.toContain("daemon.sock");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await rm(up, { recursive: true, force: true });
      await rm(tgt, { recursive: true, force: true });
    }
  });

  it("reports drift when upstream's workflow differs, and leaves the operator's in place", async () => {
    const up = await mkdtemp(join(tmpdir(), "up-drift-"));
    const tgt = await mkdtemp(join(tmpdir(), "tgt-drift-"));
    try {
      await mkdir(join(up, ".github", "workflows"), { recursive: true });
      await mkdir(join(tgt, ".github", "workflows"), { recursive: true });
      await writeFile(join(up, ".github", "workflows", "update-webhook.yml"), "NEW");
      await writeFile(join(tgt, ".github", "workflows", "update-webhook.yml"), "OLD");

      const r = await applyOverlay(up, tgt);

      // Not overwritten — pushing it would be rejected by GitHub anyway.
      expect(await readFile(join(tgt, ".github/workflows/update-webhook.yml"), "utf-8")).toBe("OLD");
      expect(r.drifted).toEqual([".github/workflows/update-webhook.yml"]);
    } finally {
      await rm(up, { recursive: true, force: true });
      await rm(tgt, { recursive: true, force: true });
    }
  });

  it("stays silent when the operator's workflow already matches upstream", async () => {
    const up = await mkdtemp(join(tmpdir(), "up-same-"));
    const tgt = await mkdtemp(join(tmpdir(), "tgt-same-"));
    try {
      await mkdir(join(up, ".github", "workflows"), { recursive: true });
      await mkdir(join(tgt, ".github", "workflows"), { recursive: true });
      await writeFile(join(up, ".github", "workflows", "update-webhook.yml"), "SAME");
      await writeFile(join(tgt, ".github", "workflows", "update-webhook.yml"), "SAME");

      const r = await applyOverlay(up, tgt);

      expect(r.drifted).toEqual([]);
    } finally {
      await rm(up, { recursive: true, force: true });
      await rm(tgt, { recursive: true, force: true });
    }
  });

  it("overlays new code without touching the operator's wrangler.toml", async () => {
    const up = await mkdtemp(join(tmpdir(), "up-"));
    const tgt = await mkdtemp(join(tmpdir(), "tgt-"));
    try {
      await mkdir(join(up, "src"), { recursive: true });
      await writeFile(join(up, "src", "app.ts"), "NEW");
      await writeFile(join(up, "wrangler.toml"), "UPSTREAM_CONFIG");
      await writeFile(join(tgt, "wrangler.toml"), "OPERATOR_CONFIG");

      const r = await applyOverlay(up, tgt);

      expect(await readFile(join(tgt, "src", "app.ts"), "utf-8")).toBe("NEW");
      expect(await readFile(join(tgt, "wrangler.toml"), "utf-8")).toBe("OPERATOR_CONFIG");
      expect(r.skipped).toContain("wrangler.toml");
    } finally {
      await rm(up, { recursive: true, force: true });
      await rm(tgt, { recursive: true, force: true });
    }
  });
});

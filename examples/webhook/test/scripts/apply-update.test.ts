// examples/webhook/test/scripts/apply-update.test.ts
import { describe, expect, it } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { planOverlay, applyOverlay } from "../../scripts/apply-update.mjs";

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
});

describe("applyOverlay", () => {
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

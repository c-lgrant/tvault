#!/usr/bin/env node
// Guards examples/webhook/wrangler.toml against the wrong branch's defaults.
//
//   `main`    carries the production values (tv-webhook, tokenvault.uk)
//   `develop` carries the development values (tv-webhook-dev, tokenvault.one)
//
// Usage: node scripts/check-wrangler-env.mjs [main|develop] [path]
// With no branch argument it reads GITHUB_BASE_REF (pull requests) or, for a
// push, GITHUB_REF_NAME. Any other branch is skipped: only the branches that
// are deployed from need the right values. See RELEASING.md.
import { readFileSync } from "node:fs";

const PROD = {
  name: "tv-webhook",
  frontend: "https://tokenvault.uk",
  database: "tv-webhook",
};
const DEV = {
  name: "tv-webhook-dev",
  frontend: "https://tokenvault.one",
  database: "tv-webhook-dev",
};

/** Extract the three environment-specific values from wrangler.toml text. */
export function readValues(text) {
  const pick = (re) => {
    const m = text.match(re);
    return m ? m[1] : undefined;
  };
  return {
    name: pick(/^name\s*=\s*"([^"]*)"/m),
    frontend: pick(/^TOKENVAULT_FRONTEND_URL\s*=\s*"([^"]*)"/m),
    database: pick(/^database_name\s*=\s*"([^"]*)"/m),
  };
}

/** Returns the list of mismatches between `got` and the target branch's values. */
export function check(branch, text) {
  const want = branch === "main" ? PROD : DEV;
  const got = readValues(text);
  const problems = [];
  for (const key of Object.keys(want)) {
    if (got[key] !== want[key]) {
      problems.push(`${key}: found ${JSON.stringify(got[key])}, ${branch} needs ${JSON.stringify(want[key])}`);
    }
  }
  return problems;
}

function main() {
  const branch = process.argv[2] || process.env.GITHUB_BASE_REF || process.env.GITHUB_REF_NAME || "";
  const file = process.argv[3] || "examples/webhook/wrangler.toml";
  if (branch !== "main" && branch !== "develop") {
    console.log(`wrangler.toml check skipped for branch ${JSON.stringify(branch)}`);
    return 0;
  }
  const problems = check(branch, readFileSync(file, "utf8"));
  if (problems.length === 0) {
    console.log(`wrangler.toml carries the ${branch} values`);
    return 0;
  }
  console.error(`${file} has the wrong environment values for ${branch}:`);
  for (const p of problems) console.error(`  ${p}`);
  console.error("See RELEASING.md (\"wrangler.toml values\") for the release steps.");
  return 1;
}

import { fileURLToPath } from "node:url";
if (process.argv[1] === fileURLToPath(import.meta.url)) process.exit(main());

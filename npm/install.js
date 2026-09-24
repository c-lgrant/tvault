#!/usr/bin/env node
/*
 * postinstall: fetch the tvault release binary matching this package version.
 *
 * Mirrors install.sh — detect OS/arch, download the release tarball, verify its
 * SHA256 against checksums.txt, extract the binary. The package version and the
 * Go release tag are kept in lockstep, so `npm i tvault@0.7.1` installs the
 * v0.7.1 binary rather than whatever is newest.
 *
 * No dependencies: https + crypto are built in, and tar ships on linux/darwin,
 * which are the only platforms the Go release targets.
 */
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const REPO = "c-lgrant/tvault";
const BINARY = "tvault";
const VERSION = require("./package.json").version;
const TAG = process.env.TVAULT_VERSION || `v${VERSION}`;

const ARCH = { x64: "amd64", arm64: "arm64" }[process.arch];
const OS = { linux: "linux", darwin: "darwin" }[process.platform];

function fail(msg) {
  console.error(`\ntvault: ${msg}\n`);
  console.error("Install the binary directly instead:");
  console.error(`  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/install.sh | bash`);
  console.error(`  go install github.com/${REPO}@latest\n`);
  process.exit(1);
}

if (!ARCH || !OS) {
  fail(
    `unsupported platform ${process.platform}/${process.arch}. ` +
      "Prebuilt binaries exist for linux and darwin on x64 and arm64."
  );
}

// Follow redirects — GitHub release downloads redirect to object storage.
function get(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error(`too many redirects for ${url}`));
    https
      .get(url, { headers: { "User-Agent": `${BINARY}-npm/${VERSION}` } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return resolve(get(new URL(res.headers.location, url).toString(), redirects + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

async function main() {
  const asset = `${BINARY}_${TAG}_${OS}_${ARCH}.tar.gz`;
  const base = `https://github.com/${REPO}/releases/download/${TAG}`;
  const libDir = path.join(__dirname, "lib");
  const target = path.join(libDir, BINARY);

  if (process.env.TVAULT_SKIP_DOWNLOAD) {
    console.log("tvault: TVAULT_SKIP_DOWNLOAD set — skipping binary download.");
    return;
  }

  console.log(`tvault: downloading ${asset}`);
  const [tarball, checksums] = await Promise.all([
    get(`${base}/${asset}`),
    get(`${base}/checksums.txt`),
  ]);

  // Verify before touching disk beyond the temp file.
  const actual = crypto.createHash("sha256").update(tarball).digest("hex");
  const line = checksums
    .toString("utf8")
    .split("\n")
    .find((l) => l.trim().endsWith(asset));
  if (!line) fail(`no checksum entry for ${asset} in checksums.txt`);
  const expected = line.trim().split(/\s+/)[0];
  if (actual !== expected) {
    fail(`checksum mismatch for ${asset}\n  expected ${expected}\n  actual   ${actual}`);
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tvault-"));
  try {
    const tarPath = path.join(tmp, asset);
    fs.writeFileSync(tarPath, tarball);
    execFileSync("tar", ["-xzf", tarPath, "-C", tmp], { stdio: "inherit" });

    fs.mkdirSync(libDir, { recursive: true });
    fs.copyFileSync(path.join(tmp, BINARY), target);
    fs.chmodSync(target, 0o755);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  // Self-test, same as install.sh.
  try {
    execFileSync(target, ["version"], { stdio: "pipe" });
  } catch (err) {
    fail(`self-test failed: ${target} version exited non-zero`);
  }

  console.log(`tvault: installed ${TAG} (${OS}/${ARCH})`);
}

main().catch((err) => fail(err.message));

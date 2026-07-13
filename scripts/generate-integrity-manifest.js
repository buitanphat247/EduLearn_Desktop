#!/usr/bin/env node
"use strict";

// C2: generate (and optionally Ed25519-sign) the app integrity manifest.
//
// Run at package time — AFTER copying `src/` into the build but BEFORE ASAR
// packing — so the shipped app carries hashes of every protected file. The
// Electron main process verifies this manifest on startup (see app-integrity.js
// / main.js) and refuses to launch a tampered packaged build.
//
// Usage:
//   node scripts/generate-integrity-manifest.js [--root <dir>] [--out <file>]
//                                                [--sign-key <pkcs8.pem>]
//
// Protected set = every .js under src/ plus package.json. Extend PROTECTED_GLOBS
// as needed (e.g. to cover the bundled rust-core.exe once its path is stable).

const fs = require("fs");
const path = require("path");
const {
  buildIntegrityManifest,
  signManifest,
  MANIFEST_FILENAME,
  SIGNATURE_FILENAME,
} = require("../src/app-integrity");

function parseArgs(argv) {
  const args = { root: process.cwd(), out: null, signKey: null };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--root") args.root = argv[++i];
    else if (a === "--out") args.out = argv[++i];
    else if (a === "--sign-key") args.signKey = argv[++i];
  }
  return args;
}

function collectProtectedFiles(rootDir) {
  const out = [];
  const srcDir = path.join(rootDir, "src");
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile() && abs.endsWith(".js")) out.push(abs);
    }
  };
  if (fs.existsSync(srcDir)) walk(srcDir);
  const pkg = path.join(rootDir, "package.json");
  if (fs.existsSync(pkg)) out.push(pkg);
  return out.sort();
}

function main() {
  const args = parseArgs(process.argv);
  const rootDir = path.resolve(args.root);
  const outPath = args.out
    ? path.resolve(args.out)
    : path.join(rootDir, MANIFEST_FILENAME);

  const files = collectProtectedFiles(rootDir);
  if (files.length === 0) {
    console.error(`[integrity] No protected files found under ${rootDir}/src`);
    process.exit(1);
  }
  const manifest = buildIntegrityManifest(rootDir, files);
  fs.writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(
    `[integrity] Wrote manifest for ${files.length} files → ${outPath}`,
  );

  if (args.signKey) {
    const privatePem = fs.readFileSync(path.resolve(args.signKey), "utf8");
    const signature = signManifest(manifest, privatePem);
    const sigPath = path.join(path.dirname(outPath), SIGNATURE_FILENAME);
    fs.writeFileSync(sigPath, `${signature}\n`);
    console.log(`[integrity] Wrote Ed25519 signature → ${sigPath}`);
  } else {
    console.log(
      "[integrity] No --sign-key provided; manifest is hash-only " +
        "(set EDULEARN_REQUIRE_SIGNED_INTEGRITY=1 + EDULEARN_INTEGRITY_PUBKEY to enforce signatures).",
    );
  }
}

main();

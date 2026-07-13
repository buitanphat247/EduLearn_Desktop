"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// C2 (integrity core) — tamper-evident app self-check.
//
// The Electron shell historically ran from editable source with no self
// integrity, so an attacker could edit `main.js`/`preload.js` (or swap the
// bundled Rust core) to neuter every JS/Electron guard — the report's single
// biggest gap vs SEB's signed installer + Browser-Exam-Key.
//
// This module provides the verifiable half of the fix, independent of the
// packaging pipeline: a manifest of sha256 hashes over the critical files,
// optionally Ed25519-signed, that the app verifies at startup. Combined with
// electron-builder ASAR packaging + code signing (see electron-builder.yml),
// tampering with any protected file is detected and the launch is refused.
//
// Pure/inspectable so the logic is unit-tested without a running Electron.

const MANIFEST_VERSION = 1;

function computeBufferHash(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function computeFileHash(filePath) {
  return computeBufferHash(fs.readFileSync(filePath));
}

// Build a manifest { version, generatedAt, files: { relPath: sha256 } } over the
// given absolute file paths, keyed by their path relative to `rootDir` (POSIX
// separators for stability across platforms).
function buildIntegrityManifest(rootDir, absoluteFilePaths) {
  const files = {};
  for (const absPath of absoluteFilePaths) {
    const rel = path.relative(rootDir, absPath).split(path.sep).join("/");
    files[rel] = computeFileHash(absPath);
  }
  return {
    version: MANIFEST_VERSION,
    generatedAt: new Date().toISOString(),
    files,
  };
}

// Verify current file hashes against a manifest. `readHash(relPath)` returns the
// current sha256 for a manifest entry (or null if unreadable/missing) — injected
// so this stays pure and testable. Returns { ok, missing, mismatched }.
function verifyIntegrityManifest(manifest, readHash) {
  const missing = [];
  const mismatched = [];

  if (!manifest || typeof manifest !== "object" || !manifest.files) {
    return { ok: false, missing: ["<manifest>"], mismatched: [] };
  }

  for (const [rel, expected] of Object.entries(manifest.files)) {
    const actual = readHash(rel);
    if (actual === null || actual === undefined) {
      missing.push(rel);
    } else if (actual !== expected) {
      mismatched.push(rel);
    }
  }

  return {
    ok: missing.length === 0 && mismatched.length === 0,
    missing,
    mismatched,
  };
}

// Convenience: verify a manifest against files under `rootDir` on disk.
function verifyIntegrityManifestOnDisk(manifest, rootDir) {
  return verifyIntegrityManifest(manifest, (rel) => {
    const abs = path.join(rootDir, rel);
    try {
      return computeFileHash(abs);
    } catch {
      return null;
    }
  });
}

// ── Optional Ed25519 signing over the canonical manifest bytes ──────────────
// Canonical form = JSON of {version, files} with sorted file keys (generatedAt
// is excluded so re-signing is deterministic for identical content).
function canonicalManifestBytes(manifest) {
  const files = manifest && manifest.files ? manifest.files : {};
  const sortedFiles = {};
  for (const key of Object.keys(files).sort()) {
    sortedFiles[key] = files[key];
  }
  return Buffer.from(
    JSON.stringify({ version: manifest?.version ?? MANIFEST_VERSION, files: sortedFiles }),
    "utf8",
  );
}

function signManifest(manifest, privateKeyPem) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(null, canonicalManifestBytes(manifest), privateKey);
  return signature.toString("base64");
}

function verifyManifestSignature(manifest, signatureBase64, publicKeyPem) {
  if (typeof signatureBase64 !== "string" || signatureBase64.length === 0) {
    return false;
  }
  try {
    const publicKey = crypto.createPublicKey(publicKeyPem);
    return crypto.verify(
      null,
      canonicalManifestBytes(manifest),
      publicKey,
      Buffer.from(signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}

const MANIFEST_FILENAME = "integrity-manifest.json";
const SIGNATURE_FILENAME = "integrity-manifest.sig";

// Startup gate used by the Electron main process. Fail-OPEN by design when there
// is nothing to enforce (dev, or an unsigned/manifest-less build) so we never
// brick a legitimate developer run; fail-CLOSED only when a manifest exists and
// the app on disk does not match it (real tampering on a packaged build).
//
// Returns { enforced, ok, reason, missing, mismatched, signatureValid }.
function verifyPackagedAppIntegrity({
  appDir,
  isPackaged,
  publicKeyPem = null,
  requireSignature = false,
}) {
  if (!isPackaged) {
    return { enforced: false, ok: true, reason: "dev-unpackaged" };
  }
  const manifestPath = path.join(appDir, MANIFEST_FILENAME);
  if (!fs.existsSync(manifestPath)) {
    return { enforced: false, ok: true, reason: "no-manifest" };
  }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch {
    return { enforced: true, ok: false, reason: "manifest-unreadable" };
  }

  // Signature check (when a public key is supplied / required).
  let signatureValid = null;
  if (publicKeyPem || requireSignature) {
    const sigPath = path.join(appDir, SIGNATURE_FILENAME);
    const signature = fs.existsSync(sigPath)
      ? fs.readFileSync(sigPath, "utf8").trim()
      : "";
    signatureValid =
      Boolean(publicKeyPem) &&
      verifyManifestSignature(manifest, signature, publicKeyPem);
    if (requireSignature && !signatureValid) {
      return {
        enforced: true,
        ok: false,
        reason: "signature-invalid",
        signatureValid,
      };
    }
  }

  const result = verifyIntegrityManifestOnDisk(manifest, appDir);
  return {
    enforced: true,
    ok: result.ok,
    reason: result.ok ? "verified" : "hash-mismatch",
    missing: result.missing,
    mismatched: result.mismatched,
    signatureValid,
  };
}

module.exports = {
  MANIFEST_VERSION,
  MANIFEST_FILENAME,
  SIGNATURE_FILENAME,
  computeBufferHash,
  computeFileHash,
  buildIntegrityManifest,
  verifyIntegrityManifest,
  verifyIntegrityManifestOnDisk,
  canonicalManifestBytes,
  signManifest,
  verifyManifestSignature,
  verifyPackagedAppIntegrity,
};

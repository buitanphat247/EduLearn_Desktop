const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const {
  computeFileHash,
  buildIntegrityManifest,
  verifyIntegrityManifest,
  verifyIntegrityManifestOnDisk,
  signManifest,
  verifyManifestSignature,
  verifyPackagedAppIntegrity,
  MANIFEST_FILENAME,
} = require("../src/app-integrity");

function makeTempAppDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "edulearn-integrity-"));
  fs.writeFileSync(path.join(dir, "main.js"), "console.log('main');");
  fs.writeFileSync(path.join(dir, "preload.js"), "console.log('preload');");
  return dir;
}

test("buildIntegrityManifest hashes each file relative to root", () => {
  const dir = makeTempAppDir();
  try {
    const manifest = buildIntegrityManifest(dir, [
      path.join(dir, "main.js"),
      path.join(dir, "preload.js"),
    ]);
    assert.equal(manifest.version, 1);
    assert.ok(manifest.files["main.js"]);
    assert.ok(manifest.files["preload.js"]);
    assert.equal(
      manifest.files["main.js"],
      computeFileHash(path.join(dir, "main.js")),
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("verify passes for an untampered app and fails after any edit", () => {
  const dir = makeTempAppDir();
  try {
    const manifest = buildIntegrityManifest(dir, [
      path.join(dir, "main.js"),
      path.join(dir, "preload.js"),
    ]);

    // Untampered → ok.
    assert.deepEqual(verifyIntegrityManifestOnDisk(manifest, dir), {
      ok: true,
      missing: [],
      mismatched: [],
    });

    // Tamper preload.js (the classic attack: neuter the guard bridge).
    fs.writeFileSync(
      path.join(dir, "preload.js"),
      "window.desktopRuntime = { sessionState: 'EXAM_RUNNING_CONFIRMED' };",
    );
    const tampered = verifyIntegrityManifestOnDisk(manifest, dir);
    assert.equal(tampered.ok, false);
    assert.deepEqual(tampered.mismatched, ["preload.js"]);

    // Delete a protected file → reported missing.
    fs.rmSync(path.join(dir, "main.js"));
    const removed = verifyIntegrityManifestOnDisk(manifest, dir);
    assert.equal(removed.ok, false);
    assert.ok(removed.missing.includes("main.js"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("verifyIntegrityManifest rejects a malformed manifest", () => {
  assert.equal(verifyIntegrityManifest(null, () => "x").ok, false);
  assert.equal(verifyIntegrityManifest({}, () => "x").ok, false);
});

test("startup gate is fail-open in dev / when no manifest, fail-closed on tamper", () => {
  const dir = makeTempAppDir();
  try {
    // Dev (unpackaged) → not enforced, never bricks a developer run.
    assert.deepEqual(
      verifyPackagedAppIntegrity({ appDir: dir, isPackaged: false }),
      { enforced: false, ok: true, reason: "dev-unpackaged" },
    );

    // Packaged but no manifest (unsigned build) → not enforced.
    assert.equal(
      verifyPackagedAppIntegrity({ appDir: dir, isPackaged: true }).reason,
      "no-manifest",
    );

    // Write a manifest → packaged + untampered verifies.
    const manifest = buildIntegrityManifest(dir, [
      path.join(dir, "main.js"),
      path.join(dir, "preload.js"),
    ]);
    fs.writeFileSync(
      path.join(dir, MANIFEST_FILENAME),
      JSON.stringify(manifest),
    );
    let verdict = verifyPackagedAppIntegrity({ appDir: dir, isPackaged: true });
    assert.equal(verdict.enforced, true);
    assert.equal(verdict.ok, true);

    // Tamper a protected file → packaged verify fails closed.
    fs.writeFileSync(path.join(dir, "main.js"), "// hacked");
    verdict = verifyPackagedAppIntegrity({ appDir: dir, isPackaged: true });
    assert.equal(verdict.enforced, true);
    assert.equal(verdict.ok, false);
    assert.deepEqual(verdict.mismatched, ["main.js"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("requireSignature fails closed when the signature is missing/invalid", () => {
  const dir = makeTempAppDir();
  try {
    const manifest = buildIntegrityManifest(dir, [path.join(dir, "main.js")]);
    fs.writeFileSync(path.join(dir, MANIFEST_FILENAME), JSON.stringify(manifest));
    const { publicKey } = crypto.generateKeyPairSync("ed25519");
    const publicPem = publicKey.export({ type: "spki", format: "pem" });

    const verdict = verifyPackagedAppIntegrity({
      appDir: dir,
      isPackaged: true,
      publicKeyPem: publicPem,
      requireSignature: true,
    });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason, "signature-invalid");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Ed25519 signature round-trips and detects manifest tampering", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const publicPem = publicKey.export({ type: "spki", format: "pem" });

  const manifest = {
    version: 1,
    generatedAt: new Date().toISOString(),
    files: { "main.js": "aaa", "preload.js": "bbb" },
  };
  const sig = signManifest(manifest, privatePem);
  assert.equal(verifyManifestSignature(manifest, sig, publicPem), true);

  // generatedAt is excluded from the signed bytes → re-timestamp still verifies.
  const reTimestamped = { ...manifest, generatedAt: "2000-01-01T00:00:00.000Z" };
  assert.equal(verifyManifestSignature(reTimestamped, sig, publicPem), true);

  // Any change to a file hash invalidates the signature.
  const tampered = { ...manifest, files: { ...manifest.files, "main.js": "ccc" } };
  assert.equal(verifyManifestSignature(tampered, sig, publicPem), false);

  // A garbage signature is rejected, never throws.
  assert.equal(verifyManifestSignature(manifest, "not-base64!!", publicPem), false);
  assert.equal(verifyManifestSignature(manifest, "", publicPem), false);
});

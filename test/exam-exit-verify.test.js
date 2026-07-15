/**
 * exam-exit-verify.test.js
 *
 * VS-02 (Offline-safe Exit Password) unit tests.
 *
 * Tests the offline exit-password cache and verification logic in the main process.
 * The module requires Electron (app, session, net) — stubbed here so the pure
 * functions can be unit-tested without a live Electron runtime.
 *
 * Test approach:
 *  - Cache/file I/O: fully exercised with temp directories (works in Node test runner)
 *  - bcryptjs: the real bcryptjs package is installed; we use the BCryptJsMock env-var
 *    injection (read per-call by the module) to override the real bcryptjs per-test.
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const os = require("os");
const Module = require("module");

// bcryptjs compare stub — per-test via BCryptJsCompareFn env-var.
// The module looks up globalThis[BCryptJsCompareFn] as the compare function.
function setBcryptCompare(fn) {
  globalThis._bcryptCompare = fn;
  process.env.BCryptJsCompareFn = "_bcryptCompare";
}
function clearBcryptCompare() {
  delete globalThis._bcryptCompare;
  delete process.env.BCryptJsCompareFn;
}

// ─── Stub Electron ────────────────────────────────────────────────────────────
const electronStub = {
  app: {
    getPath(name) {
      if (name === "userData") {
        return electronStub.app._userData || "/tmp/electron-userData";
      }
      return "/tmp";
    },
    _userData: null,
  },
  session: { fromPartition() { return {}; } },
  net: {},
};

// Unified Module._load override for this test file only.
const originalLoad = Module._load;
Module._load = function vs02Load(request, ...rest) {
  if (request === "electron") {
    return electronStub;
  }
  return originalLoad.call(this, request, ...rest);
};

const {
  cacheExitPasswordHash,
  loadExitPasswordHash,
  invalidateExitPasswordCache,
  verifyOfflineExitPassword,
  verifyExitPasswordInMain,
} = require("../src/exam-exit-verify");

Module._load = originalLoad;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function testDir() {
  const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "vs02-test-")), "userData");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function fakeSessionId() {
  return "session-" + Math.random().toString(36).slice(2, 8);
}

function withAppPath(dir, fn) {
  electronStub.app._userData = dir;
  try {
    return fn();
  } finally {
    electronStub.app._userData = null;
  }
}

// ─── Cache lifecycle ───────────────────────────────────────────────────────────

test("cacheExitPasswordHash writes a file with hash + timestamp", () => {
  const dir = testDir();
  withAppPath(dir, () => {
    const sid = fakeSessionId();
    const hash = "$2b$10$testHashAbCdefGhiJklMnOpQrS";
    cacheExitPasswordHash(sid, hash);

    const cacheFile = path.join(dir, `exam-exit-${sid}.json`);
    assert.ok(fs.existsSync(cacheFile), "cache file should exist");

    const stat = fs.statSync(cacheFile);
    // On Windows mode bits are ACL-based; skip octal check.
    if (process.platform !== "win32") {
      assert.equal(stat.mode & 0o777, 0o600, "file must be owner-only (0o600) on Unix");
    }

    const parsed = JSON.parse(fs.readFileSync(cacheFile, "utf8"));
    assert.equal(parsed.exitPasswordHash, hash);
    assert.ok(typeof parsed.cachedAt === "number" && parsed.cachedAt > 0);
  });
});

test("cacheExitPasswordHash removes stale entry when hash is null", () => {
  const dir = testDir();
  withAppPath(dir, () => {
    const sid = fakeSessionId();
    const cacheFile = path.join(dir, `exam-exit-${sid}.json`);
    cacheExitPasswordHash(sid, "$2b$10$hash");
    assert.ok(fs.existsSync(cacheFile));
    cacheExitPasswordHash(sid, null); // null = no exit password → delete entry
    assert.ok(!fs.existsSync(cacheFile), "stale cache should be removed");
  });
});

test("loadExitPasswordHash returns the cached hash", () => {
  const dir = testDir();
  withAppPath(dir, () => {
    const sid = fakeSessionId();
    const hash = "$2b$10$anotherHash";
    cacheExitPasswordHash(sid, hash);
    assert.equal(loadExitPasswordHash(sid), hash);
  });
});

test("loadExitPasswordHash returns null when no cache exists", () => {
  const dir = testDir();
  withAppPath(dir, () => {
    assert.equal(loadExitPasswordHash("nonexistent-session-xyz"), null);
  });
});

test("invalidateExitPasswordCache removes the cache file", () => {
  const dir = testDir();
  withAppPath(dir, () => {
    const sid = fakeSessionId();
    cacheExitPasswordHash(sid, "$2b$10$hash");
    invalidateExitPasswordCache(sid);
    assert.ok(!fs.existsSync(path.join(dir, `exam-exit-${sid}.json`)));
  });
});

test("invalidateExitPasswordCache is idempotent", () => {
  const dir = testDir();
  withAppPath(dir, () => {
    invalidateExitPasswordCache("never-existed-session");
    // Should not throw.
  });
});

// ─── Offline verification ──────────────────────────────────────────────────────

test("verifyOfflineExitPassword → denied when sessionId or password is missing", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    assert.equal(await verifyOfflineExitPassword("", ""), "denied");
    assert.equal(await verifyOfflineExitPassword(null, "pw"), "denied");
    assert.equal(await verifyOfflineExitPassword(fakeSessionId(), ""), "denied");
  });
});

test("verifyOfflineExitPassword → no_cache when no cache exists", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    const result = await verifyOfflineExitPassword(fakeSessionId(), "any-password");
    assert.equal(result, "no_cache", "no cache → caller must use server path");
  });
});

test("verifyOfflineExitPassword → denied when password does not match (fail-closed)", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    const sid = fakeSessionId();
    const hash = "$2b$10$someHash";
    cacheExitPasswordHash(sid, hash);
    // bcryptjs compare is injected via BCryptJsMock — always returns false here.
    setBcryptCompare(() => false);

    const result = await verifyOfflineExitPassword(sid, "wrong-password");
    assert.equal(result, "denied", "wrong password must be blocked even offline");

    clearBcryptCompare();
  });
});

test("verifyOfflineExitPassword → ok when password matches cached hash", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    const sid = fakeSessionId();
    const hash = "$2b$10$someHash";
    cacheExitPasswordHash(sid, hash);
    // bcryptjs compare always returns true (matches any password).
    setBcryptCompare(() => true);

    const result = await verifyOfflineExitPassword(sid, "correct-password");
    assert.equal(result, "ok", "correct password should allow offline exit");

    clearBcryptCompare();
  });
});

test("verifyOfflineExitPassword → no_cache when cache file is corrupt", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    const sid = fakeSessionId();
    const cacheFile = path.join(dir, `exam-exit-${sid}.json`);
    fs.writeFileSync(cacheFile, "not-valid-json{{{", { encoding: "utf8" });

    const result = await verifyOfflineExitPassword(sid, "any-password");
    assert.equal(result, "no_cache", "corrupt cache → fall through to server (NOT granted)");
  });
});

// ─── Offline-first exit flow ───────────────────────────────────────────────────

test("verifyExitPasswordInMain rejects offline on wrong password (fail-closed)", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    const sid = fakeSessionId();
    cacheExitPasswordHash(sid, "$2b$10$hash");
    setBcryptCompare(() => false); // always reject

    const result = await verifyExitPasswordInMain(sid, "wrong-password");
    assert.equal(result, "denied", "offline wrong password → BLOCKED");

    clearBcryptCompare();
  });
});

test("verifyExitPasswordInMain allows offline on correct password", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    const sid = fakeSessionId();
    cacheExitPasswordHash(sid, "$2b$10$hash");
    setBcryptCompare(() => true); // always accept

    const result = await verifyExitPasswordInMain(sid, "correct-password");
    assert.equal(result, "ok", "correct offline password → allowed");

    clearBcryptCompare();
  });
});

test("verifyExitPasswordInMain returns denied when password is empty/missing", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    assert.equal(await verifyExitPasswordInMain(fakeSessionId(), ""), "denied");
    assert.equal(await verifyExitPasswordInMain(fakeSessionId(), null), "denied");
  });
});

test("verifyExitPasswordInMain denies when offline returns denied", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    const sid = fakeSessionId();
    cacheExitPasswordHash(sid, "$2b$10$hash");
    setBcryptCompare(() => false);

    const result = await verifyExitPasswordInMain(sid, "any-password");
    assert.equal(result, "denied");

    clearBcryptCompare();
  });
});

test("verifyExitPasswordInMain denies when sessionId is empty", async () => {
  const dir = testDir();
  await withAppPath(dir, async () => {
    assert.equal(await verifyExitPasswordInMain("", "some-password"), "denied");
    assert.equal(await verifyExitPasswordInMain(null, "some-password"), "denied");
  });
});

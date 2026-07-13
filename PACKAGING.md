# EduLearn Secure-Exam Desktop — Packaging & Integrity (C2)

Closes the report's biggest gap vs SEB: the shell no longer runs from editable
source. A packaged build is ASAR-packed, (optionally) code-signed, and carries a
hash **integrity manifest** that the app verifies at startup — so editing
`main.js`/`preload.js` or swapping the Rust core is detected and the launch is
refused.

## Layers

1. **ASAR pack + integrity** (`electron-builder.yml`, `asar: true`): the app is
   packed into `app.asar`; Electron refuses to load a modified archive.
2. **Integrity manifest** (`scripts/generate-integrity-manifest.js` →
   `integrity-manifest.json`, optional `integrity-manifest.sig`): sha256 of every
   protected `src/**/*.js` + `package.json`, optionally Ed25519-signed. Generated
   in the `afterPack` hook (`build/after-pack-integrity.js`).
3. **Startup gate** (`src/app-integrity.js` + `src/main.js`): on a packaged build
   with a manifest, mismatched/missing files ⇒ `app.quit()`. **Fail-open** in dev
   and for manifest-less builds so a developer run is never bricked.
4. **Authenticode signing** (electron-builder `win`): env-driven, so the installer
   and binaries are OS-verifiable.

## Build

```bash
# 1. Build the native core (release)
npm run core:build

# 2. Package (generates the manifest, then electron-builder)
#    Requires: npm i -D electron electron-builder
npm run package
```

### Signing (production)

Authenticode (installer + exe):

```bash
export CSC_LINK=/path/to/cert.pfx          # or base64 of the pfx
export CSC_KEY_PASSWORD=********
npm run package
```

Ed25519 manifest signing + enforcement (defense-in-depth over ASAR):

```bash
# Sign the manifest at package time:
export EDULEARN_INTEGRITY_SIGN_KEY=/path/to/integrity-priv.pem   # pkcs8

# Enforce the signature at runtime (embed the matching public key):
export EDULEARN_INTEGRITY_PUBKEY="$(cat integrity-pub.pem)"
export EDULEARN_REQUIRE_SIGNED_INTEGRITY=1
```

Generate an Ed25519 key pair:

```bash
openssl genpkey -algorithm ed25519 -out integrity-priv.pem
openssl pkey -in integrity-priv.pem -pubout -out integrity-pub.pem
```

## Notes

- The startup gate is intentionally fail-open when there is nothing to enforce
  (dev / unsigned build); it only fails **closed** when a packaged build's files
  don't match its shipped manifest — i.e. real post-signing tampering.
- Pair with `EDULEARN_REQUIRE_SECURE_IPC=1` (forces authenticated named-pipe IPC,
  see `rust-sidecar.js` / rust-core) for the full production hardening posture.

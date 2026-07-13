"use strict";

// electron-builder afterPack hook (C2): generate the integrity manifest over the
// packaged app directory so the hashes match exactly what ships. If a signing
// key is configured (EDULEARN_INTEGRITY_SIGN_KEY = path to a pkcs8 PEM), the
// manifest is also Ed25519-signed.
//
// Runs against context.appOutDir/resources/app (pre-ASAR staging). electron-
// builder invokes this before ASAR packing when `asar: true`.

const path = require("path");
const { execFileSync } = require("child_process");

exports.default = async function afterPack(context) {
  const appDir = path.join(context.appOutDir, "resources", "app");
  const script = path.join(__dirname, "..", "scripts", "generate-integrity-manifest.js");
  const args = [script, "--root", appDir];
  const signKey = process.env.EDULEARN_INTEGRITY_SIGN_KEY;
  if (signKey) {
    args.push("--sign-key", signKey);
  }
  execFileSync(process.execPath, args, { stdio: "inherit" });
};

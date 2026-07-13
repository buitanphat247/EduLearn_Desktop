const fs = require("fs");
const path = require("path");

const desktopRoot = path.join(__dirname, "..");

// Mirror resolveRustCoreBinaryPath() in src/rust-sidecar.js so the launcher
// checks exactly the same locations the Electron main process will probe.
function resolveCoreBinaryPath() {
  const configured = process.env.DESKTOP_RUST_CORE_PATH;
  const candidates = configured
    ? [configured]
    : [
        path.join(desktopRoot, "rust-core", "target", "release", "rust-core.exe"),
        path.join(desktopRoot, "rust-core", "target", "debug", "rust-core.exe"),
      ];

  return candidates.find((candidate) => fs.existsSync(candidate)) ?? null;
}

// Warn loudly (but do not block) when the sidecar binary is missing, so the app
// doesn't silently boot into a "CORE CHƯA SẴN SÀNG" / "Rust sidecar is not
// running" preflight state that blocks entering the exam room.
function warnIfCoreBinaryMissing(log = console.warn) {
  const found = resolveCoreBinaryPath();
  if (found) {
    log(`[desktop] Rust core binary found: ${found}`);
    return true;
  }

  log(
    [
      "[desktop] ⚠ Rust core binary NOT found — preflight sẽ báo 'CORE CHƯA SẴN SÀNG' / 'Rust sidecar is not running' và không vào được phòng thi.",
      "[desktop]   Build core trước khi chạy desktop:",
      "[desktop]     npm run core:build",
      "[desktop]   (máy không có MSVC linker thì build bằng toolchain gnu:",
      "[desktop]     cargo +stable-x86_64-pc-windows-gnu build --release --manifest-path rust-core/Cargo.toml )",
      "[desktop]   hoặc set DESKTOP_RUST_CORE_PATH trỏ tới một rust-core.exe có sẵn.",
    ].join("\n"),
  );
  return false;
}

module.exports = { resolveCoreBinaryPath, warnIfCoreBinaryMissing };

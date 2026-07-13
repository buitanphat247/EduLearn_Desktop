const path = require("path");
const { spawn } = require("child_process");
const dotenv = require("dotenv");
const { warnIfCoreBinaryMissing } = require("./core-binary");

dotenv.config({ path: path.join(__dirname, "..", ".env") });

// Fail fast with a clear message instead of booting into a broken preflight.
warnIfCoreBinaryMissing();

const desktopRoot = path.join(__dirname, "..");
// Run electronmon through Node directly because the Windows .cmd wrapper can
// fail to spawn in some environments.
const electronMonitorCli = path.join(
  desktopRoot,
  "node_modules",
  "electronmon",
  "bin",
  "cli.js",
);
const port = process.env.DESKTOP_RENDERER_PORT || "3001";
const startUrl =
  process.env.ELECTRON_START_URL || `http://localhost:${port}`;

console.log(`[desktop] Renderer port: ${port}`);
console.log(`[desktop] Electron start URL: ${startUrl}`);

// --no-reload: run PLAIN Electron instead of electronmon. electronmon watches
// desktop/src and restarts the whole app on any file change; when the project
// lives on a synced drive (OneDrive) the sync touches source files in bursts,
// triggering a restart storm that tears down the process tree — which KILLS the
// exam-shell child mid-boot (it dies before main.js runs). Plain Electron has no
// watcher, so the isolated exam-shell can boot in peace. Use `npm run
// desktop:stable` when testing the desktop-isolation / exam flow.
const noReload =
  process.argv.includes("--no-reload") || process.env.DESKTOP_NO_RELOAD === "1";

let command;
let commandArgs;
if (noReload) {
  // `require("electron")` from Node returns the path to the electron binary.
  command = require("electron");
  commandArgs = ["."];
  console.log("[desktop] Launching plain Electron (no hot-reload watcher)...");
} else {
  command = process.execPath;
  commandArgs = [electronMonitorCli, "."];
  console.log("[desktop] Launching Electron monitor...");
}

// This script assumes the renderer is already running; use `npm run dev` when
// you want the desktop shell to start the Next.js renderer automatically.
const child = spawn(command, commandArgs, {
  cwd: desktopRoot,
  stdio: "inherit",
  shell: false,
  env: {
    ...process.env,
    ELECTRON_START_URL: startUrl,
  },
});

child.on("exit", (code) => {
  process.exit(code ?? 0);
});

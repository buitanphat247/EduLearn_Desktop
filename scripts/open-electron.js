const path = require("path");
const { spawn } = require("child_process");
const dotenv = require("dotenv");

dotenv.config({ path: path.join(__dirname, "..", ".env") });

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
console.log(`[desktop] Launching Electron monitor...`);

// This script assumes the renderer is already running; use `npm run dev` when
// you want the desktop shell to start the Next.js renderer automatically.
const child = spawn(process.execPath, [electronMonitorCli, "."], {
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

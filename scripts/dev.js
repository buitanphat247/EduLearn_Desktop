const { execFileSync, spawn } = require("child_process");
const http = require("http");
const net = require("net");
const path = require("path");
const dotenv = require("dotenv");
const { warnIfCoreBinaryMissing } = require("./core-binary");

dotenv.config({ path: path.join(__dirname, "..", ".env") });

const desktopRoot = path.join(__dirname, "..");
const clientRoot = path.join(desktopRoot, "..", "client");
// Run electronmon through Node directly because spawning the .cmd shim is not
// stable on some Windows + Node versions and can fail with spawn EINVAL.
const electronMonitorCli = path.join(
  desktopRoot,
  "node_modules",
  "electronmon",
  "bin",
  "cli.js",
);
const configuredPort = process.env.DESKTOP_RENDERER_PORT || "3001";
const startUrl =
  process.env.ELECTRON_START_URL || `http://localhost:${configuredPort}`;
// The renderer must follow the actual URL Electron will load. This avoids
// mismatches where DESKTOP_RENDERER_PORT and ELECTRON_START_URL drift apart.
const rendererPort = String(new URL(startUrl).port || configuredPort);

let nextProcess;
let electronProcess;
let shuttingDown = false;

function logDesktopRuntime(message) {
  console.log(`[desktop] ${message}`);
}

function killProcessesOnPort(targetPort) {
  // A stale dev server can keep the renderer port busy and cause Electron to
  // attach to an old build, so we clear the port before starting a new session.
  if (process.platform === "win32") {
    try {
      const output = execFileSync(
        "netstat.exe",
        ["-ano", "-p", "tcp"],
        { encoding: "utf8" },
      );

      const pids = Array.from(
        new Set(
          output
            .split(/\r?\n/)
            .filter((line) => line.includes(`:${targetPort}`) && line.includes("LISTENING"))
            .map((line) => line.trim().split(/\s+/).pop())
            .filter((pid) => pid && pid !== "0" && pid !== String(process.pid)),
        ),
      );

      for (const pid of pids) {
        execFileSync("taskkill.exe", ["/PID", pid, "/F"], { stdio: "ignore" });
        logDesktopRuntime(`Stopped process ${pid} on port ${targetPort}`);
      }
    } catch (error) {
      logDesktopRuntime(`Could not fully clean port ${targetPort}: ${error.message}`);
    }

    return;
  }

  try {
    const output = execFileSync("lsof", ["-ti", `tcp:${targetPort}`], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });

    const pids = Array.from(
      new Set(
        output
          .split(/\r?\n/)
          .map((value) => value.trim())
          .filter((value) => value && value !== String(process.pid)),
      ),
    );

    for (const pid of pids) {
      execFileSync("kill", ["-9", pid], { stdio: "ignore" });
      logDesktopRuntime(`Stopped process ${pid} on port ${targetPort}`);
    }
  } catch {
    // No process is listening on this port.
  }
}

function waitForUrl(url, timeoutMs = 120000) {
  const start = Date.now();

  return new Promise((resolve, reject) => {
    const probe = () => {
      const request = http.get(url, (response) => {
        response.resume();
        resolve();
      });

      request.on("error", () => {
        if (Date.now() - start >= timeoutMs) {
          reject(new Error(`Timed out waiting for ${url}`));
          return;
        }

        setTimeout(probe, 1000);
      });
    };

    probe();
  });
}

function isUrlReady(url, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const request = http.get(url, (response) => {
      response.resume();
      resolve(true);
    });

    request.setTimeout(timeoutMs, () => {
      request.destroy();
      resolve(false);
    });

    request.on("error", () => {
      resolve(false);
    });
  });
}

function getUrlPort(url) {
  const parsed = new URL(url);
  if (parsed.port) {
    return Number(parsed.port);
  }

  return parsed.protocol === "https:" ? 443 : 80;
}

function isPortInUse(port, host = "127.0.0.1", timeoutMs = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();

    const finalize = (value) => {
      socket.destroy();
      resolve(value);
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finalize(true));
    socket.once("timeout", () => finalize(false));
    socket.once("error", () => finalize(false));
    socket.connect(port, host);
  });
}

function spawnClientDevServer() {
  if (process.platform === "win32") {
    return spawn(
      "cmd.exe",
      ["/d", "/s", "/c", `npm run dev -- --port ${rendererPort}`],
      {
        cwd: clientRoot,
        stdio: "inherit",
        shell: false,
        env: {
          ...process.env,
          PORT: rendererPort,
        },
      },
    );
  }

  return spawn("npm", ["run", "dev", "--", "--port", rendererPort], {
    cwd: clientRoot,
    stdio: "inherit",
    shell: false,
    env: {
      ...process.env,
      PORT: rendererPort,
    },
  });
}

function spawnElectronMonitor() {
  // electronmon restarts the Electron main/preload process when desktop files
  // change, giving us "live" desktop updates without manual relaunches.
  return spawn(process.execPath, [electronMonitorCli, "."], {
    cwd: desktopRoot,
    stdio: "inherit",
    shell: false,
    env: {
      ...process.env,
      ELECTRON_START_URL: startUrl,
    },
  });
}

function killChild(child) {
  if (!child || child.killed) {
    return;
  }

  child.kill("SIGINT");
}

function shutdown(code = 0) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  killChild(electronProcess);
  killChild(nextProcess);
  setTimeout(() => process.exit(code), 250);
}

async function run() {
  logDesktopRuntime(`Configured renderer port: ${configuredPort}`);
  logDesktopRuntime(`Renderer port from start URL: ${rendererPort}`);
  logDesktopRuntime(`Electron start URL: ${startUrl}`);
  killProcessesOnPort(rendererPort);

  const rendererAlreadyRunning = await isUrlReady(startUrl);

  if (!rendererAlreadyRunning) {
    const portInUse = await isPortInUse(getUrlPort(startUrl));

    if (portInUse) {
      logDesktopRuntime(`Port ${getUrlPort(startUrl)} is in use, waiting for renderer at ${startUrl}`);
      await waitForUrl(startUrl, 30000);
    } else {
      logDesktopRuntime(`Starting Next.js renderer on port ${rendererPort}`);
      nextProcess = spawnClientDevServer();

      nextProcess.on("exit", (code) => {
        if (!shuttingDown) {
          shutdown(code ?? 0);
        }
      });

      await waitForUrl(startUrl);
    }
  } else {
    logDesktopRuntime(`Renderer already responding at ${startUrl}`);
  }

  warnIfCoreBinaryMissing(logDesktopRuntime);

  logDesktopRuntime(`Launching Electron monitor with URL ${startUrl}`);
  electronProcess = spawnElectronMonitor();

  electronProcess.on("exit", (code) => {
    shutdown(code ?? 0);
  });
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

run().catch((error) => {
  console.error("[desktop] Failed to start desktop dev mode");
  console.error(error);
  shutdown(1);
});

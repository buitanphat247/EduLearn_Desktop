const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { spawn } = require("child_process");

const {
  CORE_ERROR_CODES,
  createCoreErrorResponse,
} = require("../../shared/contracts/safe-exam");

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 3000;

function resolveRustCoreBinaryPath() {
  const configuredPath = process.env.DESKTOP_RUST_CORE_PATH;
  const candidatePaths = configuredPath
    ? [configuredPath]
    : [
        path.join(__dirname, "..", "rust-core", "target", "release", "rust-core.exe"),
        path.join(__dirname, "..", "rust-core", "target", "debug", "rust-core.exe"),
      ];

  return candidatePaths.find((candidatePath) => fs.existsSync(candidatePath)) ?? null;
}

function createRustSidecarTransport({ onEvent, onExit }) {
  let child = null;
  let stdoutReader = null;
  let requestCounter = 0;
  let connected = false;
  let binaryPath = null;
  const pendingRequests = new Map();

  function cleanupPendingRequests(code, message) {
    for (const [requestId, pendingRequest] of pendingRequests) {
      clearTimeout(pendingRequest.timeoutId);
      pendingRequest.resolve(
        createCoreErrorResponse(
          requestId,
          code,
          message,
        ),
      );
    }

    pendingRequests.clear();
  }

  function handleStdoutLine(line) {
    if (!line || !line.trim()) {
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      return;
    }

    if (parsed && typeof parsed.requestId === "string" && pendingRequests.has(parsed.requestId)) {
      const pendingRequest = pendingRequests.get(parsed.requestId);
      pendingRequests.delete(parsed.requestId);
      clearTimeout(pendingRequest.timeoutId);
      pendingRequest.resolve(parsed);
      return;
    }

    if (parsed && typeof parsed.event === "string") {
      onEvent?.(parsed);
    }
  }

  function attachChildProcess(nextChild) {
    child = nextChild;
    stdoutReader = readline.createInterface({
      input: child.stdout,
      crlfDelay: Infinity,
    });

    stdoutReader.on("line", handleStdoutLine);
    child.stderr.on("data", (chunk) => {
      const message = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      if (message.trim()) {
        console.warn(`[rust-core] ${message.trim()}`);
      }
    });

    child.on("error", (error) => {
      connected = false;
      cleanupPendingRequests(
        CORE_ERROR_CODES.IPC_FAILURE,
        error instanceof Error ? error.message : "Rust sidecar failed unexpectedly.",
      );
      onExit?.({ code: null, signal: "ERROR", binaryPath, error });
    });

    child.on("exit", (code, signal) => {
      connected = false;
      cleanupPendingRequests(
        CORE_ERROR_CODES.CORE_NOT_CONNECTED,
        "Rust sidecar exited before completing the request.",
      );

      if (stdoutReader) {
        stdoutReader.removeAllListeners();
        stdoutReader.close();
        stdoutReader = null;
      }

      child = null;
      onExit?.({ code, signal, binaryPath });
    });
  }

  async function waitForChildExit(timeoutMs = 2000) {
    if (!child) {
      return;
    }

    const currentChild = child;

    await new Promise((resolve) => {
      let settled = false;

      const finish = () => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timeoutId);
        currentChild.removeListener("exit", handleDone);
        currentChild.removeListener("error", handleDone);
        resolve();
      };

      const handleDone = () => {
        finish();
      };

      const timeoutId = setTimeout(finish, timeoutMs);
      currentChild.once("exit", handleDone);
      currentChild.once("error", handleDone);
    });
  }

  async function start() {
    if (connected && child) {
      return {
        connected: true,
        binaryPath,
      };
    }

    binaryPath = resolveRustCoreBinaryPath();
    if (!binaryPath) {
      return {
        connected: false,
        errorCode: CORE_ERROR_CODES.CORE_NOT_CONNECTED,
        message:
          "Rust sidecar binary was not found. Build desktop/rust-core first or set DESKTOP_RUST_CORE_PATH.",
      };
    }

    const nextChild = spawn(binaryPath, [], {
      cwd: path.dirname(binaryPath),
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    attachChildProcess(nextChild);
    connected = true;

    return {
      connected: true,
      binaryPath,
    };
  }

  async function request(command, options = {}) {
    const requestId =
      typeof command?.requestId === "string" && command.requestId.trim()
        ? command.requestId
        : `desktop-main-${Date.now()}-${++requestCounter}`;

    if (!connected || !child || child.killed) {
      return createCoreErrorResponse(
        requestId,
        CORE_ERROR_CODES.CORE_NOT_CONNECTED,
        "Rust sidecar is not running.",
      );
    }

    const payload = {
      requestId,
      cmd: command.cmd,
      payload: command.payload ?? {},
    };

    return new Promise((resolve) => {
      const timeoutId = setTimeout(() => {
        pendingRequests.delete(requestId);
        resolve(
          createCoreErrorResponse(
            requestId,
            CORE_ERROR_CODES.IPC_FAILURE,
            `Rust sidecar timed out while handling ${String(command.cmd)}.`,
          ),
        );
      }, options.timeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS);

      pendingRequests.set(requestId, {
        resolve,
        timeoutId,
      });

      try {
        child.stdin.write(`${JSON.stringify(payload)}\n`);
      } catch (error) {
        pendingRequests.delete(requestId);
        clearTimeout(timeoutId);
        resolve(
          createCoreErrorResponse(
            requestId,
            CORE_ERROR_CODES.IPC_FAILURE,
            error instanceof Error ? error.message : "Failed to write request to Rust sidecar.",
          ),
        );
      }
    });
  }

  async function stop() {
    if (!child) {
      connected = false;
      return;
    }

    const shutdownResponse = await request(
      {
        cmd: "shutdown",
        payload: {},
      },
      { timeoutMs: 1500 },
    );

    if (!shutdownResponse.ok && child && !child.killed) {
      child.kill("SIGTERM");
      await waitForChildExit();
      return;
    }

    setTimeout(() => {
      if (child && !child.killed) {
        child.kill("SIGTERM");
      }
    }, 1000);

    await waitForChildExit();
  }

  return {
    start,
    stop,
    request,
    isConnected() {
      return connected && Boolean(child) && !child.killed;
    },
    getBinaryPath() {
      return binaryPath;
    },
  };
}

module.exports = {
  createRustSidecarTransport,
  resolveRustCoreBinaryPath,
};

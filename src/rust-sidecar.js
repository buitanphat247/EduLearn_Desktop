const fs = require("fs");
const crypto = require("crypto");
const net = require("net");
const path = require("path");
const readline = require("readline");
const { spawn } = require("child_process");

const {
  CORE_ERROR_CODES,
  createCoreErrorResponse,
} = require("./contracts/safe-exam");
const {
  createAuthenticatedFrame,
  createSequencedFrameFactory,
  createFrameVerifier,
} = require("./ipc-auth");

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 3000;

// C1: decide the Electron↔Rust transport. Plain stdio is UNAUTHENTICATED — any
// process that can write the core's stdin could drive it. Production therefore
// requires the authenticated named pipe (HMAC + parent-PID bound) and refuses to
// fall back to stdio. Dev keeps stdio for convenience unless opted in.
//   - `NODE_ENV=production` or `EDULEARN_REQUIRE_SECURE_IPC=1` → secure required
//   - `EDULEARN_CORE_IPC_MODE=named-pipe`                      → explicit opt-in
// Named-pipe auth is Windows-only, so on a non-win32 production host we refuse
// to launch rather than silently exposing an unauthenticated channel.
function resolveCoreIpcMode(env = process.env, platform = process.platform) {
  const requireAuthenticatedIpc =
    env.NODE_ENV === "production" || env.EDULEARN_REQUIRE_SECURE_IPC === "1";
  const explicitPipe = env.EDULEARN_CORE_IPC_MODE === "named-pipe";
  const isWindows = platform === "win32";
  const useAuthenticatedPipe = isWindows && (explicitPipe || requireAuthenticatedIpc);
  const refuseUnauthenticatedStdio = requireAuthenticatedIpc && !useAuthenticatedPipe;
  return {
    requireAuthenticatedIpc,
    useAuthenticatedPipe,
    refuseUnauthenticatedStdio,
  };
}

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
  let pipeReader = null;
  let pipeSocket = null;
  let requestCounter = 0;
  let connected = false;
  let binaryPath = null;
  let ipcSecret = null;
  // P47-01: per-connection IPC v2 frame factory — emits frames carrying a
  // MONOTONIC sequence bound into the MAC, so the Rust core rejects a
  // reordered/rolled-back/duplicate frame. Recreated on each (re)connect.
  let frameFactory = null;
  let verifyResponseFrame = null;
  const ipcMode = resolveCoreIpcMode();
  const useAuthenticatedPipe = ipcMode.useAuthenticatedPipe;
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

  function handleCoreMessage(parsed) {
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

    handleCoreMessage(parsed);
  }

  function handlePipeLine(line) {
    if (!line || !line.trim()) {
      return;
    }
    try {
      const frame = JSON.parse(line);
      const payload = verifyResponseFrame(frame);
      handleCoreMessage(payload);
    } catch (error) {
      cleanupPendingRequests(
        CORE_ERROR_CODES.IPC_FAILURE,
        error instanceof Error ? error.message : "Authenticated IPC response was rejected.",
      );
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
      if (pipeReader) {
        pipeReader.removeAllListeners();
        pipeReader.close();
        pipeReader = null;
      }
      if (pipeSocket) {
        pipeSocket.destroy();
        pipeSocket = null;
      }

      child = null;
      onExit?.({ code, signal, binaryPath });
    });
  }

  async function connectAuthenticatedPipe(pipePath, timeoutMs = DEFAULT_HANDSHAKE_TIMEOUT_MS) {
    const startedAt = Date.now();
    while (Date.now() - startedAt < timeoutMs) {
      try {
        const socket = await new Promise((resolve, reject) => {
          const candidate = net.createConnection(pipePath);
          candidate.once("connect", () => resolve(candidate));
          candidate.once("error", reject);
        });
        pipeSocket = socket;
        pipeReader = readline.createInterface({
          input: socket,
          crlfDelay: Infinity,
        });
        pipeReader.on("line", handlePipeLine);
        socket.on("error", (error) => {
          connected = false;
          cleanupPendingRequests(
            CORE_ERROR_CODES.IPC_FAILURE,
            error instanceof Error ? error.message : "Authenticated named pipe failed.",
          );
        });
        return;
      } catch (error) {
        if (!child || child.exitCode !== null) {
          throw error;
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    }
    throw new Error("Timed out while connecting to the authenticated Rust named pipe.");
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

    // C1: never launch the core over unauthenticated stdio in production.
    if (ipcMode.refuseUnauthenticatedStdio) {
      return {
        connected: false,
        errorCode: CORE_ERROR_CODES.IPC_FAILURE,
        message:
          "Refusing to start Rust core over unauthenticated stdio in production. " +
          "Authenticated named-pipe IPC (Windows) is required — set EDULEARN_CORE_IPC_MODE=named-pipe on a Windows host.",
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

    let childArguments = [];
    const childEnvironment = { ...process.env };
    // C1 defense-in-depth: tell the spawned core to refuse unauthenticated stdio
    // whenever secure IPC is required, so even a mis-launched child cannot serve
    // commands over stdin.
    if (ipcMode.requireAuthenticatedIpc) {
      childEnvironment.EDULEARN_REQUIRE_SECURE_IPC = "1";
    }
    let pipePath = null;
    if (useAuthenticatedPipe) {
      ipcSecret = crypto.randomBytes(32);
      // P47-01: start a fresh monotonic sequence for this connection's v2 frames.
      frameFactory = createSequencedFrameFactory({ secret: ipcSecret });
      const pipeName = `edulearn-core-${process.pid}-${crypto.randomBytes(12).toString("hex")}`;
      pipePath = `\\\\.\\pipe\\${pipeName}`;
      childArguments = ["--named-pipe", pipeName];
      childEnvironment.EDULEARN_CORE_IPC_SECRET = ipcSecret.toString("base64url");
      childEnvironment.EDULEARN_CORE_IPC_PARENT_PID = String(process.pid);
      verifyResponseFrame = createFrameVerifier({
        expectedKind: "response",
        secret: ipcSecret,
      });
    }

    const nextChild = spawn(binaryPath, childArguments, {
      cwd: path.dirname(binaryPath),
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      env: childEnvironment,
    });

    attachChildProcess(nextChild);
    if (useAuthenticatedPipe) {
      try {
        await connectAuthenticatedPipe(pipePath);
      } catch (error) {
        connected = false;
        if (child && !child.killed) {
          child.kill("SIGTERM");
          await waitForChildExit();
        }
        return {
          connected: false,
          errorCode: CORE_ERROR_CODES.IPC_FAILURE,
          message:
            error instanceof Error
              ? error.message
              : "Authenticated Rust named-pipe startup failed.",
        };
      }
    }
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
    if (pendingRequests.has(requestId)) {
      return createCoreErrorResponse(
        requestId,
        CORE_ERROR_CODES.IPC_FAILURE,
        `Duplicate Rust sidecar request id was rejected: ${requestId}.`,
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
        if (useAuthenticatedPipe) {
          // P47-01: emit a v2 (sequenced) frame; fall back to v1 only if the
          // factory is somehow unset (defensive — it is created with the secret).
          const frame = frameFactory
            ? frameFactory.create({ kind: "request", payload })
            : createAuthenticatedFrame({ kind: "request", payload, secret: ipcSecret });
          pipeSocket.write(`${JSON.stringify(frame)}\n`);
        } else {
          child.stdin.write(`${JSON.stringify(payload)}\n`);
        }
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

    const childBeingStopped = child;
    const terminationTimer = setTimeout(() => {
      if (
        childBeingStopped &&
        !childBeingStopped.killed &&
        childBeingStopped.exitCode === null
      ) {
        childBeingStopped.kill("SIGTERM");
      }
    }, 1000);
    terminationTimer.unref?.();

    await waitForChildExit();
    clearTimeout(terminationTimer);
    if (pipeSocket) {
      pipeSocket.destroy();
      pipeSocket = null;
    }
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
    getIpcMode() {
      return useAuthenticatedPipe ? "named-pipe-authenticated" : "stdio";
    },
  };
}

module.exports = {
  createRustSidecarTransport,
  resolveRustCoreBinaryPath,
  resolveCoreIpcMode,
};

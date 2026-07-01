const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

test(
  "Rust sidecar exchanges authenticated commands over a PID-bound named pipe",
  { skip: process.platform !== "win32" },
  async () => {
    const previousMode = process.env.EDULEARN_CORE_IPC_MODE;
    const previousPath = process.env.DESKTOP_RUST_CORE_PATH;
    process.env.EDULEARN_CORE_IPC_MODE = "named-pipe";
    process.env.DESKTOP_RUST_CORE_PATH = path.join(
      __dirname,
      "..",
      "rust-core",
      "target",
      "debug",
      "rust-core.exe",
    );

    delete require.cache[require.resolve("../src/rust-sidecar")];
    const { createRustSidecarTransport } = require("../src/rust-sidecar");
    const events = [];
    const transport = createRustSidecarTransport({
      onEvent: (event) => events.push(event),
    });

    try {
      const start = await transport.start();
      assert.equal(start.connected, true);
      assert.equal(transport.getIpcMode(), "named-pipe-authenticated");

      const response = await transport.request({
        requestId: "pipe-ping",
        cmd: "ping",
        payload: {},
      });
      assert.equal(response.ok, true);
      assert.equal(response.requestId, "pipe-ping");
      assert.equal(response.data.pong, true);
    } finally {
      await transport.stop();
      if (typeof previousMode === "undefined") {
        delete process.env.EDULEARN_CORE_IPC_MODE;
      } else {
        process.env.EDULEARN_CORE_IPC_MODE = previousMode;
      }
      if (typeof previousPath === "undefined") {
        delete process.env.DESKTOP_RUST_CORE_PATH;
      } else {
        process.env.DESKTOP_RUST_CORE_PATH = previousPath;
      }
    }
  },
);

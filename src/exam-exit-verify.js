"use strict";

const { net, session } = require("electron");
const { EXAM_PARTITION } = require("./exam-session-handoff");

function roomOrigin() {
  const url = process.env.ELECTRON_START_URL || "http://localhost:3000";
  try {
    return new URL(url).origin;
  } catch {
    return "http://localhost:3000";
  }
}

function requestJson({ method, url, examSession, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const request = net.request({
      method,
      url,
      session: examSession,
      useSessionCookies: true,
    });
    for (const [key, value] of Object.entries(headers)) {
      request.setHeader(key, value);
    }
    let data = "";
    request.on("response", (response) => {
      response.on("data", (chunk) => {
        data += chunk.toString();
      });
      response.on("end", () => resolve({ status: response.statusCode, body: data }));
    });
    request.on("error", reject);
    if (body != null) {
      request.write(body);
    }
    request.end();
  });
}

/**
 * Re-verify the invigilator exit password from the MAIN process (independent of
 * the renderer), so an injected/compromised exam page cannot bypass the exit
 * gate by calling the exit IPC directly.
 *
 * Returns:
 *  - "denied": the backend rejected the password (403) or it was missing → BLOCK
 *  - "ok": the backend accepted it (2xx) → allow
 *  - "error": any technical failure (network, auth, 5xx, exception) → FAIL-OPEN
 *    (allow). Fail-open guarantees a genuine exit is never trapped by a backend
 *    hiccup, and it does not weaken the XSS defense: an injected script cannot
 *    make the main process's own HTTP request fail, so a wrong/absent password
 *    still hits the hard 403 block.
 */
async function verifyExitPasswordInMain(sessionId, password) {
  if (!sessionId || !password) {
    return "denied";
  }

  try {
    const examSession = session.fromPartition(EXAM_PARTITION);
    const origin = roomOrigin();

    let csrfToken = "";
    try {
      const csrf = await requestJson({
        method: "GET",
        url: `${origin}/api/api-proxy/auth/csrf-token`,
        examSession,
      });
      csrfToken = JSON.parse(csrf.body)?.data?.csrfToken || "";
    } catch {
      // csrf fetch failed — fall through; the POST will 4xx and we fail-open.
    }

    const verify = await requestJson({
      method: "POST",
      url: `${origin}/api/api-proxy/exams/virtual-room/${encodeURIComponent(sessionId)}/verify-exit`,
      examSession,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
      },
      body: JSON.stringify({ exitPassword: password }),
    });

    if (verify.status >= 200 && verify.status < 300) {
      return "ok";
    }
    if (verify.status === 403) {
      return "denied";
    }
    return "error";
  } catch {
    return "error";
  }
}

module.exports = { verifyExitPasswordInMain };

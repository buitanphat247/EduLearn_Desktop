"use strict";

const fs = require("fs");
const path = require("path");
const { app, session } = require("electron");

// Must match the partition the exam window uses in window.js.
const EXAM_PARTITION = "persist:edulearn-exam";
const SESSION_FILE_ENV = "EDULEARN_EXAM_SHELL_SESSION_FILE";

// Reconstruct a URL that Electron's cookies.set accepts from a stored cookie.
function cookieUrl(cookie) {
  if (!cookie || !cookie.domain) {
    return null;
  }
  const host = cookie.domain.startsWith(".") ? cookie.domain.slice(1) : cookie.domain;
  const scheme = cookie.secure ? "https" : "http";
  const cookiePath = cookie.path || "/";
  return `${scheme}://${host}${cookiePath}`;
}

// Lobby side: snapshot the authenticated exam-partition cookies to a temp file
// so the freshly spawned exam-shell (a separate Electron process with its own
// Chromium profile) can adopt the same login session instead of forcing a
// re-login. Returns the file path (owner-only) or null on failure.
async function exportExamSessionCookies() {
  try {
    const examSession = session.fromPartition(EXAM_PARTITION);
    const cookies = await examSession.cookies.get({});
    const filePath = path.join(
      app.getPath("userData"),
      `exam-shell-session-${Date.now()}-${Math.random().toString(36).slice(2)}.json`,
    );
    fs.writeFileSync(filePath, JSON.stringify(cookies), {
      encoding: "utf8",
      mode: 0o600,
    });
    return filePath;
  } catch (error) {
    console.error("[desktop] Failed to export exam session cookies", error);
    return null;
  }
}

// Exam-shell side: adopt the lobby's cookies into this process's exam partition
// BEFORE the room window loads, then delete the temp file. Idempotent and
// best-effort per cookie so one bad entry never blocks the rest.
async function importExamSessionCookies(filePath = process.env[SESSION_FILE_ENV]) {
  if (!filePath) {
    return { imported: 0 };
  }

  let imported = 0;
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const cookies = JSON.parse(raw);
    const examSession = session.fromPartition(EXAM_PARTITION);

    for (const cookie of Array.isArray(cookies) ? cookies : []) {
      const url = cookieUrl(cookie);
      if (!url || !cookie.name) {
        continue;
      }
      const details = {
        url,
        name: cookie.name,
        value: cookie.value,
        path: cookie.path || "/",
        secure: Boolean(cookie.secure),
        httpOnly: Boolean(cookie.httpOnly),
      };
      if (cookie.domain) {
        details.domain = cookie.domain;
      }
      if (cookie.sameSite) {
        details.sameSite = cookie.sameSite;
      }
      if (typeof cookie.expirationDate === "number") {
        details.expirationDate = cookie.expirationDate;
      }
      try {
        await examSession.cookies.set(details);
        imported += 1;
      } catch (error) {
        console.warn(
          `[desktop] Failed to import cookie ${cookie.name}: ${error?.message ?? error}`,
        );
      }
    }
  } catch (error) {
    console.error("[desktop] Failed to import exam session cookies", error);
  } finally {
    try {
      fs.unlinkSync(filePath);
    } catch {
      // Best-effort cleanup; the file is owner-only and in userData.
    }
  }

  return { imported };
}

// Best-effort: remove any leftover session-handoff files (which contain auth
// tokens) that were never consumed — e.g. the shell failed to spawn or crashed
// before importing. Called on lobby startup and after a failed launch.
function cleanupStaleSessionFiles() {
  try {
    const dir = app.getPath("userData");
    for (const entry of fs.readdirSync(dir)) {
      if (entry.startsWith("exam-shell-session-") && entry.endsWith(".json")) {
        try {
          fs.unlinkSync(path.join(dir, entry));
        } catch {
          // ignore individual failures
        }
      }
    }
  } catch {
    // userData not readable — nothing to clean
  }
}

function deleteSessionFile(filePath) {
  if (!filePath) return;
  try {
    fs.unlinkSync(filePath);
  } catch {
    // already gone / not writable
  }
}

module.exports = {
  EXAM_PARTITION,
  SESSION_FILE_ENV,
  exportExamSessionCookies,
  importExamSessionCookies,
  cleanupStaleSessionFiles,
  deleteSessionFile,
};

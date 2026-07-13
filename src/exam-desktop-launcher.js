"use strict";

const path = require("path");
const fs = require("fs");
const { spawnSync } = require("child_process");
const { app } = require("electron");
const { resolveRustCoreBinaryPath } = require("./rust-sidecar");
const {
  SESSION_FILE_ENV,
  exportExamSessionCookies,
  deleteSessionFile,
} = require("./exam-session-handoff");

const DESKTOP_NAME_PREFIX = "EduLearnExamDesktop";
// The suffix all exam-shell Chromium profile dirs share. Each spawn appends a
// unique instance id AFTER this, so every exam-shell gets its OWN profile dir
// (siblings of the lobby's userData). See makeExamShellInstanceId for why.
const EXAM_SHELL_PROFILE_SUFFIX = "-exam-shell";

// PID of the exam-shell currently owning the foreground desktop. Used so a stale
// watchdog (from an already-exited shell) never switches the user out of a newer
// exam desktop that has since taken over.
let activeExamShellPid = null;

// A per-spawn unique id. ROOT-CAUSE FIX: the exam-shell used to reuse a FIXED
// `--user-data-dir` (and a session-derived desktop name) on every entry. On the
// 2nd+ entry Chromium found the previous instance's SingletonLock still in that
// dir and killed the new process BEFORE main.js ran ("died before boot"), so the
// launcher fell back to an in-window always-on-top entry instead of a real
// isolated desktop. Giving every spawn its own dir + its own desktop object
// removes that collision so re-entry boots exactly like the first entry.
function makeExamShellInstanceId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// The Chromium profile dir for one exam-shell instance (a sibling of the lobby's
// userData so it never shares the lobby's profile — which would also abort boot).
function examShellProfileDir(instanceId) {
  return `${app.getPath("userData")}${EXAM_SHELL_PROFILE_SUFFIX}-${instanceId}`;
}

// Windows desktop names must avoid backslash/control chars and stay short (<=96,
// enforced by the native core). The per-spawn `instanceId` keeps every entry on
// its OWN desktop object even within the same exam session, so a lingering child
// from a previous shell can never make CreateDesktopW reopen a stale desktop
// whose compositor is already torn down (another "died before boot" trigger).
function sanitizeDesktopName(sessionId, instanceId) {
  const safe = String(sessionId || "")
    .replace(/[^A-Za-z0-9_-]/g, "")
    .slice(0, 24);
  const suffix = String(instanceId || Date.now())
    .replace(/[^A-Za-z0-9_-]/g, "")
    .slice(0, 40);
  return `${DESKTOP_NAME_PREFIX}-${safe || "exam"}-${suffix}`;
}

// Remove leftover exam-shell profile dirs from previous (now-exited) shells.
// Because every spawn uses a UNIQUE dir, any dir still on disk belongs to a shell
// that has already quit, so deleting it both reclaims disk and clears any stale
// Chromium SingletonLock. A dir that is still locked (a live shell, or a lingering
// child process) throws on removal and is simply skipped — never fatal to entry.
// `keepDir`, when given, is left untouched (the profile of the shell about to be
// / currently spawned).
function cleanupStaleExamShellProfiles(keepDir) {
  try {
    const base = app.getPath("userData");
    const parent = path.dirname(base);
    const prefix = `${path.basename(base)}${EXAM_SHELL_PROFILE_SUFFIX}-`;
    const keepResolved = keepDir ? path.resolve(keepDir) : null;
    for (const entry of fs.readdirSync(parent)) {
      if (!entry.startsWith(prefix)) {
        continue;
      }
      const full = path.join(parent, entry);
      if (keepResolved && path.resolve(full) === keepResolved) {
        continue;
      }
      try {
        fs.rmSync(full, { recursive: true, force: true });
      } catch {
        /* dir still in use (locked) -> leave it; not fatal to exam entry */
      }
    }
  } catch {
    /* profile sweep is best-effort; it must never block exam entry */
  }
}

// The exam-shell is a second instance of THIS app booted directly onto the
// isolated desktop (a window is bound to the desktop it is created on, so it
// cannot be moved — it must be spawned there). It loads the exam room URL and
// runs in exam-shell mode (kiosk + exit button), while the lobby stays on the
// Default desktop behind the switch.
function buildExamShellLaunchSpec({ roomUrl, sessionId, examCode, signedAllowlist, instanceId }) {
  // CRITICAL: the exam-shell is a SECOND Electron process. Chromium allows only
  // one process per `user-data-dir`; booting a second with a dir that is already
  // owned (the lobby's, OR a previous exam-shell's) makes Chromium's
  // process-singleton exit the shell IMMEDIATELY — before main.js runs (observed:
  // shell spawned with a PID but never wrote its boot marker / never logged
  // "Loading renderer URL"). Give EACH spawn its OWN user-data-dir (a per-instance
  // sibling of the lobby's) so it boots independently AND never collides with a
  // still-locked profile from a prior exam entry — the exact cause of the
  // "1st entry works, later entries fall back to an in-window shell" bug. Login
  // still transfers via the cookie-handoff file (imported into the shell's own
  // partition), so a separate profile does not force a re-login.
  const runId = instanceId || makeExamShellInstanceId();
  const examShellUserDataDir = examShellProfileDir(runId);
  // GPU-independent launch flags for the exam-shell. The shell is spawned onto a
  // BRAND-NEW Windows desktop object; when a remote-display / screen-hooking tool
  // (Parsec, AnyDesk, TeamViewer, RustDesk…) has taken over the GPU/compositor,
  // Electron's GPU process can fail to initialize on that fresh desktop and the
  // whole shell exits CLEANLY before main.js ever runs (observed: shell spawned +
  // desktop switched, but no boot marker and no crash report — the exact
  // "can't enter the room" symptom while remote tools are active). Software
  // rendering removes that dependency; an exam room (text/forms) does not need the
  // GPU, so this trades a little rendering speed for a shell that boots reliably
  // even in a hostile display environment. These are Chromium/Electron switches,
  // so they MUST precede the app path.
  const gpuSafeFlags = [
    "--disable-gpu",
    "--disable-gpu-compositing",
    "--disable-gpu-sandbox",
  ];
  const env = {
    EDULEARN_EXAM_SHELL: "1",
    EDULEARN_EXAM_SHELL_SESSION_ID: String(sessionId || ""),
    EDULEARN_EXAM_SHELL_EXAM_CODE: String(examCode || ""),
    ELECTRON_START_URL: roomUrl,
  };
  // P47-03: hand the server-signed URL allowlist blob to the shell so its
  // url-filter can enforce a signed (tamper-proof) host set instead of only the
  // env-derived one. Accept either the parsed blob or a pre-serialized string;
  // the shell re-verifies the Ed25519 signature, so this env channel grants no
  // authority on its own (a forged value is simply refused).
  if (signedAllowlist) {
    env.EDULEARN_SIGNED_ALLOWLIST_JSON =
      typeof signedAllowlist === "string"
        ? signedAllowlist
        : JSON.stringify(signedAllowlist);
  }
  return {
    desktopName: sanitizeDesktopName(sessionId, runId),
    executable: process.execPath, // electron.exe
    // `--user-data-dir` + the GPU-safe flags must be arguments to electron.exe
    // itself. Put them before the app path so Chromium reads them as its switches.
    args: [
      `--user-data-dir=${examShellUserDataDir}`,
      ...gpuSafeFlags,
      app.getAppPath(),
    ],
    switchToExam: true,
    env,
  };
}

// P47-03: main-side, best-effort fetch of the server-signed URL allowlist blob.
// Runs in the TRUSTED main process (not the untrusted renderer), so the renderer
// cannot influence which hosts are reachable — and the blob is Ed25519-signed, so
// the transport is not trusted anyway. Any failure returns null and the shell
// falls back to its env-derived allowlist (the filter never opens up on error).
async function fetchSignedAllowlist({
  examCode,
  apiBase = process.env.NEXT_PUBLIC_API_URL,
  cookieHeader,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (!examCode || !apiBase || typeof fetchImpl !== "function") {
    return null;
  }
  try {
    const base = String(apiBase).replace(/\/+$/, "");
    const url = `${base}/exam-security/policies/${encodeURIComponent(examCode)}/url-allowlist`;
    const headers = cookieHeader ? { cookie: cookieHeader } : {};
    const response = await fetchImpl(url, { headers });
    if (!response || !response.ok) {
      return null;
    }
    const blob = await response.json();
    if (blob && typeof blob === "object" && blob.payload && typeof blob.payload === "object") {
      return blob;
    }
    return null;
  } catch (error) {
    try {
      console.warn(`[desktop] signed url-allowlist fetch failed: ${error?.message || error}`);
    } catch {
      /* logging must never mask the fallback */
    }
    return null;
  }
}

// Lobby side: ask the native core to create the isolated desktop, spawn the
// exam-shell on it, and switch input to it.
async function enterExamDesktop(desktopCoreRuntime, { roomUrl, sessionId, examCode } = {}) {
  if (!roomUrl || typeof roomUrl !== "string") {
    return {
      ok: false,
      error: { code: "INVALID_REQUEST", message: "roomUrl is required to enter the exam desktop." },
    };
  }

  // Fresh, unique identity for THIS entry so nothing from a previous exam-shell
  // (its Chromium profile / SingletonLock, or its Windows desktop object) can
  // collide with it. Sweeping the leftover profile dirs of earlier, now-exited
  // shells first is what clears a stale SingletonLock that would otherwise abort
  // the boot and force the in-window fallback. `keepDir` protects this entry's own
  // dir; any still-locked dir (a live shell) is skipped, so this is safe to run on
  // every entry.
  const instanceId = makeExamShellInstanceId();
  const shellUserDataDir = examShellProfileDir(instanceId);
  cleanupStaleExamShellProfiles(shellUserDataDir);

  // P47-03: pull the server-signed URL allowlist (best-effort, main-side) BEFORE
  // building the spec so it can be baked into the shell's environment. A failure
  // here never blocks entry — the shell just uses its env-derived allowlist.
  const signedAllowlist = await fetchSignedAllowlist({ examCode });
  const spec = buildExamShellLaunchSpec({ roomUrl, sessionId, examCode, signedAllowlist, instanceId });

  // Hand the lobby's authenticated session to the exam-shell so it doesn't force
  // a re-login on the isolated desktop.
  const sessionFile = await exportExamSessionCookies();
  if (sessionFile) {
    spec.env[SESSION_FILE_ENV] = sessionFile;
  }

  const response = await desktopCoreRuntime.handleCommand({
    requestId: `enter-exam-desktop-${Date.now()}`,
    cmd: "create_exam_desktop",
    payload: spec,
  });

  const shellPid = response?.data?.shellPid;
  if (response?.ok && typeof shellPid === "number") {
    // rust returns ok as soon as the shell is spawned + the desktop is switched,
    // but on machines running remote-display tools (Parsec/AnyDesk/TeamViewer)
    // the shell can die on the isolated desktop BEFORE main.js — leaving the user
    // staring at a reverted lobby with no room. Confirm the shell actually
    // survives its boot window before declaring isolation a success; if it dies
    // early, undo the desktop switch and report failure so the caller falls back
    // to in-window entry (still screen-proctored) instead of stranding the user.
    const booted = await confirmExamShellBooted(shellPid);
    if (!booted) {
      switchBackToDefaultDesktop();
      // The shell is confirmed dead — reclaim its (now-unlocked) profile dir so it
      // can't accumulate and so a retry starts from a clean slate. Pass no keepDir:
      // this dead shell's dir must be removed, and any OTHER still-running shell's
      // dir is protected implicitly (a live Chromium holds its SingletonLock, so
      // rmSync throws on it and the sweep skips it).
      cleanupStaleExamShellProfiles();
      if (sessionFile) {
        deleteSessionFile(sessionFile);
      }
      const detail = `exam-shell pid=${shellPid} died before finishing boot on its isolated desktop (profile=${path.basename(shellUserDataDir)}). Falling back to in-window entry. Possible causes: a GPU/desktop-object init failure, a remote-display tool (Parsec/AnyDesk/TeamViewer), or antivirus blocking the child process.`;
      try {
        console.error(`[desktop] ${detail}`);
      } catch {
        /* logging must never mask the fallback */
      }
      try {
        global.__eduWriteCrash?.("exam-shell-early-death", detail);
      } catch {
        /* diagnostics must never throw */
      }
      return {
        ok: false,
        error: {
          code: "SHELL_DIED_BEFORE_BOOT",
          message:
            "Desktop cách ly không khởi động kịp. Mở phòng thi trong cửa sổ hiện tại và vẫn giám sát màn hình. Nếu lặp lại, kiểm tra phần mềm điều khiển từ xa (Parsec/AnyDesk) hoặc phần mềm diệt virus.",
        },
      };
    }
    activeExamShellPid = shellPid;
    watchExamShellForRecovery(shellPid, Date.now(), shellUserDataDir);
  } else if (sessionFile) {
    // No shell was spawned — don't leave the auth-token handoff file behind.
    deleteSessionFile(sessionFile);
  }
  return response;
}

// Lobby watchdog: if the exam-shell exits (crash OR normal exit) the visible
// desktop must return to Default, otherwise the lobby is stranded behind a
// destroyed exam desktop (black screen). switch_default_desktop is idempotent,
// so this is safe even when the shell already switched back on a clean exit.
//
// RESIDUAL RISK (Windows PID reuse): the exam-shell is spawned by the native
// core (CreateProcessW), so the lobby holds only its PID — not a Node
// ChildProcess handle or an OS process HANDLE — and cannot subscribe to a real
// "exit" event. Liveness is therefore polled via `process.kill(pid, 0)`. If the
// shell dies and Windows recycles its PID onto an unrelated process before the
// next poll, this reads "alive" and recovery is delayed until that process also
// exits (lobby briefly stranded). The clean-exit path does NOT depend on this
// (the shell switches back to Default itself on a password-verified exit); this
// watchdog is only the crash safety-net. Fully closing the gap needs the native
// core to expose a HANDLE-based wait (immune to PID reuse) — tracked separately
// as it requires a rust-core command, out of scope for this JS module.
// A shell that exits within this window of being spawned almost certainly died
// BEFORE reaching main.js (native-level exit — e.g. a remote-display tool
// breaking GPU/desktop-object init). We surface that distinctly so "can't enter
// the room" is self-diagnosing instead of a silent revert to the lobby.
const EXAM_SHELL_EARLY_DEATH_MS = 8000;

// How long to watch a freshly-spawned shell before trusting it booted. The
// observed native failure kills the shell in ~1.5s, so surviving this window is
// strong evidence the shell reached its renderer. Kept short so a healthy entry
// isn't noticeably delayed.
const EXAM_SHELL_BOOT_CONFIRM_MS = 3000;

// Returns true if the shell process stays alive for the whole confirm window
// (booted), false if it exits during it (died before boot). Poll-based because
// the shell is spawned by the native core (CreateProcessW), so the lobby holds
// only its PID — not a Node ChildProcess to await an 'exit' on.
async function confirmExamShellBooted(
  shellPid,
  settleMs = EXAM_SHELL_BOOT_CONFIRM_MS,
  pollMs = 400,
) {
  const deadline = Date.now() + settleMs;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, pollMs));
    let alive = true;
    try {
      process.kill(shellPid, 0);
    } catch (error) {
      alive = error && error.code === "EPERM";
    }
    if (!alive) {
      return false;
    }
  }
  return true;
}

function watchExamShellForRecovery(shellPid, spawnedAt = Date.now(), userDataDir) {
  const timer = setInterval(() => {
    let alive = true;
    try {
      process.kill(shellPid, 0);
    } catch (error) {
      // EPERM means the process exists but we lack permission — still alive.
      alive = error && error.code === "EPERM";
    }
    if (!alive) {
      clearInterval(timer);
      const lifetimeMs = Date.now() - spawnedAt;
      if (lifetimeMs < EXAM_SHELL_EARLY_DEATH_MS) {
        // Loud, persisted signal: the shell died almost immediately, so it never
        // booted. Written to the synchronous crash file too (survives a hard
        // exit) so the failure is diagnosable without live logs.
        const detail = `exam-shell pid=${shellPid} exited ${lifetimeMs}ms after spawn — died before finishing boot. Possible causes: GPU/desktop-object init failure, a remote-display tool (Parsec/AnyDesk/TeamViewer), or antivirus blocking the child.`;
        try {
          console.error(`[desktop] ${detail}`);
        } catch {
          /* logging must never mask recovery */
        }
        try {
          global.__eduWriteCrash?.("exam-shell-early-death", detail);
        } catch {
          /* diagnostics must never throw */
        }
      }
      // Only recover if this shell still owns the foreground; if a newer exam
      // desktop has taken over, leave it alone (avoid yanking the user out).
      if (shellPid === activeExamShellPid) {
        activeExamShellPid = null;
        switchBackToDefaultDesktop();
        // This shell is gone and no newer one took over, so its profile dir is
        // safe to reclaim (removes any SingletonLock it left behind).
        if (userDataDir) {
          cleanupStaleExamShellProfiles(undefined);
        }
      }
    }
  }, 1500);
  timer.unref?.();
}

// Exam-shell side: on a password-verified exit, switch the visible desktop back
// to Default via a quick one-shot native call, then let the shell quit (which
// tears down the isolated desktop once its last thread leaves it).
function switchBackToDefaultDesktop() {
  const binaryPath = resolveRustCoreBinaryPath();
  if (!binaryPath) {
    return { applied: false, detail: "rust-core binary not found for desktop restore." };
  }

  try {
    const result = spawnSync(binaryPath, ["--switch-default-desktop"], {
      windowsHide: true,
      timeout: 5000,
      encoding: "utf8",
    });
    return {
      applied: result.status === 0,
      detail: String(result.stdout || result.stderr || "").trim(),
    };
  } catch (error) {
    return {
      applied: false,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
}

function isExamShellProcess() {
  return process.env.EDULEARN_EXAM_SHELL === "1";
}

// The exam-shell window blocks close (Alt+F4 / X) so a student cannot bail out
// of the exam. A real exit (password-verified submit/exit) flips this flag first
// so the programmatic quit is allowed through.
let examShellCloseAllowed = false;
function allowExamShellClose() {
  examShellCloseAllowed = true;
}
function isExamShellCloseAllowed() {
  return examShellCloseAllowed;
}

module.exports = {
  sanitizeDesktopName,
  makeExamShellInstanceId,
  examShellProfileDir,
  cleanupStaleExamShellProfiles,
  buildExamShellLaunchSpec,
  fetchSignedAllowlist,
  enterExamDesktop,
  switchBackToDefaultDesktop,
  isExamShellProcess,
  allowExamShellClose,
  isExamShellCloseAllowed,
};

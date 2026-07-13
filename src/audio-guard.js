"use strict";

const { execFile } = require("child_process");

const MEDIA_PROCESS_NAMES = new Set([
  "chrome",
  "msedge",
  "spotify",
  "tiktok",
  "tiktok live studio",
  "brave",
  "firefox",
  "opera",
]);
const PROCESS_SCAN_INTERVAL_MS = 5000;

// ─── V10.9X: State-Driven Audio Governor ────────────────────────────────────
// The periodic enforcement loop (`periodic_audio_lock_enforcement`) has been
// REMOVED.  Audio state is now driven EXCLUSIVELY by the State Governor via
// `handleRuntimeChanged`.  This eliminates a class of race conditions where a
// stale timer would re-mute audio after exit cleanup had already restored it.
//
// State rules:
//   EXAM_RUNNING_CONFIRMED                 → audio.mute()
//   EXAM_EXITING / EXITED                  → audio.forceRestore(), stop locks
//   ENTERING_KIOSK                         → NO audio unlock (transition only)
//   All other states                       → no-op (preserve current)
// ─────────────────────────────────────────────────────────────────────────────

const AUDIO_MUTE_SESSION_STATES = new Set([
  "EXAM_RUNNING_CONFIRMED",
]);

const AUDIO_FORCE_RESTORE_SESSION_STATES = new Set([
  "EXAM_EXITING",
  "EXITED",
]);

function resolveAudioDirective(snapshot, governorAudioState = null) {
  const sessionState = snapshot?.sessionState ?? "INIT";
  const nextAudioLockActive = Boolean(snapshot?.audioLockActive);
  return (
    governorAudioState ??
    (AUDIO_FORCE_RESTORE_SESSION_STATES.has(sessionState)
      ? "RESTORE"
      : nextAudioLockActive && AUDIO_MUTE_SESSION_STATES.has(sessionState)
        ? "MUTE"
        : nextAudioLockActive
          ? "HOLD"
          : "RESTORE")
  );
}

// Pure helper: pick the disallowed media/browser processes out of a Get-Process
// dump. Exported for unit testing.
function selectMediaProcesses(processes, allowedNames) {
  const matched = [];
  for (const info of processes) {
    const name = String(info?.ProcessName ?? "").toLowerCase();
    if (allowedNames.has(name)) {
      matched.push({ name, id: Number(info?.Id) });
    }
  }
  return matched;
}

// Enforcement mode for the per-process media scan. Defaults to "report" (log
// only, unchanged behaviour) so enabling termination is a deliberate, tested
// step — mirroring the URL-filter and GPO report-first posture. The master
// endpoint is already muted while the lock is active regardless of this mode.
function resolveAudioEnforceMode(env = process.env) {
  return env.EDULEARN_AUDIO_ENFORCE === "kill" ? "kill" : "report";
}

function runPowerShell(script, timeoutMs = 3000) {
  return new Promise((resolve) => {
    execFile(
      "powershell.exe",
      ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
      { windowsHide: true, timeout: timeoutMs },
      (error, stdout, stderr) => {
        resolve({
          ok: !error,
          stdout: String(stdout ?? "").trim(),
          stderr: String(stderr ?? "").trim(),
          error: error ? String(error.message ?? error) : null,
        });
      },
    );
  });
}

const CORE_AUDIO_SCRIPT = `
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
public class MMDeviceEnumerator {}
public enum EDataFlow { eRender, eCapture, eAll }
public enum ERole { eConsole, eMultimedia, eCommunications }
[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IMMDeviceEnumerator {
  int NotImpl1();
  int GetDefaultAudioEndpoint(EDataFlow dataFlow, ERole role, out IMMDevice ppDevice);
}
[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IMMDevice {
  int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, out IAudioEndpointVolume ppInterface);
}
[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IAudioEndpointVolume {
  int RegisterControlChangeNotify(IntPtr pNotify);
  int UnregisterControlChangeNotify(IntPtr pNotify);
  int GetChannelCount(out uint pnChannelCount);
  int SetMasterVolumeLevel(float fLevelDB, Guid pguidEventContext);
  int SetMasterVolumeLevelScalar(float fLevel, Guid pguidEventContext);
  int GetMasterVolumeLevel(out float pfLevelDB);
  int GetMasterVolumeLevelScalar(out float pfLevel);
  int SetChannelVolumeLevel(uint nChannel, float fLevelDB, Guid pguidEventContext);
  int SetChannelVolumeLevelScalar(uint nChannel, float fLevel, Guid pguidEventContext);
  int GetChannelVolumeLevel(uint nChannel, out float pfLevelDB);
  int GetChannelVolumeLevelScalar(uint nChannel, out float pfLevel);
  int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, Guid pguidEventContext);
  int GetMute(out bool pbMute);
}
public class AudioEndpoint {
  static IAudioEndpointVolume Volume() {
    IMMDeviceEnumerator enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumerator());
    IMMDevice device;
    Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(EDataFlow.eRender, ERole.eMultimedia, out device));
    Guid iid = typeof(IAudioEndpointVolume).GUID;
    IAudioEndpointVolume volume;
    Marshal.ThrowExceptionForHR(device.Activate(ref iid, 23, IntPtr.Zero, out volume));
    return volume;
  }
  public static bool GetMute() {
    bool muted;
    Marshal.ThrowExceptionForHR(Volume().GetMute(out muted));
    return muted;
  }
  public static void SetMute(bool muted) {
    Guid context = Guid.Empty;
    Marshal.ThrowExceptionForHR(Volume().SetMute(muted, context));
  }
}
"@;
`;

function createAudioGuard({ getMainWindow, examGuardTracer }) {
  let audioLockActive = false;
  let lastProcessScanAt = 0;
  let previousSystemMute = null;

  function record(event, details = {}) {
    examGuardTracer?.recordAudio?.({
      event,
      processName: details.processName ?? "electron",
      action: details.action ?? event,
      state: details.state ?? null,
      audioLockActive,
      reason: details.reason ?? null,
      source: details.source ?? "audio-guard",
    });
  }

  function setWindowMuted(muted, reason) {
    const mainWindow = getMainWindow?.();
    if (!mainWindow || mainWindow.isDestroyed()) {
      return;
    }

    if (muted && audioLockActive && !mainWindow.webContents.isAudioMuted()) {
      record("AUDIO_FORCE_UNMUTE_ATTEMPT", {
        action: "electron_window_was_unmuted_during_audio_lock",
        state: mainWindow.webContents.isLoading() ? "loading" : "loaded",
        reason,
      });
    }
    mainWindow.webContents.setAudioMuted(muted);
    record(muted ? "AUDIO_LOCK_MAINTAINED" : "AUDIO_LOCK_RELEASED", {
      action: muted ? "electron_window_muted" : "electron_window_unmuted",
      state: mainWindow.webContents.isLoading() ? "loading" : "loaded",
      reason,
    });
  }

  async function setSystemMute(muted, reason) {
    if (process.platform !== "win32") {
      record(muted ? "AUDIO_LOCK_MAINTAINED" : "AUDIO_LOCK_RELEASED", {
        action: "system_mute_unavailable",
        reason: `platform_${process.platform}_${reason}`,
      });
      return;
    }

    if (previousSystemMute === null) {
      const query = await runPowerShell(`${CORE_AUDIO_SCRIPT} [AudioEndpoint]::GetMute()`);
      if (query.ok) {
        previousSystemMute = /^true$/i.test(query.stdout);
      }
    }

    const command = `${CORE_AUDIO_SCRIPT} [AudioEndpoint]::SetMute($${muted ? "true" : "false"})`;
    const result = await runPowerShell(command);
    record(muted ? "AUDIO_LOCK_MAINTAINED" : "AUDIO_LOCK_RELEASED", {
      action: muted ? "system_master_mute_on" : "system_master_mute_restore",
      reason: result.ok ? reason : result.error ?? result.stderr,
    });
  }

  async function scanMediaProcesses(reason) {
    if (process.platform !== "win32") {
      return;
    }

    const now = Date.now();
    if (now - lastProcessScanAt < PROCESS_SCAN_INTERVAL_MS) {
      return;
    }
    lastProcessScanAt = now;

    const result = await runPowerShell(
      "Get-Process | Select-Object ProcessName,Id | ConvertTo-Json -Compress",
      4000,
    );
    if (!result.ok || !result.stdout) {
      record("AUDIO_BLOCKED_PROCESS", {
        processName: "unknown",
        action: "process_scan_failed",
        reason: result.error ?? result.stderr ?? reason,
      });
      return;
    }

    let processes = [];
    try {
      const parsed = JSON.parse(result.stdout);
      processes = Array.isArray(parsed) ? parsed : [parsed];
    } catch (error) {
      record("AUDIO_BLOCKED_PROCESS", {
        processName: "unknown",
        action: "process_scan_parse_failed",
        reason: error instanceof Error ? error.message : String(error),
      });
      return;
    }

    const matched = selectMediaProcesses(processes, MEDIA_PROCESS_NAMES);
    if (matched.length === 0) {
      return;
    }

    const mode = resolveAudioEnforceMode();
    for (const media of matched) {
      record("AUDIO_BLOCKED_PROCESS", {
        processName: media.name,
        action:
          mode === "kill"
            ? "terminate_media_process"
            : "flagged_report_only_master_endpoint_muted",
        reason: `${reason}:pid=${media.id}:mode=${mode}`,
      });
    }

    if (mode === "kill") {
      // Kill by NAME in a single pipeline so there is no window between listing
      // PIDs and terminating them (a PID could be reused by an unrelated, even
      // critical, process in that gap). Names come from MEDIA_PROCESS_NAMES, so
      // there is no injection surface. Each is single-quoted to survive spaces.
      const names = [...new Set(matched.map((media) => media.name))];
      if (names.length > 0) {
        const quoted = names.map((name) => `'${name}'`).join(",");
        const killResult = await runPowerShell(
          `Get-Process -Name ${quoted} -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue`,
          4000,
        );
        record("AUDIO_BLOCKED_PROCESS", {
          processName: "media-batch",
          action: killResult.ok
            ? "terminate_media_process_done"
            : "terminate_media_process_failed",
          reason: killResult.ok
            ? `killed:${names.join(",")}`
            : killResult.error ?? killResult.stderr ?? reason,
        });
      }
    }
  }

  function maintain(reason) {
    if (!audioLockActive) {
      return;
    }

    setWindowMuted(true, reason);
    void setSystemMute(true, reason);
    void scanMediaProcesses(reason);
  }

  async function restoreAudio(reason) {
    setWindowMuted(false, reason);
    if (previousSystemMute !== null) {
      await setSystemMute(previousSystemMute, reason);
      previousSystemMute = null;
    }
  }

  function handleRuntimeChanged(snapshot, governorAudioState = null) {
    const sessionState = snapshot?.sessionState ?? "INIT";
    const nextAudioLockActive = Boolean(snapshot?.audioLockActive);
    const audioState = resolveAudioDirective(snapshot, governorAudioState);

    // ── V10.9X: GLOBAL PRIORITY OVERRIDE ──
    // Exit confirmation/request states return HOLD. Restore is only legal
    // after the governor advances to EXAM_EXITING or EXITED.
    if (audioState === "RESTORE") {
      if (audioLockActive) {
        audioLockActive = false;
        record("AUDIO_LOCK_RELEASED", {
          action: "restoreAudio",
          state: sessionState,
          reason: "state_governor_restore",
        });
        void restoreAudio("state_governor_restore");
      }
      return;
    }

    // ── V10.9X: State-driven audio decisions ──
    if (audioState === "HOLD") {
      if (audioLockActive) {
        maintain("state_engine_audio_freeze");
      }
      return;
    }

    if (audioState === "MUTE") {
      const reason = "state_engine_audio_mute";
      if (!audioLockActive) {
        audioLockActive = true;
        record("AUDIO_LOCK_ACTIVATED", {
          action: "applyFullSystemMute",
          state: sessionState,
          reason,
        });
      }
      // Apply mute once per state change — NO periodic loop
      maintain(reason);
      return;
    }

    // Audio lock was released via state governor
    if (!nextAudioLockActive && audioLockActive) {
      audioLockActive = false;
      record("AUDIO_LOCK_RELEASED", {
        action: "restoreAudio",
        state: sessionState,
        reason: "runtime_audio_lock_released",
      });
      void restoreAudio("runtime_audio_lock_released");
    }
  }

  function dispose() {
    audioLockActive = false;
    void restoreAudio("audio_guard_dispose");
  }

  return {
    dispose,
    handleRuntimeChanged,
    maintain,
  };
}

module.exports = {
  createAudioGuard,
  resolveAudioDirective,
  selectMediaProcesses,
  resolveAudioEnforceMode,
};

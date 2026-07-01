# Exam Guard Native Validation Report

Generated: 2026-07-01T04:55:21.338Z

## Final Verdict

Overall: **NOT TESTED**

| Metric | Value |
|---|---:|
| Evidence records | 0 |
| Invalid | 0 |
| Failed | 0 |
| Blocked | 0 |
| Not tested | 0 |
| Pass with limitations | 0 |

## Category Verdicts

| Category | Records | Verdict | Expected |
|---|---:|---|---|
| Capture Validation | 0 | NOT TESTED | Candidate sees exam content locally; receiver capture is black, excluded, blocked, or explicitly classified as best-effort/unsupported. |
| Runtime Validation | 0 | NOT TESTED | Runtime tick, watcher, detection, remediation, guard restart and heartbeat latency stay under configured thresholds. |
| ETW Producer Validation | 0 | NOT TESTED | A real Microsoft-Windows-Kernel-Process session emits start, stop and rundown events; TDH fields reach RuntimeStateEngine; loss is detected; restart and polling reconciliation are proven under flood. |
| Fault Injection | 0 | NOT TESTED | Injected failure is recorded, recovery is observed, desktop/taskbar/cursor are restored, and audit evidence exists. |
| Soak Test | 0 | NOT TESTED | No CPU, memory, handle, thread, overlay, desktop lifetime or guard health leak over the requested duration. |
| Stress Test | 0 | NOT TESTED | Repeated start/restore, monitor, DPI, clipboard, focus, process and policy stress does not corrupt runtime state. |
| Desktop Validation | 0 | NOT TESTED | Dedicated desktop is created before Electron, switched during exam, restored and destroyed after exit or crash. |
| Service Validation | 0 | NOT TESTED | Installed Windows Service starts, stops, rejects stalled/flood clients and performs authorized elevated remediation. |
| Benchmark Validation | 0 | NOT TESTED | Runtime, producer, queue, remediation and recovery latency remain under release thresholds. |

## Detailed Rejection Report

Release is rejected because one or more required evidence categories are missing or not tested.

| Category | Records | Verdict | Required Action |
|---|---:|---|---|
| Capture Validation | 0 | NOT TESTED | Attach reviewed evidence records for capture-validation. |
| Runtime Validation | 0 | NOT TESTED | Attach reviewed evidence records for runtime-validation. |
| ETW Producer Validation | 0 | NOT TESTED | Attach reviewed evidence records for etw-producer-validation. |
| Fault Injection | 0 | NOT TESTED | Attach reviewed evidence records for fault-injection. |
| Soak Test | 0 | NOT TESTED | Attach reviewed evidence records for soak-test. |
| Stress Test | 0 | NOT TESTED | Attach reviewed evidence records for stress-test. |
| Desktop Validation | 0 | NOT TESTED | Attach reviewed evidence records for desktop-validation. |
| Service Validation | 0 | NOT TESTED | Attach reviewed evidence records for service-validation. |
| Benchmark Validation | 0 | NOT TESTED | Attach reviewed evidence records for benchmark-validation. |

## Coverage Gaps

Missing capture apps: OBS, Discord, Zoom, Teams, Google Meet, Webex, Skype, AnyDesk, TeamViewer, UltraViewer, RustDesk, RDP, Quick Assist, Windows Snipping Tool, Win+Shift+S, Lightshot, Greenshot, ShareX, Game Bar, Xbox Capture, VMware, VirtualBox

Missing display scenarios: single-monitor, dual-monitor, triple-monitor, hot-plug, resolution-change, orientation-change, sleep-resume, hibernate-resume, lock-unlock, fast-user-switching, rdp-attach, rdp-detach, uac-prompt, explorer-restart, dwm-restart, dock, undock

Missing fault scenarios: kill-electron, kill-rust-core, kill-bootstrapper, kill-watchdog, kill-service, close-stdin, named-pipe-disconnect, named-pipe-failure, heartbeat-timeout, kill-explorer, restart-explorer, restart-dwm, uac-prompt, crash-during-kiosk, crash-during-restore, crash-during-desktop-switch, clipboard-failure, guard-thread-exit, late-runtime-tick-after-restore, display-sync-after-restore, process-pid-reuse, process-churn-debounce-bound, etw-session-stop, etw-provider-disable, etw-buffer-loss, named-pipe-accept-cancellation, service-client-response-timeout, sleep-during-kiosk, power-interruption-simulated

## Performance Gate

Performance records: 0

Performance summary: **NOT TESTED**

## Known Limitations

- Windows: Ctrl+Alt+Del and UAC Secure Desktop are OS-controlled and cannot be blocked by user-mode code.
- Windows: RDP attach/detach can alter session and display behavior and must be classified from evidence.
- Electron: Electron content protection behavior depends on OS compositor and capture path.
- Electron: BrowserWindow content protection must be verified with receiver-side evidence for every supported capture stack.
- WDA: SetWindowDisplayAffinity is not DRM and cannot stop physical cameras, hardware capture cards, kernel drivers or future unsupported capture APIs.
- WDA: WDA results vary by capture API, DWM state and Windows build.
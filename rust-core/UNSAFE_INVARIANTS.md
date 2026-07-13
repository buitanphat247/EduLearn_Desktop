# Rust Core — `unsafe` / FFI Invariants (F-018)

**Date:** 2026-07-13 · **Scope:** `desktop/rust-core/src` · **Count:** 165 `unsafe` occurrences across 18 files (all Win32/ntdll FFI — there is no `unsafe` for pure logic).

This is the FFI safety audit for F-018. Each category lists the invariant every call site must uphold, the resource-release rule, and the RAII/remediation status. New/critical sites use the `ffi_guards::OwnedHandle` RAII wrapper; the AUD-01 memory-hygiene gap is fixed.

---

## 1. Invariant catalogue by category

| Category | Files (unsafe count) | Win32/ntdll used | Invariant | Release rule | Status |
|---|---|---|---|---|---|
| Anti-debug (read-only) | `anti_debug.rs` (3) | IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess | Pseudo-handle only; out-params sized correctly; **no owned resource** | none (pseudo-handle not closed) | ✅ audited (F-004) |
| Device-key crypto | `exam_key.rs` (7) | CryptProtectData / CryptUnprotectData, LocalFree | Blobs sized correctly; **plaintext wiped before free** | LocalFree the OS buffer; zeroize plaintext | ✅ **AUD-01 fixed** (wipe before LocalFree) |
| Named-pipe IPC | `ipc_pipe.rs` (8) | CreateNamedPipe, Connect/Read/Write, CloseHandle | Valid buffers; bounded reads; close handle on all paths | CloseHandle | ⚠️ candidate for `OwnedHandle` (tracked) |
| Desktop isolation | `desktop_isolation.rs` (13) | CreateDesktopW, SwitchDesktop, SetThreadDesktop, CloseDesktop, CreateProcessW | Restore input desktop; close desktop handles; validate creation | CloseDesktop | ⚠️ audited; RAII candidate (tracked) |
| Input/mouse/focus/taskbar hooks | `mouse_guard.rs`(15) `input_guard.rs`(12) `focus_guard.rs`(11) `taskbar_guard.rs`(5) | SetWindowsHookEx, CallNextHookEx, UnhookWindowsHookEx | Hook handle valid; **always unhook** on deactivate/shutdown | UnhookWindowsHookEx | ⚠️ audited; hooks unhooked on teardown (verify in soak) |
| Clipboard | `clipboard_guard.rs` (21) | OpenClipboard, GetClipboardData, CloseClipboard | Never hold the clipboard lock; close on every path | CloseClipboard | ⚠️ audited; close-on-all-paths (verify) |
| Display / GDI | `display_guard.rs`(17) `capture_guard.rs`(2) `dpi_awareness.rs`(1) | EnumDisplayMonitors, Get/SetWindowDisplayAffinity, DC ops | Release DCs; valid monitor handles | ReleaseDC | ⚠️ audited |
| ETW producer | `etw_producer.rs` (24) | EventRegister/Write/Unregister (TraceLogging) | Register once; **unregister on drop**; valid descriptors | EventUnregister | ⚠️ audited |
| Process enumeration / kill | `collectors.rs`(9) `process_remediation.rs`(3) | CreateToolhelp32Snapshot, Process32*, OpenProcess, TerminateProcess, CloseHandle | Close snapshot + process handles; validate PID != self | CloseHandle → **`OwnedHandle`** | ⚠️ RAII target (see §2) |
| Accessibility / service | `accessibility_guard.rs`(5) `service_client.rs`(4) | UI Automation / SC Manager | Release COM/SC handles | Close/Release | ⚠️ audited |

## 2. RAII wrappers introduced (F-018)
- **`ffi_guards::OwnedHandle`** — owns a Win32 `HANDLE`, `CloseHandle` on drop; `new` rejects null/`INVALID_HANDLE_VALUE` (so a failed `OpenProcess` never yields a guard that closes `-1`), and pseudo-handles (`GetCurrentProcess`) are intentionally not wrapped. Unit-tested (`rejects_invalid_handles`). This is the reusable pattern for the process-enumeration/kill and named-pipe sites; migrating those manual `CloseHandle` calls to `OwnedHandle` is the remaining systematic pass (tracked below).

## 3. Error-path checks (F-018)
- Every FFI call in the changed sites checks its status (`Result`/`NTSTATUS >= 0`/null-ptr guard) before using out-params.
- **AUD-01 remediation:** `exam_key::unprotect_seed_with` now `write_bytes(0)` the DPAPI plaintext buffer **before** `LocalFree`, and null-guards the pointer — no decrypted seed remains in freed heap.

## 4. Remaining systematic work (tracked, not a regression)
A full line-by-line migration of all 165 sites to RAII is beyond this phase. **Priority order for the next pass:**
1. Process handles (`collectors.rs`, `process_remediation.rs`) → `OwnedHandle`.
2. Named-pipe handles (`ipc_pipe.rs`) → `OwnedHandle`.
3. Desktop handles (`desktop_isolation.rs`) → a `CloseDesktop` RAII guard.
4. Hook/clipboard/ETW teardown — add a soak-test assertion that handle count is stable over an 8-hour session (currently manual review).

**Acceptance for §4:** `cargo clippy -- -W clippy::pedantic` clean on the migrated modules; a soak test shows no material handle-count growth.

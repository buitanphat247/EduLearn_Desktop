# Electron Security Review (Phase 5)

**Date:** 2026-07-13 · Audit of the exam BrowserWindow: preload API, isolation, CSP, permissions, navigation, window creation, external protocols. Applied hardening + residual gaps.

---

## 1. webPreferences posture (`window.js`)
| Setting | Value | Verdict |
|---|---|---|
| `contextIsolation` | **true** | ✅ isolated world; page cannot reach preload internals |
| `nodeIntegration` | **false** | ✅ no Node in the renderer |
| `webSecurity` | **true** | ✅ same-origin + mixed-content enforced |
| `webviewTag` | **false** (added) | ✅ blocks injected `<webview>` that would bypass window guards |
| `spellcheck` | **false** (added) | ✅ no spellcheck network calls |
| `sandbox` | **false** | ⚠️ **residual** — preload imports local contract files; kept off until the bridge is bundled. Tracked (P2). Mitigated by contextIsolation + capability-token IPC + no nodeIntegration. |
| `partition` | `persist:edulearn-exam` | ✅ dedicated session (URL-filter/CSP hooks isolated from the global session) |
| capability token | via `additionalArguments` (argv) | ✅ delivered to preload only, not the page |

**Confirmed absent (good):** no `nodeIntegration:true`, `webSecurity:false`, or `contextIsolation:false` anywhere in `src/`.

## 2. Preload API surface (`preload.js`)
Five `contextBridge.exposeInMainWorld` bridges (`desktopRuntime`, `desktopCore`, `desktopExam`, `desktopOAuth`, `examGuardTrace`) — all isolated-world, typed method surfaces (no raw `ipcRenderer` exposed to the page). Privileged `desktopCore` commands carry the capability token and are gated by the `SAFE_EXAM_COMMANDS` allow-list (now incl. `check_debugger`, `scan_process_heuristics`). **Verdict:** minimal, mediated surface — no arbitrary IPC exposed.
- **Residual (P2):** the surface is broad; a follow-up should confirm each exposed method is still needed and typed (a `.d.ts` contract exists client-side).

## 3. CSP (`csp.js`, new)
- **Report-only by default** (`Content-Security-Policy-Report-Only`); `EDULEARN_CSP=enforce` sends the blocking header — the staged report→enforce rollout the mission requires.
- Always-on hardening directives (safe for the app): `object-src 'none'`, `frame-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'` (close clickjacking, injected `<object>`/`<base>`, off-origin form posts).
- `connect-src` widened to the URL-filter's allowed hosts so the API/socket keep working; upstream CSP headers are stripped so ours is authoritative.
- **Residual (P1→P2):** `script-src`/`style-src` still allow `'unsafe-inline'`/`'unsafe-eval'` (Next.js hydration). Tighten to nonces once the renderer supports it; run report-only first to collect violations.

## 4. Navigation / window / protocol (`url-filter.js`)
| Vector | Handling |
|---|---|
| Sub-resource requests | `webRequest.onBeforeRequest` → cancel when enforcing + off-allowlist |
| `window.open` / popups | `setWindowOpenHandler` → `deny` when enforcing |
| `will-navigate` / `will-redirect` | `event.preventDefault()` when enforcing + off-allowlist |
| Non-network protocols (`file:`, `ftp:`, custom `xxx:`) | `isAllowedUrl` denies everything except http(s)/ws(s) to allowed hosts + internal schemes (data/blob/about/devtools) |
| Host scope | exact host or subdomain of an allowed host; `localhost` only when the exam itself is served locally |

**Verdict:** external navigation, popups, and non-http protocols are all blocked under enforce, with structured **telemetry** (blocked/flagged counts by kind). Report mode logs-but-allows for a safe dry-run.

## 5. F-006 signed allowlist (new)
The authoritative host set can come from a **policy signed with the exam-policy Ed25519 key** (`verifySignedAllowlist`), verified against `EDULEARN_EXAM_POLICY_PUBLIC_KEYS_JSON` within a freshness window, canonicalization matching the server + IPC layer. A tampered/unsigned/expired/unknown-key blob is **refused** (never widens the reachable hosts) and logged. **Blocker:** the *server* must emit these signed allowlist blobs (a cross-component contract) — the desktop verification path + tests are done.

## 6. Permissions
`setPermissionRequestHandler` → deny all; `setPermissionCheckHandler` → false. No camera/mic/geolocation/display-capture (proctoring removed). Wrapped so it can never throw and block entry. **Verdict:** default-deny ✅.

## 7. Keyboard / exit lockdown (exam-shell)
`before-input-event` suppresses all Ctrl/Alt/Meta combos, F1–F12, PrintScreen, ContextMenu, Meta; `close` prevented unless a password-verified exit set the allow flag. **Verdict:** ✅ (unchanged this phase).

## 8. Residual risks (tracked)
| Item | Severity | Plan |
|---|---|---|
| `sandbox:false` | P2 | Bundle the preload, then enable sandbox |
| CSP `'unsafe-inline'`/`'unsafe-eval'` | P2 | Nonce-based script-src after report-only telemetry |
| Signed-allowlist producer | P1 | Server must emit signed allowlist blobs (contract defined here) |
| Preload surface breadth | P2 | Prune + type-audit exposed methods |
| Client IPC v2 emission wiring into the live pipe client | P2 | `createSequencedFrameFactory` ready; wire the desktop pipe client to emit v2 |

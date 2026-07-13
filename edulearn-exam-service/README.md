# EduLearn Exam Guard Windows Service

The service runs elevated remediation in Session 0. It does not manipulate the
interactive desktop; crash restoration remains owned by the user-session
bootstrapper.

Every termination request must pass all gates:

- named-pipe caller path and SHA-256 match installer-managed configuration;
- policy and receipt are signed by a pinned server Ed25519 key;
- receipt binds exam, session, policy version and device ID;
- request is signed by that device key;
- nonce and timestamp pass replay checks;
- the actual target executable name read by the service is blocked by policy;
- the service process itself and explicitly allowed executables cannot be killed.

`Install-ExamGuardService.ps1` requires administrator rights, writes configuration
under ProgramData with SYSTEM/Administrators ACLs, installs the service and starts
it. Deployment still requires publisher-signed binaries and organization change
control.

## Option B — end-to-end setup (kill remote-control tools without student admin)

Once installed, the service runs as SYSTEM at boot. At **"Vào phòng thi"**, the
rust-core preflight already tries to terminate policy-blocked processes
(`terminate_with_service_fallback`): first user-mode, and if that fails because the
target runs as SYSTEM (e.g. `parsecd.exe`, AnyDesk services), it escalates the
kill to this service. The student never needs admin at exam time — only this
one-time install does.

The three parts must share one Ed25519 keypair or every kill is rejected as an
invalid signature:

1. **Generate the keypair** (self-tests the backend↔service round-trip):

   ```
   cd desktop/edulearn-exam-service
   node generate-service-keys.mjs
   ```

   - Paste **STEP 1** (`EXAM_POLICY_KEY_ID` + `EXAM_POLICY_PRIVATE_KEY_PEM`) into
     `server/server-nest/.env`, then **restart the NestJS backend** so it can sign
     the exam policy and the `elevated-remediation` receipt.
   - Keep **STEP 2** (the `{"exam-policy-primary":"<base64>"}` public key) for the
     next step. Never commit the private key; use a fresh keypair for production.

2. **Build + install the service** — from an **elevated (Administrator)** PowerShell:

   ```
   cd desktop/edulearn-exam-service
   .\Setup-ExamGuardService.ps1 -TrustedServerKeysJson '{"exam-policy-primary":"<base64 from STEP 2>"}'
   ```

   This builds `edulearn-exam-service.exe` + `rust-core.exe`, writes
   `C:\ProgramData\Edulearn\ExamGuard\service-config.json` (trusted key + the pinned
   rust-core path/hash), and creates + starts the auto-start `EduLearnExamGuard`
   service. Verify: `sc.exe query EduLearnExamGuard`.

3. **Enter an exam.** Preflight now kills Parsec/AnyDesk via the service before the
   isolated exam-shell launches. If any remote tool can't be removed (e.g. RDP, a
   hardware KVM, or a phone camera — none of which are killable), the desktop
   launcher's boot-confirm still falls back to in-window entry (screen-proctored).

### Notes / gotchas

- **Rebuilding rust-core changes its hash** → the service will stop trusting the
  client. Re-run `Setup-ExamGuardService.ps1` after any rust-core rebuild.
- The signed policy's remote/blocked lists (which processes may be killed) come
  from `shared/contracts/exam-guard-policy-catalog.json` — Parsec and the common
  remote tools are already listed there.
- Production: sign the binaries, store the private PEM in a secrets manager, and
  gate the install behind your device-management/change-control process.

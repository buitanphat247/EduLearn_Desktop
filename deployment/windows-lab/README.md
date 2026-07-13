# EduLearn Exam Lab Policy

These profiles are **only** for organization-managed Windows lab devices (kiosk /
exam workstations), never for a student's personal machine.

There are two profiles and two scripts:

| Mode | Profile | Script | Touches the system? |
|------|---------|--------|---------------------|
| **Audit** (default) | `managed-lab-profile.json` (`deploymentMode: audit`) | `Audit-ExamLabPolicy.ps1` | No — read-only inspection |
| **Enforce** | `enforced-lab-profile.json` (`deploymentMode: enforce`) | `Enforce-ExamLabPolicy.ps1` | Yes — applies GPO registry keys + generates AppLocker policy |

## Audit (inspect only)

```powershell
.\Audit-ExamLabPolicy.ps1
```

Collects the current lockdown state to `exam-lab-policy-audit.json`. Never changes
registry, AppLocker, WDAC or Assigned Access.

## Enforce (apply the lockdown)

`Enforce-ExamLabPolicy.ps1` turns the audit-only profile into real enforcement:
it blocks inbound RDP, disables Fast User Switching, and (for the candidate
account) disables Task Manager, Command Prompt, registry tools, `Win+L`, and
Control Panel — then generates an AppLocker enforce policy that denies unmanaged
remote-control / screen-capture tools.

**Safety model**
- **Dry run by default.** Without `-Apply` the script only prints what it *would*
  change (equivalent to `-WhatIf`) and writes a report to `exam-lab-policy-apply.json`.
  A dry run is read-only and does **not** require Administrator.
- **Reversible.** Before changing any value, the previous value is captured to
  `exam-lab-policy-restore.json`. `-Rollback` reverts every recorded change.
- Every registry write honors `-WhatIf` / `-Confirm`.
- `-Apply` and `-Rollback` require an elevated (Administrator) session.

```powershell
# 1. Preview (no admin, no changes):
.\Enforce-ExamLabPolicy.ps1

# 2. Apply for real to the candidate account's hive (run elevated; log the account off first):
.\Enforce-ExamLabPolicy.ps1 -Apply -TargetUserProfile "C:\Users\EduLearnExamCandidate"

# 3. Import the generated AppLocker policy (elevated):
Set-AppLockerPolicy -XmlPolicy .\exam-lab-applocker.xml -Merge

# 4. Undo everything:
.\Enforce-ExamLabPolicy.ps1 -Rollback
```

Per-user policies (Task Manager, CMD, etc.) are written to the candidate account's
hive: pass `-TargetUserProfile` and make sure that account is **logged off** so its
`NTUSER.DAT` can be loaded. Omit it to target the current user's `HKCU` (useful when
you run the script while logged in *as* the candidate account).

## Rollout gates (do not enforce until all complete)

The profile must not be enforced in production until:

1. A recovery administrator account is tested.
2. AppLocker and WDAC audit events are reviewed for at least seven days.
3. The packaged EduLearn binaries are publisher-signed.
4. Assigned Access uses the final package AppUserModelId.
5. A restore runbook is tested on the pilot ring, including `-Rollback`.
6. A system restore point is created before the first `-Apply`.
7. The native Exam Guard matrix is complete for the target hardware image.

For fleet deployment, prefer delivering the same keys via Intune/GPO with change
control; this script is for lab imaging and pilot-ring validation.

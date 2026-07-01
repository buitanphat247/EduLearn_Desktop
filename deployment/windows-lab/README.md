# EduLearn Exam Lab Policy

This profile is only for organization-managed Windows lab devices.

The checked-in profile is deliberately `audit`/`AuditOnly`. It must not be
changed to enforcement until all of these gates are complete:

1. A recovery administrator account is tested.
2. AppLocker and WDAC audit events are reviewed for at least seven days.
3. The packaged EduLearn binaries are publisher-signed.
4. Assigned Access uses the final package AppUserModelId.
5. A restore runbook is tested on the pilot ring.
6. The native Exam Guard matrix is complete for the target hardware image.

Run `Audit-ExamLabPolicy.ps1` without elevation to collect the current policy
state. The script never changes registry, AppLocker, WDAC or Assigned Access.
Enforcement should be delivered by Intune/GPO with change control and rollback,
not by the exam application.

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

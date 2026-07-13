<#
.SYNOPSIS
    One-shot setup for EduLearn Exam Guard "Option B" - the SYSTEM Windows
    service that performs elevated remediation (killing remote-control software
    like Parsec/AnyDesk) so the exam-shell can launch on the isolated desktop
    WITHOUT the student needing admin rights at exam time.

.DESCRIPTION
    Builds the two Rust binaries, then hands them to Install-ExamGuardService.ps1
    which writes the locked-down service-config.json and creates + starts the
    auto-start service. Run this ONCE, from an elevated (Administrator) shell.

    The -TrustedServerKeysJson value comes from generate-service-keys.mjs
    (STEP 2). The matching private key must already be in the backend .env
    (STEP 1) or the service will reject every kill as an invalid signature.

.EXAMPLE
    # 1) node generate-service-keys.mjs   -> copy STEP 1 into server .env, STEP 2 below
    # 2) (elevated PowerShell)
    .\Setup-ExamGuardService.ps1 -TrustedServerKeysJson '{"exam-policy-primary":"<base64>"}'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TrustedServerKeysJson,

    # rust-core / the service currently build with the gnu toolchain on this
    # machine (no MSVC linker). Override if you have MSVC set up.
    [string]$Toolchain = "stable-x86_64-pc-windows-gnu",

    # Skip cargo build and use whatever is already in target/release.
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

# --- must be elevated (New-Service / sc create require admin) ------------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an elevated (Administrator) PowerShell - installing a Windows service requires admin."
}

# --- validate the trusted-keys blob up front ----------------------------------
# (no -AsHashtable: Windows PowerShell 5.1 compatibility)
try {
    $parsedKeys = $TrustedServerKeysJson | ConvertFrom-Json
} catch {
    throw "TrustedServerKeysJson is not valid JSON. Use the STEP 2 output of generate-service-keys.mjs."
}
if (@($parsedKeys.PSObject.Properties).Count -lt 1) {
    throw "TrustedServerKeysJson must contain at least one keyId -> base64PublicKey entry."
}

$serviceDir = $PSScriptRoot
$desktopDir = Split-Path $serviceDir -Parent
$coreDir = Join-Path $desktopDir "rust-core"

$serviceExe = Join-Path $serviceDir "target\release\edulearn-exam-service.exe"
$coreExe = Join-Path $coreDir "target\release\rust-core.exe"

if (-not $SkipBuild) {
    Write-Host "[setup] Building edulearn-exam-service (release, +$Toolchain)..." -ForegroundColor Cyan
    & cargo "+$Toolchain" build --release --manifest-path (Join-Path $serviceDir "Cargo.toml")
    if ($LASTEXITCODE -ne 0) { throw "Building edulearn-exam-service failed." }

    Write-Host "[setup] Building rust-core client (release, +$Toolchain)..." -ForegroundColor Cyan
    & cargo "+$Toolchain" build --release --manifest-path (Join-Path $coreDir "Cargo.toml")
    if ($LASTEXITCODE -ne 0) { throw "Building rust-core failed." }
}

foreach ($exe in @($serviceExe, $coreExe)) {
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "Expected binary not found: $exe (build failed or -SkipBuild used without a prior build)."
    }
}

Write-Host "[setup] Installing the EduLearn Exam Guard service..." -ForegroundColor Cyan
& (Join-Path $serviceDir "Install-ExamGuardService.ps1") `
    -ServiceBinary $serviceExe `
    -RustCoreBinary $coreExe `
    -TrustedServerKeysJson $TrustedServerKeysJson

Write-Host ""
Write-Host "[setup] Done. Verify with:  sc.exe query EduLearnExamGuard" -ForegroundColor Green
Write-Host "[setup] The service now auto-starts at boot as SYSTEM. Students no longer need admin;" -ForegroundColor Green
Write-Host "[setup] at exam entry, rust-core preflight will kill remote-control tools via the service." -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT: the allowed client hash is pinned to THIS rust-core.exe." -ForegroundColor Yellow
Write-Host "If you rebuild rust-core, re-run this setup so the new hash is trusted." -ForegroundColor Yellow

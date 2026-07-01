param(
    [switch]$AllowNonElevated
)

$ErrorActionPreference = "Stop"
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
$isAdministrator = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdministrator -and -not $AllowNonElevated) {
    [Console]::Error.WriteLine(
        "Real ETW smoke test requires an elevated Windows lab session. " +
        "Start PowerShell as Administrator or use -AllowNonElevated only to record the expected access-denied path."
    )
    exit 2
}

$manifestPath = Join-Path $PSScriptRoot "..\rust-core\Cargo.toml"
$testName = "etw_producer::tests::native_etw_session_observes_spawned_process"

Write-Output "Running real Microsoft-Windows-Kernel-Process ETW smoke test."
Write-Output "Administrator: $isAdministrator"
Write-Output "Test: $testName"

& cargo test --manifest-path $manifestPath $testName -- --ignored --exact --nocapture
exit $LASTEXITCODE

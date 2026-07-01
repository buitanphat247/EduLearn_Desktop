[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$ServiceBinary,

    [Parameter(Mandatory)]
    [string]$RustCoreBinary,

    [Parameter(Mandatory)]
    [string]$TrustedServerKeysJson
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Administrator privileges are required to install the Exam Guard service."
}

$trustedKeys = $TrustedServerKeysJson | ConvertFrom-Json -AsHashtable
if ($trustedKeys.Count -lt 1) {
    throw "At least one trusted server public key is required."
}

$installDirectory = Join-Path $env:ProgramFiles "Edulearn\ExamGuard"
$configDirectory = Join-Path $env:ProgramData "Edulearn\ExamGuard"
$installedService = Join-Path $installDirectory "edulearn-exam-service.exe"
$configPath = Join-Path $configDirectory "service-config.json"
$clientHash = (Get-FileHash -LiteralPath $RustCoreBinary -Algorithm SHA256).Hash.ToLowerInvariant()

if ($PSCmdlet.ShouldProcess("EduLearnExamGuard", "Install Windows service")) {
    New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $configDirectory -Force | Out-Null
    Copy-Item -LiteralPath $ServiceBinary -Destination $installedService -Force

    @{
        trustedServerKeys = $trustedKeys
        allowedClientPath = (Resolve-Path -LiteralPath $RustCoreBinary).Path
        allowedClientSha256 = $clientHash
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath -Encoding UTF8

    & icacls.exe $configDirectory /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    & icacls.exe $installDirectory /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

    $existing = Get-Service -Name "EduLearnExamGuard" -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service -Name "EduLearnExamGuard" -Force -ErrorAction SilentlyContinue
        & sc.exe delete "EduLearnExamGuard" | Out-Null
        Start-Sleep -Seconds 1
    }
    New-Service `
        -Name "EduLearnExamGuard" `
        -BinaryPathName "`"$installedService`"" `
        -DisplayName "EduLearn Exam Guard" `
        -Description "Authenticated elevated remediation for managed exam devices." `
        -StartupType Automatic | Out-Null
    Start-Service -Name "EduLearnExamGuard"
}

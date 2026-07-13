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

# NOTE: no -AsHashtable (that is PowerShell 7+ only; this must also run under
# Windows PowerShell 5.1). ConvertTo-Json below serializes the PSCustomObject to
# the same {"keyId":"base64"} object the service expects.
$trustedKeys = $TrustedServerKeysJson | ConvertFrom-Json
if (@($trustedKeys.PSObject.Properties).Count -lt 1) {
    throw "At least one trusted server public key is required."
}

$installDirectory = Join-Path $env:ProgramFiles "Edulearn\ExamGuard"
$configDirectory = Join-Path $env:ProgramData "Edulearn\ExamGuard"
$installedService = Join-Path $installDirectory "edulearn-exam-service.exe"
$configPath = Join-Path $configDirectory "service-config.json"
$clientHash = (Get-FileHash -LiteralPath $RustCoreBinary -Algorithm SHA256).Hash.ToLowerInvariant()

if ($PSCmdlet.ShouldProcess("EduLearnExamGuard", "Install Windows service")) {
    $svcName = "EduLearnExamGuard"
    # Stop any prior install so its .exe unlocks before we overwrite it. IMPORTANT:
    # do NOT `sc delete` a running service and immediately re-create it — the delete
    # is deferred while a handle is open, leaving the name "marked for deletion"
    # (error 1072) so the fresh service refuses to start until reboot. Instead we
    # REUSE the existing service entry (its binPath is the fixed install path) and
    # just rewrite its binary + config, which sidesteps that trap entirely.
    $existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        for ($i = 0; $i -lt 30; $i++) {
            $s = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $s -or $s.Status -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    # A service stuck in StartPending will not stop cleanly and keeps its .exe
    # locked — force-kill the process so the overwrite can proceed.
    Get-Process -Name "edulearn-exam-service" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $configDirectory -Force | Out-Null

    # Wait until the old exe is actually unlocked (service deletion + process exit
    # are asynchronous) before overwriting it.
    if (Test-Path -LiteralPath $installedService) {
        for ($i = 0; $i -lt 20; $i++) {
            try {
                $fs = [System.IO.File]::Open($installedService, 'Open', 'ReadWrite', 'None')
                $fs.Close()
                break
            } catch {
                Start-Sleep -Milliseconds 500
            }
        }
    }

    Copy-Item -LiteralPath $ServiceBinary -Destination $installedService -Force

    $configJson = @{
        trustedServerKeys = $trustedKeys
        allowedClientPath = (Resolve-Path -LiteralPath $RustCoreBinary).Path
        allowedClientSha256 = $clientHash
    } | ConvertTo-Json -Depth 5
    # Write UTF-8 WITHOUT a BOM. Windows PowerShell 5.1's `Set-Content -Encoding
    # UTF8` prepends a BOM that the Rust service's serde_json rejects at column 1.
    [System.IO.File]::WriteAllText(
        $configPath,
        $configJson,
        (New-Object System.Text.UTF8Encoding($false))
    )

    & icacls.exe $configDirectory /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    & icacls.exe $installDirectory /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

    if (-not $existing) {
        New-Service `
            -Name $svcName `
            -BinaryPathName "`"$installedService`"" `
            -DisplayName "EduLearn Exam Guard" `
            -Description "Authenticated elevated remediation for managed exam devices." `
            -StartupType Automatic | Out-Null
    } else {
        # Reused entry: make sure it still points at the (re)installed binary and
        # stays auto-start. (`key= value` must each be a single sc.exe arg token.)
        & sc.exe config $svcName "binPath= `"$installedService`"" "start= auto" | Out-Null
    }

    # Start with a few retries — right after a stop/config the SCM can briefly
    # report the service busy. Then verify it actually reached RUNNING and fail
    # loudly (with the real status) instead of leaving a silently-stopped service.
    $started = $false
    for ($i = 0; $i -lt 6; $i++) {
        try {
            Start-Service -Name $svcName -ErrorAction Stop
            $started = $true
            break
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    Start-Sleep -Milliseconds 500
    $final = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $final -or $final.Status -ne 'Running') {
        $status = (& sc.exe query $svcName) -join [Environment]::NewLine
        throw @"
EduLearnExamGuard was installed but did NOT reach RUNNING.
$status

Most common causes:
  1. The -TrustedServerKeysJson base64 is wrong (an O<->0 / I<->l typo makes it a
     non-curve Ed25519 point and the service rejects its config at startup). Use
     the value from:  node derive-trusted-key.mjs
  2. A prior 'sc delete' left the name marked-for-deletion (error 1072). Reboot
     once, then re-run this setup (this version reuses the entry and won't re-trap).
"@
    }
    Write-Host "[install] EduLearnExamGuard is RUNNING." -ForegroundColor Green
}

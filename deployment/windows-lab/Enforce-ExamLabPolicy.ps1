<#
.SYNOPSIS
    Applies (enforces) the EduLearn managed exam-lab lockdown policy on a managed device.

.DESCRIPTION
    Counterpart to Audit-ExamLabPolicy.ps1. Where the audit script only *reads* the
    current state, this script *applies* the Group Policy registry keys, generates an
    AppLocker enforce policy for prohibited remote-control / screen-capture tools, and
    (optionally) turns on the Windows RDP block and Fast-User-Switching lockout.

    SAFETY MODEL
      * Nothing is changed unless you pass -Apply. Without it the script performs a
        dry run (equivalent to -WhatIf) and only prints what it *would* do.
      * Before changing any registry value, the previous value is captured into a
        restore file (default: exam-lab-policy-restore.json). Run with -Rollback to
        revert every change using that file.
      * Every registry write honors -WhatIf / -Confirm (SupportsShouldProcess).
      * The script refuses to run on a profile whose deploymentMode is not "enforce"
        and refuses to run without Administrator rights.

    This is intended for *managed lab machines only* (kiosk / exam workstations), never
    for a student's personal device. Pair it with a recovery account and a restore point.

.PARAMETER ProfilePath
    Path to the enforced profile JSON. Defaults to enforced-lab-profile.json next to this script.

.PARAMETER Apply
    Actually apply the changes. Omit for a dry run.

.PARAMETER Rollback
    Revert all changes recorded in the restore file, then exit.

.PARAMETER RestorePath
    Where the pre-change values are stored (and read from during -Rollback).

.PARAMETER OutputPath
    Where the apply/dry-run report JSON is written.

.PARAMETER TargetUserProfile
    Path to the candidate account's profile directory (contains NTUSER.DAT) so that
    per-user policies (Task Manager, CMD, etc.) can be written to that account's hive
    without being logged in as them. If omitted, per-user policies are written to the
    CURRENT user's hive (HKCU) — useful when you run this while logged in AS the
    candidate account.

.EXAMPLE
    # Dry run — see exactly what would change:
    .\Enforce-ExamLabPolicy.ps1

.EXAMPLE
    # Apply for real to the candidate account's hive:
    .\Enforce-ExamLabPolicy.ps1 -Apply -TargetUserProfile "C:\Users\EduLearnExamCandidate"

.EXAMPLE
    # Undo everything:
    .\Enforce-ExamLabPolicy.ps1 -Rollback
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter()]
    [string]$ProfilePath = (Join-Path $PSScriptRoot "enforced-lab-profile.json"),

    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [switch]$Rollback,

    [Parameter()]
    [string]$RestorePath = (Join-Path $PSScriptRoot "exam-lab-policy-restore.json"),

    [Parameter()]
    [string]$OutputPath = (Join-Path $PSScriptRoot "exam-lab-policy-apply.json"),

    [Parameter()]
    [string]$TargetUserProfile,

    [Parameter()]
    [string]$AppLockerPolicyPath = (Join-Path $PSScriptRoot "exam-lab-applocker.xml")
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------
function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run elevated (Administrator). Machine-wide lockdown keys cannot be set otherwise."
    }
}

# When -Apply is not passed we force -WhatIf so ShouldProcess reports without changing anything.
if (-not $Apply -and -not $Rollback) {
    $WhatIfPreference = $true
    Write-Host "[dry-run] No -Apply flag. Showing intended changes only; nothing will be modified." -ForegroundColor Yellow
}

# Elevation is only required to actually mutate machine/user policy. A dry run
# (no -Apply / -Rollback) is read-only, so reviewers can preview without admin.
if ($Apply -or $Rollback) {
    Assert-Administrator
}

# ---------------------------------------------------------------------------
# Registry helpers with backup
# ---------------------------------------------------------------------------
$script:RestoreEntries = [System.Collections.Generic.List[object]]::new()
$script:ChangeLog = [System.Collections.Generic.List[object]]::new()

function Read-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        return $null
    }
}

function Set-PolicyValue {
    param(
        [Parameter(Mandatory)][string]$Scope,      # "machine" | "user"
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value,
        [Parameter(Mandatory)][string]$Description
    )

    $previous = Read-RegistryValue -Path $Path -Name $Name
    $current = if ($null -eq $previous) { "<unset>" } else { "$previous" }

    if ($current -eq "$Value") {
        $script:ChangeLog.Add([ordered]@{ scope = $Scope; path = $Path; name = $Name; description = $Description; from = $current; to = "$Value"; status = "already-compliant" })
        return
    }

    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value ($Description)")) {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null

        $script:RestoreEntries.Add([ordered]@{ path = $Path; name = $Name; previousValue = $previous; hadValue = ($null -ne $previous) })
        $script:ChangeLog.Add([ordered]@{ scope = $Scope; path = $Path; name = $Name; description = $Description; from = $current; to = "$Value"; status = "applied" })
        Write-Host "  [applied] $Path\$Name : $current -> $Value" -ForegroundColor Green
    } else {
        $script:ChangeLog.Add([ordered]@{ scope = $Scope; path = $Path; name = $Name; description = $Description; from = $current; to = "$Value"; status = "would-apply" })
        Write-Host "  [would ] $Path\$Name : $current -> $Value ($Description)" -ForegroundColor Cyan
    }
}

# ---------------------------------------------------------------------------
# Candidate user hive resolution
# ---------------------------------------------------------------------------
$script:LoadedHiveName = $null

function Resolve-UserRegistryRoot {
    param([string]$UserProfilePath)

    if ([string]::IsNullOrWhiteSpace($UserProfilePath)) {
        Write-Host "[info] No -TargetUserProfile; per-user policies target the current user's HKCU." -ForegroundColor Yellow
        return "HKCU:"
    }

    $ntuser = Join-Path $UserProfilePath "NTUSER.DAT"
    if (-not (Test-Path -LiteralPath $ntuser)) {
        throw "NTUSER.DAT not found at $ntuser. Ensure the candidate profile exists and is logged off."
    }

    $hiveName = "EduLearnExamCandidate"
    if ($PSCmdlet.ShouldProcess("HKU\$hiveName", "Load candidate hive from $ntuser")) {
        & reg.exe load "HKU\$hiveName" "$ntuser" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to load candidate hive (reg load exit $LASTEXITCODE). The account may be logged in — log it off first."
        }
        $script:LoadedHiveName = $hiveName
        if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script | Out-Null
        }
        return "HKU:\$hiveName"
    }

    # Dry run: return a virtual root so we still print intended writes.
    return "HKU:\$hiveName"
}

function Dismount-UserHive {
    if ($null -ne $script:LoadedHiveName) {
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        & reg.exe unload "HKU\$($script:LoadedHiveName)" | Out-Null
        $script:LoadedHiveName = $null
    }
}

# ---------------------------------------------------------------------------
# Rollback path
# ---------------------------------------------------------------------------
function Invoke-Rollback {
    if (-not (Test-Path -LiteralPath $RestorePath)) {
        throw "Restore file not found at $RestorePath. Nothing to roll back."
    }
    $restore = Get-Content -Raw -LiteralPath $RestorePath | ConvertFrom-Json
    Write-Host "[rollback] Reverting $($restore.entries.Count) change(s) recorded at $($restore.capturedAt)." -ForegroundColor Yellow

    # If the restore file references the candidate hive, load it first.
    $needsHive = $restore.entries | Where-Object { $_.path -like "HKU:\EduLearnExamCandidate*" }
    if ($needsHive -and $restore.targetUserProfile) {
        Resolve-UserRegistryRoot -UserProfilePath $restore.targetUserProfile | Out-Null
    }

    try {
        foreach ($entry in $restore.entries) {
            if ($PSCmdlet.ShouldProcess("$($entry.path)\$($entry.name)", "Rollback")) {
                if ($entry.hadValue) {
                    if (-not (Test-Path -LiteralPath $entry.path)) { New-Item -Path $entry.path -Force | Out-Null }
                    New-ItemProperty -LiteralPath $entry.path -Name $entry.name -Value $entry.previousValue -PropertyType DWord -Force | Out-Null
                    Write-Host "  [restored] $($entry.path)\$($entry.name) -> $($entry.previousValue)" -ForegroundColor Green
                } else {
                    Remove-ItemProperty -LiteralPath $entry.path -Name $entry.name -ErrorAction SilentlyContinue
                    Write-Host "  [removed ] $($entry.path)\$($entry.name)" -ForegroundColor Green
                }
            }
        }
    } finally {
        Dismount-UserHive
    }
    Write-Host "[rollback] Done. You may now delete $RestorePath." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# AppLocker enforce policy generation
# ---------------------------------------------------------------------------
function New-AppLockerEnforcePolicy {
    param(
        [Parameter(Mandatory)][string[]]$DeniedImages,
        [Parameter(Mandatory)][string]$OutFile
    )

    $denyRules = ""
    $index = 0
    foreach ($image in $DeniedImages) {
        $index++
        $guid = [guid]::NewGuid().ToString()
        $denyRules += @"
      <FilePathRule Id="$guid" Name="Deny $image" Description="EduLearn exam lockdown" UserOrGroupSid="S-1-1-0" Action="Deny">
        <Conditions>
          <FilePathCondition Path="*\$image" />
        </Conditions>
      </FilePathRule>
"@
    }

    $xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default) Allow Program Files" Description="Allow everyone to run from Program Files" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default) Allow Windows" Description="Allow everyone to run from the Windows folder" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
$denyRules
  </RuleCollection>
</AppLockerPolicy>
"@

    if ($PSCmdlet.ShouldProcess($OutFile, "Write AppLocker enforce policy ($($DeniedImages.Count) deny rules)")) {
        Set-Content -LiteralPath $OutFile -Value $xml -Encoding UTF8
        Write-Host "  [applied] AppLocker policy written to $OutFile" -ForegroundColor Green
        Write-Host "            Import with: Set-AppLockerPolicy -XmlPolicy `"$OutFile`" -Merge" -ForegroundColor DarkGray
    } else {
        Write-Host "  [would ] Write AppLocker enforce policy to $OutFile ($($DeniedImages.Count) deny rules)" -ForegroundColor Cyan
    }
}

# ===========================================================================
# MAIN
# ===========================================================================
if ($Rollback) {
    Invoke-Rollback
    return
}

$profile = Get-Content -Raw -LiteralPath $ProfilePath | ConvertFrom-Json
if (-not $profile.managedDevicesOnly -or $profile.deploymentMode -ne "enforce") {
    throw "This script only runs against a managed-device profile with deploymentMode = 'enforce'."
}

Write-Host "=== EduLearn Exam Lab Enforcement ($($profile.profileId)) ===" -ForegroundColor White
$gp = $profile.groupPolicy
$userRoot = $null

try {
    # -- Machine-scoped policies (HKLM) --
    Write-Host "[machine policies]" -ForegroundColor White
    if ($gp.disableRemoteDesktop) {
        Set-PolicyValue -Scope machine -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections" -Value 1 -Description "Block inbound Remote Desktop (RDP)"
    }
    if ($gp.disableFastUserSwitching) {
        Set-PolicyValue -Scope machine -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "HideFastUserSwitching" -Value 1 -Description "Disable Fast User Switching"
    }

    # -- User-scoped policies (candidate hive or current HKCU) --
    Write-Host "[user policies]" -ForegroundColor White
    $userRoot = Resolve-UserRegistryRoot -UserProfilePath $TargetUserProfile
    $sysPolicy = "$userRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $explorerPolicy = "$userRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $cmdPolicy = "$userRoot\Software\Policies\Microsoft\Windows\System"

    if ($gp.disableTaskManager) {
        Set-PolicyValue -Scope user -Path $sysPolicy -Name "DisableTaskMgr" -Value 1 -Description "Disable Task Manager"
    }
    if ($gp.disableCommandPrompt) {
        Set-PolicyValue -Scope user -Path $cmdPolicy -Name "DisableCMD" -Value 1 -Description "Disable Command Prompt and .bat/.cmd scripts"
    }
    if ($gp.disableRegistryTools) {
        Set-PolicyValue -Scope user -Path $sysPolicy -Name "DisableRegistryTools" -Value 1 -Description "Disable regedit / registry editing tools"
    }
    if ($gp.disableLockWorkstation) {
        Set-PolicyValue -Scope user -Path $sysPolicy -Name "DisableLockWorkstation" -Value 1 -Description "Disable Win+L lock workstation"
    }
    if ($gp.disableChangePassword) {
        Set-PolicyValue -Scope user -Path $sysPolicy -Name "DisableChangePassword" -Value 1 -Description "Disable change password on the secure screen"
    }
    if ($gp.noControlPanel) {
        Set-PolicyValue -Scope user -Path $explorerPolicy -Name "NoControlPanel" -Value 1 -Description "Hide Control Panel and Settings"
    }

    # -- AppLocker enforce policy --
    Write-Host "[applocker]" -ForegroundColor White
    if ($profile.appLocker.denyUnmanagedRemoteAndCaptureTools -and $profile.deniedProcessImages) {
        New-AppLockerEnforcePolicy -DeniedImages $profile.deniedProcessImages -OutFile $AppLockerPolicyPath
    }

    # -- Persist restore file (only if we actually applied something) --
    if ($Apply -and $script:RestoreEntries.Count -gt 0) {
        $restore = [ordered]@{
            profileId         = $profile.profileId
            capturedAt        = (Get-Date).ToUniversalTime().ToString("o")
            computerName      = $env:COMPUTERNAME
            targetUserProfile = $TargetUserProfile
            entries           = $script:RestoreEntries
        }
        $restore | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $RestorePath -Encoding UTF8
        Write-Host "[restore] Previous values saved to $RestorePath (use -Rollback to revert)." -ForegroundColor Yellow
    }
}
finally {
    Dismount-UserHive
}

# -- Report --
$report = [ordered]@{
    profileId    = $profile.profileId
    ranAt        = (Get-Date).ToUniversalTime().ToString("o")
    computerName = $env:COMPUTERNAME
    mode         = if ($Apply) { "apply" } else { "dry-run" }
    changesApplied = ($Apply -and $script:RestoreEntries.Count -gt 0)
    changes      = $script:ChangeLog
    appLockerPolicy = $AppLockerPolicyPath
    rolloutRequirements = $profile.rollout
}
# The report is an output artifact (not a system change), so write it even during a dry run.
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8 -WhatIf:$false

Write-Host ""
Write-Host "Report written to $OutputPath" -ForegroundColor White
if (-not $Apply) {
    Write-Host "This was a DRY RUN. Re-run with -Apply to enforce, e.g.:" -ForegroundColor Yellow
    Write-Host "  .\Enforce-ExamLabPolicy.ps1 -Apply -TargetUserProfile `"C:\Users\$($profile.candidateAccount)`"" -ForegroundColor Yellow
}
Write-Output $OutputPath

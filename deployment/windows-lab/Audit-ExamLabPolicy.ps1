[CmdletBinding()]
param(
    [Parameter()]
    [string]$ProfilePath = (Join-Path $PSScriptRoot "managed-lab-profile.json"),

    [Parameter()]
    [string]$OutputPath = (Join-Path $PSScriptRoot "exam-lab-policy-audit.json")
)

$ErrorActionPreference = "Stop"
$profile = Get-Content -Raw -LiteralPath $ProfilePath | ConvertFrom-Json
if (-not $profile.managedDevicesOnly -or $profile.deploymentMode -ne "audit") {
    throw "Only an audit-mode managed-device profile can be inspected by this script."
}

function Read-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        return Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop
    } catch {
        return $null
    }
}

$audit = [ordered]@{
    profileId = $profile.profileId
    auditedAt = (Get-Date).ToUniversalTime().ToString("o")
    computerName = $env:COMPUTERNAME
    managedDevicesOnly = $true
    changesApplied = $false
    capabilities = @{
        appLockerService = [bool](Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue)
        assignedAccessCmdlet = [bool](Get-Command Get-AssignedAccess -ErrorAction SilentlyContinue)
        secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)
    }
    currentPolicy = @{
        disableTaskManager = Read-RegistryValue `
            -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "DisableTaskMgr"
        disableCommandPrompt = Read-RegistryValue `
            -Path "HKCU:\Software\Policies\Microsoft\Windows\System" `
            -Name "DisableCMD"
        disableRemoteDesktop = Read-RegistryValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections"
        hideFastUserSwitching = Read-RegistryValue `
            -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "HideFastUserSwitching"
    }
    rolloutRequirements = $profile.rollout
}

$audit | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output $OutputPath

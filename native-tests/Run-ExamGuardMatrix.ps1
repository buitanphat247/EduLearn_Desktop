[CmdletBinding()]
param(
    [Parameter()]
    [string]$ManifestPath = "",

    [Parameter()]
    [string]$OutputDirectory = "",

    [Parameter()]
    [ValidateSet("non-destructive", "destructive-vm-only", "manual-evidence", "automated-validation")]
    [string]$Mode = "non-destructive",

    [Parameter()]
    [switch]$AllowDestructive
)

$ErrorActionPreference = "Stop"

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ManifestPath) {
    $ManifestPath = Join-Path $scriptRoot "matrix.json"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $scriptRoot "results"
}

function Get-MonitorCount {
    Add-Type -AssemblyName System.Windows.Forms
    return [System.Windows.Forms.Screen]::AllScreens.Count
}

function Get-DpiScale {
    $value = Get-ItemPropertyValue `
        -LiteralPath "HKCU:\Control Panel\Desktop\WindowMetrics" `
        -Name "AppliedDPI" `
        -ErrorAction SilentlyContinue
    if (-not $value) {
        return $null
    }
    return [Math]::Round(([double]$value / 96.0) * 100)
}

function Get-AppProbe {
    param([Parameter(Mandatory)][string]$Name)

    $aliases = @{
        "OBS" = @("obs64", "obs32", "obs")
        "Discord" = @("Discord")
        "Zoom" = @("Zoom")
        "Teams" = @("ms-teams", "Teams")
        "Google Meet" = @("chrome", "msedge", "firefox")
        "Webex" = @("CiscoCollabHost", "Webex")
        "Skype" = @("Skype", "SkypeApp")
        "AnyDesk" = @("AnyDesk")
        "TeamViewer" = @("TeamViewer", "TeamViewer_Service")
        "UltraViewer" = @("UltraViewer")
        "RustDesk" = @("rustdesk")
        "RDP" = @("mstsc", "msrdc")
        "Quick Assist" = @("QuickAssist", "quickassist")
        "Windows Snipping Tool" = @("SnippingTool", "ScreenClippingHost")
        "Win+Shift+S" = @("ScreenClippingHost")
        "Lightshot" = @("Lightshot")
        "Greenshot" = @("Greenshot")
        "ShareX" = @("ShareX")
        "Game Bar" = @("GameBar", "GameBarFTServer")
        "Xbox Capture" = @("GameBar", "XboxGameBar")
        "VMware" = @("vmtoolsd", "vmwaretray")
        "VirtualBox" = @("VBoxService", "VBoxTray")
    }
    if (-not $aliases.ContainsKey($Name)) {
        return @{
            name = $Name
            runningPids = @()
            observed = $false
            note = "No process aliases configured for this app."
        }
    }
    $running = foreach ($alias in $aliases[$Name]) {
        Get-Process -Name $alias -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Id
    }
    return @{
        name = $Name
        runningPids = @($running)
        observed = @($running).Count -gt 0
    }
}

$manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1) {
    throw "Unsupported native matrix schema version."
}
if ($Mode -eq "destructive-vm-only" -and -not $AllowDestructive) {
    throw "destructive-vm-only mode requires -AllowDestructive and must run only inside a disposable Windows VM."
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runId = "exam-guard-matrix-$timestamp"
$resultPath = Join-Path $OutputDirectory "exam-guard-matrix-$timestamp.json"
$startedAt = (Get-Date).ToUniversalTime().ToString("o")
$packagePath = Join-Path (Split-Path -Parent $scriptRoot) "package.json"
$packageVersion = if (Test-Path -LiteralPath $packagePath) {
    (Get-Content -Raw -LiteralPath $packagePath | ConvertFrom-Json).version
} else {
    "unknown"
}

$result = [ordered]@{
    schemaVersion = 2
    artifactType = "native-matrix-run-manifest"
    runId = $runId
    version = $packageVersion
    commitHash = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "unknown" }
    startedAt = $startedAt
    completedAt = $null
    collectedAt = $startedAt
    mode = $Mode
    destructiveEnabled = [bool]($Mode -eq "destructive-vm-only" -and $AllowDestructive)
    machine = @{
        windowsProductName = (Get-CimInstance Win32_OperatingSystem).Caption
        windowsBuild = [Environment]::OSVersion.Version.ToString()
        architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        dpiScale = Get-DpiScale
        monitorCount = Get-MonitorCount
        computerName = $env:COMPUTERNAME
    }
    appProbes = @($manifest.captureAndRemoteApps | ForEach-Object { Get-AppProbe -Name $_ })
    matrixCoverage = @{
        windowsVersions = @($manifest.windowsVersions)
        windowsBuilds = @($manifest.windowsBuilds)
        architectures = @($manifest.architectures)
        dpiScales = @($manifest.dpiScales)
        monitorTopologies = @($manifest.monitorTopologies)
        displayScenarios = @($manifest.displayScenarios)
        captureAndRemoteApps = @($manifest.captureAndRemoteApps)
        captureModes = @($manifest.captureModes)
        soakDurationsMinutes = @($manifest.soakDurationsMinutes)
        stressScenarios = @($manifest.stressScenarios)
        etwValidationScenarios = @($manifest.etwValidationScenarios)
        serviceValidationScenarios = @($manifest.serviceValidationScenarios)
        benchmarkScenarios = @($manifest.benchmarkScenarios)
    }
    captureScenarios = @($manifest.captureAndRemoteApps | ForEach-Object {
        $app = $_
        @($manifest.captureModes | ForEach-Object {
            @{
                id = "capture-$($app)-$($_)" -replace '[^A-Za-z0-9_-]', '-'
                app = $app
                mode = $_
                status = "not-tested"
                classification = "Best Effort"
                evidence = @()
            }
        })
    })
    runtimeScenarios = @(
        "runtime-tick",
        "watcher-latency",
        "detection-latency",
        "remediation-latency",
        "guard-restart",
        "overlay-recovery",
        "desktop-restore",
        "service-restart",
        "heartbeat-delay",
        "maximum-tick-jitter"
    ) | ForEach-Object {
        @{
            id = $_
            status = "not-tested"
            metrics = $null
            evidence = @()
        }
    }
    faultInjectionEnabled = [bool]($Mode -eq "destructive-vm-only" -and $AllowDestructive)
    faultScenarios = @($manifest.faultScenarios | ForEach-Object {
        @{
            id = $_
            status = if ($Mode -eq "destructive-vm-only" -and $AllowDestructive) { "not-tested" } else { "skipped" }
            evidence = @()
        }
    })
    soakScenarios = @($manifest.soakDurationsMinutes | ForEach-Object {
        @{
            durationMinutes = $_
            status = "not-tested"
            evidence = @()
        }
    })
    stressScenarios = @($manifest.stressScenarios | ForEach-Object {
        @{
            id = $_
            status = "not-tested"
            evidence = @()
        }
    })
    etwValidationScenarios = @($manifest.etwValidationScenarios | ForEach-Object {
        @{
            id = $_
            status = "not-tested"
            evidence = @()
        }
    })
    serviceValidationScenarios = @($manifest.serviceValidationScenarios | ForEach-Object {
        @{
            id = $_
            status = "not-tested"
            evidence = @()
        }
    })
    benchmarkScenarios = @($manifest.benchmarkScenarios | ForEach-Object {
        @{
            id = $_
            status = "not-tested"
            evidence = @()
        }
    })
    evidenceRequirements = @($manifest.requiredEvidence)
    notes = @(
        "This runner records environment and evidence slots.",
        "not-tested means no production claim has been made for that scenario.",
        "Capture receiver output and destructive fault injection require an isolated Windows VM."
    )
}

$result.completedAt = (Get-Date).ToUniversalTime().ToString("o")
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
Write-Output $resultPath

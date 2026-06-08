param(
    [string]$WatchPath = "",
    [string]$StatePath = (Join-Path $env:LOCALAPPDATA "CodexMonitor\alert-helper-state.json"),
    [int]$PollSeconds = 30
)

$ErrorActionPreference = "Stop"

function Get-SettingsPath {
    return (Join-Path $PSScriptRoot "codex-monitor.settings.json")
}

function Get-HelperWatchPath {
    param([string]$ConfiguredWatchPath)

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredWatchPath)) {
        return $ConfiguredWatchPath
    }

    if (-not [string]::IsNullOrWhiteSpace($env:CODEX_MONITOR_WATCHPATH)) {
        return $env:CODEX_MONITOR_WATCHPATH
    }

    $settingsPath = Get-SettingsPath
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.AlertWatchPath)) {
                return [string]$settings.AlertWatchPath
            }
        } catch {
        }
    }

    return $PSScriptRoot
}

function Ensure-ParentDirectory {
    param([string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        $Object,
        [int]$Depth = 8
    )

    Ensure-ParentDirectory -Path $Path
    $json = ConvertTo-Json -InputObject $Object -Depth $Depth
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function Get-State {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) {
        try {
            return (Get-Content $Path -Raw | ConvertFrom-Json)
        } catch {
        }
    }

    return [PSCustomObject]@{
        SeenAlerts = @()
        LastRunUtc = $null
    }
}

function Save-State {
    param(
        [string]$Path,
        [System.Collections.Generic.HashSet[string]]$SeenAlerts
    )

    $state = [PSCustomObject]@{
        SeenAlerts = @($SeenAlerts)
        LastRunUtc = (Get-Date).ToUniversalTime().ToString("o")
    }
    Write-JsonFile -Path $Path -Object $state
}

function Show-AlertPopup {
    param(
        [string]$Title,
        [string]$Message
    )

    try {
        $escapedTitle = $Title.Replace("'", "''")
        $escapedMessage = $Message.Replace("'", "''")
        $command = "Import-Module BurntToast -ErrorAction Stop; New-BurntToastNotification -Text '{0}','{1}'" -f $escapedTitle, $escapedMessage
        Start-Process -WindowStyle Hidden powershell.exe -ArgumentList @(
            "-ExecutionPolicy", "Bypass",
            "-WindowStyle", "Hidden",
            "-Command", $command
        ) | Out-Null
        return $true
    } catch {
    }

    try {
        $wshShell = New-Object -ComObject WScript.Shell
        [void]$wshShell.Popup($Message, 10, $Title, 64)
        return $true
    } catch {
    }

    return $false
}

function Get-AlertIdentity {
    param($Alert)

    $sourceReport = [string]$Alert.Metadata.SourceReport
    $collectionTimeUtc = [string]$Alert.Metadata.CollectionTimeUtc
    $alertType = [string]$Alert.Metadata.AlertType
    return "{0}|{1}|{2}" -f $alertType, $collectionTimeUtc, $sourceReport
}

$WatchPath = Get-HelperWatchPath -ConfiguredWatchPath $WatchPath

if (-not (Test-Path -LiteralPath $WatchPath)) {
    throw "Watch path not found: $WatchPath"
}

$state = Get-State -Path $StatePath
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in @($state.SeenAlerts)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$entry)) {
        [void]$seen.Add([string]$entry)
    }
}

while ($true) {
    $alerts = @(Get-ChildItem -LiteralPath $WatchPath -Filter "ALERT_*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    foreach ($file in $alerts) {
        try {
            $alert = Get-Content $file.FullName -Raw | ConvertFrom-Json
        } catch {
            continue
        }

        $identity = Get-AlertIdentity -Alert $alert
        if ($seen.Contains($identity)) {
            continue
        }

        $title = [string]$alert.Summary.Title
        $message = [string]$alert.Summary.Message
        if ([string]::IsNullOrWhiteSpace($title)) {
            $title = "Codex monitor alert"
        }
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = [string]$file.Name
        }

        [void](Show-AlertPopup -Title $title -Message $message)
        [void]$seen.Add($identity)
        Save-State -Path $StatePath -SeenAlerts $seen
    }

    Start-Sleep -Seconds $PollSeconds
}

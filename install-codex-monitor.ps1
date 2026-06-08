param(
    [string]$SourceRoot = $PSScriptRoot,
    [string]$RuntimeRoot = "C:\Program Files\CodexMonitor",
    [switch]$CreateSystemTasks,
    [switch]$CreateUserNotifierTask,
    [string]$NotifierScriptPath = (Join-Path $PSScriptRoot "start-codex-alert-helper.ps1")
)

$ErrorActionPreference = "Stop"

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Copy-IfExists {
    param(
        [string]$Path,
        [string]$Destination
    )

    if (Test-Path -LiteralPath $Path) {
        Copy-Item -LiteralPath $Path -Destination $Destination -Force
    }
}

Ensure-Directory -Path $RuntimeRoot

$runtimeFiles = @(
    "invoke-host-ioc.ps1",
    "invoke-host-tripwire.ps1",
    "monitor-threat-rss.ps1",
    "host-tripwire-config.json"
)

foreach ($file in $runtimeFiles) {
    Copy-IfExists -Path (Join-Path $SourceRoot $file) -Destination (Join-Path $RuntimeRoot $file)
}

if (Test-Path -LiteralPath (Join-Path $SourceRoot "ioc-packs")) {
    Copy-Item -LiteralPath (Join-Path $SourceRoot "ioc-packs") -Destination (Join-Path $RuntimeRoot "ioc-packs") -Recurse -Force
}

$settings = [PSCustomObject]@{
    AlertWatchPath = $RuntimeRoot
}
$settings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $SourceRoot "codex-monitor.settings.json") -Encoding UTF8

$runtimeRootTaskPath = $RuntimeRoot
if ($runtimeRootTaskPath -like "C:\Program Files\*") {
    $runtimeRootTaskPath = $runtimeRootTaskPath -replace '^C:\\Program Files', 'C:\Progra~1'
}

if ($CreateSystemTasks) {
    schtasks /Create /SC HOURLY /MO 1 /TN "Codex Host Tripwire" /TR ("powershell.exe -ExecutionPolicy Bypass -File {0}\invoke-host-tripwire.ps1 -Mode Check" -f $runtimeRootTaskPath) /RU SYSTEM /RL HIGHEST /F | Out-Null
    schtasks /Create /SC HOURLY /MO 1 /TN "Codex Threat RSS Monitor" /TR ("powershell.exe -ExecutionPolicy Bypass -File {0}\monitor-threat-rss.ps1 -RunTripwireCheckOnMatch" -f $runtimeRootTaskPath) /RU SYSTEM /RL HIGHEST /F | Out-Null
}

if ($CreateUserNotifierTask) {
    schtasks /Create /SC ONLOGON /TN "Codex Alert Helper" /TR ("powershell.exe -ExecutionPolicy Bypass -File {0} -WatchPath {1}" -f $NotifierScriptPath, $runtimeRootTaskPath) /RL LIMITED /F | Out-Null
}

Write-Host ("Runtime root: {0}" -f $RuntimeRoot)
Write-Host ("Settings file: {0}" -f (Join-Path $SourceRoot "codex-monitor.settings.json"))
if ($CreateSystemTasks) {
    Write-Host "Created system scheduled tasks."
}
if ($CreateUserNotifierTask) {
    Write-Host "Created user notifier task."
}

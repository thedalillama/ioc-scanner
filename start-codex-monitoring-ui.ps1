# CODEX_MONITOR_SELF_EVENT
param(
    [string]$SettingsPath = (Join-Path $PSScriptRoot "codex-monitor.settings.json"),
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8766,
    [string]$OpenPath = "/",
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"

function Stop-ExistingMonitoringUiProcesses {
    $existing = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*codex_monitor_ui.py*" -and $_.CommandLine -like "*--app-mode monitoring*"
    })
    foreach ($process in $existing) {
        try { Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop } catch { }
    }
    if (@($existing).Count -gt 0) { Start-Sleep -Milliseconds 500 }
}

function Get-PythonCommand {
    param([string]$ResolvedSettingsPath)
    if (Test-Path -LiteralPath $ResolvedSettingsPath) {
        try {
            $settings = Get-Content -LiteralPath $ResolvedSettingsPath -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.PythonCommand) -and (Test-Path -LiteralPath ([string]$settings.PythonCommand))) {
                return [string]$settings.PythonCommand
            }
        } catch {
        }
    }
    foreach ($candidate in @(@{ Command = "python"; Arguments = @() }, @{ Command = "py"; Arguments = @("-3") })) {
        try {
            $output = & $candidate.Command @($candidate.Arguments + @("-c", "import sys; print(sys.executable)")) 2>$null
            if ($LASTEXITCODE -eq 0) {
                $resolved = (@($output) | Select-Object -Last 1).Trim()
                if (-not [string]::IsNullOrWhiteSpace($resolved) -and (Test-Path -LiteralPath $resolved)) { return $resolved }
            }
        } catch {
        }
    }
    throw "A usable Python runtime was not found. Update codex-monitor.settings.json or install Python."
}

$pythonCommand = Get-PythonCommand -ResolvedSettingsPath $SettingsPath
$uiScriptPath = Join-Path $PSScriptRoot "codex_monitor_ui.py"
if (-not (Test-Path -LiteralPath $uiScriptPath)) { throw "Monitoring UI script not found: $uiScriptPath" }

Stop-ExistingMonitoringUiProcesses

$arguments = @($uiScriptPath, "--settings", $SettingsPath, "--host", $BindHost, "--port", [string]$Port, "--app-mode", "monitoring")
if ($OpenBrowser) { $arguments += @("--open-browser", "--open-path", $OpenPath) }
& $pythonCommand @arguments

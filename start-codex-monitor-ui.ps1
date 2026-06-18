param(
    [string]$SettingsPath = (Join-Path $PSScriptRoot "codex-monitor.settings.json"),
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8765,
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"

function Stop-ExistingUiProcesses {
    $existing = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*codex_monitor_ui.py*"
    })

    foreach ($process in $existing) {
        try {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
        } catch {
        }
    }

    if (@($existing).Count -gt 0) {
        Start-Sleep -Milliseconds 500
    }
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

    $candidates = @(
        @{ Command = "python"; Arguments = @() },
        @{ Command = "py"; Arguments = @("-3") }
    )

    foreach ($candidate in $candidates) {
        try {
            $output = & $candidate.Command @($candidate.Arguments + @("-c", "import sys; print(sys.executable)")) 2>$null
            if ($LASTEXITCODE -eq 0) {
                $resolved = (@($output) | Select-Object -Last 1).Trim()
                if (-not [string]::IsNullOrWhiteSpace($resolved) -and (Test-Path -LiteralPath $resolved)) {
                    return $resolved
                }
            }
        } catch {
        }
    }

    throw "A usable Python runtime was not found. Update codex-monitor.settings.json or install Python."
}

$pythonCommand = Get-PythonCommand -ResolvedSettingsPath $SettingsPath
$uiScriptPath = Join-Path $PSScriptRoot "codex_monitor_ui.py"
if (-not (Test-Path -LiteralPath $uiScriptPath)) {
    throw "UI script not found: $uiScriptPath"
}

Stop-ExistingUiProcesses

$arguments = @(
    $uiScriptPath,
    "--settings", $SettingsPath,
    "--host", $BindHost,
    "--port", [string]$Port
)

if ($OpenBrowser) {
    $arguments += "--open-browser"
}

& $pythonCommand @arguments

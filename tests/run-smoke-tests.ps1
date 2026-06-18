param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"

function Assert-ParseFile {
    param([string]$Path)

    $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    Write-Host ("PARSE_OK {0}" -f $Path)
}

function Assert-PathExists {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Expected path not found: $Path"
    }
    Write-Host ("EXISTS {0}" -f $Path)
}

$scripts = @(
    "invoke-host-ioc.ps1",
    "invoke-host-tripwire.ps1",
    "monitor-threat-rss.ps1",
    "start-codex-alert-helper.ps1",
    "install-codex-monitor.ps1",
    "get-codex-monitor-status.ps1",
    "import-threat-feeds.ps1",
    "start-codex-monitor-ui.ps1"
) | ForEach-Object { Join-Path $Root $_ }

foreach ($script in $scripts) {
    Assert-ParseFile -Path $script
}

$fixture = Join-Path $Root "tests\fixtures\normalized-indicators.min.json"
Assert-PathExists -Path $fixture

& python -m py_compile (Join-Path $Root "ioc_store.py")
Write-Host "PY_COMPILE_OK ioc_store.py"
& python -m py_compile (Join-Path $Root "codex_monitor_ui.py")
Write-Host "PY_COMPILE_OK codex_monitor_ui.py"

& python -m unittest discover -s (Join-Path $Root "tests") -p "test_*.py" -v
if ($LASTEXITCODE -ne 0) {
    throw "Python unit tests failed."
}

Write-Host "SMOKE_TESTS_OK"

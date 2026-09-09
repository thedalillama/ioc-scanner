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

function Assert-InstallerManifestEntry {
    param(
        [string]$InstallerPath,
        [string]$Target
    )

    $escapedTarget = [regex]::Escape($Target)
    $pattern = 'Target\s*=\s*"{0}"' -f $escapedTarget
    if (-not (Select-String -LiteralPath $InstallerPath -Pattern $pattern -Quiet)) {
        throw "Installer runtime manifest is missing required target: $Target"
    }
    Write-Host ("INSTALLER_MANIFEST_OK {0}" -f $Target)
}

function Assert-TransferManifestEntry {
    param(
        [string]$TransferBuilderPath,
        [string]$Target
    )

    if (-not (Select-String -LiteralPath $TransferBuilderPath -SimpleMatch ("'{0}'" -f $Target) -Quiet)) {
        throw "Transfer-media manifest is missing required target: $Target"
    }
    Write-Host ("TRANSFER_MANIFEST_OK {0}" -f $Target)
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

$installerPath = Join-Path $Root "install-codex-monitor.ps1"
$requiredRuntimeTargets = @(
    "accept-posture-drift.ps1",
    "posture-drift-rules.ps1",
    "tripwire-posture-baseline.ps1",
    "protection-profiles.json",
    "profiles\persona-profiles.json",
    "profiles\system-profiles.json",
    "profiles\posture-drift-rules.json"
)
foreach ($target in $requiredRuntimeTargets) {
    Assert-InstallerManifestEntry -InstallerPath $installerPath -Target $target
}

$transferBuilderPath = Join-Path $Root "tests\build-transfer-iso.ps1"
Assert-TransferManifestEntry -TransferBuilderPath $transferBuilderPath -Target "tripwire-posture-baseline.ps1"
Assert-TransferManifestEntry -TransferBuilderPath $transferBuilderPath -Target "profiles"

$hiddenRunnerPath = Join-Path $Root "run-hidden.vbs"
if (-not (Select-String -LiteralPath $hiddenRunnerPath -Pattern 'command\s*=\s*Chr\(34\).*WScript\.Arguments\(0\).*Chr\(34\)' -Quiet)) {
    throw "Hidden task launcher must quote its command path."
}
Write-Host "HIDDEN_LAUNCHER_QUOTING_OK"

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

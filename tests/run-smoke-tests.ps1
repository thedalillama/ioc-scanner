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
$iocLauncherLines = @(Select-String -LiteralPath $installerPath -Pattern 'Write-LauncherScript\s+-Path\s+\$iocScanLauncher')
if ($iocLauncherLines.Count -ne 1) {
    throw "Installer must define exactly one IOC scheduled-task launcher."
}
if ($iocLauncherLines[0].Line -match '-IocPath|feed-indicators-latest\.json') {
    throw "Installer IOC scheduled-task launcher must use SQLite by default, not an implicit JSON indicator export."
}
Write-Host "INSTALLER_IOC_SQLITE_DEFAULT_OK"

$transferBuilderPath = Join-Path $Root "tests\build-transfer-iso.ps1"
Assert-TransferManifestEntry -TransferBuilderPath $transferBuilderPath -Target "tripwire-posture-baseline.ps1"
Assert-TransferManifestEntry -TransferBuilderPath $transferBuilderPath -Target "profiles"

$hiddenRunnerPath = Join-Path $Root "run-hidden.vbs"
if (-not (Select-String -LiteralPath $hiddenRunnerPath -Pattern 'command\s*=\s*"cmd\.exe /d /s /c ".*WScript\.Arguments\(0\)' -Quiet)) {
    throw "Hidden task launcher must run quoted batch launchers through cmd.exe."
}
Write-Host "HIDDEN_LAUNCHER_QUOTING_OK"

if (-not (Select-String -LiteralPath $installerPath -Pattern 'Grant-NotifierStateAccess' -Quiet)) {
    throw "Installer must grant the interactive notifier access only to SQLite state."
}
Write-Host "INSTALLER_NOTIFIER_SQLITE_ACL_OK"

$iocScriptPath = Join-Path $Root "invoke-host-ioc.ps1"
if (-not (Select-String -LiteralPath $iocScriptPath -Pattern 'Get-SqliteActiveIndicators' -Quiet)) {
    throw "IOC scanner must expose the SQLite active-indicator reader."
}
if (-not (Select-String -LiteralPath $iocScriptPath -Pattern '\$indicatorSource\s*=\s*"sqlite"' -Quiet)) {
    throw "IOC scanner must default to SQLite indicators."
}
if (Select-String -LiteralPath $iocScriptPath -Pattern 'Get-DefaultIocPath|IndicatorExportPath|feed-indicators-latest\.json' -Quiet) {
    throw "IOC scanner must not retain an implicit JSON indicator-export fallback."
}
if (-not (Select-String -LiteralPath $iocScriptPath -Pattern 'function Save-IocReportToSqlite|persist-collector-report' -Quiet)) {
    throw "IOC scanner must persist its report through the Phase 2 collector-report contract."
}
$tripwireScriptPath = Join-Path $Root "invoke-host-tripwire.ps1"
if (-not (Select-String -LiteralPath $tripwireScriptPath -Pattern 'function Save-TripwireReportToSqlite|persist-collector-report' -Quiet)) {
    throw "Tripwire must preserve its report and findings through the Phase 2 collector-report contract."
}
$missingDbPath = Join-Path $Root "tmp\smoke-missing-sqlite\ioc-store.db"
if (Test-Path -LiteralPath $missingDbPath) {
    throw "The isolated missing-SQLite smoke path already exists: $missingDbPath"
}
$previousStateDbPath = $env:CODEX_MONITOR_STATEDBPATH
$previousErrorActionPreference = $ErrorActionPreference
$iocReportCountBefore = @(Get-ChildItem -LiteralPath $Root -Filter "HOST_IOC_IOC_*.json").Count
try {
    $env:CODEX_MONITOR_STATEDBPATH = $missingDbPath
    $ErrorActionPreference = "Continue"
    $missingDbOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $iocScriptPath -Mode IOC 2>&1
    if ($LASTEXITCODE -ne 1) {
        throw "IOC scanner must return exit code 1 when its SQLite store is unavailable."
    }
    if ((@($missingDbOutput) -join [Environment]::NewLine) -notmatch "SQLite returned no active-indicator payload") {
        throw "IOC scanner must emit a clear unavailable-SQLite error."
    }
    $iocReportCountAfter = @(Get-ChildItem -LiteralPath $Root -Filter "HOST_IOC_IOC_*.json").Count
    if ($iocReportCountAfter -ne $iocReportCountBefore) {
        throw "IOC scanner must not write a report when its SQLite store is unavailable."
    }
} finally {
    $ErrorActionPreference = $previousErrorActionPreference
    if ([string]::IsNullOrWhiteSpace($previousStateDbPath)) {
        Remove-Item Env:CODEX_MONITOR_STATEDBPATH -ErrorAction SilentlyContinue
    } else {
        $env:CODEX_MONITOR_STATEDBPATH = $previousStateDbPath
    }
}
Write-Host "IOC_SQLITE_INDICATOR_READER_OK"

$fixture = Join-Path $Root "tests\fixtures\normalized-indicators.min.json"
Assert-PathExists -Path $fixture

$pythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($null -eq $pythonCommand) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
}
if ($null -eq $pythonCommand) {
    throw "A Python runtime is required for smoke tests. Install python.exe or the Windows py launcher."
}
$pythonExecutable = $pythonCommand.Source

& $pythonExecutable -m py_compile (Join-Path $Root "ioc_store.py")
if ($LASTEXITCODE -ne 0) {
    throw "Python compilation failed for ioc_store.py."
}
Write-Host "PY_COMPILE_OK ioc_store.py"
& $pythonExecutable -m py_compile (Join-Path $Root "codex_monitor_ui.py")
if ($LASTEXITCODE -ne 0) {
    throw "Python compilation failed for codex_monitor_ui.py."
}
Write-Host "PY_COMPILE_OK codex_monitor_ui.py"

& $pythonExecutable -m unittest discover -s (Join-Path $Root "tests") -p "test_*.py" -v
if ($LASTEXITCODE -ne 0) {
    throw "Python unit tests failed."
}

Write-Host "SMOKE_TESTS_OK"

param(
    [string]$SettingsPath = (Join-Path $PSScriptRoot "codex-monitor.settings.json"),
    [string]$StateDbPath = "",
    [switch]$AsJson
)

$ErrorActionPreference = "Stop"

function Get-Settings {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) {
        try {
            return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
        } catch {
        }
    }

    return [PSCustomObject]@{}
}

function Resolve-ValueOrDefault {
    param(
        [string]$ConfiguredValue,
        [string]$DefaultValue
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredValue)) {
        return $ConfiguredValue
    }

    return $DefaultValue
}

function Get-PythonCommand {
    $settings = Get-Settings -Path $SettingsPath
    if (-not [string]::IsNullOrWhiteSpace([string]$settings.PythonCommand) -and (Test-Path -LiteralPath ([string]$settings.PythonCommand))) {
        return [string]$settings.PythonCommand
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

function Get-StateStoreScriptPath {
    $path = Join-Path $PSScriptRoot "ioc_store.py"
    if (-not (Test-Path -LiteralPath $path)) {
        throw "SQLite state helper not found: $path"
    }
    return $path
}

function Invoke-StateStore {
    param(
        [string]$DbPath,
        [string[]]$Arguments
    )

    $scriptPath = Get-StateStoreScriptPath
    $pythonCommand = Get-PythonCommand
    $output = & $pythonCommand $scriptPath --db $DbPath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("State store command failed: {0} {1} --db {2} {3}`n{4}" -f $pythonCommand, $scriptPath, $DbPath, ($Arguments -join ' '), (@($output) -join [Environment]::NewLine))
    }
    return (@($output) -join [Environment]::NewLine)
}

function Get-ResolvedStateDbPath {
    param(
        [string]$ConfiguredStateDbPath,
        $Settings
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredStateDbPath)) {
        return $ConfiguredStateDbPath
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Settings.StateDbPath)) {
        return [string]$Settings.StateDbPath
    }

    return (Join-Path $PSScriptRoot "state\ioc-store.db")
}

function Get-SqliteState {
    param(
        [string]$DbPath,
        [string]$Namespace,
        [string]$Key
    )

    if (-not (Test-Path -LiteralPath $DbPath)) {
        return $null
    }

    try {
        $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("state-get", "--namespace", $Namespace, "--key", $Key)
        $payload = $raw | ConvertFrom-Json
        if ($payload.found) {
            return $payload.value
        }
    } catch {
    }

    return $null
}

function Get-SqliteStateMeta {
    param(
        [string]$DbPath,
        [string]$Namespace,
        [string]$Key
    )

    if (-not (Test-Path -LiteralPath $DbPath)) {
        return $null
    }

    try {
        $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("state-meta", "--namespace", $Namespace, "--key", $Key)
        $payload = $raw | ConvertFrom-Json
        if ($payload.found) {
            return $payload
        }
    } catch {
    }

    return $null
}

function Get-ScheduledTaskStatus {
    param([string]$TaskName)

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        return [PSCustomObject]@{
            Name = $TaskName
            Installed = $false
            Enabled = $false
            State = "Missing"
            LastRunTime = $null
            NextRunTime = $null
            LastTaskResult = $null
        }
    }

    $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    return [PSCustomObject]@{
        Name = $TaskName
        Installed = $true
        Enabled = [bool]$task.Settings.Enabled
        State = [string]$task.State
        LastRunTime = if ($info) { [string]$info.LastRunTime } else { $null }
        NextRunTime = if ($info) { [string]$info.NextRunTime } else { $null }
        LastTaskResult = if ($info) { [long]$info.LastTaskResult } else { $null }
    }
}

function Get-LatestFileMetadata {
    param([string]$Pattern)

    $items = @(Get-ChildItem -Path $PSScriptRoot -Filter $Pattern -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if (@($items).Count -eq 0) {
        return $null
    }

    $item = $items[0]
    return [PSCustomObject]@{
        Path = $item.FullName
        LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString("o")
    }
}

function Add-HealthFinding {
    param(
        [System.Collections.ArrayList]$List,
        [string]$Severity,
        [string]$Message
    )

    [void]$List.Add([PSCustomObject]@{
        Severity = $Severity
        Message = $Message
    })
}

function Test-StaleHours {
    param(
        [string]$Timestamp,
        [double]$ThresholdHours
    )

    if ([string]::IsNullOrWhiteSpace($Timestamp)) {
        return $true
    }

    try {
        $age = (New-TimeSpan -Start ([datetimeoffset]::Parse($Timestamp)).UtcDateTime -End (Get-Date).ToUniversalTime()).TotalHours
        return ($age -gt $ThresholdHours)
    } catch {
        return $true
    }
}

$settings = Get-Settings -Path $SettingsPath
$resolvedStateDbPath = Get-ResolvedStateDbPath -ConfiguredStateDbPath $StateDbPath -Settings $settings
$dataRoot = Resolve-ValueOrDefault -ConfiguredValue ([string]$settings.DataRoot) -DefaultValue $PSScriptRoot
$alertInboxPath = Resolve-ValueOrDefault -ConfiguredValue ([string]$settings.AlertInboxPath) -DefaultValue (Join-Path $PSScriptRoot "alerts\pending")
$alertArchivePath = Resolve-ValueOrDefault -ConfiguredValue ([string]$settings.AlertArchivePath) -DefaultValue (Join-Path $PSScriptRoot "alerts\archive")
$indicatorExportPath = Resolve-ValueOrDefault -ConfiguredValue ([string]$settings.IndicatorExportPath) -DefaultValue (Join-Path $PSScriptRoot "indicators\feed-indicators-latest.json")

$taskNames = @(
    "Codex Threat Feed Import",
    "Codex IOC Daily Scan",
    "Codex Host Tripwire",
    "Codex Threat RSS Monitor",
    "Codex Alert Notifier"
)
$tasks = @($taskNames | ForEach-Object { Get-ScheduledTaskStatus -TaskName $_ })

$rssState = Get-SqliteState -DbPath $resolvedStateDbPath -Namespace "threat_rss" -Key "feed_state"
$tripwireBaselineMeta = Get-SqliteStateMeta -DbPath $resolvedStateDbPath -Namespace "host_tripwire" -Key "baseline"
$alertHelperState = Get-SqliteState -DbPath $resolvedStateDbPath -Namespace "alert_helper" -Key "seen_alerts"

$pendingAlertCount = if (Test-Path -LiteralPath $alertInboxPath) { @(Get-ChildItem -LiteralPath $alertInboxPath -Filter "ALERT_*.json" -File -ErrorAction SilentlyContinue).Count } else { 0 }
$archivedAlertCount = if (Test-Path -LiteralPath $alertArchivePath) { @(Get-ChildItem -LiteralPath $alertArchivePath -Filter "ALERT_*.json" -File -ErrorAction SilentlyContinue).Count } else { 0 }

$healthFindings = [System.Collections.ArrayList]::new()

if (-not (Test-Path -LiteralPath $resolvedStateDbPath)) {
    Add-HealthFinding -List $healthFindings -Severity "High" -Message "SQLite state database is missing."
}

if (-not (Test-Path -LiteralPath $indicatorExportPath)) {
    Add-HealthFinding -List $healthFindings -Severity "High" -Message "Normalized indicator export is missing."
}

foreach ($task in @($tasks)) {
    if (-not $task.Installed) {
        Add-HealthFinding -List $healthFindings -Severity "Medium" -Message ("Scheduled task missing: {0}" -f $task.Name)
        continue
    }

    if (-not $task.Enabled) {
        Add-HealthFinding -List $healthFindings -Severity "Medium" -Message ("Scheduled task disabled: {0}" -f $task.Name)
    }
}

if ($null -eq $tripwireBaselineMeta) {
    Add-HealthFinding -List $healthFindings -Severity "High" -Message "Tripwire baseline is missing from SQLite."
}

if ($null -eq $rssState) {
    Add-HealthFinding -List $healthFindings -Severity "Medium" -Message "Threat RSS state is missing from SQLite."
} elseif (Test-StaleHours -Timestamp ([string]$rssState.LastRunUtc) -ThresholdHours 26) {
    Add-HealthFinding -List $healthFindings -Severity "Medium" -Message "Threat RSS polling state is stale."
}

if (Test-Path -LiteralPath $indicatorExportPath) {
    $indicatorAgeTimestamp = (Get-Item -LiteralPath $indicatorExportPath).LastWriteTimeUtc.ToString("o")
    if (Test-StaleHours -Timestamp $indicatorAgeTimestamp -ThresholdHours 48) {
        Add-HealthFinding -List $healthFindings -Severity "Medium" -Message "Normalized indicator export is older than 48 hours."
    }
}

if ($pendingAlertCount -gt 0) {
    Add-HealthFinding -List $healthFindings -Severity "Medium" -Message ("There are {0} pending alert(s) awaiting popup handling." -f $pendingAlertCount)
}

$overallStatus = "Healthy"
if (@($healthFindings | Where-Object { $_.Severity -eq "High" }).Count -gt 0) {
    $overallStatus = "High"
} elseif (@($healthFindings | Where-Object { $_.Severity -eq "Medium" }).Count -gt 0) {
    $overallStatus = "Warning"
}

$status = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        CollectionTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
        OverallStatus = $overallStatus
    }
    Paths = [PSCustomObject]@{
        SettingsPath = $SettingsPath
        DataRoot = $dataRoot
        StateDbPath = $resolvedStateDbPath
        IndicatorExportPath = $indicatorExportPath
        AlertInboxPath = $alertInboxPath
        AlertArchivePath = $alertArchivePath
    }
    ScheduledTasks = @($tasks)
    State = [PSCustomObject]@{
        TripwireBaselineCollectionTimeUtc = if ($tripwireBaselineMeta -and $tripwireBaselineMeta.metadata) { [string]$tripwireBaselineMeta.metadata.CollectionTimeUtc } else { $null }
        ThreatRssLastRunUtc = if ($rssState) { [string]$rssState.LastRunUtc } else { $null }
        SeenAlertCount = if ($alertHelperState) { @($alertHelperState.SeenAlerts).Count } else { 0 }
        PendingAlertCount = $pendingAlertCount
        ArchivedAlertCount = $archivedAlertCount
    }
    LatestArtifacts = [PSCustomObject]@{
        LatestIocReport = Get-LatestFileMetadata -Pattern "HOST_IOC_*.json"
        LatestTripwireReport = Get-LatestFileMetadata -Pattern "HOST_TRIPWIRE_*.json"
        LatestThreatRssReport = Get-LatestFileMetadata -Pattern "THREAT_RSS_*.json"
    }
    HealthFindings = @($healthFindings)
}

if ($AsJson) {
    $status | ConvertTo-Json -Depth 8
    exit 0
}

Write-Host ("Overall status: {0}" -f $status.Metadata.OverallStatus)
Write-Host ("Tripwire baseline: {0}" -f $(if ($status.State.TripwireBaselineCollectionTimeUtc) { $status.State.TripwireBaselineCollectionTimeUtc } else { "missing" }))
Write-Host ("Threat RSS last run: {0}" -f $(if ($status.State.ThreatRssLastRunUtc) { $status.State.ThreatRssLastRunUtc } else { "missing" }))
Write-Host ("Indicator export: {0}" -f $(if (Test-Path -LiteralPath $indicatorExportPath) { $indicatorExportPath } else { "missing" }))
Write-Host ("Pending alerts: {0}" -f $status.State.PendingAlertCount)
Write-Host ("Seen alerts: {0}" -f $status.State.SeenAlertCount)
Write-Host ""
Write-Host "Scheduled tasks:"
foreach ($task in @($status.ScheduledTasks)) {
    Write-Host ("- {0}: Installed={1}; Enabled={2}; State={3}; LastResult={4}" -f $task.Name, $task.Installed, $task.Enabled, $task.State, $task.LastTaskResult)
}

Write-Host ""
if (@($status.HealthFindings).Count -eq 0) {
    Write-Host "Health findings: none"
} else {
    Write-Host "Health findings:"
    foreach ($finding in @($status.HealthFindings)) {
        Write-Host ("- [{0}] {1}" -f $finding.Severity, $finding.Message)
    }
}

# CODEX_MONITOR_SELF_EVENT
param(
    [ValidateSet("Baseline", "Deep", "IOC")]
    [string]$Mode = "Baseline",

    [string]$IocPath,
    [switch]$Export
)

$ErrorActionPreference = "SilentlyContinue"

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$computerName = $env:COMPUTERNAME
$collectionTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
$outBase = Join-Path $PSScriptRoot ("HOST_IOC_{0}_{1}" -f $Mode.ToUpperInvariant(), $timestamp)
$jsonFile = "$outBase.json"
$mdFile = "$outBase.md"
$MonitorSelfEventMarker = "CODEX_MONITOR_SELF_EVENT"

function Write-JsonFile {
    param(
        [string]$Path,
        $Object,
        [int]$Depth = 12
    )

    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    try {
        $json = ConvertTo-Json -InputObject $Object -Depth $Depth
        if ([string]::IsNullOrWhiteSpace($json)) {
            throw "ConvertTo-Json returned empty output."
        }
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
    } finally {
        $ErrorActionPreference = $previousPreference
    }
}

function Write-MdLine {
    param([string]$Text = "")
    Add-Content -LiteralPath $mdFile -Value $Text
}

function Write-MdSection {
    param([string]$Title)
    Write-MdLine ""
    Write-MdLine "## $Title"
    Write-MdLine ""
}

function Write-MdBlock {
    param(
        [string]$Title,
        $Object
    )

    Write-MdLine "### $Title"
    Write-MdLine ""

    if ($null -eq $Object) {
        Write-MdLine "_No data returned._"
        Write-MdLine ""
        return
    }

    $text = $Object | Out-String -Width 220
    Write-MdLine '```text'
    foreach ($line in $text.TrimEnd("`r", "`n").Split([Environment]::NewLine)) {
        Write-MdLine $line
    }
    Write-MdLine '```'
    Write-MdLine ""
}

function Get-SettingsPath {
    return (Join-Path $PSScriptRoot "codex-monitor.settings.json")
}

function Resolve-SettingsPathValue {
    param(
        [string]$Value,
        [string]$SettingsPath = (Get-SettingsPath)
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }

    if ([System.IO.Path]::IsPathRooted($Value)) {
        return $Value
    }

    $settingsDirectory = Split-Path -Path $SettingsPath -Parent
    if ([string]::IsNullOrWhiteSpace($settingsDirectory)) {
        $settingsDirectory = $PSScriptRoot
    }

    return [System.IO.Path]::GetFullPath((Join-Path $settingsDirectory $Value))
}

function Get-Settings {
    $settingsPath = Get-SettingsPath
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            return (Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json)
        } catch {
        }
    }
    return [PSCustomObject]@{}
}

function Get-ResolvedStateDbPath {
    if (-not [string]::IsNullOrWhiteSpace($env:CODEX_MONITOR_STATEDBPATH)) {
        return $env:CODEX_MONITOR_STATEDBPATH
    }

    $settings = Get-Settings
    if (-not [string]::IsNullOrWhiteSpace([string]$settings.StateDbPath)) {
        return (Resolve-SettingsPathValue -Value ([string]$settings.StateDbPath))
    }
    return (Join-Path $PSScriptRoot "state\ioc-store.db")
}

function Get-StateDbContext {
    $settings = Get-Settings
    $defaultPath = if (-not [string]::IsNullOrWhiteSpace([string]$settings.StateDbPath)) {
        Resolve-SettingsPathValue -Value ([string]$settings.StateDbPath)
    } else {
        Join-Path $PSScriptRoot "state\ioc-store.db"
    }

    $resolvedPath = Get-ResolvedStateDbPath
    $overrideDetected = $false
    $overrideReason = ""

    if (-not [string]::IsNullOrWhiteSpace($env:CODEX_MONITOR_STATEDBPATH)) {
        $overrideDetected = $true
        $overrideReason = "Environment override"
    } elseif ([string]$resolvedPath -ne [string]$defaultPath) {
        $overrideDetected = $true
        $overrideReason = "Non-default configured path"
    }

    [PSCustomObject]@{
        ResolvedPath = [string]$resolvedPath
        DefaultPath = [string]$defaultPath
        IsDefault = (-not $overrideDetected)
        OverrideDetected = $overrideDetected
        OverrideReason = $overrideReason
        DatabaseLabel = if ($overrideDetected) { "non-default/test database" } else { "default database" }
    }
}

function Get-PythonCommand {
    $settings = Get-Settings
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

    if ([string]::IsNullOrWhiteSpace($DbPath) -or -not (Test-Path -LiteralPath $DbPath)) {
        return $null
    }

    $scriptPath = Get-StateStoreScriptPath
    $pythonCommand = Get-PythonCommand
    $output = & $pythonCommand $scriptPath --db $DbPath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("State store command failed: {0} {1} --db {2} {3}`n{4}" -f $pythonCommand, $scriptPath, $DbPath, ($Arguments -join ' '), (@($output) -join [Environment]::NewLine))
    }
    return (@($output) -join [Environment]::NewLine)
}

function Get-BaselineHashJoinResults {
    param([string]$DbPath)

    try {
        $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("baseline-hash-match")
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $null
        }
        return ($raw | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Get-BaselineHashStatus {
    param([string]$DbPath)

    try {
        $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("baseline-hash-status")
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $null
        }
        return ($raw | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Save-IocCoverageState {
    param(
        [string]$DbPath,
        $Coverage
    )

    if ([string]::IsNullOrWhiteSpace($DbPath)) {
        return
    }

    $tempPath = [System.IO.Path]::GetTempFileName()
    try {
        $json = ConvertTo-Json -InputObject $Coverage -Depth 8
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)
        [void](Invoke-StateStore -DbPath $DbPath -Arguments @("state-put", "--namespace", "ioc_scan", "--key", "latest_hash_coverage", "--input", $tempPath))
    } catch {
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            [System.IO.File]::Delete($tempPath)
        }
    }
}

function Save-IocReportToSqlite {
    param(
        [string]$DbPath,
        [string]$ReportId,
        $Data,
        [string]$JsonPath,
        [string]$MarkdownPath
    )

    if ([string]::IsNullOrWhiteSpace($DbPath) -or [string]::IsNullOrWhiteSpace($ReportId) -or $null -eq $Data) {
        throw "IOC report persistence requires a SQLite path, report ID, and report data."
    }

    $findings = @()
    $highestSeverity = "informational"
    $severityRank = @{ informational = 0; low = 1; medium = 2; high = 3; critical = 4 }
    $highestRank = 0
    $index = 0
    foreach ($finding in @($Data.Findings)) {
        $severity = ([string]$finding.severity).ToLowerInvariant()
        if (-not $severityRank.ContainsKey($severity)) { $severity = "informational" }
        if ($severityRank[$severity] -gt $highestRank) {
            $highestSeverity = $severity
            $highestRank = $severityRank[$severity]
        }
        $findings += [PSCustomObject]@{
            finding_id = [string]$finding.finding_id
            finding_sequence = $index
            category = [string]$finding.indicator_type
            severity = $severity
            classification = [string]$finding.match_method
            title = ("{0} match: {1}" -f [string]$finding.indicator_type, [string]$finding.indicator_value)
            summary = [string]$finding.interpretation
            evidence = [PSCustomObject]@{
                matched_field = [string]$finding.matched_field
                matched_value = [string]$finding.matched_value
                evidence = [string]$finding.evidence
                scope_note = [string]$finding.scope_note
                snapshot_id = [string]$finding.snapshot_id
                matched_observation = $finding.matched_observation
                references = @($finding.references)
            }
            csf_mapping = "DE.CM"
            guardrail_state = ""
            response_state = "open"
        }
        $index++
    }

    $collectionTimeUtc = [string]$Data.Metadata.CollectionTimeUtc
    $collectorRunId = "{0}-collector" -f $ReportId
    $envelope = [PSCustomObject]@{
        collector_run = [PSCustomObject]@{
            collector_run_id = $collectorRunId
            collector_name = "ioc"
            collector_version = "invoke-host-ioc.ps1"
            started_at = $collectionTimeUtc
            completed_at = $collectionTimeUtc
            outcome = "success"
            summary = [PSCustomObject]@{
                IndicatorCount = [int]$Data.IndicatorCount
                MatchCount = [int]$Data.MatchCount
                IndicatorSource = [string]$Data.Metadata.IndicatorSource
            }
        }
        report = [PSCustomObject]@{
            report_id = $ReportId
            collector_run_id = $collectorRunId
            report_type = "ioc"
            collection_time_utc = $collectionTimeUtc
            overall_status = if ([int]$Data.MatchCount -gt 0) { "attention" } else { "clear" }
            severity = $highestSeverity
            summary = [PSCustomObject]@{
                MatchCount = [int]$Data.MatchCount
                IndicatorCount = [int]$Data.IndicatorCount
                MatchInterpretation = [string]$Data.MatchInterpretation
                HashCoverage = $Data.HashCoverage
            }
            export_json_path = $JsonPath
            export_markdown_path = $MarkdownPath
        }
        findings = @($findings)
    }

    $tempPath = [System.IO.Path]::GetTempFileName()
    try {
        $json = ConvertTo-Json -InputObject $envelope -Depth 12
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)
        $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("persist-collector-report", "--input", $tempPath)
        if ([string]::IsNullOrWhiteSpace($raw)) {
            throw "SQLite returned no IOC report persistence payload: $DbPath"
        }
        return ($raw | ConvertFrom-Json -ErrorAction Stop)
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            [System.IO.File]::Delete($tempPath)
        }
    }
}

function Save-EvidenceSnapshotToSqlite {
    param(
        [string]$DbPath,
        $Dataset,
        [string]$SnapshotId,
        [string]$SnapshotType,
        [string]$SourceJsonPath,
        [string]$SourceMarkdownPath,
        [string]$TrustLabel = "unknown"
    )

    if ([string]::IsNullOrWhiteSpace($DbPath) -or -not $Dataset -or [string]::IsNullOrWhiteSpace($SnapshotId)) {
        return $null
    }

    $tempPath = [System.IO.Path]::GetTempFileName()
    try {
        $json = ConvertTo-Json -InputObject $Dataset -Depth 12
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)
        $raw = Invoke-StateStore -DbPath $DbPath -Arguments @(
            "import-evidence-snapshot",
            "--input", $tempPath,
            "--snapshot-id", $SnapshotId,
            "--snapshot-type", $SnapshotType,
            "--source-json-path", $SourceJsonPath,
            "--source-markdown-path", $SourceMarkdownPath,
            "--collector-version", "invoke-host-ioc.ps1",
            "--trust-label", $TrustLabel
        )
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $null
        }
        return ($raw | ConvertFrom-Json)
    } catch {
        return $null
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            [System.IO.File]::Delete($tempPath)
        }
    }
}

function Get-SnapshotEvidenceMatches {
    param(
        [string]$DbPath,
        [string]$SnapshotId
    )

    if ([string]::IsNullOrWhiteSpace($SnapshotId)) {
        return $null
    }

    try {
        $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("evidence-snapshot-match", "--snapshot-id", $SnapshotId)
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $null
        }
        return ($raw | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Get-IocMatchInterpretation {
    param(
        [int]$MatchCount,
        [bool]$AllTestMatches = $false
    )

    if ($AllTestMatches -and $MatchCount -gt 0) {
        return "Controlled local test IOC matches were found in indexed local evidence snapshots and/or the latest indexed baseline hash inventory. These findings are labeled LOCAL_TEST_DO_NOT_ALERT and should be treated as verification results, not real malware detections."
    }

    if ($MatchCount -gt 0) {
        return "IOC matches were found in indexed local evidence snapshots and/or the latest indexed baseline hash inventory. Review the findings to determine whether the evidence is current-scan activity, baseline/reference evidence, or historical evidence."
    }

    return "No match was found in indexed local evidence snapshots or the latest indexed baseline hash inventory for the loaded indicators."
}

function Test-ExactTaskIndicatorMatch {
    param(
        [string]$Indicator,
        [string]$TaskRecordName
    )

    if ([string]::IsNullOrWhiteSpace($Indicator) -or [string]::IsNullOrWhiteSpace($TaskRecordName)) {
        return $false
    }

    $normalizedIndicator = $Indicator.Trim()
    $normalizedTaskName = $TaskRecordName.Trim()

    if ($normalizedTaskName -ieq $normalizedIndicator) {
        return $true
    }

    $taskLeafName = Split-Path -Path $normalizedTaskName -Leaf
    return ($taskLeafName -ieq $normalizedIndicator)
}

function New-NormalizedRecord {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Value = "",
        [string]$Path,
        [string]$Hash,
        [string]$HashAlgorithm,
        [string]$Timestamp,
        [string]$Owner,
        $ProcessId,
        $ParentProcessId,
        [string]$CommandLine,
        [string]$RegistryPath,
        $EventIDs = @(),
        $Source = @(),
        [string]$Severity = "Info",
        [string]$Notes = ""
    )

    [PSCustomObject]@{
        ComputerName      = $computerName
        CollectionTimeUtc = $collectionTimeUtc
        Category          = $Category
        Name              = $Name
        Value             = $Value
        Path              = $Path
        Hash              = $Hash
        HashAlgorithm     = $HashAlgorithm
        Timestamp         = $Timestamp
        Owner             = $Owner
        PID               = $ProcessId
        ParentPID         = $ParentProcessId
        CommandLine       = $CommandLine
        RegistryPath      = $RegistryPath
        EventIDs          = @($EventIDs)
        Source            = @($Source)
        Severity          = $Severity
        Notes             = $Notes
    }
}

function Get-SafeFileHash {
    param(
        [string]$Path,
        [ValidateSet("SHA256","SHA1","MD5")]
        [string]$Algorithm = "SHA256"
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm).Hash
    } catch {
        return $null
    }
}

function Get-ProcessMap {
    $userMap = @{}
    Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object {
        $userMap[$_.Id] = $_.UserName
    }

    Get-CimInstance Win32_Process | ForEach-Object {
        [PSCustomObject]@{
            Name            = $_.Name
            ExecutablePath  = $_.ExecutablePath
            CreationDate    = [string]$_.CreationDate
            ProcessId       = $_.ProcessId
            ParentProcessId = $_.ParentProcessId
            CommandLine     = $_.CommandLine
            Owner           = $userMap[$_.ProcessId]
        }
    }
}

function Get-ServiceMap {
    Get-CimInstance Win32_Service | ForEach-Object {
        [PSCustomObject]@{
            Name         = $_.Name
            DisplayName  = $_.DisplayName
            State        = $_.State
            StartMode    = $_.StartMode
            StartName    = $_.StartName
            ProcessId    = $_.ProcessId
            PathName     = $_.PathName
            RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)"
        }
    }
}

function Get-TaskMap {
    Get-ScheduledTask | ForEach-Object {
        $task = $_
        $info = $task | Get-ScheduledTaskInfo
        [PSCustomObject]@{
            TaskPath       = $task.TaskPath
            TaskName       = $task.TaskName
            Author         = $task.Author
            State          = $task.State
            LastRunTime    = [string]$info.LastRunTime
            NextRunTime    = [string]$info.NextRunTime
            LastTaskResult = $info.LastTaskResult
            Actions        = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join "; "
        }
    }
}

function Get-DriverMap {
    Get-CimInstance Win32_SystemDriver | Select-Object Name, DisplayName, State, StartMode, PathName, ServiceType, ExitCode
}

function Get-ConnectionMap {
    Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Protocol      = "TCP"
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
            OwningProcess = $_.OwningProcess
        }
    }
}

function Get-DnsCacheMap {
    Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Entry = $_.Entry
            Name  = $_.Name
            Type  = [string]$_.Type
            Data  = [string]$_.Data
            TimeToLive = [string]$_.TimeToLive
        }
    }
}

function Get-RunKeyEntries {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    [PSCustomObject]@{
                        RegistryPath = $path
                        Name         = $prop.Name
                        CommandLine  = [string]$prop.Value
                    }
                }
            }
        }
    }
}

function Get-RecentFiles {
    param(
        [datetime]$Start,
        [int]$Depth = 2,
        [int]$MaxFiles = 100
    )

    $paths = @(
        $env:TEMP,
        $env:ProgramData,
        (Join-Path $env:USERPROFILE "Downloads"),
        $env:LOCALAPPDATA
    ) | Where-Object { $_ -and (Test-Path $_) }

    $results = foreach ($path in $paths) {
        Get-ChildItem -Path $path -Recurse -Depth $Depth -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -ge $Start.ToUniversalTime() } |
            Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc
    }

    $results | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First $MaxFiles
}

function Get-FileHashes {
    param(
        $Files,
        [int]$MaxFiles = 25,
        [int64]$MaxSizeBytes = 10485760
    )

    $Files |
        Where-Object { $_.Length -le $MaxSizeBytes } |
        Select-Object -First $MaxFiles |
        ForEach-Object {
            $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256
            [PSCustomObject]@{
                FullName         = $_.FullName
                LastWriteTimeUtc = [string]$_.LastWriteTimeUtc
                SHA256           = $hash.Hash
            }
        }
}

function Get-PrefetchFiles {
    param([datetime]$Start)
    $path = "C:\Windows\Prefetch"
    if (Test-Path $path) {
        Get-ChildItem $path -Filter *.pf -Force |
            Where-Object { $_.LastWriteTimeUtc -ge $Start.ToUniversalTime() } |
            Select-Object Name, FullName, CreationTimeUtc, LastWriteTimeUtc, Length
    }
}

function Get-RecentLinks {
    param([datetime]$Start)
    $path = Join-Path $env:APPDATA "Microsoft\Windows\Recent"
    if (Test-Path $path) {
        Get-ChildItem $path -Filter *.lnk -Force |
            Where-Object { $_.LastWriteTimeUtc -ge $Start.ToUniversalTime() } |
            Select-Object FullName, CreationTimeUtc, LastWriteTimeUtc, Length
    }
}

function Get-Certificates {
    foreach ($store in @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")) {
        if (Test-Path $store) {
            Get-ChildItem $store | Select-Object @{Name="StorePath";Expression={$store}}, Subject, Thumbprint, NotBefore, NotAfter, FriendlyName
        }
    }
}

function Test-IsMonitorOwnedPowerShellEvent {
    param($Event)

    if ($null -eq $Event -or [string]::IsNullOrWhiteSpace([string]$Event.Message)) {
        return $false
    }

    return ([string]$Event.Message).IndexOf($MonitorSelfEventMarker, [System.StringComparison]::Ordinal) -ge 0
}

function Get-MonitorRelevantPowerShellEvents {
    param(
        [datetime]$Start,
        [int]$EventId
    )

    # Retrieve beyond the retained limit before filtering so monitor activity cannot
    # crowd external PowerShell telemetry out of the evidence snapshot.
    $candidateEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; StartTime = $Start; Id = $EventId } -MaxEvents 200 |
        Select-Object TimeCreated, Id, ProviderName, Message)
    $excludedEvents = @($candidateEvents | Where-Object { Test-IsMonitorOwnedPowerShellEvent -Event $_ })

    [PSCustomObject]@{
        Events = @($candidateEvents |
            Where-Object { -not (Test-IsMonitorOwnedPowerShellEvent -Event $_) } |
            Select-Object -First 40)
        ExcludedCount = @($excludedEvents).Count
    }
}

function Get-KeyEvents {
    param([datetime]$Start)

    $powerShell4103 = Get-MonitorRelevantPowerShellEvents -Start $Start -EventId 4103
    $powerShell4104 = Get-MonitorRelevantPowerShellEvents -Start $Start -EventId 4104

    [PSCustomObject]@{
        PowerShell4103 = @($powerShell4103.Events)
        PowerShell4104 = @($powerShell4104.Events)
        SelfGeneratedPowerShellEventCount = [int]$powerShell4103.ExcludedCount + [int]$powerShell4104.ExcludedCount
        Security4688 = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $Start; Id = 4688 } -MaxEvents 40 |
            Select-Object TimeCreated, Id, Message
        Security4698 = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $Start; Id = 4698 } -MaxEvents 20 |
            Select-Object TimeCreated, Id, Message
        System7045 = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $Start; Id = 7045 } -MaxEvents 20 |
            Select-Object TimeCreated, Id, ProviderName, Message
    }
}

function New-NormalizedIndicator {
    param(
        [string]$IndicatorId,
        [string]$Type,
        [string]$Value,
        [string]$Source = "internal",
        [int]$Confidence = 50,
        [string]$Severity = "medium",
        [string]$FirstSeen = "",
        [string]$LastSeen = "",
        [string]$ValidFrom = "",
        [string]$ValidUntil = "",
        [string]$Tlp = "clear",
        [string]$MalwareFamily = "",
        [string]$Campaign = "",
        [string]$ThreatActor = "",
        [string]$AttackTechnique = "",
        [string]$ReferenceUrl = "",
        $RawSourceRecord = $null
    )

    [PSCustomObject]@{
        indicator_id      = $IndicatorId
        type              = $Type
        value             = $Value
        source            = $Source
        confidence        = $Confidence
        severity          = $Severity
        first_seen        = $FirstSeen
        last_seen         = $LastSeen
        valid_from        = $ValidFrom
        valid_until       = $ValidUntil
        tlp               = $Tlp
        malware_family    = $MalwareFamily
        campaign          = $Campaign
        threat_actor      = $ThreatActor
        attack_technique  = $AttackTechnique
        reference_url     = $ReferenceUrl
        raw_source_record = $RawSourceRecord
    }
}

function Convert-StixBundleToIndicators {
    param($Bundle)

    $indicators = @()
    foreach ($object in @($Bundle.objects)) {
        if ([string]$object.type -ne "indicator") {
            continue
        }

        $pattern = [string]$object.pattern
        $type = $null
        $value = $null

        if ($pattern -match "file:hashes\.'SHA-256'\s*=\s*'([^']+)'") {
            $type = "sha256"; $value = $matches[1]
        } elseif ($pattern -match "domain-name:value\s*=\s*'([^']+)'") {
            $type = "domain"; $value = $matches[1]
        } elseif ($pattern -match "ipv4-addr:value\s*=\s*'([^']+)'") {
            $type = "ipv4"; $value = $matches[1]
        } elseif ($pattern -match "url:value\s*=\s*'([^']+)'") {
            $type = "url"; $value = $matches[1]
        } elseif ($pattern -match "file:name\s*=\s*'([^']+)'") {
            $type = "filename"; $value = $matches[1]
        } elseif ($pattern -match "file:path\s*=\s*'([^']+)'") {
            $type = "file_path"; $value = $matches[1]
        }

        if (-not $type -or -not $value) {
            continue
        }

        $indicators += New-NormalizedIndicator `
            -IndicatorId ([string]$object.id) `
            -Type $type `
            -Value $value `
            -Source "stix" `
            -Confidence 70 `
            -Severity "medium" `
            -ValidFrom ([string]$object.valid_from) `
            -ReferenceUrl ([string]$object.external_references[0].url) `
            -RawSourceRecord $object
    }

    return @($indicators)
}

function Import-Indicators {
    param([string]$Path)

    $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json

    if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string]) -and -not ($raw.PSObject.Properties.Name -contains "type")) {
        return @($raw)
    }

    if ($raw.PSObject.Properties.Name -contains "Indicators") {
        return @($raw.Indicators)
    }

    if ([string]$raw.type -eq "bundle" -and $raw.objects) {
        return @(Convert-StixBundleToIndicators -Bundle $raw)
    }

    throw "Unsupported IOC input format. Provide a normalized indicator JSON array, an object with an Indicators array, or a STIX bundle."
}

function Get-SqliteActiveIndicators {
    param([string]$DbPath)

    $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("query-active-indicators")
    if ([string]::IsNullOrWhiteSpace($raw)) {
        Write-Error "SQLite returned no active-indicator payload: $DbPath" -ErrorAction Continue
        exit 1
    }
    try {
        $payload = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Error "SQLite returned an invalid active-indicator payload: $DbPath" -ErrorAction Continue
        exit 1
    }
    if ($null -eq $payload -or -not ($payload.PSObject.Properties.Name -contains "Indicators")) {
        Write-Error "SQLite active-indicator payload is invalid: $DbPath" -ErrorAction Continue
        exit 1
    }
    return @($payload.Indicators)
}

function Test-IndicatorStillValid {
    param($Indicator)

    if ([string]::IsNullOrWhiteSpace([string]$Indicator.valid_until)) {
        return $true
    }

    try {
        return (([datetimeoffset]::Parse([string]$Indicator.valid_until)).UtcDateTime -gt (Get-Date).ToUniversalTime())
    } catch {
        return $true
    }
}

function Build-BaselineDataset {
    $processes = Get-ProcessMap
    $services = Get-ServiceMap
    $tasks = Get-TaskMap
    $drivers = Get-DriverMap
    $runKeys = Get-RunKeyEntries
    $defender = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureLastUpdated
    $connections = Get-ConnectionMap
    $dnsCache = Get-DnsCacheMap
    $certs = Get-Certificates
    $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet

    $records = @()

    foreach ($p in $processes) {
        $processSha256 = Get-SafeFileHash -Path $p.ExecutablePath -Algorithm SHA256
        $records += New-NormalizedRecord -Category "Process" -Name $p.Name -Value $p.Name -Path $p.ExecutablePath -Hash $processSha256 -HashAlgorithm "SHA256" -Timestamp $p.CreationDate -Owner $p.Owner -ProcessId $p.ProcessId -ParentProcessId $p.ParentProcessId -CommandLine $p.CommandLine -Source @("Win32_Process")
    }
    foreach ($s in $services) {
        $records += New-NormalizedRecord -Category "Service" -Name $s.Name -Value $s.DisplayName -Path $s.PathName -Owner $s.StartName -ProcessId $s.ProcessId -CommandLine $s.PathName -RegistryPath $s.RegistryPath -Source @("Win32_Service")
    }
    foreach ($d in $drivers) {
        $records += New-NormalizedRecord -Category "Driver" -Name $d.Name -Value $d.DisplayName -Path $d.PathName -CommandLine $d.PathName -Source @("Win32_SystemDriver") -Notes ("State={0}; StartMode={1}" -f $d.State, $d.StartMode)
    }
    foreach ($t in $tasks) {
        $records += New-NormalizedRecord -Category "ScheduledTask" -Name ("{0}{1}" -f $t.TaskPath, $t.TaskName) -Value $t.TaskName -Path ("{0}{1}" -f $t.TaskPath, $t.TaskName) -Timestamp $t.LastRunTime -Owner $t.Author -CommandLine $t.Actions -EventIDs @(4698) -Source @("ScheduledTasks") -Notes ("NextRun={0}; Result={1}" -f $t.NextRunTime, $t.LastTaskResult)
    }
    foreach ($r in $runKeys) {
        $records += New-NormalizedRecord -Category "Autorun" -Name $r.Name -Value $r.Name -CommandLine $r.CommandLine -RegistryPath $r.RegistryPath -Source @("Registry")
    }
    foreach ($c in $connections) {
        $records += New-NormalizedRecord -Category "NetworkConnection" -Name $c.RemoteAddress -Value $c.RemoteAddress -Path "" -Timestamp "" -ProcessId $c.OwningProcess -CommandLine ("{0}:{1}->{2}:{3} [{4}]" -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State) -Source @("Get-NetTCPConnection")
    }
    foreach ($d in $dnsCache) {
        $records += New-NormalizedRecord -Category "DnsCache" -Name $d.Entry -Value $d.Entry -Path "" -Timestamp "" -CommandLine ("Type={0}; Data={1}; TTL={2}" -f $d.Type, $d.Data, $d.TimeToLive) -Source @("Get-DnsClientCache")
    }
    foreach ($cert in $certs) {
        $records += New-NormalizedRecord -Category "Certificate" -Name $cert.Subject -Value $cert.Thumbprint -Path $cert.StorePath -Timestamp ([string]$cert.NotAfter) -Source @("CertProvider") -Notes ("FriendlyName={0}" -f $cert.FriendlyName)
    }

    [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            ComputerName = $computerName
            CollectionTimeUtc = $collectionTimeUtc
            Mode = "Baseline"
        }
        Summary = [PSCustomObject]@{
            Defender = $defender
            ProcessCount = @($processes).Count
            ServiceCount = @($services).Count
            DriverCount = @($drivers).Count
            TaskCount = @($tasks).Count
            AutorunCount = @($runKeys).Count
            ConnectionCount = @($connections).Count
            DnsCacheCount = @($dnsCache).Count
            CertificateCount = @($certs).Count
            LocalUserCount = @($users).Count
        }
        Processes = @($processes)
        Services = @($services)
        Drivers = @($drivers)
        ScheduledTasks = @($tasks)
        Autoruns = @($runKeys)
        Connections = @($connections)
        DnsCache = @($dnsCache)
        Certificates = @($certs)
        LocalUsers = @($users)
        NormalizedIOCRecords = @($records)
    }
}

function Build-DeepDataset {
    $start = (Get-Date).AddDays(-7)
    $baseline = Build-BaselineDataset
    $files = Get-RecentFiles -Start $start -Depth 2 -MaxFiles 100
    $hashes = Get-FileHashes -Files $files -MaxFiles 25
    $prefetch = Get-PrefetchFiles -Start $start
    $links = Get-RecentLinks -Start $start
    $certs = Get-Certificates
    $events = Get-KeyEvents -Start $start

    $records = @($baseline.NormalizedIOCRecords)
    foreach ($f in $files) {
        $records += New-NormalizedRecord -Category "RecentFile" -Name ([IO.Path]::GetFileName($f.FullName)) -Path $f.FullName -Timestamp ([string]$f.LastWriteTimeUtc) -Source @("FileSystem") -Notes ("Length={0}" -f $f.Length)
    }
    foreach ($h in $hashes) {
        $records += New-NormalizedRecord -Category "Hash" -Name ([IO.Path]::GetFileName($h.FullName)) -Path $h.FullName -Hash $h.SHA256 -HashAlgorithm "SHA256" -Timestamp $h.LastWriteTimeUtc -Source @("Get-FileHash")
    }
    foreach ($l in $links) {
        $records += New-NormalizedRecord -Category "LNK" -Name ([IO.Path]::GetFileName($l.FullName)) -Path $l.FullName -Timestamp ([string]$l.LastWriteTimeUtc) -Source @("RecentItems")
    }
    foreach ($p in $prefetch) {
        $records += New-NormalizedRecord -Category "Prefetch" -Name $p.Name -Path $p.FullName -Timestamp ([string]$p.LastWriteTimeUtc) -Source @("Prefetch")
    }
    foreach ($c in $certs) {
        $records += New-NormalizedRecord -Category "Certificate" -Name $c.Subject -Path $c.StorePath -Timestamp ([string]$c.NotAfter) -Source @("CertProvider") -Notes ("Thumbprint={0}" -f $c.Thumbprint)
    }
    foreach ($e in $events.PowerShell4103) {
        $records += New-NormalizedRecord -Category "PowerShellLog" -Name "4103" -Timestamp ([string]$e.TimeCreated) -CommandLine $e.Message -EventIDs @(4103) -Source @("PowerShell/Operational")
    }
    foreach ($e in $events.PowerShell4104) {
        $records += New-NormalizedRecord -Category "PowerShellLog" -Name "4104" -Timestamp ([string]$e.TimeCreated) -CommandLine $e.Message -EventIDs @(4104) -Source @("PowerShell/Operational")
    }
    foreach ($e in $events.Security4688) {
        $records += New-NormalizedRecord -Category "EventLog" -Name "4688" -Timestamp ([string]$e.TimeCreated) -CommandLine $e.Message -EventIDs @(4688) -Source @("Security")
    }
    foreach ($e in $events.Security4698) {
        $records += New-NormalizedRecord -Category "EventLog" -Name "4698" -Timestamp ([string]$e.TimeCreated) -CommandLine $e.Message -EventIDs @(4698) -Source @("Security")
    }
    foreach ($e in $events.System7045) {
        $records += New-NormalizedRecord -Category "EventLog" -Name "7045" -Timestamp ([string]$e.TimeCreated) -CommandLine $e.Message -EventIDs @(7045) -Source @("System")
    }

    [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            ComputerName = $computerName
            CollectionTimeUtc = $collectionTimeUtc
            Mode = "Deep"
        }
        Baseline = $baseline
        RecentFiles = @($files)
        RecentFileHashes = @($hashes)
        RecentLinks = @($links)
        PrefetchFiles = @($prefetch)
        Certificates = @($certs)
        KeyEvents = $events
        NormalizedIOCRecords = @($records)
    }
}

function Add-RecordToLookup {
    param(
        [hashtable]$Lookup,
        [string]$Key,
        $Record
    )

    if ([string]::IsNullOrWhiteSpace($Key)) {
        return
    }

    $normalizedKey = $Key.ToLowerInvariant()
    if (-not $Lookup.ContainsKey($normalizedKey)) {
        $Lookup[$normalizedKey] = [System.Collections.ArrayList]::new()
    }

    [void]$Lookup[$normalizedKey].Add($Record)
}

function Get-UrlTokensFromText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    $matches = [regex]::Matches($Text, 'https?://[^\s''"<>]+')
    return @($matches | ForEach-Object { $_.Value.TrimEnd('.', ',', ';', ')', ']') } | Sort-Object -Unique)
}

function New-FindingFromMatch {
    param(
        $Indicator,
        $Record,
        [string]$Evidence,
        [string]$SnapshotId = "",
        [string]$SnapshotType = "current_scan"
    )

    $indicatorType = ([string]$Indicator.type).ToLowerInvariant()
    $matchedField = "value"
    $matchedValue = [string]$Record.Value

    switch ($indicatorType) {
        { $_ -in @("sha256", "sha1", "md5") } {
            $matchedField = "hash"
            $matchedValue = [string]$Record.Hash
        }
        { $_ -in @("ipv4", "ipv6") } {
            $matchedField = "remote_address"
            $matchedValue = [string]$Record.Value
        }
        "domain" {
            $matchedField = "dns_or_text"
            $matchedValue = [string]$Record.Value
        }
        "url" {
            $matchedField = "command_line_or_event_text"
            $matchedValue = [string]$Indicator.value
        }
        "registry_key" {
            $matchedField = "key_path"
            $matchedValue = [string]$Record.RegistryPath
        }
        "registry_value" {
            $matchedField = "value_data"
            $matchedValue = if ($Record.CommandLine) { [string]$Record.CommandLine } else { [string]$Record.RegistryPath }
        }
        "service_name" {
            $matchedField = "service_name"
            $matchedValue = [string]$Record.Name
        }
        "scheduled_task" {
            $matchedField = "task_name"
            $matchedValue = [string]$Record.Name
        }
        "command_line_pattern" {
            $matchedField = "command_line"
            $matchedValue = [string]$Record.CommandLine
        }
    }

    [PSCustomObject]@{
        finding_id = ([guid]::NewGuid().ToString())
        host = $computerName
        scan_time = $collectionTimeUtc
        match_source = "in_memory_fallback"
        match_method = "in_memory_fallback"
        snapshot_id = $SnapshotId
        snapshot_type = $SnapshotType
        snapshot_time = $collectionTimeUtc
        evidence_strength = if ($indicatorType -in @("sha256", "sha1", "md5")) { "strong" } else { "medium" }
        false_positive_risk = if ($indicatorType -in @("sha256", "sha1", "md5")) { "low" } else { "medium" }
        indicator_type = [string]$Indicator.type
        indicator_value = [string]$Indicator.value
        indicator_source = [string]$Indicator.source
        confidence = [int]$Indicator.confidence
        severity = [string]$Indicator.severity
        matched_field = $matchedField
        matched_value = $matchedValue
        interpretation = "Matched against current collected local evidence using the in-memory fallback matcher. SQLite snapshot evidence was not used for this indicator path."
        scope_note = "Matched against current collected local evidence only. This does not imply that the observation exists outside the collected snapshot."
        matched_observation_type = [string]$Record.Category
        matched_observation = [PSCustomObject]@{
            name = $Record.Name
            value = $Record.Value
            path = $Record.Path
            hash = $Record.Hash
            hash_algorithm = $Record.HashAlgorithm
            timestamp = $Record.Timestamp
            command_line = $Record.CommandLine
            registry_path = $Record.RegistryPath
            source = @($Record.Source)
        }
        evidence = $Evidence
        collection_command = ($Record.Source -join ", ")
        recommended_action = if (@('sha256','sha1','md5','service_name','scheduled_task') -contains ([string]$Indicator.type).ToLowerInvariant()) { 'investigate' } else { 'review_context' }
        references = @([string]$Indicator.reference_url)
    }
}

function New-FindingFromBaselineHashJoin {
    param($Match)

    $isTest = ([string]$Match.source -eq "LOCAL_TEST_DO_NOT_ALERT")
    $interpretation = "This file hash was present in the tripwire baseline inventory. Verify whether the file still exists and whether the baseline should be trusted."
    $scopeNote = "Matched against indexed tripwire baseline file hashes."
    if ($isTest) {
        $interpretation = "Controlled local test indicator: this file hash was present in the tripwire baseline inventory. Treat this as a verification result, not a real malware finding."
        $scopeNote = "Matched against indexed tripwire baseline file hashes for a controlled LOCAL_TEST_DO_NOT_ALERT verification."
    }

    [PSCustomObject]@{
        finding_id = ([guid]::NewGuid().ToString())
        host = $computerName
        scan_time = $collectionTimeUtc
        match_source = "baseline_file_hashes"
        match_method = "sqlite_hash_join"
        snapshot_id = [string]$Match.baseline_id
        snapshot_type = "baseline_reference"
        snapshot_time = [string]$Match.baseline_timestamp
        evidence_strength = "strong"
        false_positive_risk = "low"
        indicator_type = "sha256"
        indicator_value = [string]$Match.indicator_value
        indicator_source = [string]$Match.source
        confidence = if ($null -ne $Match.confidence) { [int]$Match.confidence } else { 50 }
        severity = [string]$Match.severity
        matched_field = "sha256"
        matched_value = [string]$Match.sha256
        baseline_id = [string]$Match.baseline_id
        baseline_timestamp = [string]$Match.baseline_timestamp
        matched_path = [string]$Match.path
        matched_sha256 = [string]$Match.sha256
        matched_observation_type = "BaselineFileHash"
        scope_note = $scopeNote
        interpretation = $interpretation
        matched_observation = [PSCustomObject]@{
            name = [IO.Path]::GetFileName([string]$Match.path)
            value = [string]$Match.path
            path = [string]$Match.path
            hash = [string]$Match.sha256
            hash_algorithm = "SHA256"
            timestamp = [string]$Match.last_write_time_utc
            size_bytes = $Match.size_bytes
            source = @("SQLiteBaselineHashIndex")
        }
        evidence = "Tripwire baseline file hash matched an indexed SHA-256 indicator through SQLite."
        collection_command = "ioc_store.py baseline-hash-match"
        recommended_action = "investigate"
        references = @()
    }
}

function New-FindingFromSqliteEvidenceMatch {
    param($Match)

    $isTest = ([string]$Match.indicator_source -eq "LOCAL_TEST_DO_NOT_ALERT")
    $interpretation = [string]$Match.interpretation
    $scopeNote = [string]$Match.scope_note
    if ($isTest) {
        $interpretation = "Controlled local test indicator: " + $interpretation
        $scopeNote = $scopeNote + " This is a LOCAL_TEST_DO_NOT_ALERT verification result."
    }

    [PSCustomObject]@{
        finding_id = ([guid]::NewGuid().ToString())
        host = $computerName
        scan_time = $collectionTimeUtc
        match_source = [string]$Match.match_source
        match_method = "sqlite_evidence_snapshot"
        snapshot_id = [string]$Match.snapshot_id
        snapshot_type = [string]$Match.snapshot_type
        snapshot_time = [string]$Match.snapshot_time
        evidence_strength = [string]$Match.evidence_strength
        false_positive_risk = [string]$Match.false_positive_risk
        indicator_type = [string]$Match.indicator_type
        indicator_value = [string]$Match.indicator_value
        indicator_source = [string]$Match.indicator_source
        confidence = if ($null -ne $Match.confidence) { [int]$Match.confidence } else { 50 }
        severity = [string]$Match.severity
        matched_field = [string]$Match.matched_field
        matched_value = [string]$Match.matched_value
        interpretation = $interpretation
        scope_note = $scopeNote
        matched_observation_type = [string]$Match.matched_observation_type
        matched_observation = [PSCustomObject]@{
            name = [string]$Match.matched_name
            value = [string]$Match.matched_value
            path = [string]$Match.matched_path
            hash = [string]$Match.matched_sha256
            hash_algorithm = if ([string]$Match.indicator_type -eq "sha256") { "SHA256" } else { "" }
            timestamp = [string]$Match.snapshot_time
            command_line = [string]$Match.matched_command_line
            registry_path = [string]$Match.matched_registry_key
            source = @([string]$Match.match_source)
        }
        evidence = $interpretation
        collection_command = "ioc_store.py evidence-snapshot-match"
        recommended_action = if ($isTest) { "document_test_result" } elseif (@("sha256", "service_name", "scheduled_task") -contains ([string]$Match.indicator_type).ToLowerInvariant()) { "investigate" } else { "review_context" }
        references = @()
    }
}

function Build-RecordIndexes {
    param($Records)

    $indexes = @{
        HashByAlgorithm = @{
            sha256 = @{}
            sha1   = @{}
            md5    = @{}
        }
        NetworkIp = @{}
        DnsDomain = @{}
        Url = @{}
        CertificateThumbprint = @{}
        ServiceName = @{}
        TaskFullName = @{}
        TaskLeafName = @{}
        FileName = @{}
        RecordName = @{}
        PathRecords = [System.Collections.ArrayList]::new()
        RegistryPathRecords = [System.Collections.ArrayList]::new()
        RegistryValueRecords = [System.Collections.ArrayList]::new()
        CommandLineRecords = [System.Collections.ArrayList]::new()
    }

    foreach ($record in @($Records)) {
        if ($record.Hash -and $record.HashAlgorithm) {
            $algorithm = ([string]$record.HashAlgorithm).ToLowerInvariant()
            if ($indexes.HashByAlgorithm.ContainsKey($algorithm)) {
                Add-RecordToLookup -Lookup $indexes.HashByAlgorithm[$algorithm] -Key ([string]$record.Hash) -Record $record
            }
        }

        if ($record.Category -eq 'NetworkConnection' -and $record.Value) {
            Add-RecordToLookup -Lookup $indexes.NetworkIp -Key ([string]$record.Value) -Record $record
        }
        if ($record.Category -eq 'DnsCache' -and $record.Value) {
            Add-RecordToLookup -Lookup $indexes.DnsDomain -Key ([string]$record.Value) -Record $record
        }
        if ($record.Category -eq 'Certificate' -and $record.Value) {
            Add-RecordToLookup -Lookup $indexes.CertificateThumbprint -Key ([string]$record.Value) -Record $record
        }
        if ($record.Category -eq 'Service' -and $record.Name) {
            Add-RecordToLookup -Lookup $indexes.ServiceName -Key ([string]$record.Name) -Record $record
        }
        if ($record.Category -eq 'ScheduledTask' -and $record.Name) {
            Add-RecordToLookup -Lookup $indexes.TaskFullName -Key ([string]$record.Name) -Record $record
            $leaf = Split-Path -Path ([string]$record.Name) -Leaf
            Add-RecordToLookup -Lookup $indexes.TaskLeafName -Key $leaf -Record $record
        }
        if ($record.Name) {
            Add-RecordToLookup -Lookup $indexes.RecordName -Key ([string]$record.Name) -Record $record
        }
        if ($record.Path) {
            $fileName = [IO.Path]::GetFileName([string]$record.Path)
            if (-not [string]::IsNullOrWhiteSpace($fileName)) {
                Add-RecordToLookup -Lookup $indexes.FileName -Key $fileName -Record $record
            }
            [void]$indexes.PathRecords.Add($record)
        }
        if ($record.RegistryPath) {
            [void]$indexes.RegistryPathRecords.Add($record)
        }
        if ($record.RegistryPath -or $record.CommandLine) {
            [void]$indexes.RegistryValueRecords.Add($record)
        }
        if ($record.CommandLine) {
            [void]$indexes.CommandLineRecords.Add($record)
            foreach ($url in @(Get-UrlTokensFromText -Text ([string]$record.CommandLine))) {
                Add-RecordToLookup -Lookup $indexes.Url -Key $url -Record $record
            }
        }
    }

    return $indexes
}

function Test-IocMatch {
    param(
        $Dataset,
        $Indicators,
        [string]$StateDbPath = "",
        [string]$CurrentSnapshotId = ""
    )

    $records = @($Dataset.NormalizedIOCRecords)
    $indexes = Build-RecordIndexes -Records $records
    $findings = @()
    $sqliteSnapshotMatches = Get-SnapshotEvidenceMatches -DbPath $StateDbPath -SnapshotId $CurrentSnapshotId
    $baselineHashJoin = Get-BaselineHashJoinResults -DbPath $StateDbPath
    $baselineHashStatus = Get-BaselineHashStatus -DbPath $StateDbPath
    $processHashesChecked = @($records | Where-Object { $_.Category -eq "Process" -and $_.Hash -and ([string]$_.HashAlgorithm).ToLowerInvariant() -eq "sha256" }).Count
    $recentFileHashesChecked = @($Dataset.RecentFileHashes | Where-Object { $_.SHA256 }).Count
    $baselineHashesChecked = 0
    $baselineHashIndexStatus = "unavailable"
    $baselineIdUsed = $null
    $baselineTimestampUsed = $null

    if ($null -ne $baselineHashJoin) {
        $baselineHashIndexStatus = [string]$baselineHashJoin.baseline_hash_index_status
        $baselineHashesChecked = if ($null -ne $baselineHashJoin.baseline_hashes_checked) { [int]$baselineHashJoin.baseline_hashes_checked } else { 0 }
        $baselineIdUsed = [string]$baselineHashJoin.baseline_id
        $baselineTimestampUsed = [string]$baselineHashJoin.baseline_timestamp
    } elseif ($null -ne $baselineHashStatus) {
        $baselineHashIndexStatus = [string]$baselineHashStatus.status
        $baselineHashesChecked = if ($null -ne $baselineHashStatus.baseline_hash_count) { [int]$baselineHashStatus.baseline_hash_count } else { 0 }
        $baselineIdUsed = [string]$baselineHashStatus.latest_baseline_id
        $baselineTimestampUsed = [string]$baselineHashStatus.baseline_timestamp
    }

    $sqliteSnapshotAvailable = ($null -ne $sqliteSnapshotMatches -and $sqliteSnapshotMatches.snapshot_available)
    if ($sqliteSnapshotAvailable) {
        foreach ($match in @($sqliteSnapshotMatches.current_matches)) {
            $findings += New-FindingFromSqliteEvidenceMatch -Match $match
        }
        foreach ($match in @($sqliteSnapshotMatches.historical_matches)) {
            $findings += New-FindingFromSqliteEvidenceMatch -Match $match
        }
    }

    $sqlitePreferredTypes = @(
        "sha256",
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "registry_key",
        "registry_value",
        "service_name",
        "scheduled_task",
        "command_line_pattern"
    )

    foreach ($indicator in @($Indicators | Where-Object { Test-IndicatorStillValid -Indicator $_ })) {
        $indicatorType = ([string]$indicator.type).ToLowerInvariant()
        if ($sqliteSnapshotAvailable -and ($sqlitePreferredTypes -contains $indicatorType)) {
            continue
        }
        $indicatorValue = [string]$indicator.value
        $matchedRecords = @()
        $evidence = ""

        switch -Regex ($indicatorType) {
            '^(sha256|sha1|md5)$' {
                $lookup = $indexes.HashByAlgorithm[$indicatorType]
                $matchedRecords = @($lookup[$indicatorValue.ToLowerInvariant()])
                $evidence = "File or process hash matched exactly."
            }
            '^(ipv4|ipv6)$' {
                $matchedRecords = @($indexes.NetworkIp[$indicatorValue.ToLowerInvariant()])
                $evidence = "Remote IP matched active network connection."
            }
            '^domain$' {
                $matchedRecords = @($indexes.DnsDomain[$indicatorValue.ToLowerInvariant()])
                $evidence = "Domain matched DNS client cache."
            }
            '^url$' {
                $matchedRecords = @($indexes.Url[$indicatorValue.ToLowerInvariant()])
                $evidence = "URL matched text extracted from collected command or log data."
            }
            '^registry_key$' {
                $matchedRecords = @($indexes.RegistryPathRecords | Where-Object { $_.RegistryPath -and $_.RegistryPath.ToLowerInvariant().Contains($indicatorValue.ToLowerInvariant()) })
                $evidence = "Registry key path matched collected registry observation."
            }
            '^registry_value$' {
                $matchedRecords = @($indexes.RegistryValueRecords | Where-Object {
                    ($_.RegistryPath -and $_.RegistryPath.ToLowerInvariant().Contains($indicatorValue.ToLowerInvariant())) -or
                    ($_.CommandLine -and $_.CommandLine.ToLowerInvariant().Contains($indicatorValue.ToLowerInvariant()))
                })
                $evidence = "Registry value text matched collected registry-related observation."
            }
            '^file_path$' {
                $matchedRecords = @($indexes.PathRecords | Where-Object { $_.Path -and $_.Path.ToLowerInvariant().Contains($indicatorValue.ToLowerInvariant()) })
                $evidence = "File path matched collected file or process path."
            }
            '^filename$' {
                $matchedRecords = @($indexes.FileName[$indicatorValue.ToLowerInvariant()])
                if (@($matchedRecords).Count -eq 0) {
                    $matchedRecords = @($indexes.RecordName[$indicatorValue.ToLowerInvariant()])
                }
                $evidence = "Filename matched collected file, process, or task observation."
            }
            '^certificate_thumbprint$' {
                $matchedRecords = @($indexes.CertificateThumbprint[$indicatorValue.ToLowerInvariant()])
                $evidence = "Certificate thumbprint matched local certificate store."
            }
            '^service_name$' {
                $matchedRecords = @($indexes.ServiceName[$indicatorValue.ToLowerInvariant()])
                $evidence = "Service name matched installed service."
            }
            '^scheduled_task$' {
                $matchedRecords = @($indexes.TaskFullName[$indicatorValue.ToLowerInvariant()])
                if (@($matchedRecords).Count -eq 0) {
                    $matchedRecords = @($indexes.TaskLeafName[$indicatorValue.ToLowerInvariant()])
                }
                $evidence = "Scheduled task name matched installed task."
            }
            '^command_line_pattern$' {
                $matchedRecords = @($indexes.CommandLineRecords | Where-Object { $_.CommandLine -and $_.CommandLine -match $indicatorValue })
                $evidence = "Command line pattern matched collected process or event text."
            }
            '^cve$' {
                $matchedRecords = @()
            }
        }

        foreach ($record in @($matchedRecords | Where-Object { $null -ne $_ })) {
            $findings += New-FindingFromMatch -Indicator $indicator -Record $record -Evidence $evidence -SnapshotId $CurrentSnapshotId -SnapshotType "current_scan"
        }
    }

    if ($null -ne $baselineHashJoin -and @($baselineHashJoin.matches).Count -gt 0) {
        foreach ($match in @($baselineHashJoin.matches)) {
            $findings += New-FindingFromBaselineHashJoin -Match $match
        }
    }

    [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            ComputerName = $computerName
            CollectionTimeUtc = $collectionTimeUtc
            Mode = "IOC"
            IocPath = $IocPath
            CurrentSnapshotId = $CurrentSnapshotId
            EvidenceSnapshotAvailable = [bool]$sqliteSnapshotAvailable
            BaselineHashIndexStatus = $baselineHashIndexStatus
            BaselineId = $baselineIdUsed
            BaselineTimestamp = $baselineTimestampUsed
        }
        Indicators = $Indicators
        MatchCount = @($findings).Count
        Findings = @($findings)
        HashCoverage = [PSCustomObject]@{
            process_hashes_checked = $processHashesChecked
            recent_file_hashes_checked = $recentFileHashesChecked
            baseline_hashes_checked = $baselineHashesChecked
            total_sha256_corpus = ($processHashesChecked + $recentFileHashesChecked + $baselineHashesChecked)
            baseline_hash_index_status = $baselineHashIndexStatus
            baseline_id = $baselineIdUsed
            baseline_timestamp = $baselineTimestampUsed
            baseline_hash_scope = if ($baselineIdUsed) { "latest_indexed_baseline" } elseif ($baselineHashIndexStatus -eq "available") { "indexed_baseline_hashes" } else { "none" }
            coverage_summary = if ($baselineHashIndexStatus -in @("empty", "unavailable")) {
                "Baseline hash IOC coverage is not available yet."
            } else {
                "Current process hashes: $processHashesChecked; current recent-file hashes: $recentFileHashesChecked; latest indexed baseline hashes: $baselineHashesChecked; total SHA-256 corpus: $($processHashesChecked + $recentFileHashesChecked + $baselineHashesChecked)."
            }
            current_snapshot_id = $CurrentSnapshotId
            evidence_snapshot_available = [bool]$sqliteSnapshotAvailable
            coverage_breakdown = [PSCustomObject]@{
                current_process_hashes = [PSCustomObject]@{
                    scope = "Current process hash coverage"
                    count = $processHashesChecked
                    description = "SHA-256 hashes collected from currently observed processes during this IOC run."
                }
                current_recent_file_hashes = [PSCustomObject]@{
                    scope = "Current recent-file hash coverage"
                    count = $recentFileHashesChecked
                    description = "SHA-256 hashes collected from the current recent-file sample during this IOC run."
                }
                latest_indexed_baseline_hashes = [PSCustomObject]@{
                    scope = "Latest indexed baseline hash coverage"
                    count = $baselineHashesChecked
                    description = "SHA-256 hashes read from the latest indexed tripwire baseline inventory."
                    baseline_id = $baselineIdUsed
                    baseline_timestamp = $baselineTimestampUsed
                    index_status = $baselineHashIndexStatus
                }
            }
        }
    }
}

function Get-IndicatorSummary {
    param($Indicators)

    [PSCustomObject]@{
        Total = @($Indicators).Count
        ByType = @(
            $Indicators |
                Group-Object type |
                Sort-Object Count -Descending |
                ForEach-Object {
                    [PSCustomObject]@{
                        Type = $_.Name
                        Count = $_.Count
                    }
                }
        )
        BySource = @(
            $Indicators |
                Group-Object source |
                Sort-Object Count -Descending |
                ForEach-Object {
                    [PSCustomObject]@{
                        Source = $_.Name
                        Count = $_.Count
                    }
                }
        )
        Sample = @($Indicators | Select-Object -First 25)
    }
}

function Write-ModeMarkdown {
    param($Data)

    Write-MdLine "# Host IOC Report"
    Write-MdLine ""
    Write-MdLine ("Mode: [{0}]" -f $Mode)
    Write-MdLine ("Host: [{0}]" -f $computerName)
    Write-MdLine ("CollectionTimeUtc: [{0}]" -f $collectionTimeUtc)

    switch ($Mode) {
        "Baseline" {
            Write-MdSection "Summary"
            Write-MdBlock -Title "Summary" -Object $Data.Summary
            Write-MdSection "Key Data"
            Write-MdBlock -Title "Processes (First 30)" -Object ($Data.Processes | Select-Object -First 30)
            Write-MdBlock -Title "Services (First 30)" -Object ($Data.Services | Select-Object -First 30)
            Write-MdBlock -Title "Scheduled Tasks (First 30)" -Object ($Data.ScheduledTasks | Select-Object -First 30)
            Write-MdBlock -Title "Autoruns" -Object $Data.Autoruns
            Write-MdBlock -Title "Normalized IOC Records (First 40)" -Object ($Data.NormalizedIOCRecords | Select-Object -First 40)
        }
        "Deep" {
            Write-MdSection "Summary"
            Write-MdLine ("Normalized IOC record count: [{0}]" -f @($Data.NormalizedIOCRecords).Count)
            Write-MdSection "Deep Data"
            Write-MdBlock -Title "Recent Files (First 30)" -Object ($Data.RecentFiles | Select-Object -First 30)
            Write-MdBlock -Title "Recent Hashes" -Object $Data.RecentFileHashes
            Write-MdBlock -Title "PowerShell 4104 (First 10)" -Object ($Data.KeyEvents.PowerShell4104 | Select-Object -First 10)
            Write-MdBlock -Title "7045 Events" -Object $Data.KeyEvents.System7045
            Write-MdBlock -Title "Normalized IOC Records (First 40)" -Object ($Data.NormalizedIOCRecords | Select-Object -First 40)
        }
        "IOC" {
            Write-MdSection "Summary"
            Write-MdLine ("Match count: [{0}]" -f $Data.MatchCount)
            Write-MdLine ("Indicator count: [{0}]" -f $Data.IndicatorCount)
            Write-MdLine ("Interpretation: [{0}]" -f $Data.MatchInterpretation)
            Write-MdLine ("Current process hash coverage: [{0}]" -f $Data.HashCoverage.process_hashes_checked)
            Write-MdLine ("Current recent-file hash coverage: [{0}]" -f $Data.HashCoverage.recent_file_hashes_checked)
            Write-MdLine ("Latest indexed baseline hash coverage: [{0}]" -f $Data.HashCoverage.baseline_hashes_checked)
            Write-MdLine ("Total SHA-256 corpus: [{0}]" -f $Data.HashCoverage.total_sha256_corpus)
            Write-MdLine ("Baseline hash index status: [{0}]" -f $Data.HashCoverage.baseline_hash_index_status)
            if (-not [string]::IsNullOrWhiteSpace([string]$Data.HashCoverage.baseline_id)) {
                Write-MdLine ("Baseline ID: [{0}]" -f $Data.HashCoverage.baseline_id)
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$Data.HashCoverage.baseline_timestamp)) {
                Write-MdLine ("Baseline timestamp: [{0}]" -f $Data.HashCoverage.baseline_timestamp)
            }
            Write-MdBlock -Title "Indicator Summary" -Object $Data.IndicatorSummary
            Write-MdBlock -Title "Hash Coverage" -Object $Data.HashCoverage
            Write-MdBlock -Title "Hash Coverage Breakdown" -Object $Data.HashCoverage.coverage_breakdown
            Write-MdBlock -Title "Findings" -Object ($Data.Findings | Select-Object -First 50)
        }
    }
}

switch ($Mode) {
    "Baseline" {
        $data = Build-BaselineDataset
        $stateDbContext = Get-StateDbContext
        $snapshotId = [IO.Path]::GetFileNameWithoutExtension($jsonFile)
        [void](Save-EvidenceSnapshotToSqlite -DbPath $stateDbContext.ResolvedPath -Dataset $data -SnapshotId $snapshotId -SnapshotType "baseline" -SourceJsonPath $jsonFile -SourceMarkdownPath $mdFile -TrustLabel "known_good")
    }
    "Deep" {
        $data = Build-DeepDataset
        $stateDbContext = Get-StateDbContext
        $snapshotId = [IO.Path]::GetFileNameWithoutExtension($jsonFile)
        [void](Save-EvidenceSnapshotToSqlite -DbPath $stateDbContext.ResolvedPath -Dataset $data -SnapshotId $snapshotId -SnapshotType "current_scan" -SourceJsonPath $jsonFile -SourceMarkdownPath $mdFile -TrustLabel "unknown")
    }
    "IOC" {
        $stateDbContext = Get-StateDbContext
        $resolvedStateDbPath = $stateDbContext.ResolvedPath
        $indicatorSource = "sqlite"
        if (-not [string]::IsNullOrWhiteSpace($IocPath)) {
            if (-not (Test-Path -LiteralPath $IocPath)) {
                throw "Explicit IOC JSON path was not found: $IocPath"
            }
            $indicators = Import-Indicators -Path $IocPath
            $indicatorSource = "json_override"
        } else {
            $indicators = Get-SqliteActiveIndicators -DbPath $resolvedStateDbPath
        }
        $dataset = Build-DeepDataset
        $snapshotId = [IO.Path]::GetFileNameWithoutExtension($jsonFile)
        [void](Save-EvidenceSnapshotToSqlite -DbPath $resolvedStateDbPath -Dataset $dataset -SnapshotId $snapshotId -SnapshotType "current_scan" -SourceJsonPath $jsonFile -SourceMarkdownPath $mdFile -TrustLabel "unknown")
        $rawIoc = Test-IocMatch -Dataset $dataset -Indicators $indicators -StateDbPath $resolvedStateDbPath -CurrentSnapshotId $snapshotId
        $data = [PSCustomObject]@{
            Metadata = [PSCustomObject]@{
                ComputerName = $rawIoc.Metadata.ComputerName
                CollectionTimeUtc = $rawIoc.Metadata.CollectionTimeUtc
                Mode = $rawIoc.Metadata.Mode
                IocPath = $rawIoc.Metadata.IocPath
                IndicatorSource = $indicatorSource
                CurrentSnapshotId = $rawIoc.Metadata.CurrentSnapshotId
                EvidenceSnapshotAvailable = [bool]$rawIoc.Metadata.EvidenceSnapshotAvailable
                BaselineHashIndexStatus = $rawIoc.Metadata.BaselineHashIndexStatus
                BaselineId = $rawIoc.Metadata.BaselineId
                BaselineTimestamp = $rawIoc.Metadata.BaselineTimestamp
                StateDbPath = $resolvedStateDbPath
                StateDbMode = $stateDbContext.DatabaseLabel
                StateDbOverrideDetected = [bool]$stateDbContext.OverrideDetected
                StateDbOverrideReason = [string]$stateDbContext.OverrideReason
            }
            IndicatorCount = @($indicators).Count
            IndicatorSummary = Get-IndicatorSummary -Indicators $indicators
            MatchCount = [int]$rawIoc.MatchCount
            Findings = @($rawIoc.Findings)
            HashCoverage = $rawIoc.HashCoverage
            MatchInterpretation = Get-IocMatchInterpretation -MatchCount ([int]$rawIoc.MatchCount) -AllTestMatches ([int]$rawIoc.MatchCount -gt 0 -and @($rawIoc.Findings | Where-Object { [string]$_.indicator_source -ne "LOCAL_TEST_DO_NOT_ALERT" }).Count -eq 0)
        }
        Save-IocCoverageState -DbPath $resolvedStateDbPath -Coverage $rawIoc.HashCoverage
    }
}

if ($Export) {
    Write-JsonFile -Path $jsonFile -Object $data -Depth 12
    Write-ModeMarkdown -Data $data
}
if ($Mode -eq "IOC") {
    [void](Save-IocReportToSqlite -DbPath $resolvedStateDbPath -ReportId $snapshotId -Data $data -JsonPath $(if ($Export) { $jsonFile } else { "" }) -MarkdownPath $(if ($Export) { $mdFile } else { "" }))
}

Write-Output "Mode: $Mode"
if ($Export) {
    Write-Output "Markdown written to: $mdFile"
    Write-Output "JSON written to: $jsonFile"
}

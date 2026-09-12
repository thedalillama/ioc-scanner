# CODEX_MONITOR_SELF_EVENT
param(
    [string]$OutputPath = "",
    [switch]$Export,
    [string]$LocationConfigPath = (Join-Path $PSScriptRoot "ioc-monitor-locations.json"),
    [string]$IocStorePath = ""
)

$ErrorActionPreference = "Stop"

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        $Object,
        [int]$Depth = 12
    )

    $parent = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Ensure-Directory -Path $parent
    }

    $json = ConvertTo-Json -InputObject $Object -Depth $Depth
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
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

function Get-IocMonitorLocationConfig {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) {
        return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
    }

    return [PSCustomObject]@{
        WatchFiles = @()
        WatchDirectories = @()
    }
}

function New-NormalizedIndicator {
    param(
        [string]$IndicatorId,
        [string]$Type,
        [string]$Value,
        [string]$Source,
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

function Add-Indicator {
    param(
        [System.Collections.Generic.Dictionary[string, object]]$Map,
        $Indicator
    )

    if ([string]::IsNullOrWhiteSpace([string]$Indicator.type) -or [string]::IsNullOrWhiteSpace([string]$Indicator.value)) {
        return
    }

    $key = ("{0}|{1}" -f ([string]$Indicator.type).ToLowerInvariant(), ([string]$Indicator.value).ToLowerInvariant())
    if (-not $Map.ContainsKey($key)) {
        $Map[$key] = $Indicator
    }
}

function Get-PathLikeValue {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $trimmed = $Value.Trim()
    if ($trimmed -match '^[A-Za-z]:\\' -or $trimmed.StartsWith('\\')) {
        return $trimmed
    }

    return $null
}

function Get-FiltersForPath {
    param([string]$Path)

    $extension = [IO.Path]::GetExtension($Path)
    if ([string]::IsNullOrWhiteSpace($extension)) {
        return @('*')
    }

    return @("*$extension")
}

function Add-UniqueWatchFile {
    param(
        [System.Collections.ArrayList]$WatchFiles,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $exists = @($WatchFiles | Where-Object { ([string]$_).ToLowerInvariant() -eq $Path.ToLowerInvariant() }).Count -gt 0
    if (-not $exists) {
        [void]$WatchFiles.Add($Path)
        return $true
    }

    return $false
}

function Add-UniqueWatchDirectory {
    param(
        [System.Collections.ArrayList]$WatchDirectories,
        [string]$Path,
        [string[]]$Filters,
        [bool]$Recurse
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $normalizedFilters = @($Filters | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if (@($normalizedFilters).Count -eq 0) {
        $normalizedFilters = @('*')
    }

    $key = "{0}|{1}|{2}" -f $Path.ToLowerInvariant(), (($normalizedFilters -join ';').ToLowerInvariant()), $Recurse
    $exists = @($WatchDirectories | Where-Object {
        $existingFilters = @()
        if ($_.PSObject.Properties.Name -contains 'Filters') {
            $existingFilters = @($_.Filters | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        } elseif ($_.PSObject.Properties.Name -contains 'Filter' -and -not [string]::IsNullOrWhiteSpace([string]$_.Filter)) {
            $existingFilters = @([string]$_.Filter)
        } else {
            $existingFilters = @('*')
        }

        ("{0}|{1}|{2}" -f ([string]$_.Path).ToLowerInvariant(), (($existingFilters -join ';').ToLowerInvariant()), [bool]$_.Recurse) -eq $key
    }).Count -gt 0

    if (-not $exists) {
        [void]$WatchDirectories.Add([PSCustomObject]@{
            Path = $Path
            Filters = @($normalizedFilters)
            Recurse = $Recurse
        })
        return $true
    }

    return $false
}

function Update-IocMonitorLocations {
    param(
        [string]$Path,
        $Indicators
    )

    $config = Get-IocMonitorLocationConfig -Path $Path
    $watchFiles = [System.Collections.ArrayList]::new()
    $watchDirectories = [System.Collections.ArrayList]::new()

    foreach ($item in @($config.WatchFiles)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item)) {
            [void]$watchFiles.Add([string]$item)
        }
    }
    foreach ($item in @($config.WatchDirectories)) {
        if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item.Path)) {
            [void]$watchDirectories.Add([PSCustomObject]@{
                Path = [string]$item.Path
                Filters = if ($item.PSObject.Properties.Name -contains 'Filters') { @($item.Filters) } elseif ($item.PSObject.Properties.Name -contains 'Filter') { @([string]$item.Filter) } else { @('*') }
                Recurse = [bool]$item.Recurse
            })
        }
    }

    $addedFiles = 0
    $addedDirectories = 0

    foreach ($indicator in @($Indicators)) {
        if (([string]$indicator.type).ToLowerInvariant() -ne 'file_path') {
            continue
        }

        $pathValue = Get-PathLikeValue -Value ([string]$indicator.value)
        if (-not $pathValue) {
            continue
        }

        $isDirectory = $pathValue.EndsWith('\') -or [string]::IsNullOrWhiteSpace([IO.Path]::GetExtension($pathValue))
        if ($isDirectory) {
            if (Add-UniqueWatchDirectory -WatchDirectories $watchDirectories -Path $pathValue.TrimEnd('\') -Filters @('*') -Recurse $true) {
                $addedDirectories++
            }
            continue
        }

        if (Add-UniqueWatchFile -WatchFiles $watchFiles -Path $pathValue) {
            $addedFiles++
        }

        $parent = Split-Path -Path $pathValue -Parent
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
            if (Add-UniqueWatchDirectory -WatchDirectories $watchDirectories -Path $parent -Filters (Get-FiltersForPath -Path $pathValue) -Recurse $false) {
                $addedDirectories++
            }
        }
    }

    $updatedConfig = [PSCustomObject]@{
        WatchFiles = @($watchFiles | Sort-Object -Unique)
        WatchDirectories = @($watchDirectories | Sort-Object Path)
    }

    Write-JsonFile -Path $Path -Object $updatedConfig -Depth 8

    return [PSCustomObject]@{
        Path = $Path
        AddedFiles = $addedFiles
        AddedDirectories = $addedDirectories
        TotalFiles = @($updatedConfig.WatchFiles).Count
        TotalDirectories = @($updatedConfig.WatchDirectories).Count
    }
}

function Import-ThreatFoxIndicators {
    $uri = "https://threatfox.abuse.ch/export/json/recent/"
    $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 60
    $records = @()

    foreach ($item in @($response.data)) {
        $iocType = [string]$item.ioc_type
        $normalizedType = switch -Regex ($iocType) {
            '^ip:port$' { 'ipv4'; break }
            '^ip$' { 'ipv4'; break }
            '^domain$' { 'domain'; break }
            '^url$' { 'url'; break }
            '^md5_hash$' { 'md5'; break }
            '^sha1_hash$' { 'sha1'; break }
            '^sha256_hash$' { 'sha256'; break }
            default { $null }
        }

        if (-not $normalizedType) {
            continue
        }

        $value = [string]$item.ioc
        if ($normalizedType -eq 'ipv4' -and $value -match '^([^:]+):') {
            $value = $matches[1]
        }

        $records += New-NormalizedIndicator `
            -IndicatorId ("threatfox:{0}" -f [string]$item.id) `
            -Type $normalizedType `
            -Value $value `
            -Source "ThreatFox" `
            -Confidence 75 `
            -Severity "high" `
            -FirstSeen ([string]$item.first_seen_utc) `
            -LastSeen ([string]$item.last_seen_utc) `
            -ValidFrom ([string]$item.first_seen_utc) `
            -MalwareFamily ([string]$item.malware) `
            -ReferenceUrl "https://threatfox.abuse.ch/" `
            -RawSourceRecord $item
    }

    return @($records)
}

function Import-MalwareBazaarIndicators {
    $uri = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
    $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 60
    $records = @()
    $lines = @($response.Content -split "`r?`n")

    foreach ($line in $lines) {
        $value = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($value) -or $value.StartsWith('#')) {
            continue
        }

        $records += New-NormalizedIndicator `
            -IndicatorId ("malwarebazaar:{0}" -f $value) `
            -Type "sha256" `
            -Value $value `
            -Source "MalwareBazaar" `
            -Confidence 80 `
            -Severity "high" `
            -ReferenceUrl "https://bazaar.abuse.ch/" `
            -RawSourceRecord $line
    }

    return @($records)
}

function Import-UrlHausIndicators {
    $uri = "https://urlhaus.abuse.ch/downloads/text/"
    $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 60
    $records = @()
    $lines = @($response.Content -split "`r?`n")

    foreach ($line in $lines) {
        $value = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($value) -or $value.StartsWith('#')) {
            continue
        }

        $records += New-NormalizedIndicator `
            -IndicatorId ("urlhaus:{0}" -f $value) `
            -Type "url" `
            -Value $value `
            -Source "URLhaus" `
            -Confidence 70 `
            -Severity "high" `
            -ReferenceUrl "https://urlhaus.abuse.ch/" `
            -RawSourceRecord $line
    }

    return @($records)
}

function Import-FeodoIndicators {
    $uri = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 60
    $records = @()
    $lines = @($response.Content -split "`r?`n")

    foreach ($line in $lines) {
        $value = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($value) -or $value.StartsWith('#')) {
            continue
        }

        $records += New-NormalizedIndicator `
            -IndicatorId ("feodo:{0}" -f $value) `
            -Type "ipv4" `
            -Value $value `
            -Source "Feodo Tracker" `
            -Confidence 65 `
            -Severity "medium" `
            -ReferenceUrl "https://feodotracker.abuse.ch/" `
            -RawSourceRecord $line
    }

    return @($records)
}

function Import-CisaKevIndicators {
    $uri = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 60
    $records = @()

    foreach ($item in @($response.vulnerabilities)) {
        $records += New-NormalizedIndicator `
            -IndicatorId ("cisa-kev:{0}" -f [string]$item.cveID) `
            -Type "cve" `
            -Value ([string]$item.cveID) `
            -Source "CISA KEV" `
            -Confidence 60 `
            -Severity "high" `
            -FirstSeen ([string]$item.dateAdded) `
            -LastSeen ([string]$item.dateAdded) `
            -ValidFrom ([string]$item.dateAdded) `
            -ReferenceUrl "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" `
            -RawSourceRecord $item
    }

    return @($records)
}

$settings = Get-Settings
$emitExport = $Export -or -not [string]::IsNullOrWhiteSpace($OutputPath)
if ($Export -and [string]::IsNullOrWhiteSpace($OutputPath)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$settings.IndicatorExportPath)) {
        $OutputPath = Resolve-SettingsPathValue -Value ([string]$settings.IndicatorExportPath)
    } else {
        $OutputPath = (Join-Path $PSScriptRoot "indicators\feed-indicators-latest.json")
    }
}
if ([string]::IsNullOrWhiteSpace($IocStorePath)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$settings.StateDbPath)) {
        $IocStorePath = Resolve-SettingsPathValue -Value ([string]$settings.StateDbPath)
    } else {
        $IocStorePath = (Join-Path $PSScriptRoot "state\ioc-store.db")
    }
}

$indicatorMap = New-Object 'System.Collections.Generic.Dictionary[string, object]' ([System.StringComparer]::OrdinalIgnoreCase)
$feedResults = @()
$rawIndicatorCount = 0

$feedImports = @(
    @{ Name = "ThreatFox"; Loader = { Import-ThreatFoxIndicators } },
    @{ Name = "MalwareBazaar"; Loader = { Import-MalwareBazaarIndicators } },
    @{ Name = "URLhaus"; Loader = { Import-UrlHausIndicators } },
    @{ Name = "Feodo Tracker"; Loader = { Import-FeodoIndicators } },
    @{ Name = "CISA KEV"; Loader = { Import-CisaKevIndicators } }
)

foreach ($feed in $feedImports) {
    try {
        $items = @(& $feed.Loader)
        $rawIndicatorCount += @($items).Count
        foreach ($item in $items) {
            Add-Indicator -Map $indicatorMap -Indicator $item
        }

        $feedResults += [PSCustomObject]@{
            Name = $feed.Name
            Status = "Success"
            IndicatorCount = @($items).Count
        }
    } catch {
        $feedResults += [PSCustomObject]@{
            Name = $feed.Name
            Status = "Error"
            IndicatorCount = 0
            Error = $_.Exception.Message
        }
    }
}

$bundle = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        CollectionTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
        ComputerName = $env:COMPUTERNAME
        SourceCount = @($feedResults).Count
        RawIndicatorCount = $rawIndicatorCount
        IndicatorCount = $indicatorMap.Count
        Format = "normalized-indicator-set"
    }
    FeedResults = @($feedResults)
    Indicators = @($indicatorMap.Values | Sort-Object type, value)
}

$locationUpdate = Update-IocMonitorLocations -Path $LocationConfigPath -Indicators $bundle.Indicators

$temporaryBundlePath = ""
if ($emitExport) {
    Write-JsonFile -Path $OutputPath -Object $bundle -Depth 12
} else {
    $temporaryBundlePath = [IO.Path]::GetTempFileName()
    [IO.File]::WriteAllText($temporaryBundlePath, (ConvertTo-Json $bundle -Depth 12), (New-Object Text.UTF8Encoding($false)))
}

$iocStoreToolPath = Join-Path $PSScriptRoot "ioc_store.py"
try {
    if (Test-Path -LiteralPath $iocStoreToolPath) {
        $pythonCommand = Get-PythonCommand
        & $pythonCommand $iocStoreToolPath --db $IocStorePath import-json --input $(if ($emitExport) { $OutputPath } else { $temporaryBundlePath }) | Out-Null
        $reportId = "THREAT_FEED_IMPORT_" + ([string]$bundle.Metadata.CollectionTimeUtc -replace '[:\.]', '-')
        $envelope = [PSCustomObject]@{ collector_run = [PSCustomObject]@{ collector_run_id = "$reportId-collector"; collector_name = "threat_feed_import"; started_at = $bundle.Metadata.CollectionTimeUtc; completed_at = $bundle.Metadata.CollectionTimeUtc; outcome = "success"; summary = $bundle.Metadata }; report = [PSCustomObject]@{ report_id = $reportId; collector_run_id = "$reportId-collector"; report_type = "threat_feed_import"; collection_time_utc = $bundle.Metadata.CollectionTimeUtc; overall_status = "success"; severity = "informational"; summary = [PSCustomObject]@{ FeedResults = $feedResults; LocationUpdate = $locationUpdate }; export_json_path = $(if ($emitExport) { $OutputPath } else { "" }); export_markdown_path = "" }; findings = @() }
        $tempPath = [IO.Path]::GetTempFileName()
        try { [IO.File]::WriteAllText($tempPath, (ConvertTo-Json $envelope -Depth 12), (New-Object Text.UTF8Encoding($false))); & $pythonCommand $iocStoreToolPath --db $IocStorePath persist-collector-report --input $tempPath | Out-Null } finally { if (Test-Path $tempPath) { [IO.File]::Delete($tempPath) } }
    }
} finally {
    if (-not [string]::IsNullOrWhiteSpace($temporaryBundlePath) -and (Test-Path -LiteralPath $temporaryBundlePath)) { [IO.File]::Delete($temporaryBundlePath) }
}

if ($emitExport) { Write-Output ("Indicators written to: {0}" -f $OutputPath) }
Write-Output ("Raw indicator count: {0}" -f $bundle.Metadata.RawIndicatorCount)
Write-Output ("Normalized indicator count: {0}" -f $bundle.Metadata.IndicatorCount)
Write-Output ("IOC monitor locations updated: {0}" -f $locationUpdate.Path)
Write-Output ("Added files: {0}; Added directories: {1}" -f $locationUpdate.AddedFiles, $locationUpdate.AddedDirectories)
Write-Output ("IOC store updated: {0}" -f $IocStorePath)

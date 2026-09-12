param(
    [string]$StatePath = "",
    [string]$StateDbPath = "",
    [int]$LookbackHours = 72,
    [switch]$RunDeepOnMatch,
    [switch]$RunBaselineOnMatch,
    [switch]$RunTripwireCheckOnMatch,
    [switch]$Export
)

$ErrorActionPreference = "Stop"

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$collectionTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
$outBase = Join-Path $PSScriptRoot ("THREAT_RSS_{0}" -f $timestamp)
$jsonFile = "$outBase.json"
$mdFile = "$outBase.md"

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
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

function Get-AlertInboxPath {
    $settingsPath = Join-Path $PSScriptRoot "codex-monitor.settings.json"
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.AlertInboxPath)) {
                $configuredInboxPath = Resolve-SettingsPathValue -Value ([string]$settings.AlertInboxPath) -SettingsPath $settingsPath
                Ensure-Directory -Path $configuredInboxPath
                return $configuredInboxPath
            }
        } catch {
        }
    }

    $defaultInbox = Join-Path (Join-Path $PSScriptRoot "alerts") "pending"
    Ensure-Directory -Path $defaultInbox
    return $defaultInbox
}

$alertBase = Join-Path (Get-AlertInboxPath) ("ALERT_THREAT_RSS_{0}" -f $timestamp)
$iocScriptPath = Join-Path $PSScriptRoot "invoke-host-ioc.ps1"
$tripwireScriptPath = Join-Path $PSScriptRoot "invoke-host-tripwire.ps1"

$feeds = @(
    [PSCustomObject]@{
        Name = "CISA Cybersecurity Advisories"
        Url = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
        Trust = "High"
        Type = "RSS"
    },
    [PSCustomObject]@{
        Name = "Microsoft Security Blog"
        Url = "https://www.microsoft.com/en-us/security/blog/feed/"
        Trust = "High"
        Type = "RSS"
    }
)

$includeKeywords = @(
    "windows",
    "microsoft defender",
    "defender",
    "powershell",
    "ransomware",
    "malware",
    "trojan",
    "stealer",
    "infostealer",
    "credential",
    "edge",
    "browser",
    "office",
    "phishing",
    "endpoint",
    "lateral movement",
    "persistence"
)

$excludeKeywords = @(
    "ics",
    "industrial control",
    "ot",
    "scada"
)

function Write-JsonFile {
    param(
        [string]$Path,
        $Object,
        [int]$Depth = 12
    )

    $json = ConvertTo-Json -InputObject $Object -Depth $Depth
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function Get-PythonCommand {
    $settingsPath = Join-Path $PSScriptRoot "codex-monitor.settings.json"
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
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

function Get-StateDbPath {
    param(
        [string]$ConfiguredStateDbPath,
        [string]$LegacyStatePath
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredStateDbPath)) {
        return $ConfiguredStateDbPath
    }

    if (-not [string]::IsNullOrWhiteSpace($env:CODEX_MONITOR_STATEDBPATH)) {
        return $env:CODEX_MONITOR_STATEDBPATH
    }

    $settingsPath = Join-Path $PSScriptRoot "codex-monitor.settings.json"
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.StateDbPath)) {
                return (Resolve-SettingsPathValue -Value ([string]$settings.StateDbPath) -SettingsPath $settingsPath)
            }
        } catch {
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($LegacyStatePath)) {
        $legacyParent = Split-Path -Path $LegacyStatePath -Parent
        if (-not [string]::IsNullOrWhiteSpace($legacyParent) -and $legacyParent -ne $PSScriptRoot) {
            return (Join-Path $legacyParent "ioc-store.db")
        }
    }

    return (Join-Path $PSScriptRoot "state\ioc-store.db")
}

function Read-LegacyStateFile {
    param([string]$Path)

    if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path)) {
        try {
            return (Get-Content $Path -Raw | ConvertFrom-Json)
        } catch {
        }
    }

    return $null
}

function Get-SqliteState {
    param(
        [string]$DbPath,
        [string]$Namespace,
        [string]$Key
    )

    $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("state-get", "--namespace", $Namespace, "--key", $Key)
    $payload = $raw | ConvertFrom-Json
    if ($payload.found) {
        return $payload.value
    }
    return $null
}

function Save-SqliteState {
    param(
        [string]$DbPath,
        [string]$Namespace,
        [string]$Key,
        $Object,
        [int]$Depth = 12
    )

    $json = ConvertTo-Json -InputObject $Object -Depth $Depth
    $tempPath = [System.IO.Path]::GetTempFileName()
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)
        [void](Invoke-StateStore -DbPath $DbPath -Arguments @("state-put", "--namespace", $Namespace, "--key", $Key, "--input", $tempPath))
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            [System.IO.File]::Delete($tempPath)
        }
    }
}

function Write-MdLine {
    param([string]$Text = "")
    Add-Content -LiteralPath $mdFile -Value $Text
}

function Get-FeedItemDateUtc {
    param($Item)

    foreach ($propertyName in @("pubDate", "updated", "published")) {
        $value = [string]$Item.$propertyName
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            try {
                return ([datetimeoffset]::Parse($value)).UtcDateTime
            } catch {
            }
        }
    }

    return $null
}

function Get-FeedItemLink {
    param($Item)

    if ($Item.link -is [string]) {
        return [string]$Item.link
    }

    if ($Item.link.href) {
        return [string]$Item.link.href
    }

    if ($Item.origLink) {
        return [string]$Item.origLink
    }

    return ""
}

function Get-FeedItemSummaryText {
    param($Item)

    foreach ($propertyName in @("description", "summary", "content")) {
        $value = $Item.$propertyName
        if ($value) {
            return [string]$value
        }
    }

    return ""
}

function Get-FeedItems {
    param($Feed)

    $response = Invoke-RestMethod -Uri $Feed.Url -TimeoutSec 60

    if ($response.rss.channel.item) {
        return @($response.rss.channel.item)
    }

    if ($response.feed.entry) {
        return @($response.feed.entry)
    }

    return @()
}

function Test-ItemRelevance {
    param(
        [string]$Title,
        [string]$Summary
    )

    $haystack = ("{0}`n{1}" -f $Title, $Summary).ToLowerInvariant()

    foreach ($word in $excludeKeywords) {
        if ($haystack -like "*$word*") {
            return $false
        }
    }

    foreach ($word in $includeKeywords) {
        if ($haystack -like "*$word*") {
            return $true
        }
    }

    return $false
}

function Get-ItemIdentity {
    param(
        [string]$FeedName,
        [string]$Title,
        [string]$Link
    )

    return "{0}|{1}|{2}" -f $FeedName.Trim(), $Title.Trim(), $Link.Trim()
}

$resolvedStateDbPath = Get-StateDbPath -ConfiguredStateDbPath $StateDbPath -LegacyStatePath $StatePath
$state = Get-SqliteState -DbPath $resolvedStateDbPath -Namespace "threat_rss" -Key "feed_state"
if ($null -eq $state) {
    $legacyState = Read-LegacyStateFile -Path $StatePath
    if ($null -ne $legacyState) {
        Save-SqliteState -DbPath $resolvedStateDbPath -Namespace "threat_rss" -Key "feed_state" -Object $legacyState
        $state = $legacyState
    }
}
if ($null -eq $state) {
    $state = [PSCustomObject]@{
        SeenIds = @()
        LastRunUtc = $null
    }
}

$seenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($id in @($state.SeenIds)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$id)) {
        [void]$seenIds.Add([string]$id)
    }
}

$startUtc = (Get-Date).ToUniversalTime().AddHours(-1 * $LookbackHours)
$newRelevantItems = @()

foreach ($feed in $feeds) {
    try {
        $items = Get-FeedItems -Feed $feed
    } catch {
        $newRelevantItems += [PSCustomObject]@{
            FeedName = $feed.Name
            FeedUrl = $feed.Url
            Title = "Feed retrieval failed"
            Link = $feed.Url
            PublishedUtc = $null
            Summary = $_.Exception.Message
            Relevance = "Error"
            Identity = Get-ItemIdentity -FeedName $feed.Name -Title "Feed retrieval failed" -Link $feed.Url
        }
        continue
    }

    foreach ($item in $items) {
        $title = [string]$item.title
        $link = Get-FeedItemLink -Item $item
        $summary = Get-FeedItemSummaryText -Item $item
        $publishedUtc = Get-FeedItemDateUtc -Item $item

        if ($publishedUtc -and $publishedUtc -lt $startUtc) {
            continue
        }

        $identity = Get-ItemIdentity -FeedName $feed.Name -Title $title -Link $link
        if ($seenIds.Contains($identity)) {
            continue
        }

        if (-not (Test-ItemRelevance -Title $title -Summary $summary)) {
            [void]$seenIds.Add($identity)
            continue
        }

        $newRelevantItems += [PSCustomObject]@{
            FeedName = $feed.Name
            FeedUrl = $feed.Url
            Title = $title
            Link = $link
            PublishedUtc = if ($publishedUtc) { $publishedUtc.ToString("o") } else { $null }
            Summary = $summary
            Relevance = "Relevant"
            Identity = $identity
        }

        [void]$seenIds.Add($identity)
    }
}

$state = [PSCustomObject]@{
    SeenIds = @($seenIds)
    LastRunUtc = $collectionTimeUtc
}

Save-SqliteState -DbPath $resolvedStateDbPath -Namespace "threat_rss" -Key "feed_state" -Object $state

$iocFollowUp = @()
if (@($newRelevantItems | Where-Object { $_.Relevance -eq "Relevant" }).Count -gt 0) {
    if ($RunTripwireCheckOnMatch -and (Test-Path $tripwireScriptPath)) {
        $tripwireOutput = & powershell -ExecutionPolicy Bypass -File $tripwireScriptPath -Mode Check 2>&1
        $iocFollowUp += [PSCustomObject]@{
            Mode = "TripwireCheck"
            Output = @($tripwireOutput)
        }
    }

    if ($RunBaselineOnMatch -and (Test-Path $iocScriptPath)) {
        $baselineOutput = & powershell -ExecutionPolicy Bypass -File $iocScriptPath -Mode Baseline 2>&1
        $iocFollowUp += [PSCustomObject]@{
            Mode = "Baseline"
            Output = @($baselineOutput)
        }
    }

    if ($RunDeepOnMatch -and (Test-Path $iocScriptPath)) {
        $deepOutput = & powershell -ExecutionPolicy Bypass -File $iocScriptPath -Mode Deep 2>&1
        $iocFollowUp += [PSCustomObject]@{
            Mode = "Deep"
            Output = @($deepOutput)
        }
    }
}

$report = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        CollectionTimeUtc = $collectionTimeUtc
        StateDbPath = $resolvedStateDbPath
        LookbackHours = $LookbackHours
        FeedCount = @($feeds).Count
        RelevantItemCount = @($newRelevantItems | Where-Object { $_.Relevance -eq "Relevant" }).Count
    }
    Feeds = $feeds
    NewItems = @($newRelevantItems | Sort-Object PublishedUtc -Descending)
    IocFollowUp = @($iocFollowUp)
}

if ($Export) {
Write-JsonFile -Path $jsonFile -Object $report

Set-Content -LiteralPath $mdFile -Value "# Threat RSS Report`r`n"
Write-MdLine ""
Write-MdLine ("CollectionTimeUtc: {0}" -f $collectionTimeUtc)
Write-MdLine ("LookbackHours: {0}" -f $LookbackHours)
Write-MdLine ("Relevant items: {0}" -f $report.Metadata.RelevantItemCount)
Write-MdLine ""
Write-MdLine "## Feeds"
Write-MdLine ""
foreach ($feed in $feeds) {
    Write-MdLine ("- {0}: {1}" -f $feed.Name, $feed.Url)
}
Write-MdLine ""
Write-MdLine "## New Relevant Items"
Write-MdLine ""

if (@($report.NewItems).Count -eq 0) {
    Write-MdLine "_No new relevant items matched the current filters._"
} else {
    foreach ($item in $report.NewItems) {
        Write-MdLine ("### {0}" -f $item.Title)
        Write-MdLine ""
        Write-MdLine ("- Feed: {0}" -f $item.FeedName)
        Write-MdLine ("- PublishedUtc: {0}" -f $item.PublishedUtc)
        Write-MdLine ("- Link: {0}" -f $item.Link)
        Write-MdLine ("- Summary: {0}" -f (($item.Summary -replace '\s+', ' ').Trim()))
        Write-MdLine ""
    }
}
}

$rssReportId = [IO.Path]::GetFileNameWithoutExtension($jsonFile)
$rssFindings = @($report.NewItems | ForEach-Object -Begin { $i = 0 } -Process {
    $item = $_; $result = [PSCustomObject]@{ finding_id = "$rssReportId-finding-$i"; finding_sequence = $i; category = "threat_rss"; severity = "medium"; classification = [string]$item.Relevance; title = [string]$item.Title; summary = [string]$item.Summary; evidence = $item; csf_mapping = "DE.CM"; guardrail_state = ""; response_state = "open" }; $i++; $result
})
$rssEnvelope = [PSCustomObject]@{ collector_run = [PSCustomObject]@{ collector_run_id = "$rssReportId-collector"; collector_name = "threat_rss"; started_at = $collectionTimeUtc; completed_at = $collectionTimeUtc; outcome = "success"; summary = [PSCustomObject]@{ FeedCount = $report.Metadata.FeedCount; RelevantItemCount = $report.Metadata.RelevantItemCount } }; report = [PSCustomObject]@{ report_id = $rssReportId; collector_run_id = "$rssReportId-collector"; report_type = "threat_rss"; collection_time_utc = $collectionTimeUtc; overall_status = if ([int]$report.Metadata.RelevantItemCount -gt 0) { "attention" } else { "clear" }; severity = if ([int]$report.Metadata.RelevantItemCount -gt 0) { "medium" } else { "informational" }; summary = $report.Metadata; export_json_path = $(if ($Export) { $jsonFile } else { "" }); export_markdown_path = $(if ($Export) { $mdFile } else { "" }) }; findings = $rssFindings }
$rssTemp = [IO.Path]::GetTempFileName()
try { [IO.File]::WriteAllText($rssTemp, (ConvertTo-Json $rssEnvelope -Depth 12), (New-Object Text.UTF8Encoding($false))); [void](Invoke-StateStore -DbPath $resolvedStateDbPath -Arguments @("persist-collector-report", "--input", $rssTemp)) } finally { if (Test-Path $rssTemp) { [IO.File]::Delete($rssTemp) } }

if ($Export -and [int]$report.Metadata.RelevantItemCount -gt 0) {
    $topItems = @($report.NewItems | Select-Object -First 3)
    $detailLines = @($topItems | ForEach-Object { "{0} ({1})" -f $_.Title, $_.FeedName })
    $alert = [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            AlertType = "ThreatRss"
            ComputerName = $env:COMPUTERNAME
            CollectionTimeUtc = $collectionTimeUtc
            Severity = "Medium"
            RelevantItemCount = [int]$report.Metadata.RelevantItemCount
            SourceReport = $jsonFile
        }
        Summary = [PSCustomObject]@{
            Title = "Codex threat feed monitor found relevant advisories"
            Message = "{0} relevant advisory item(s) found in the monitored feeds." -f [int]$report.Metadata.RelevantItemCount
            DetailLines = @($detailLines)
        }
        NewItems = @($report.NewItems)
        IocFollowUp = @($report.IocFollowUp)
    }

    $alertJson = "$alertBase.json"
    $alertMd = "$alertBase.md"
    Write-JsonFile -Path $alertJson -Object $alert
    Set-Content -LiteralPath $alertMd -Value "# Codex Threat Feed Alert`r`n"
    Add-Content -LiteralPath $alertMd -Value ""
    Add-Content -LiteralPath $alertMd -Value ("Severity: {0}" -f $alert.Metadata.Severity)
    Add-Content -LiteralPath $alertMd -Value ("RelevantItemCount: {0}" -f $alert.Metadata.RelevantItemCount)
    Add-Content -LiteralPath $alertMd -Value ("SourceReport: {0}" -f $alert.Metadata.SourceReport)
    Add-Content -LiteralPath $alertMd -Value ""
    foreach ($item in $alert.NewItems) {
        Add-Content -LiteralPath $alertMd -Value ("- {0} ({1})" -f $item.Title, $item.FeedName)
    }
    Write-Host ("Alert JSON written to: {0}" -f $alertJson)
    Write-Host ("Alert Markdown written to: {0}" -f $alertMd)
}

if ($Export) { Write-Host ("JSON written to: {0}" -f $jsonFile); Write-Host ("Markdown written to: {0}" -f $mdFile) }

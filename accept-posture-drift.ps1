[CmdletBinding(DefaultParameterSetName = 'ByIndex')]
param(
    [string]$ReportPath,

    [string]$ReportId,

    [Parameter(ParameterSetName = 'ByIndex')]
    [int]$FindingIndex,

    [Parameter(ParameterSetName = 'ById')]
    [string]$FindingId,

    [string]$Reason,

    [string]$AcceptedBy,

    [string]$ExpiresUtc,

    [string]$StateDbPath = (Join-Path $PSScriptRoot 'state\ioc-store.db')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PythonCommand {
    foreach ($candidate in @('py', 'python')) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            if ($command.Name -eq 'py') { return @('py', '-3') }
            if ($null -ne $command.Source -and $command.Source.Length -gt 0) {
                return @($command.Source)
            }
            return @($command.Name)
        }
    }
    throw 'Python is required to update the accepted-drift registry.'
}

function Get-ReportFindings {
    param([Parameter(Mandatory = $true)][object]$Report)
    $candidates = @()
    foreach ($key in @('Changes', 'Findings', 'Drift', 'Items')) {
        if ($null -ne $Report.PSObject.Properties[$key]) {
            $value = @($Report.$key)
            if (@($value).Count -gt 0) { $candidates += $value }
        }
    }
    return @($candidates | Where-Object { $null -ne $_ })
}

function Get-PropertyText {
    param(
        [object]$Object,
        [string]$Name,
        [string]$Default = ''
    )
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    $value = $property.Value
    if ($null -eq $value) { return $Default }
    $text = [string]$value
    if ([string]::IsNullOrWhiteSpace($text)) { return $Default }
    return $text
}

function Get-SectionNameFromCategory {
    param([string]$Category)
    $value = ''
    if ($null -ne $Category) { $value = [string]$Category }
    switch ($value.ToLowerInvariant()) {
        'appintegrity' { return 'AppIntegrityBaseline' }
        'securitycontrol' { return 'SecurityControlBaseline' }
        'loggingaudit' { return 'LoggingAuditBaseline' }
        'scheduledtask' { return 'RuntimeDrift' }
        'service' { return 'RuntimeDrift' }
        'autorun' { return 'RuntimeDrift' }
        default { return 'RuntimeDrift' }
    }
}

function Get-CurrentValueText {
    param([object]$Finding)
    foreach ($name in @('CurrentValue', 'NewValue', 'Value', 'Hash', 'Sha256', 'CurrentHash', 'ObservedValue', 'CurrentText')) {
        $text = Get-PropertyText -Object $Finding -Name $name
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            return $text
        }
    }
    return ''
}

function Get-FindingId {
    param([object]$Finding)
    foreach ($name in @('FindingId', 'Id', 'Key', 'ReportItemId', 'Name', 'Path')) {
        $text = Get-PropertyText -Object $Finding -Name $name
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            return $text
        }
    }
    return ''
}

function Test-RegexAny {
    param(
        [string]$Text,
        [string[]]$Patterns
    )
    foreach ($pattern in $Patterns) {
        if ($Text -match $pattern) { return $true }
    }
    return $false
}

function Test-DangerousTripwireFinding {
    param([object]$Finding)

    $section = Get-PropertyText -Object $Finding -Name 'Section'
    if ([string]::IsNullOrWhiteSpace($section)) {
        $section = Get-SectionNameFromCategory -Category (Get-PropertyText -Object $Finding -Name 'Category')
    }
    $name = Get-PropertyText -Object $Finding -Name 'ItemName'
    if ([string]::IsNullOrWhiteSpace($name)) { $name = Get-PropertyText -Object $Finding -Name 'Name' }
    $itemType = Get-PropertyText -Object $Finding -Name 'ItemType'
    $ruleId = Get-PropertyText -Object $Finding -Name 'MatchedRuleId'
    $classification = Get-PropertyText -Object $Finding -Name 'Classification'
    $severity = Get-PropertyText -Object $Finding -Name 'Severity'
    $path = Get-PropertyText -Object $Finding -Name 'Path'
    $text = @(
        $section,
        $name,
        $itemType,
        $ruleId,
        $classification,
        $severity,
        $path,
        (Get-CurrentValueText -Finding $Finding),
        (Get-PropertyText -Object $Finding -Name 'Interpretation'),
        (Get-PropertyText -Object $Finding -Name 'Notes')
    ) -join ' | '

    $dangerPatterns = @(
        'defender.*(disable|disabled|off|weak|exclusion)',
        'firewall.*(disable|disabled|off)',
        'security.*log.*(unavailable|missing|disable|disabled)',
        'powershell.*logging.*(disable|disabled|weak)',
        'trusted.*tool.*(missing|unsigned|invalid|untrusted)',
        'temp',
        'downloads',
        'appdata',
        'encodedcommand',
        'download',
        'invoke-webrequest',
        '\biwr\b',
        '\bcurl\b',
        '\bwget\b',
        'mshta',
        'rundll32',
        'regsvr32',
        'wscript',
        'cscript'
    )

    if ($ruleId -match '^guardrail-') {
        if (Test-RegexAny -Text $text -Patterns $dangerPatterns) {
            return $true
        }
    }

    if ($section -match 'SecurityControlBaseline|LoggingAuditBaseline') {
        if (Test-RegexAny -Text $text -Patterns @(
            'defender.*(disable|disabled|off|weak|exclusion)',
            'firewall.*(disable|disabled|off)',
            'uac.*weaken',
            'remote desktop',
            'local administr',
            'shared folder',
            'bitlocker.*disable',
            'secure boot.*disable',
            'tpm.*unavail',
            'security.*log.*(unavailable|missing)',
            'powershell.*logging.*(disable|disabled|weak)',
            'audit policy.*weaken',
            'event log.*retention.*reduc',
            'trusted.*tool.*(missing|unsigned|invalid|unexpected)'
        )) {
            return $true
        }
    }

    if ($section -match 'RuntimeDrift') {
        if (Test-RegexAny -Text $text -Patterns @(
            'temp',
            'downloads',
            'appdata',
            'encodedcommand',
            'cmd\s*/c.*(http|https|download)',
            'invoke-webrequest',
            '\biwr\b',
            '\bcurl\b',
            '\bwget\b',
            'mshta',
            'rundll32',
            'regsvr32',
            'wscript',
            'cscript'
        )) {
            return $true
        }
    }

    return $false
}

function Get-EligibleFindings {
    param([Parameter(Mandatory = $true)][object[]]$Findings)
    $eligible = @()
    $index = 1
    foreach ($finding in $Findings) {
        if ($null -eq $finding) { continue }
        $section = Get-PropertyText -Object $finding -Name 'Section'
        if ([string]::IsNullOrWhiteSpace($section)) {
            $section = Get-SectionNameFromCategory -Category (Get-PropertyText -Object $finding -Name 'Category')
        }
        $itemName = Get-PropertyText -Object $finding -Name 'ItemName'
        if ([string]::IsNullOrWhiteSpace($itemName)) { $itemName = Get-PropertyText -Object $finding -Name 'Name' }
        $currentValue = Get-CurrentValueText -Finding $finding
        $findingId = Get-FindingId -Finding $finding
        if ([string]::IsNullOrWhiteSpace($itemName) -and [string]::IsNullOrWhiteSpace($findingId)) { continue }
        $isAcceptedDrift = $false
        if (-not [string]::IsNullOrWhiteSpace((Get-PropertyText -Object $finding -Name 'IsAcceptedDrift'))) {
            $isAcceptedDrift = [bool](Get-PropertyText -Object $finding -Name 'IsAcceptedDrift')
        }
        if ($isAcceptedDrift) { continue }
        $dangerous = Test-DangerousTripwireFinding -Finding $finding
        $eligible += [pscustomobject]@{
            Index = $index
            Finding = $finding
            FindingId = $findingId
            Section = $section
            ItemName = $itemName
            ItemType = Get-PropertyText -Object $finding -Name 'ItemType'
            Field = if ([string]::IsNullOrWhiteSpace((Get-PropertyText -Object $finding -Name 'Field'))) { 'CurrentValue' } else { Get-PropertyText -Object $finding -Name 'Field' }
            CurrentValue = $currentValue
            Dangerous = $dangerous
            MatchedRuleId = Get-PropertyText -Object $finding -Name 'MatchedRuleId'
            MatchedRuleDescription = Get-PropertyText -Object $finding -Name 'MatchedRuleDescription'
            Classification = Get-PropertyText -Object $finding -Name 'Classification'
            Severity = Get-PropertyText -Object $finding -Name 'Severity'
        }
        $index++
    }
    return @($eligible)
}

function Show-EligibleFindings {
    param([object[]]$EligibleFindings)
    if (@($EligibleFindings).Count -eq 0) {
        Write-Host 'No accept-eligible findings were found in the report.'
        return
    }
    Write-Host 'Accept-eligible findings:'
    foreach ($entry in $EligibleFindings) {
        $summary = if ($entry.CurrentValue) { $entry.CurrentValue } else { '<no current value captured>' }
        $prefix = if ($entry.Dangerous) { '[DANGEROUS] ' } else { '' }
        Write-Host ('[{0}] {1}{2} | {3} | {4} | {5}' -f $entry.Index, $prefix, $entry.Section, $entry.ItemName, $entry.MatchedRuleId, $summary)
    }
}

function Get-PersistedReportAsLegacyShape {
    param([Parameter(Mandatory = $true)][string]$Id)
    $iocStore = Join-Path $PSScriptRoot 'ioc_store.py'
    $raw = & 'C:\Windows\py.exe' -3 $iocStore --db ([IO.Path]::GetFullPath($StateDbPath)) get-persisted-report --report-id $Id
    if ($LASTEXITCODE -ne 0) { throw "Unable to read persisted report: $Id" }
    $detail = $raw | ConvertFrom-Json -ErrorAction Stop
    if (-not [bool]$detail.found) { throw "Persisted report not found: $Id" }
    $changes = @($detail.findings | ForEach-Object {
        $evidence = $_.evidence
        [pscustomobject]@{ FindingId = [string]$_.finding_id; Category = [string]$_.category; Section = [string]$_.category; Name = [string]$_.title; ItemName = [string]$_.title; ItemType = [string]$_.category; Field = 'CurrentValue'; CurrentValue = [string]$evidence.new_value; OldValue = [string]$evidence.old_value; BaselineValue = [string]$evidence.old_value; Severity = [string]$_.severity; Classification = [string]$_.classification; CsfMapping = [string]$_.csf_mapping; MatchedRuleId = [string]$evidence.rule_id; MatchedRuleDescription = [string]$evidence.rule_description; GuardrailMatched = ([string]$_.guardrail_state -eq 'protected'); GuardrailReason = [string]$evidence.guardrail_reason; IsAcceptedDrift = ([string]$_.response_state -eq 'accepted') }
    })
    return [pscustomobject]@{ ReportId = [string]$detail.report.report_id; Changes = $changes; ExportPath = [string]$detail.report.export_json_path }
}

if (-not [string]::IsNullOrWhiteSpace($ReportId)) {
    if ($PSCmdlet.ParameterSetName -ne 'ById') { throw 'Persisted-report acceptance requires -FindingId.' }
    $report = Get-PersistedReportAsLegacyShape -Id $ReportId
    $ReportPath = [string]$report.ExportPath
} else {
    if (-not (Test-Path -LiteralPath $ReportPath)) { throw "ReportPath not found: $ReportPath" }
    $report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
}
$findings = @(Get-EligibleFindings -Findings (Get-ReportFindings -Report $report))

if (@($findings).Count -eq 0) {
    Show-EligibleFindings -EligibleFindings $findings
    throw 'No accept-eligible findings were available.'
}

Show-EligibleFindings -EligibleFindings $findings

$selected = $null
if ($PSCmdlet.ParameterSetName -eq 'ByIndex') {
    $selected = $findings | Where-Object { $_.Index -eq $FindingIndex } | Select-Object -First 1
} else {
    $selected = $findings | Where-Object { $_.FindingId -eq $FindingId } | Select-Object -First 1
}

if ($null -eq $selected) {
    throw 'Specify -FindingIndex or -FindingId to create an acceptance.'
}

$finding = $selected.Finding

if ([string]::IsNullOrWhiteSpace($Reason)) {
    throw 'Reason is required.'
}

if (Test-DangerousTripwireFinding -Finding $finding) {
    throw "Refusing to create accepted drift for dangerous finding: $($selected.ItemName)"
}

if ([string]::IsNullOrWhiteSpace($AcceptedBy)) {
    $AcceptedBy = [Environment]::UserName
}

$expiresValue = $null
if (-not [string]::IsNullOrWhiteSpace($ExpiresUtc)) {
    $parsed = $null
    if (-not [DateTimeOffset]::TryParse($ExpiresUtc, [ref]$parsed)) {
        throw "ExpiresUtc is not a valid UTC timestamp: $ExpiresUtc"
    }
    $expiresValue = $parsed.ToUniversalTime().ToString('o')
}

$currentValue = [string]$selected.CurrentValue
$baselineValue = [string]$finding.BaselineValue
if ([string]::IsNullOrWhiteSpace($baselineValue)) { $baselineValue = [string]$finding.OldValue }
if ([string]::IsNullOrWhiteSpace($baselineValue)) { $baselineValue = [string]$finding.PreviousValue }
if ($null -eq $baselineValue) { $baselineValue = '' }
$sourceReportId = [string]$report.ReportId
if ([string]::IsNullOrWhiteSpace($sourceReportId)) { $sourceReportId = [string]$report.Id }
if ([string]::IsNullOrWhiteSpace($sourceReportId)) { $sourceReportId = [IO.Path]::GetFileNameWithoutExtension($ReportPath) }
$sourceReportPath = if (-not [string]::IsNullOrWhiteSpace($ReportPath) -and (Test-Path -LiteralPath $ReportPath)) { (Resolve-Path -LiteralPath $ReportPath).Path } else { '' }
$acceptedUtc = [DateTimeOffset]::UtcNow.ToString('o')
$acceptanceId = ('ACC-{0}-{1}' -f ([DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')), ([System.Guid]::NewGuid().ToString('N').Substring(0, 8)))
$itemName = [string]$selected.ItemName
$section = [string]$selected.Section
$itemType = [string]$selected.ItemType
$field = [string]$selected.Field
$matchedRuleId = [string]$selected.MatchedRuleId
$matchedRuleDescription = [string]$selected.MatchedRuleDescription
$csfMapping = [string]$finding.CsfMapping
if ([string]::IsNullOrWhiteSpace($csfMapping)) { $csfMapping = [string]$finding.CsfMappingText }

$acceptanceEntry = [ordered]@{
    AcceptanceId = $acceptanceId
    Enabled = $true
    Scope = 'exact'
    Section = $section
    ItemName = $itemName
    ItemType = $itemType
    Field = $field
    AcceptedCurrentValue = $currentValue
    BaselineValue = $baselineValue
    MatchedRuleId = $matchedRuleId
    MatchedRuleDescription = $matchedRuleDescription
    Reason = $Reason
    AcceptedBy = $AcceptedBy
    AcceptedUtc = $acceptedUtc
    ExpiresUtc = $expiresValue
    SourceReportId = $sourceReportId
    SourceReportPath = $sourceReportPath
    CsfMapping = $csfMapping
    CreatedUtc = $acceptedUtc
    CreatedByAppVersion = 'accept-posture-drift.ps1'
}

$tempJson = [IO.Path]::Combine([IO.Path]::GetTempPath(), ([IO.Path]::GetRandomFileName() + '.json'))
try {
    $payloadJson = @{
        schema_version = 1
        entries = @($acceptanceEntry)
    } | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($tempJson, $payloadJson, (New-Object System.Text.UTF8Encoding($false)))

    $iocStore = Join-Path $PSScriptRoot 'ioc_store.py'
    $dbPath = [IO.Path]::GetFullPath($StateDbPath)
    $stateDir = Split-Path -Parent $dbPath
    if (-not [string]::IsNullOrWhiteSpace($stateDir) -and -not (Test-Path -LiteralPath $stateDir)) {
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    }

    $args = @($iocStore, '--db', $dbPath, 'accepted-drift-import-json', '--input', $tempJson)
    $pythonExe = 'C:\Windows\py.exe'
    $pythonArgs = @('-3')
    if (-not (Test-Path -LiteralPath $pythonExe)) {
        $pythonCommand = Get-PythonCommand
        $pythonExe = [string]$pythonCommand[0]
        $pythonArgs = @()
        if (@($pythonCommand).Count -gt 1) { $pythonArgs += @($pythonCommand)[1..(@($pythonCommand).Count - 1)] }
    }
    $tempOut = [IO.Path]::GetTempFileName()
    $tempErr = [IO.Path]::GetTempFileName()
    try {
        $processArgs = @()
        if ($pythonArgs.Count -gt 0) { $processArgs += $pythonArgs }
        $processArgs += $args
        $process = Start-Process -FilePath $pythonExe -ArgumentList $processArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tempOut -RedirectStandardError $tempErr
        $stdout = if (Test-Path -LiteralPath $tempOut) { Get-Content -LiteralPath $tempOut -Raw } else { '' }
        $stderr = if (Test-Path -LiteralPath $tempErr) { Get-Content -LiteralPath $tempErr -Raw } else { '' }
        $output = ($stdout + $stderr).Trim()
        if ($process.ExitCode -ne 0) {
            throw "SQLite import failed: $output"
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempOut) { Remove-Item -LiteralPath $tempOut -Force }
        if (Test-Path -LiteralPath $tempErr) { Remove-Item -LiteralPath $tempErr -Force }
    }

    Write-Host "AcceptanceId: $acceptanceId"
    Write-Host "Accepted item: $section / $itemName"
    Write-Host "Accepted current value: $currentValue"
    Write-Host 'Reminder: acceptance is exact, local, and does not disable future detection.'
    if ($output) { Write-Host $output }
}
finally {
    if (Test-Path -LiteralPath $tempJson) {
        Remove-Item -LiteralPath $tempJson -Force
    }
}


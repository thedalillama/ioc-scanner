param(
    [ValidateSet("Baseline", "Deep", "IOC")]
    [string]$Mode = "Baseline",

    [string]$IocPath
)

$ErrorActionPreference = "SilentlyContinue"

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$computerName = $env:COMPUTERNAME
$collectionTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
$outBase = Join-Path $PSScriptRoot ("HOST_IOC_{0}_{1}" -f $Mode.ToUpperInvariant(), $timestamp)
$jsonFile = "$outBase.json"
$mdFile = "$outBase.md"

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

function Get-DefaultIocPath {
    if (-not [string]::IsNullOrWhiteSpace($IocPath) -and (Test-Path -LiteralPath $IocPath)) {
        return $IocPath
    }

    $settingsPath = Join-Path $PSScriptRoot "codex-monitor.settings.json"
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.IndicatorExportPath) -and (Test-Path -LiteralPath ([string]$settings.IndicatorExportPath))) {
                return [string]$settings.IndicatorExportPath
            }
        } catch {
        }
    }

    $defaultPath = Join-Path $PSScriptRoot "indicators\feed-indicators-latest.json"
    if (Test-Path -LiteralPath $defaultPath) {
        return $defaultPath
    }

    return $IocPath
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

function Get-KeyEvents {
    param([datetime]$Start)

    [PSCustomObject]@{
        PowerShell4103 = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; StartTime = $Start; Id = 4103 } -MaxEvents 40 |
            Select-Object TimeCreated, Id, ProviderName, Message
        PowerShell4104 = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; StartTime = $Start; Id = 4104 } -MaxEvents 40 |
            Select-Object TimeCreated, Id, ProviderName, Message
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
        [string]$Evidence
    )

    [PSCustomObject]@{
        finding_id = ([guid]::NewGuid().ToString())
        host = $computerName
        scan_time = $collectionTimeUtc
        indicator_type = [string]$Indicator.type
        indicator_value = [string]$Indicator.value
        indicator_source = [string]$Indicator.source
        confidence = [int]$Indicator.confidence
        severity = [string]$Indicator.severity
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
        $Indicators
    )

    $records = @($Dataset.NormalizedIOCRecords)
    $indexes = Build-RecordIndexes -Records $records
    $findings = @()

    foreach ($indicator in @($Indicators | Where-Object { Test-IndicatorStillValid -Indicator $_ })) {
        $indicatorType = ([string]$indicator.type).ToLowerInvariant()
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
            $findings += New-FindingFromMatch -Indicator $indicator -Record $record -Evidence $evidence
        }
    }

    [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            ComputerName = $computerName
            CollectionTimeUtc = $collectionTimeUtc
            Mode = "IOC"
            IocPath = $IocPath
        }
        Indicators = $Indicators
        MatchCount = @($findings).Count
        Findings = @($findings)
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
            Write-MdBlock -Title "Indicator Summary" -Object $Data.IndicatorSummary
            Write-MdBlock -Title "Findings" -Object ($Data.Findings | Select-Object -First 50)
        }
    }
}

switch ($Mode) {
    "Baseline" {
        $data = Build-BaselineDataset
    }
    "Deep" {
        $data = Build-DeepDataset
    }
    "IOC" {
        $resolvedIocPath = Get-DefaultIocPath
        if (-not $resolvedIocPath -or -not (Test-Path -LiteralPath $resolvedIocPath)) {
            throw "IOC mode requires -IocPath pointing to a JSON file, or codex-monitor.settings.json must define a valid IndicatorExportPath."
        }
        $IocPath = $resolvedIocPath
        $indicators = Import-Indicators -Path $IocPath
        $dataset = Build-DeepDataset
        $rawIoc = Test-IocMatch -Dataset $dataset -Indicators $indicators
        $data = [PSCustomObject]@{
            Metadata = [PSCustomObject]@{
                ComputerName = $rawIoc.Metadata.ComputerName
                CollectionTimeUtc = $rawIoc.Metadata.CollectionTimeUtc
                Mode = $rawIoc.Metadata.Mode
                IocPath = $rawIoc.Metadata.IocPath
            }
            IndicatorCount = @($indicators).Count
            IndicatorSummary = Get-IndicatorSummary -Indicators $indicators
            MatchCount = [int]$rawIoc.MatchCount
            Findings = @($rawIoc.Findings)
        }
    }
}

Write-JsonFile -Path $jsonFile -Object $data -Depth 12
Write-ModeMarkdown -Data $data

Write-Output "Mode: $Mode"
Write-Output "Markdown written to: $mdFile"
Write-Output "JSON written to: $jsonFile"

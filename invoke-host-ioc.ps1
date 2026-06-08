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

function Build-BaselineDataset {
    $processes = Get-ProcessMap
    $services = Get-ServiceMap
    $tasks = Get-TaskMap
    $drivers = Get-DriverMap
    $runKeys = Get-RunKeyEntries
    $defender = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureLastUpdated
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet

    $records = @()

    foreach ($p in $processes) {
        $records += New-NormalizedRecord -Category "Process" -Name $p.Name -Path $p.ExecutablePath -Timestamp $p.CreationDate -Owner $p.Owner -ProcessId $p.ProcessId -ParentProcessId $p.ParentProcessId -CommandLine $p.CommandLine -Source @("Win32_Process")
    }
    foreach ($s in $services) {
        $records += New-NormalizedRecord -Category "Service" -Name $s.Name -Path $s.PathName -Owner $s.StartName -ProcessId $s.ProcessId -CommandLine $s.PathName -RegistryPath $s.RegistryPath -Source @("Win32_Service")
    }
    foreach ($d in $drivers) {
        $records += New-NormalizedRecord -Category "Driver" -Name $d.Name -Path $d.PathName -CommandLine $d.PathName -Source @("Win32_SystemDriver") -Notes ("State={0}; StartMode={1}" -f $d.State, $d.StartMode)
    }
    foreach ($t in $tasks) {
        $records += New-NormalizedRecord -Category "ScheduledTask" -Name ("{0}{1}" -f $t.TaskPath, $t.TaskName) -Path ("{0}{1}" -f $t.TaskPath, $t.TaskName) -Timestamp $t.LastRunTime -Owner $t.Author -CommandLine $t.Actions -EventIDs @(4698) -Source @("ScheduledTasks") -Notes ("NextRun={0}; Result={1}" -f $t.NextRunTime, $t.LastTaskResult)
    }
    foreach ($r in $runKeys) {
        $records += New-NormalizedRecord -Category "Autorun" -Name $r.Name -CommandLine $r.CommandLine -RegistryPath $r.RegistryPath -Source @("Registry")
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
            LocalUserCount = @($users).Count
        }
        Processes = @($processes)
        Services = @($services)
        Drivers = @($drivers)
        ScheduledTasks = @($tasks)
        Autoruns = @($runKeys)
        Connections = @($connections)
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

function Test-IocMatch {
    param(
        $Dataset,
        $Indicators
    )

    $records = @($Dataset.NormalizedIOCRecords)
    $iocMatches = @()

    foreach ($record in $records) {
        if ($Indicators.Hashes -and $record.Hash -and $Indicators.Hashes -contains $record.Hash) {
            $iocMatches += [PSCustomObject]@{ IndicatorType = "Hash"; Indicator = $record.Hash; Category = $record.Category; Name = $record.Name; Path = $record.Path; Timestamp = $record.Timestamp; CommandLine = $record.CommandLine; RegistryPath = $record.RegistryPath; Source = @($record.Source); EventIDs = @($record.EventIDs) }
        }
        if ($Indicators.Paths -and $record.Path) {
            foreach ($path in $Indicators.Paths) {
                if ($record.Path -like "*$path*") {
                    $iocMatches += [PSCustomObject]@{ IndicatorType = "Path"; Indicator = $path; Category = $record.Category; Name = $record.Name; Path = $record.Path; Timestamp = $record.Timestamp; CommandLine = $record.CommandLine; RegistryPath = $record.RegistryPath; Source = @($record.Source); EventIDs = @($record.EventIDs) }
                }
            }
        }
        if ($Indicators.ServiceNames -and $record.Category -eq "Service" -and $Indicators.ServiceNames -contains $record.Name) {
            $iocMatches += [PSCustomObject]@{ IndicatorType = "ServiceName"; Indicator = $record.Name; Category = $record.Category; Name = $record.Name; Path = $record.Path; Timestamp = $record.Timestamp; CommandLine = $record.CommandLine; RegistryPath = $record.RegistryPath; Source = @($record.Source); EventIDs = @($record.EventIDs) }
        }
        if ($Indicators.TaskNames -and $record.Category -eq "ScheduledTask") {
            foreach ($taskName in $Indicators.TaskNames) {
                if (Test-ExactTaskIndicatorMatch -Indicator $taskName -TaskRecordName $record.Name) {
                    $iocMatches += [PSCustomObject]@{ IndicatorType = "TaskName"; Indicator = $taskName; Category = $record.Category; Name = $record.Name; Path = $record.Path; Timestamp = $record.Timestamp; CommandLine = $record.CommandLine; RegistryPath = $record.RegistryPath; Source = @($record.Source); EventIDs = @($record.EventIDs) }
                }
            }
        }
        if ($Indicators.RegistryPaths -and $record.RegistryPath) {
            foreach ($regPath in $Indicators.RegistryPaths) {
                if ($record.RegistryPath -like "*$regPath*") {
                    $iocMatches += [PSCustomObject]@{ IndicatorType = "RegistryPath"; Indicator = $regPath; Category = $record.Category; Name = $record.Name; Path = $record.Path; Timestamp = $record.Timestamp; CommandLine = $record.CommandLine; RegistryPath = $record.RegistryPath; Source = @($record.Source); EventIDs = @($record.EventIDs) }
                }
            }
        }
        if ($Indicators.CommandLinePatterns -and $record.CommandLine) {
            foreach ($pattern in $Indicators.CommandLinePatterns) {
                if ($record.CommandLine -match $pattern) {
                    $iocMatches += [PSCustomObject]@{ IndicatorType = "CommandLine"; Indicator = $pattern; Category = $record.Category; Name = $record.Name; Path = $record.Path; Timestamp = $record.Timestamp; CommandLine = $record.CommandLine; RegistryPath = $record.RegistryPath; Source = @($record.Source); EventIDs = @($record.EventIDs) }
                }
            }
        }
        if ($Indicators.FileNames -and $record.Path) {
            foreach ($name in $Indicators.FileNames) {
                if ([IO.Path]::GetFileName($record.Path) -ieq $name) {
                    $iocMatches += [PSCustomObject]@{ IndicatorType = "FileName"; Indicator = $name; Category = $record.Category; Name = $record.Name; Path = $record.Path; Timestamp = $record.Timestamp; CommandLine = $record.CommandLine; RegistryPath = $record.RegistryPath; Source = @($record.Source); EventIDs = @($record.EventIDs) }
                }
            }
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
        MatchCount = @($iocMatches).Count
        Matches = @($iocMatches)
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
            Write-MdBlock -Title "Indicators" -Object $Data.Indicators
            Write-MdBlock -Title "Matches" -Object ($Data.Matches | Select-Object -First 50)
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
        if (-not $IocPath -or -not (Test-Path $IocPath)) {
            throw "IOC mode requires -IocPath pointing to a JSON file."
        }
        $indicators = Get-Content -LiteralPath $IocPath -Raw | ConvertFrom-Json
        $dataset = Build-DeepDataset
        $rawIoc = Test-IocMatch -Dataset $dataset -Indicators $indicators
        $data = [PSCustomObject]@{
            Metadata = [PSCustomObject]@{
                ComputerName = $rawIoc.Metadata.ComputerName
                CollectionTimeUtc = $rawIoc.Metadata.CollectionTimeUtc
                Mode = $rawIoc.Metadata.Mode
                IocPath = $rawIoc.Metadata.IocPath
            }
            Indicators = $indicators | Select-Object Hashes, Paths, ServiceNames, TaskNames, RegistryPaths, CommandLinePatterns, FileNames
            MatchCount = [int]$rawIoc.MatchCount
            Matches = @($rawIoc.Matches | Select-Object IndicatorType, Indicator, Category, Name, Path, Timestamp, CommandLine, RegistryPath, Source, EventIDs)
        }
    }
}

Write-JsonFile -Path $jsonFile -Object $data -Depth 12
Write-ModeMarkdown -Data $data

Write-Output "Mode: $Mode"
Write-Output "Markdown written to: $mdFile"
Write-Output "JSON written to: $jsonFile"

$ErrorActionPreference = "SilentlyContinue"

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outFile = Join-Path $PSScriptRoot ("SYSTEM_SECURITY_BASELINE_{0}.md" -f $timestamp)
$jsonFile = Join-Path $PSScriptRoot ("SYSTEM_SECURITY_BASELINE_{0}.json" -f $timestamp)
$normalizedJsonFile = Join-Path $PSScriptRoot ("SYSTEM_IOC_RECORDS_{0}.json" -f $timestamp)

function Add-Line {
    param(
        [string]$Text = ""
    )

    Add-Content -LiteralPath $outFile -Value $Text
}

function Add-Section {
    param(
        [string]$Title
    )

    Add-Line ""
    Add-Line "## $Title"
    Add-Line ""
}

function Add-Subsection {
    param(
        [string]$Title
    )

    Add-Line ""
    Add-Line "### $Title"
    Add-Line ""
}

function Add-CodeBlock {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    begin {
        Add-Line '```text'
    }

    process {
        if ($null -eq $InputObject) {
            Add-Line ""
        } else {
            Add-Line ([string]$InputObject)
        }
    }

    end {
        Add-Line '```'
    }
}

function Write-ObjectBlock {
    param(
        [string]$Header,
        $Object
    )

    Add-Subsection $Header

    if ($null -eq $Object) {
        Add-Line "_No data returned._"
        return
    }

    $lines = $Object | Out-String -Width 240
    $lines.TrimEnd("`r", "`n").Split([Environment]::NewLine) | Add-CodeBlock
}

function Get-RunKeySnapshot {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $paths) {
        [PSCustomObject]@{
            Path    = $path
            Entries = if (Test-Path $path) {
                (Get-ItemProperty -Path $path |
                    Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider |
                    Out-String -Width 240).Trim()
            } else {
                "Missing"
            }
        }
    }
}

function Get-StartupFolderSnapshot {
    $paths = @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup")
    )

    foreach ($path in $paths) {
        [PSCustomObject]@{
            Path    = $path
            Entries = if (Test-Path $path) {
                (Get-ChildItem -Force $path |
                    Select-Object Name, FullName, LastWriteTime, Attributes |
                    Format-Table -AutoSize |
                    Out-String -Width 240).Trim()
            } else {
                "Missing"
            }
        }
    }
}

function Get-WmiSubscriptionSnapshot {
    [PSCustomObject]@{
        EventFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
            Select-Object Name, Query, EventNamespace
        CommandLineConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
            Select-Object Name, CommandLineTemplate, ExecutablePath
        ActiveScriptConsumers = Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer |
            Select-Object Name, ScriptingEngine, ScriptText
        Bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
            Select-Object Filter, Consumer
    }
}

function Get-NetworkConnectionSnapshot {
    $procMap = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $procMap[$_.ProcessId] = $_ }

    Get-NetTCPConnection -State Established | ForEach-Object {
        $proc = $procMap[$_.OwningProcess]
        [PSCustomObject]@{
            LocalAddress   = $_.LocalAddress
            LocalPort      = $_.LocalPort
            RemoteAddress  = $_.RemoteAddress
            RemotePort     = $_.RemotePort
            ProcessId      = $_.OwningProcess
            ProcessName    = if ($proc) { $proc.Name } else { $null }
            ExecutablePath = if ($proc) { $proc.ExecutablePath } else { $null }
        }
    } | Sort-Object ProcessName, RemoteAddress, RemotePort
}

function Get-UnusualServicesSnapshot {
    Get-CimInstance Win32_Service |
        Where-Object {
            $_.PathName -and
            $_.PathName -notmatch '^"?C:\\Windows\\' -and
            $_.PathName -notmatch '^"?C:\\Program Files( \(x86\))?\\' -and
            $_.PathName -notmatch '^\\SystemRoot\\'
        } |
        Select-Object Name, State, StartMode, PathName, DisplayName |
        Sort-Object Name
}

function Get-StartupApprovedSnapshot {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
    )

    foreach ($path in $paths) {
        [PSCustomObject]@{
            Path    = $path
            Entries = if (Test-Path $path) {
                (Get-ItemProperty -Path $path |
                    Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider |
                    Out-String -Width 240).Trim()
            } else {
                "Missing"
            }
        }
    }
}

function Get-WinlogonSnapshot {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )

    foreach ($path in $paths) {
        [PSCustomObject]@{
            Path    = $path
            Entries = if (Test-Path $path) {
                (Get-ItemProperty -Path $path |
                    Select-Object Shell, Userinit, AutoAdminLogon, DefaultUserName, DefaultDomainName |
                    Out-String -Width 240).Trim()
            } else {
                "Missing"
            }
        }
    }
}

function Get-IFEOSnapshot {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (-not (Test-Path $path)) {
        return "Missing"
    }

    Get-ChildItem -Path $path | ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath
        [PSCustomObject]@{
            ImageName      = $_.PSChildName
            Debugger       = $props.Debugger
            VerifierDlls   = $props.VerifierDlls
            GlobalFlag     = $props.GlobalFlag
            Mitigation     = $props.MitigationOptions
        }
    } | Where-Object { $_.Debugger -or $_.VerifierDlls -or $_.GlobalFlag -or $_.Mitigation }
}

function Get-BrowserExtensionsSnapshot {
    $results = @()

    $firefoxProfilesRoot = Join-Path $env:APPDATA "Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfilesRoot) {
        Get-ChildItem -Path $firefoxProfilesRoot -Directory | ForEach-Object {
            $extFile = Join-Path $_.FullName "extensions.json"
            if (Test-Path $extFile) {
                try {
                    $json = Get-Content -LiteralPath $extFile -Raw | ConvertFrom-Json
                    foreach ($addon in $json.addons) {
                        $results += [PSCustomObject]@{
                            Browser = "Firefox"
                            Profile = $_.Name
                            Name    = $addon.defaultLocale.name
                            Id      = $addon.id
                            Version = $addon.version
                            Active  = $addon.active
                            Source  = $addon.sourceURI
                        }
                    }
                } catch {
                }
            }
        }
    }

    $edgeExtRoot = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data\Default\Extensions"
    if (Test-Path $edgeExtRoot) {
        Get-ChildItem -Path $edgeExtRoot -Directory | ForEach-Object {
            $extId = $_.Name
            Get-ChildItem -Path $_.FullName -Directory | ForEach-Object {
                $manifest = Join-Path $_.FullName "manifest.json"
                if (Test-Path $manifest) {
                    try {
                        $json = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
                        $results += [PSCustomObject]@{
                            Browser = "Edge"
                            Profile = "Default"
                            Name    = $json.name
                            Id      = $extId
                            Version = $json.version
                            Active  = $true
                            Source  = $manifest
                        }
                    } catch {
                    }
                }
            }
        }
    }

    $results
}

function New-NormalizedRecord {
    param(
        [string]$ComputerName,
        [string]$CollectionTimeUtc,
        [string]$Category,
        [string]$Name,
        [string]$Path,
        [string]$Hash,
        [string]$HashAlgorithm,
        $Timestamp,
        [string]$Owner,
        $PID,
        $ParentPID,
        [string]$CommandLine,
        [string]$RegistryPath,
        [object[]]$EventIDs,
        [object[]]$Source,
        [string]$Severity = "Info",
        [string]$Notes = ""
    )

    [PSCustomObject]@{
        ComputerName      = $ComputerName
        CollectionTimeUtc = $CollectionTimeUtc
        Category          = $Category
        Name              = $Name
        Path              = $Path
        Hash              = $Hash
        HashAlgorithm     = $HashAlgorithm
        Timestamp         = if ($Timestamp) { [string]$Timestamp } else { $null }
        Owner             = $Owner
        PID               = $PID
        ParentPID         = $ParentPID
        CommandLine       = $CommandLine
        RegistryPath      = $RegistryPath
        EventIDs          = @($EventIDs)
        Source            = @($Source)
        Severity          = $Severity
        Notes             = $Notes
    }
}

function Get-DetailedProcessSnapshot {
    $userMap = @{}
    Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object {
        $userMap[$_.Id] = $_.UserName
    }

    Get-CimInstance Win32_Process | ForEach-Object {
        [PSCustomObject]@{
            Name            = $_.Name
            ExecutablePath  = $_.ExecutablePath
            CreationDate    = $_.CreationDate
            ProcessId       = $_.ProcessId
            ParentProcessId = $_.ParentProcessId
            CommandLine     = $_.CommandLine
            Owner           = $userMap[$_.ProcessId]
        }
    } | Sort-Object Name, ProcessId
}

function Get-DetailedServiceSnapshot {
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
    } | Sort-Object Name
}

function Get-DriverSnapshot {
    Get-CimInstance Win32_SystemDriver | Select-Object Name, DisplayName, State, StartMode, PathName, ServiceType, ExitCode | Sort-Object Name
}

function Get-DetailedScheduledTaskSnapshot {
    Get-ScheduledTask | ForEach-Object {
        $task = $_
        $info = $task | Get-ScheduledTaskInfo
        [PSCustomObject]@{
            TaskPath    = $task.TaskPath
            TaskName    = $task.TaskName
            State       = $task.State
            Author      = $task.Author
            LastRunTime = $info.LastRunTime
            NextRunTime = $info.NextRunTime
            LastTaskResult = $info.LastTaskResult
            Actions     = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join "; "
            Principal   = ($task.Principal.UserId, $task.Principal.GroupId | Where-Object { $_ }) -join "; "
        }
    } | Sort-Object TaskPath, TaskName
}

function Get-RecentFileSnapshot {
    param(
        [datetime]$Start,
        [int]$MaxFiles = 100
    )

    $paths = @(
        $env:TEMP,
        $env:ProgramData,
        (Join-Path $env:USERPROFILE "Downloads"),
        $env:LOCALAPPDATA
    ) | Where-Object { $_ -and (Test-Path $_) }

    $results = foreach ($path in $paths) {
        Get-ChildItem -Path $path -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -ge $Start.ToUniversalTime() } |
            Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc
    }

    $results | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First $MaxFiles
}

function Get-HashSnapshot {
    param(
        $Files,
        [int]$MaxHashedFiles = 50,
        [int64]$MaxFileSizeBytes = 26214400
    )

    $Files |
        Where-Object { $_.Length -le $MaxFileSizeBytes } |
        Select-Object -First $MaxHashedFiles |
        ForEach-Object {
            $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256
            [PSCustomObject]@{
                FullName         = $_.FullName
                Length           = $_.Length
                LastWriteTimeUtc = $_.LastWriteTimeUtc
                SHA256           = $hash.Hash
            }
        }
}

function Get-LnkSnapshot {
    param(
        [datetime]$Start
    )

    $recentPath = Join-Path $env:APPDATA "Microsoft\Windows\Recent"
    if (-not (Test-Path $recentPath)) {
        return @()
    }

    Get-ChildItem $recentPath -Filter *.lnk -Force |
        Where-Object { $_.LastWriteTimeUtc -ge $Start.ToUniversalTime() } |
        Select-Object FullName, CreationTimeUtc, LastWriteTimeUtc, Length
}

function Get-PrefetchSnapshot {
    param(
        [datetime]$Start
    )

    $prefetchPath = "C:\Windows\Prefetch"
    if (-not (Test-Path $prefetchPath)) {
        return @()
    }

    Get-ChildItem $prefetchPath -Filter *.pf -Force |
        Where-Object { $_.LastWriteTimeUtc -ge $Start.ToUniversalTime() } |
        Select-Object Name, FullName, CreationTimeUtc, LastWriteTimeUtc, Length
}

function Get-CertificateSnapshot {
    $stores = @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")
    foreach ($store in $stores) {
        if (Test-Path $store) {
            Get-ChildItem $store | Select-Object @{Name="StorePath";Expression={$store}}, Subject, Thumbprint, NotBefore, NotAfter, FriendlyName
        }
    }
}

function Get-ScheduledJobSnapshot {
    if (Get-Command Get-ScheduledJob -ErrorAction SilentlyContinue) {
        Get-ScheduledJob | Select-Object Name, Enabled, Command, ExecutionHistoryLength, ID
    } else {
        @()
    }
}

function Get-EventSnapshot {
    param(
        [string]$LogName,
        [int[]]$Ids,
        [datetime]$Start,
        [int]$MaxEvents = 60
    )

    Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $Start; Id = $Ids } -MaxEvents $MaxEvents |
        Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
}

function ConvertTo-NormalizedRecords {
    param(
        [string]$ComputerName,
        [string]$CollectionTimeUtc,
        $Processes,
        $Services,
        $Drivers,
        $Tasks,
        $RecentFiles,
        $Hashes,
        $LnkFiles,
        $PrefetchFiles,
        $Certificates,
        $ScheduledJobs,
        $PowerShellEvents,
        $Events4688,
        $Events4698,
        $Events7045
    )

    $records = @()

    foreach ($item in $Processes) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "Process" -Name $item.Name -Path $item.ExecutablePath -Timestamp $item.CreationDate -Owner $item.Owner -PID $item.ProcessId -ParentPID $item.ParentProcessId -CommandLine $item.CommandLine -Source @("Win32_Process")
    }

    foreach ($item in $Services) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "Service" -Name $item.Name -Path $item.PathName -Owner $item.StartName -PID $item.ProcessId -CommandLine $item.PathName -RegistryPath $item.RegistryPath -Source @("Win32_Service")
    }

    foreach ($item in $Drivers) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "Driver" -Name $item.Name -Path $item.PathName -CommandLine $item.PathName -Source @("Win32_SystemDriver") -Notes ("State={0}; StartMode={1}; ServiceType={2}" -f $item.State, $item.StartMode, $item.ServiceType)
    }

    foreach ($item in $Tasks) {
        $taskPath = "{0}{1}" -f $item.TaskPath, $item.TaskName
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "ScheduledTask" -Name $taskPath -Path $taskPath -Timestamp $item.LastRunTime -Owner $item.Author -CommandLine $item.Actions -EventIDs @(4698) -Source @("ScheduledTasks") -Notes ("NextRun={0}; State={1}; Result={2}" -f $item.NextRunTime, $item.State, $item.LastTaskResult)
    }

    foreach ($item in $RecentFiles) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "RecentFile" -Name ([System.IO.Path]::GetFileName($item.FullName)) -Path $item.FullName -Timestamp $item.LastWriteTimeUtc -Source @("FileSystem") -Notes ("Length={0}" -f $item.Length)
    }

    foreach ($item in $Hashes) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "Hash" -Name ([System.IO.Path]::GetFileName($item.FullName)) -Path $item.FullName -Hash $item.SHA256 -HashAlgorithm "SHA256" -Timestamp $item.LastWriteTimeUtc -Source @("Get-FileHash")
    }

    foreach ($item in $LnkFiles) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "LNK" -Name ([System.IO.Path]::GetFileName($item.FullName)) -Path $item.FullName -Timestamp $item.LastWriteTimeUtc -Source @("RecentItems")
    }

    foreach ($item in $PrefetchFiles) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "Prefetch" -Name $item.Name -Path $item.FullName -Timestamp $item.LastWriteTimeUtc -Source @("Prefetch")
    }

    foreach ($item in $Certificates) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "Certificate" -Name $item.Subject -Path $item.StorePath -Timestamp $item.NotAfter -Source @("CertProvider") -Notes ("Thumbprint={0}; NotBefore={1}; FriendlyName={2}" -f $item.Thumbprint, $item.NotBefore, $item.FriendlyName)
    }

    foreach ($item in $ScheduledJobs) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "ScheduledJob" -Name $item.Name -CommandLine $item.Command -Source @("PSScheduledJob") -Notes ("Enabled={0}; HistoryLength={1}; ID={2}" -f $item.Enabled, $item.ExecutionHistoryLength, $item.ID)
    }

    foreach ($item in $PowerShellEvents) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "PowerShellLog" -Name ("Event {0}" -f $item.Id) -Timestamp $item.TimeCreated -CommandLine $item.Message -EventIDs @($item.Id) -Source @("Microsoft-Windows-PowerShell/Operational")
    }

    foreach ($item in $Events4688) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "EventLog" -Name "Security 4688" -Timestamp $item.TimeCreated -CommandLine $item.Message -EventIDs @(4688) -Source @("Security")
    }

    foreach ($item in $Events4698) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "EventLog" -Name "Security 4698" -Timestamp $item.TimeCreated -CommandLine $item.Message -EventIDs @(4698) -Source @("Security")
    }

    foreach ($item in $Events7045) {
        $records += New-NormalizedRecord -ComputerName $ComputerName -CollectionTimeUtc $CollectionTimeUtc -Category "EventLog" -Name "System 7045" -Timestamp $item.TimeCreated -CommandLine $item.Message -EventIDs @(7045) -Source @("System")
    }

    $records
}

$computerInfo = Get-CimInstance Win32_ComputerSystem
$osInfo = Get-CimInstance Win32_OperatingSystem
$collectionTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
$collectionStart = (Get-Date).AddDays(-7)
$defenderStatus = Get-MpComputerStatus
$defenderPrefs = Get-MpPreference
$physicalDisks = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, Size
$volumes = Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, HealthStatus, OperationalStatus, SizeRemaining, Size
$runKeys = Get-RunKeySnapshot
$startupApproved = Get-StartupApprovedSnapshot
$startupFolders = Get-StartupFolderSnapshot
$winlogonSettings = Get-WinlogonSnapshot
$ifeoEntries = Get-IFEOSnapshot
$wmiSubscriptions = Get-WmiSubscriptionSnapshot
$scheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | Select-Object TaskName, TaskPath, State, Author
$scheduledTaskDetails = Get-DetailedScheduledTaskSnapshot
$listeningPorts = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Sort-Object LocalPort
$establishedConnections = Get-NetworkConnectionSnapshot
$processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath | Sort-Object Name
$detailedProcesses = Get-DetailedProcessSnapshot
$unusualServices = Get-UnusualServicesSnapshot
$detailedServices = Get-DetailedServiceSnapshot
$drivers = Get-DriverSnapshot
$browserExtensions = Get-BrowserExtensionsSnapshot
$localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet
$localAdministrators = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource
$firewallRules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
    Select-Object DisplayName, Enabled, Profile, Direction, Action
$scheduledJobs = Get-ScheduledJobSnapshot
$recentFiles = Get-RecentFileSnapshot -Start $collectionStart
$recentFileHashes = Get-HashSnapshot -Files $recentFiles
$recentLnkFiles = Get-LnkSnapshot -Start $collectionStart
$prefetchFiles = Get-PrefetchSnapshot -Start $collectionStart
$certificates = Get-CertificateSnapshot
$defenderThreats = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 InitialDetectionTime, ThreatName, ActionSuccess, Resources
$recentSystemEvents = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddDays(-3) } -MaxEvents 40 |
    Where-Object { $_.LevelDisplayName -in @('Critical', 'Error') } |
    Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
$recentApplicationEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddDays(-3) } -MaxEvents 40 |
    Where-Object { $_.LevelDisplayName -in @('Critical', 'Error') } |
    Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
$recentPowerShellEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 60 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message
$recent4103 = Get-EventSnapshot -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids @(4103) -Start $collectionStart
$recent4104 = Get-EventSnapshot -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids @(4104) -Start $collectionStart
$recent4688 = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = (Get-Date).AddDays(-3); Id = 4688 } -MaxEvents 60 |
    Select-Object TimeCreated, Id, Message
$recent4698 = Get-EventSnapshot -LogName 'Security' -Ids @(4698) -Start $collectionStart
$recent7045 = Get-EventSnapshot -LogName 'System' -Ids @(7045) -Start $collectionStart
$hostsContent = Get-Content "C:\Windows\System32\drivers\etc\hosts"
$vboxBindings = Get-NetAdapterBinding -AllBindings | Where-Object { $_.ComponentID -eq 'oracle_VBoxNetLwf' } | Select-Object Name, DisplayName, Enabled

$normalizedRecords = ConvertTo-NormalizedRecords -ComputerName $computerInfo.Name -CollectionTimeUtc $collectionTimeUtc -Processes $detailedProcesses -Services $detailedServices -Drivers $drivers -Tasks $scheduledTaskDetails -RecentFiles $recentFiles -Hashes $recentFileHashes -LnkFiles $recentLnkFiles -PrefetchFiles $prefetchFiles -Certificates $certificates -ScheduledJobs $scheduledJobs -PowerShellEvents ($recent4103 + $recent4104) -Events4688 $recent4688 -Events4698 $recent4698 -Events7045 $recent7045

$snapshot = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        ComputerName       = $computerInfo.Name
        UserName           = $env:USERNAME
        CollectionTimeLocal = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
        CollectionTimeUtc  = $collectionTimeUtc
        ScriptName         = "collect-security-baseline.ps1"
        MarkdownReport     = (Split-Path -Leaf $outFile)
        JsonReport         = (Split-Path -Leaf $jsonFile)
        NormalizedJsonReport = (Split-Path -Leaf $normalizedJsonFile)
    }
    SecurityPosture = [PSCustomObject]@{
        DefenderStatus     = $defenderStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, BehaviorMonitorEnabled, NISEnabled, IsTamperProtected, AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge
        DefenderExclusions = $defenderPrefs | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress
        DefenderDetections = @($defenderThreats)
    }
    Persistence = [PSCustomObject]@{
        StartupFolders      = @($startupFolders)
        RunKeys             = @($runKeys)
        StartupApproved     = @($startupApproved)
        WinlogonSettings    = @($winlogonSettings)
        IFEOEntries         = @($ifeoEntries)
        WmiEventFilters     = @($wmiSubscriptions.EventFilters)
        WmiCommandConsumers = @($wmiSubscriptions.CommandLineConsumers)
        WmiScriptConsumers  = @($wmiSubscriptions.ActiveScriptConsumers)
        WmiBindings         = @($wmiSubscriptions.Bindings)
        ScheduledTasks      = @($scheduledTasks)
        DetailedScheduledTasks = @($scheduledTaskDetails)
        ScheduledJobs       = @($scheduledJobs)
        BrowserExtensions   = @($browserExtensions)
    }
    ServicesAndDrivers = [PSCustomObject]@{
        UnusualServices          = @($unusualServices)
        DetailedServices         = @($detailedServices)
        Drivers                  = @($drivers)
        VirtualBoxBridgedFilters = @($vboxBindings)
    }
    Network = [PSCustomObject]@{
        ListeningTcpPorts        = @($listeningPorts)
        EstablishedTcpConnections = @($establishedConnections)
        EnabledInboundAllowRules = @($firewallRules)
    }
    IdentityAndAccess = [PSCustomObject]@{
        LocalUsers          = @($localUsers)
        LocalAdministrators = @($localAdministrators)
    }
    Processes = @($processes)
    DetailedProcesses = @($detailedProcesses)
    HostsFile = @($hostsContent)
    Storage = [PSCustomObject]@{
        PhysicalDisks = @($physicalDisks)
        Volumes       = @($volumes)
    }
    FileArtifacts = [PSCustomObject]@{
        RecentFiles      = @($recentFiles)
        RecentFileHashes = @($recentFileHashes)
        RecentLnkFiles   = @($recentLnkFiles)
        PrefetchFiles    = @($prefetchFiles)
    }
    Certificates = @($certificates)
    Events = [PSCustomObject]@{
        RecentSystemCriticalAndError       = @($recentSystemEvents)
        RecentApplicationCriticalAndError  = @($recentApplicationEvents)
        RecentPowerShellOperational        = @($recentPowerShellEvents)
        RecentPowerShell4103               = @($recent4103)
        RecentPowerShell4104               = @($recent4104)
        RecentSecurity4688                 = @($recent4688)
        RecentSecurity4698                 = @($recent4698)
        RecentSystem7045                   = @($recent7045)
    }
}

$snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonFile -Encoding UTF8
$normalizedRecords | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $normalizedJsonFile -Encoding UTF8

Add-Line "# System Security Baseline"
Add-Line ""
Add-Line ("Date captured: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"))
Add-Line ("Host: [{0}]" -f $computerInfo.Name)
Add-Line ("User context observed: [{0}]" -f $env:USERNAME)
Add-Line "Scope: point-in-time baseline from local host checks, event logs, service state, storage health, persistence locations, and live network/process inspection."

Add-Section "Summary"
Add-Line "- Baseline generated by collect-security-baseline.ps1."
Add-Line "- Review this snapshot as a comparison point for future IOC triage."
Add-Line "- This is a host-state snapshot, not a forensic guarantee of cleanliness."
Add-Line ("- Canonical JSON snapshot: {0}" -f (Split-Path -Leaf $jsonFile))
Add-Line ("- Normalized IOC dataset: {0}" -f (Split-Path -Leaf $normalizedJsonFile))

Add-Section "Current Security Posture"
Write-ObjectBlock -Header "Microsoft Defender Status" -Object (
    $defenderStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, BehaviorMonitorEnabled, NISEnabled, IsTamperProtected, AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge
)
Write-ObjectBlock -Header "Defender Exclusions" -Object (
    $defenderPrefs | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress
)
Write-ObjectBlock -Header "Recent Defender Detections" -Object $defenderThreats

Add-Section "Persistence Baseline"
foreach ($item in $startupFolders) {
    Write-ObjectBlock -Header ("Startup Folder: {0}" -f $item.Path) -Object $item.Entries
}
foreach ($item in $runKeys) {
    Write-ObjectBlock -Header ("Run Key: {0}" -f $item.Path) -Object $item.Entries
}
foreach ($item in $startupApproved) {
    Write-ObjectBlock -Header ("StartupApproved: {0}" -f $item.Path) -Object $item.Entries
}
foreach ($item in $winlogonSettings) {
    Write-ObjectBlock -Header ("Winlogon: {0}" -f $item.Path) -Object $item.Entries
}
Write-ObjectBlock -Header "IFEO Entries" -Object $ifeoEntries
Write-ObjectBlock -Header "WMI Event Filters" -Object $wmiSubscriptions.EventFilters
Write-ObjectBlock -Header "WMI CommandLineEventConsumer" -Object $wmiSubscriptions.CommandLineConsumers
Write-ObjectBlock -Header "WMI ActiveScriptEventConsumer" -Object $wmiSubscriptions.ActiveScriptConsumers
Write-ObjectBlock -Header "WMI Filter-To-Consumer Bindings" -Object $wmiSubscriptions.Bindings
Write-ObjectBlock -Header "Non-Microsoft Scheduled Tasks" -Object $scheduledTasks
Write-ObjectBlock -Header "Detailed Scheduled Tasks" -Object $scheduledTaskDetails
Write-ObjectBlock -Header "Detailed Scheduled Tasks (First 40)" -Object ($scheduledTaskDetails | Select-Object -First 40)
Write-ObjectBlock -Header "PowerShell Scheduled Jobs" -Object $scheduledJobs
Write-ObjectBlock -Header "Browser Extensions" -Object $browserExtensions

Add-Section "Service and Driver Baseline"
Write-ObjectBlock -Header "Services From Unusual Paths" -Object $unusualServices
Write-ObjectBlock -Header "Detailed Services (First 40)" -Object ($detailedServices | Select-Object -First 40)
Write-ObjectBlock -Header "Drivers (First 40)" -Object ($drivers | Select-Object -First 40)
Write-ObjectBlock -Header "VirtualBox Bridged Filter Bindings" -Object $vboxBindings

Add-Section "Network Exposure Baseline"
Write-ObjectBlock -Header "Listening TCP Ports" -Object $listeningPorts
Write-ObjectBlock -Header "Established TCP Connections" -Object $establishedConnections
Write-ObjectBlock -Header "Enabled Inbound Allow Firewall Rules" -Object $firewallRules

Add-Section "Running Process Baseline"
Write-ObjectBlock -Header "Running Processes" -Object $processes
Write-ObjectBlock -Header "Detailed Processes (First 40)" -Object ($detailedProcesses | Select-Object -First 40)

Add-Section "Identity and Access Baseline"
Write-ObjectBlock -Header "Local Users" -Object $localUsers
Write-ObjectBlock -Header "Local Administrators Group Members" -Object $localAdministrators

Add-Section "Hosts File Baseline"
$hostsContent | Add-CodeBlock

Add-Section "Storage and Filesystem Health"
Write-ObjectBlock -Header "Physical Disks" -Object $physicalDisks
Write-ObjectBlock -Header "Volumes" -Object $volumes

Add-Section "File Artifacts"
Write-ObjectBlock -Header "Recent Files (First 40)" -Object ($recentFiles | Select-Object -First 40)
Write-ObjectBlock -Header "Recent File Hashes (First 40)" -Object ($recentFileHashes | Select-Object -First 40)
Write-ObjectBlock -Header "Recent LNK Files (First 40)" -Object ($recentLnkFiles | Select-Object -First 40)
Write-ObjectBlock -Header "Prefetch Files (First 40)" -Object ($prefetchFiles | Select-Object -First 40)
Write-ObjectBlock -Header "Certificates (First 40)" -Object ($certificates | Select-Object -First 40)

Add-Section "Recent Event Baseline"
Write-ObjectBlock -Header "Recent System Critical and Error Events" -Object $recentSystemEvents
Write-ObjectBlock -Header "Recent Application Critical and Error Events" -Object $recentApplicationEvents
Write-ObjectBlock -Header "Recent PowerShell Operational Events" -Object $recentPowerShellEvents
Write-ObjectBlock -Header "Recent PowerShell 4103 Events" -Object $recent4103
Write-ObjectBlock -Header "Recent PowerShell 4104 Events" -Object $recent4104
Write-ObjectBlock -Header "Recent Security 4688 Process Creation Events (First 20)" -Object ($recent4688 | Select-Object -First 20)
Write-ObjectBlock -Header "Recent Security 4698 Scheduled Task Creation Events (First 20)" -Object ($recent4698 | Select-Object -First 20)
Write-ObjectBlock -Header "Recent System 7045 Service Install Events (First 20)" -Object ($recent7045 | Select-Object -First 20)

Add-Section "Normalized IOC Dataset"
Write-ObjectBlock -Header "Normalized IOC Records (First 40)" -Object ($normalizedRecords | Select-Object -First 40)

Add-Section "Collection Notes"
Add-Line ("- Generated file: {0}" -f (Split-Path -Leaf $outFile))
Add-Line ("- Generated JSON: {0}" -f (Split-Path -Leaf $jsonFile))
Add-Line ("- Generated normalized JSON: {0}" -f (Split-Path -Leaf $normalizedJsonFile))
Add-Line "- Re-run this script after major software changes, after cleanup, and after any suspected incident."
Add-Line "- Compare future snapshots for changes in services, tasks, startup entries, WMI consumers, ports, process paths, and recurring event IDs."

Write-Output "Baseline written to: $outFile"
Write-Output "JSON written to: $jsonFile"
Write-Output "Normalized JSON written to: $normalizedJsonFile"

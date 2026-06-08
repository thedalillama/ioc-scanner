param(
    [ValidateSet("Baseline", "Check")]
    [string]$Mode = "Baseline",

    [string]$StatePath = (Join-Path $PSScriptRoot "host-tripwire-state.json"),
    [string]$ConfigPath = (Join-Path $PSScriptRoot "host-tripwire-config.json")
)

$ErrorActionPreference = "Stop"

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$collectionTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
$outBase = Join-Path $PSScriptRoot ("HOST_TRIPWIRE_{0}_{1}" -f $Mode.ToUpperInvariant(), $timestamp)
$jsonFile = "$outBase.json"
$mdFile = "$outBase.md"
$alertBase = Join-Path $PSScriptRoot ("ALERT_HOST_TRIPWIRE_{0}" -f $timestamp)

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

function Write-MdLine {
    param([string]$Text = "")
    Add-Content -LiteralPath $mdFile -Value $Text
}

function New-ChangeRecord {
    param(
        [string]$Category,
        [string]$Name,
        [string]$ChangeType,
        [string]$Path = "",
        [string]$OldValue = "",
        [string]$NewValue = "",
        [string]$Notes = ""
    )

    [PSCustomObject]@{
        Category = $Category
        Name = $Name
        ChangeType = $ChangeType
        Path = $Path
        OldValue = $OldValue
        NewValue = $NewValue
        Notes = $Notes
    }
}

function Get-ChangeSeverity {
    param($Change)

    if ($Change.Category -in @("LocalGroupMember", "ScheduledTask", "Autorun")) {
        return "High"
    }

    if ($Change.Category -eq "Service" -or $Change.Category -eq "WatchedFile") {
        return "Medium"
    }

    return "Low"
}

function ConvertTo-StableDateString {
    param($Value)

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    try {
        return ([datetimeoffset]::Parse($text)).UtcDateTime.ToString("o")
    } catch {
        return $text.Trim()
    }
}

function Get-DefaultConfig {
    [PSCustomObject]@{
        LocalGroups = @("Administrators")
        WatchFiles = @(
            "C:\Windows\System32\drivers\etc\hosts",
            (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini"),
            (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini")
        )
        WatchDirectories = @(
            [PSCustomObject]@{
                Path = (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup")
                Filters = @("*")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup")
                Filters = @("*")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = $env:ProgramData
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = $env:PUBLIC
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr", "*.lnk")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = $env:APPDATA
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr", "*.lnk")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = $env:LOCALAPPDATA
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr", "*.lnk")
                Recurse = $false
            }
        )
        RecentWindowHours = 24
    }
}

function Get-TripwireConfig {
    param([string]$Path)

    if (Test-Path $Path) {
        return (Get-Content $Path -Raw | ConvertFrom-Json)
    }

    $config = Get-DefaultConfig
    Write-JsonFile -Path $Path -Object $config
    return $config
}

function Get-LocalUsersSnapshot {
    Get-LocalUser | Sort-Object Name | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Enabled = $_.Enabled
            PasswordRequired = $_.PasswordRequired
            PasswordExpires = ConvertTo-StableDateString $_.PasswordExpires
            LastLogon = ConvertTo-StableDateString $_.LastLogon
            PasswordLastSet = ConvertTo-StableDateString $_.PasswordLastSet
        }
    }
}

function Get-LocalGroupMembersSnapshot {
    param([string[]]$Groups)

    foreach ($group in $Groups) {
        $members = @(Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Sort-Object Name)
        [PSCustomObject]@{
            Group = $group
            Members = @($members | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    ObjectClass = $_.ObjectClass
                    PrincipalSource = [string]$_.PrincipalSource
                }
            })
        }
    }
}

function Get-ServiceSnapshot {
    Get-CimInstance Win32_Service | Sort-Object Name | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            State = $_.State
            StartMode = $_.StartMode
            StartName = $_.StartName
            PathName = $_.PathName
        }
    }
}

function Get-TaskSnapshot {
    Get-ScheduledTask | Sort-Object TaskPath, TaskName | ForEach-Object {
        $task = $_
        [PSCustomObject]@{
            Name = "{0}{1}" -f $task.TaskPath, $task.TaskName
            TaskPath = $task.TaskPath
            TaskName = $task.TaskName
            Author = $task.Author
            Actions = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join "; "
            Triggers = ($task.Triggers | ForEach-Object { [string]$_.CimClass.CimClassName }) -join ", "
        }
    }
}

function Get-RunKeySnapshot {
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
                        Name = $prop.Name
                        Value = [string]$prop.Value
                    }
                }
            }
        }
    }
}

function Get-FileRecord {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]@{
            Path = $Path
            Exists = $false
            Length = $null
            LastWriteTimeUtc = $null
            SHA256 = $null
        }
    }

    $item = Get-Item -LiteralPath $Path -Force
    $hash = $null
    if (-not $item.PSIsContainer) {
        try {
            $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        } catch {
        }
    }

    [PSCustomObject]@{
        Path = $Path
        Exists = $true
        Length = if ($item.PSIsContainer) { $null } else { [int64]$item.Length }
        LastWriteTimeUtc = [string]$item.LastWriteTimeUtc
        SHA256 = $hash
    }
}

function Get-WatchedFilesSnapshot {
    param($Config)

    $records = @()

    foreach ($path in @($Config.WatchFiles)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$path)) {
            $records += Get-FileRecord -Path ([string]$path)
        }
    }

    foreach ($entry in @($Config.WatchDirectories)) {
        $directoryPath = [string]$entry.Path
        if ([string]::IsNullOrWhiteSpace($directoryPath) -or -not (Test-Path -LiteralPath $directoryPath)) {
            continue
        }

        $recurse = [bool]$entry.Recurse
        $filters = @()

        if ($entry.PSObject.Properties.Name -contains "Filters") {
            $filters = @($entry.Filters | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
        }

        if (@($filters).Count -eq 0) {
            $legacyFilter = [string]$entry.Filter
            if ([string]::IsNullOrWhiteSpace($legacyFilter)) {
                $filters = @("*")
            } else {
                $filters = @($legacyFilter)
            }
        }

        foreach ($filter in $filters) {
            $items = Get-ChildItem -LiteralPath $directoryPath -File -Filter $filter -Recurse:$recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $records += Get-FileRecord -Path $item.FullName
            }
        }
    }

    $records | Sort-Object Path -Unique
}

function Get-KeyEventSnapshot {
    param([int]$RecentWindowHours)

    $start = (Get-Date).AddHours(-1 * $RecentWindowHours)

    function Get-SafeEventWindow {
        param(
            [string]$LogName,
            [int]$Id,
            [int]$MaxEvents = 20
        )

        try {
            return @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $start; Id = $Id } -MaxEvents $MaxEvents | Select-Object TimeCreated, Id, ProviderName, Message)
        } catch {
            return @()
        }
    }

    [PSCustomObject]@{
        Security4720 = Get-SafeEventWindow -LogName 'Security' -Id 4720
        Security4722 = Get-SafeEventWindow -LogName 'Security' -Id 4722
        Security4725 = Get-SafeEventWindow -LogName 'Security' -Id 4725
        Security4726 = Get-SafeEventWindow -LogName 'Security' -Id 4726
        Security4738 = Get-SafeEventWindow -LogName 'Security' -Id 4738
        Security4732 = Get-SafeEventWindow -LogName 'Security' -Id 4732
        Security4733 = Get-SafeEventWindow -LogName 'Security' -Id 4733
        Security4698 = Get-SafeEventWindow -LogName 'Security' -Id 4698
        Security4702 = Get-SafeEventWindow -LogName 'Security' -Id 4702
        Security4699 = Get-SafeEventWindow -LogName 'Security' -Id 4699
        Security4688 = Get-SafeEventWindow -LogName 'Security' -Id 4688 -MaxEvents 40
        System7045 = Get-SafeEventWindow -LogName 'System' -Id 7045
        TaskSchedulerOperational = try {
            @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; StartTime = $start } -MaxEvents 40 |
                Select-Object TimeCreated, Id, ProviderName, Message)
        } catch {
            @()
        }
    }
}

function ConvertTo-Map {
    param(
        $Items,
        [scriptblock]$KeySelector
    )

    $map = @{}
    foreach ($item in @($Items)) {
        $key = & $KeySelector $item
        if (-not [string]::IsNullOrWhiteSpace([string]$key)) {
            $map[[string]$key] = $item
        }
    }
    return $map
}

function Compare-SimpleRecords {
    param(
        [string]$Category,
        $OldItems,
        $NewItems,
        [scriptblock]$KeySelector,
        [string[]]$PropertyNames
    )

    $changes = @()
    $oldMap = ConvertTo-Map -Items $OldItems -KeySelector $KeySelector
    $newMap = ConvertTo-Map -Items $NewItems -KeySelector $KeySelector
    $keys = @($oldMap.Keys + $newMap.Keys | Sort-Object -Unique)

    foreach ($key in $keys) {
        $oldItem = $oldMap[$key]
        $newItem = $newMap[$key]

        if ($null -eq $oldItem -and $null -ne $newItem) {
            $changes += New-ChangeRecord -Category $Category -Name $key -ChangeType "Added" -NewValue ($newItem | ConvertTo-Json -Compress -Depth 5)
            continue
        }

        if ($null -ne $oldItem -and $null -eq $newItem) {
            $changes += New-ChangeRecord -Category $Category -Name $key -ChangeType "Removed" -OldValue ($oldItem | ConvertTo-Json -Compress -Depth 5)
            continue
        }

        foreach ($propertyName in $PropertyNames) {
            $oldValue = [string]$oldItem.$propertyName
            $newValue = [string]$newItem.$propertyName
            if ($oldValue -cne $newValue) {
                $changes += New-ChangeRecord -Category $Category -Name $key -ChangeType "Modified" -Path $propertyName -OldValue $oldValue -NewValue $newValue
            }
        }
    }

    return @($changes)
}

function Compare-GroupMembership {
    param(
        $OldGroups,
        $NewGroups
    )

    $changes = @()
    $oldMap = ConvertTo-Map -Items $OldGroups -KeySelector { param($item) $item.Group }
    $newMap = ConvertTo-Map -Items $NewGroups -KeySelector { param($item) $item.Group }
    $groupNames = @($oldMap.Keys + $newMap.Keys | Sort-Object -Unique)

    foreach ($groupName in $groupNames) {
        $oldMembers = @($oldMap[$groupName].Members | ForEach-Object { $_.Name })
        $newMembers = @($newMap[$groupName].Members | ForEach-Object { $_.Name })
        foreach ($member in @($newMembers | Where-Object { $_ -notin $oldMembers })) {
            $changes += New-ChangeRecord -Category "LocalGroupMember" -Name $member -ChangeType "Added" -Path $groupName
        }
        foreach ($member in @($oldMembers | Where-Object { $_ -notin $newMembers })) {
            $changes += New-ChangeRecord -Category "LocalGroupMember" -Name $member -ChangeType "Removed" -Path $groupName
        }
    }

    return @($changes)
}

function Compare-FileRecords {
    param(
        $OldFiles,
        $NewFiles
    )

    $changes = @()
    $oldMap = ConvertTo-Map -Items $OldFiles -KeySelector { param($item) $item.Path }
    $newMap = ConvertTo-Map -Items $NewFiles -KeySelector { param($item) $item.Path }
    $paths = @($oldMap.Keys + $newMap.Keys | Sort-Object -Unique)

    foreach ($path in $paths) {
        $oldItem = $oldMap[$path]
        $newItem = $newMap[$path]

        if ($null -eq $oldItem -and $null -ne $newItem) {
            $changes += New-ChangeRecord -Category "WatchedFile" -Name ([IO.Path]::GetFileName($path)) -ChangeType "Added" -Path $path -NewValue ($newItem | ConvertTo-Json -Compress)
            continue
        }

        if ($null -ne $oldItem -and $null -eq $newItem) {
            $changes += New-ChangeRecord -Category "WatchedFile" -Name ([IO.Path]::GetFileName($path)) -ChangeType "Removed" -Path $path -OldValue ($oldItem | ConvertTo-Json -Compress)
            continue
        }

        foreach ($propertyName in @("Exists", "Length", "LastWriteTimeUtc", "SHA256")) {
            $oldValue = [string]$oldItem.$propertyName
            $newValue = [string]$newItem.$propertyName
            if ($oldValue -cne $newValue) {
                $changes += New-ChangeRecord -Category "WatchedFile" -Name ([IO.Path]::GetFileName($path)) -ChangeType "Modified" -Path $path -OldValue ("{0}={1}" -f $propertyName, $oldValue) -NewValue ("{0}={1}" -f $propertyName, $newValue)
            }
        }
    }

    return @($changes)
}

$config = Get-TripwireConfig -Path $ConfigPath

$snapshot = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        CollectionTimeUtc = $collectionTimeUtc
        ConfigPath = $ConfigPath
    }
    LocalUsers = @(Get-LocalUsersSnapshot)
    LocalGroups = @(Get-LocalGroupMembersSnapshot -Groups @($config.LocalGroups))
    Services = @(Get-ServiceSnapshot)
    ScheduledTasks = @(Get-TaskSnapshot)
    Autoruns = @(Get-RunKeySnapshot)
    WatchedFiles = @(Get-WatchedFilesSnapshot -Config $config)
    RecentEvents = Get-KeyEventSnapshot -RecentWindowHours ([int]$config.RecentWindowHours)
}

if ($Mode -eq "Baseline") {
    Write-JsonFile -Path $StatePath -Object $snapshot
    Write-JsonFile -Path $jsonFile -Object $snapshot

    Set-Content -LiteralPath $mdFile -Value "# Host Tripwire Baseline`r`n"
    Write-MdLine ""
    Write-MdLine ("CollectionTimeUtc: {0}" -f $collectionTimeUtc)
    Write-MdLine ("StatePath: {0}" -f $StatePath)
    Write-MdLine ""
    Write-MdLine ("- Local users: {0}" -f @($snapshot.LocalUsers).Count)
    Write-MdLine ("- Group snapshots: {0}" -f @($snapshot.LocalGroups).Count)
    Write-MdLine ("- Services: {0}" -f @($snapshot.Services).Count)
    Write-MdLine ("- Tasks: {0}" -f @($snapshot.ScheduledTasks).Count)
    Write-MdLine ("- Autoruns: {0}" -f @($snapshot.Autoruns).Count)
    Write-MdLine ("- Watched files: {0}" -f @($snapshot.WatchedFiles).Count)

    Write-Host ("State written to: {0}" -f $StatePath)
    Write-Host ("JSON written to: {0}" -f $jsonFile)
    Write-Host ("Markdown written to: {0}" -f $mdFile)
    exit 0
}

if (-not (Test-Path $StatePath)) {
    throw "Tripwire baseline state file not found: $StatePath"
}

$oldState = Get-Content $StatePath -Raw | ConvertFrom-Json

$changes = @()
$changes += Compare-SimpleRecords -Category "LocalUser" -OldItems $oldState.LocalUsers -NewItems $snapshot.LocalUsers -KeySelector { param($item) $item.Name } -PropertyNames @("Enabled", "PasswordRequired", "PasswordExpires", "LastLogon", "PasswordLastSet")
$changes += Compare-GroupMembership -OldGroups $oldState.LocalGroups -NewGroups $snapshot.LocalGroups
$changes += Compare-SimpleRecords -Category "Service" -OldItems $oldState.Services -NewItems $snapshot.Services -KeySelector { param($item) $item.Name } -PropertyNames @("StartMode", "StartName", "PathName")
$changes += Compare-SimpleRecords -Category "ScheduledTask" -OldItems $oldState.ScheduledTasks -NewItems $snapshot.ScheduledTasks -KeySelector { param($item) $item.Name } -PropertyNames @("Author", "Actions", "Triggers")
$changes += Compare-SimpleRecords -Category "Autorun" -OldItems $oldState.Autoruns -NewItems $snapshot.Autoruns -KeySelector { param($item) "{0}|{1}" -f $item.RegistryPath, $item.Name } -PropertyNames @("Value")
$changes += Compare-FileRecords -OldFiles $oldState.WatchedFiles -NewFiles $snapshot.WatchedFiles

$report = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        CollectionTimeUtc = $collectionTimeUtc
        StatePath = $StatePath
        ConfigPath = $ConfigPath
        ChangeCount = @($changes).Count
        HighestSeverity = if (@($changes).Count -gt 0) { (@($changes | ForEach-Object { Get-ChangeSeverity $_ }) | ForEach-Object {
            switch ($_) {
                "High" { 3 }
                "Medium" { 2 }
                default { 1 }
            }
        } | Measure-Object -Maximum).Maximum } else { 0 }
    }
    Changes = @($changes)
    RecentEvents = $snapshot.RecentEvents
}

Write-JsonFile -Path $jsonFile -Object $report
Write-JsonFile -Path $StatePath -Object $snapshot

Set-Content -LiteralPath $mdFile -Value "# Host Tripwire Report`r`n"
Write-MdLine ""
Write-MdLine ("CollectionTimeUtc: {0}" -f $collectionTimeUtc)
Write-MdLine ("ChangeCount: {0}" -f $report.Metadata.ChangeCount)
Write-MdLine ""
Write-MdLine "## Changes"
Write-MdLine ""

if (@($report.Changes).Count -eq 0) {
    Write-MdLine "_No baseline deviations detected in the monitored categories._"
} else {
    foreach ($change in $report.Changes) {
        Write-MdLine ("- [{0}] {1} {2}" -f $change.Category, $change.Name, $change.ChangeType)
        if (-not [string]::IsNullOrWhiteSpace($change.Path)) {
            Write-MdLine ("  Path/Field: {0}" -f $change.Path)
        }
        if (-not [string]::IsNullOrWhiteSpace($change.OldValue)) {
            Write-MdLine ("  Old: {0}" -f $change.OldValue)
        }
        if (-not [string]::IsNullOrWhiteSpace($change.NewValue)) {
            Write-MdLine ("  New: {0}" -f $change.NewValue)
        }
    }
}

if (@($report.Changes).Count -gt 0) {
    $severityMap = @{
        3 = "High"
        2 = "Medium"
        1 = "Low"
        0 = "Info"
    }
    $alert = [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            AlertType = "HostTripwire"
            ComputerName = $env:COMPUTERNAME
            CollectionTimeUtc = $collectionTimeUtc
            Severity = $severityMap[[int]$report.Metadata.HighestSeverity]
            ChangeCount = @($report.Changes).Count
            SourceReport = $jsonFile
        }
        Summary = [PSCustomObject]@{
            Title = "Codex tripwire detected host changes"
            Message = "{0} change(s) detected. Highest severity: {1}." -f @($report.Changes).Count, $severityMap[[int]$report.Metadata.HighestSeverity]
        }
        Changes = @($report.Changes)
    }

    $alertJson = "$alertBase.json"
    $alertMd = "$alertBase.md"
    Write-JsonFile -Path $alertJson -Object $alert
    Set-Content -LiteralPath $alertMd -Value "# Codex Tripwire Alert`r`n"
    Add-Content -LiteralPath $alertMd -Value ""
    Add-Content -LiteralPath $alertMd -Value ("Severity: {0}" -f $alert.Metadata.Severity)
    Add-Content -LiteralPath $alertMd -Value ("ChangeCount: {0}" -f $alert.Metadata.ChangeCount)
    Add-Content -LiteralPath $alertMd -Value ("SourceReport: {0}" -f $alert.Metadata.SourceReport)
    Add-Content -LiteralPath $alertMd -Value ""
    foreach ($change in $alert.Changes) {
        Add-Content -LiteralPath $alertMd -Value ("- [{0}] {1} {2}" -f $change.Category, $change.Name, $change.ChangeType)
    }
    Write-Host ("Alert JSON written to: {0}" -f $alertJson)
    Write-Host ("Alert Markdown written to: {0}" -f $alertMd)
}

Write-Host ("JSON written to: {0}" -f $jsonFile)
Write-Host ("Markdown written to: {0}" -f $mdFile)

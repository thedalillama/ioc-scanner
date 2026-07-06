param(
    [ValidateSet("Baseline", "Check")]
    [string]$Mode = "Baseline",

    [string]$StatePath = "",
    [string]$StateDbPath = "",
    [string]$ConfigPath = (Join-Path $PSScriptRoot "host-tripwire-config.json"),
    [string]$IocLocationConfigPath = (Join-Path $PSScriptRoot "ioc-monitor-locations.json"),
    [string]$BaselineReason = "",
    [string]$CreatedBy = "",
    [bool]$CreatedAfterReview = $true
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "tripwire-posture-baseline.ps1")

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$collectionTimeUtc = (Get-Date).ToUniversalTime().ToString("o")
$outBase = Join-Path $PSScriptRoot ("HOST_TRIPWIRE_{0}_{1}" -f $Mode.ToUpperInvariant(), $timestamp)
$jsonFile = "$outBase.json"
$mdFile = "$outBase.md"

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-TripwireLockPath {
    param([string]$DbPath)

    $stateDirectory = Split-Path -Path $DbPath -Parent
    if ([string]::IsNullOrWhiteSpace($stateDirectory)) {
        $stateDirectory = $PSScriptRoot
    }
    return (Join-Path $stateDirectory 'host-tripwire-run.lock.json')
}

function Get-TripwireLockInfo {
    param([string]$LockPath)

    if (-not (Test-Path -LiteralPath $LockPath)) {
        return $null
    }

    try {
        return (Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json)
    } catch {
        return [PSCustomObject]@{
            Mode = 'unknown'
            Pid = $null
            ComputerName = $env:COMPUTERNAME
            StartedUtc = $null
            LockPath = $LockPath
            ParseError = $_.Exception.Message
        }
    }
}

function Test-TripwireBaselineRunning {
    param([string]$LockPath)

    $lockInfo = Get-TripwireLockInfo -LockPath $LockPath
    if ($null -eq $lockInfo) {
        return $null
    }

    if ([string]$lockInfo.Mode -ine 'Baseline') {
        return $null
    }

    $pidValue = 0
    try {
        $pidValue = [int]$lockInfo.Pid
    } catch {
        $pidValue = 0
    }

    if ($pidValue -le 0) {
        return $null
    }

    $runningProcess = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($null -eq $runningProcess) {
        return $null
    }

    return $lockInfo
}

function Set-TripwireRunLock {
    param(
        [string]$LockPath,
        [string]$Mode
    )

    $lockInfo = [PSCustomObject]@{
        Mode = $Mode
        Pid = $PID
        ComputerName = $env:COMPUTERNAME
        StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    [System.IO.File]::WriteAllText($LockPath, ($lockInfo | ConvertTo-Json -Depth 4), [System.Text.UTF8Encoding]::new($false))
}

function Clear-TripwireRunLock {
    param([string]$LockPath)

    if (Test-Path -LiteralPath $LockPath) {
        [System.IO.File]::Delete($LockPath)
    }
}

function Get-ExecutionContextInfo {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = [string]$identity.Name
    $userSid = ""
    try {
        $userSid = [string]$identity.User.Value
    } catch {
    }

    $pathDirectories = @(
        ($env:Path -split ';') |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim() } |
            Sort-Object -Unique
    )

    $isSystem = $userSid -eq 'S-1-5-18' -or $userName -ieq 'NT AUTHORITY\SYSTEM' -or $userName -ieq 'SYSTEM'
    $scope = if ($isSystem) { 'System' } else { "User:$userName" }

    return [PSCustomObject]@{
        UserName = $userName
        UserSid = $userSid
        IsSystem = $isSystem
        Scope = $scope
        PathDirectoryCount = @($pathDirectories).Count
    }
}

function Test-ExecutionContextCompatible {
    param(
        $BaselineContext,
        $CurrentContext
    )

    if ($null -eq $BaselineContext) {
        return [PSCustomObject]@{
            IsCompatible = $false
            Message = "Tripwire baseline does not include execution-context metadata. Recreate the baseline in the same context used for checks, ideally SYSTEM."
        }
    }

    $baselineScope = [string]$BaselineContext.Scope
    $currentScope = [string]$CurrentContext.Scope
    $baselineSid = [string]$BaselineContext.UserSid
    $currentSid = [string]$CurrentContext.UserSid

    if (-not [string]::IsNullOrWhiteSpace($baselineSid) -and -not [string]::IsNullOrWhiteSpace($currentSid)) {
        if ($baselineSid -ceq $currentSid) {
            return [PSCustomObject]@{
                IsCompatible = $true
                Message = ""
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($baselineScope) -and $baselineScope -ceq $currentScope) {
        return [PSCustomObject]@{
            IsCompatible = $true
            Message = ""
        }
    }

    return [PSCustomObject]@{
        IsCompatible = $false
        Message = ("Tripwire baseline context mismatch. Baseline was captured as {0}; current run is {1}. Recreate the baseline in the same context used for checks, ideally SYSTEM." -f $baselineScope, $currentScope)
    }
}

function Get-AlertInboxPath {
    $settingsPath = Join-Path $PSScriptRoot "codex-monitor.settings.json"
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.AlertInboxPath)) {
                Ensure-Directory -Path ([string]$settings.AlertInboxPath)
                return [string]$settings.AlertInboxPath
            }
        } catch {
        }
    }

    $defaultInbox = Join-Path (Join-Path $PSScriptRoot "alerts") "pending"
    Ensure-Directory -Path $defaultInbox
    return $defaultInbox
}

$alertBase = Join-Path (Get-AlertInboxPath) ("ALERT_HOST_TRIPWIRE_{0}" -f $timestamp)

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
                return [string]$settings.StateDbPath
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
        [int]$Depth = 16
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

function Index-TripwireBaselineInSqlite {
    param(
        [string]$DbPath,
        [string]$BaselineJsonPath,
        [string]$BaselineMarkdownPath = ""
    )

    if ([string]::IsNullOrWhiteSpace($DbPath) -or [string]::IsNullOrWhiteSpace($BaselineJsonPath)) {
        return $null
    }

    $arguments = @("index-tripwire-baseline", "--input", $BaselineJsonPath)
    if (-not [string]::IsNullOrWhiteSpace($BaselineMarkdownPath)) {
        $arguments += @("--markdown", $BaselineMarkdownPath)
    }

    $raw = Invoke-StateStore -DbPath $DbPath -Arguments $arguments
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }
    return ($raw | ConvertFrom-Json)
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
        [string]$Notes = "",
        [string]$Severity = "",
        [string]$Classification = "",
        [string]$CsfMapping = "",
        [string]$Interpretation = "",
        [bool]$GuardrailMatched = $false,
        [string]$GuardrailReason = "",
        [string]$MatchedRuleId = "",
        [string]$MatchedRuleDescription = "",
        [string]$RecommendedAction = ""
    )

    [PSCustomObject]@{
        Category = $Category
        Name = $Name
        ChangeType = $ChangeType
        Path = $Path
        OldValue = $OldValue
        NewValue = $NewValue
        Notes = $Notes
        Severity = $Severity
        Classification = $Classification
        CsfMapping = $CsfMapping
        Interpretation = $Interpretation
        GuardrailMatched = $GuardrailMatched
        GuardrailReason = $GuardrailReason
        MatchedRuleId = $MatchedRuleId
        MatchedRuleDescription = $MatchedRuleDescription
        RecommendedAction = $RecommendedAction
    }
}

function Get-ChangeSeverity {
    param($Change)

    $explicit = [string]$Change.Severity
    if (-not [string]::IsNullOrWhiteSpace($explicit)) {
        return $explicit
    }

    if ($Change.Category -eq "ScheduledTask" -and -not [string]::IsNullOrWhiteSpace([string]$Change.Name) -and ([string]$Change.Name).StartsWith('\Codex ', [System.StringComparison]::OrdinalIgnoreCase)) {
        return "Info"
    }

    if ($Change.Category -in @("LocalGroupMember", "ScheduledTask", "Autorun")) {
        return "Warning"
    }

    if ($Change.Category -eq "WatchedFile" -and -not [string]::IsNullOrWhiteSpace([string]$Change.Path) -and ([string]$Change.Path).ToLowerInvariant().StartsWith('c:\windows\system32\tasks\')) {
        if ([string]$Change.Notes -like "LikelySystemManagedTask:*" -or [string]$Change.Notes -like "LikelySelfManagedTask:*") {
            return "Info"
        }
        return "Warning"
    }

    if ($Change.Category -eq "Service" -or $Change.Category -eq "WatchedFile") {
        return "Review"
    }

    return "Info"
}

function Get-ChangeSeverityRank {
    param($Change)

    switch ((Get-ChangeSeverity $Change)) {
        'Critical' { return 4 }
        'High' { return 4 }
        'Warning' { return 3 }
        'Medium' { return 3 }
        'Review' { return 2 }
        'Low' { return 1 }
        default { return 1 }
    }
}

function Format-ChangeHeadline {
    param($Change)

    if ($null -eq $Change) {
        return "Host change detected"
    }

    if ([string]::IsNullOrWhiteSpace($Change.Path)) {
        return "{0} {1}: {2}" -f $Change.Category, $Change.ChangeType, $Change.Name
    }

    return "{0} {1}: {2} ({3})" -f $Change.Category, $Change.ChangeType, $Change.Name, $Change.Path
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
        WatchAllExecutables = $true
        WatchPathExecutables = $true
        ExecutableRoots = @(
            "$($env:SystemDrive)\"
        )
        ExecutableExtensions = @(
            "*.exe",
            "*.dll",
            "*.com",
            "*.scr",
            "*.ocx",
            "*.cpl",
            "*.sys",
            "*.drv",
            "*.bat",
            "*.cmd",
            "*.ps1",
            "*.psm1",
            "*.psd1",
            "*.vbs",
            "*.vbe",
            "*.js",
            "*.jse",
            "*.wsf",
            "*.wsh",
            "*.hta"
        )
        WatchFiles = @(
            "C:\Windows\System32\drivers\etc\hosts",
            (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini"),
            (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini")
        )
        ExcludePathPrefixes = @()
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

function Get-DefaultIocLocationConfig {
    [PSCustomObject]@{
        WatchFiles = @(
            "C:\Windows\System32\drivers\etc\hosts"
        )
        ExcludePathPrefixes = @(
            "C:\Windows\System32\Tasks\Microsoft\Windows\Flighting\OneSettings",
            "C:\Windows\System32\Tasks\Microsoft\Windows\SoftwareProtectionPlatform",
            "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator"
        )
        WatchDirectories = @(
            [PSCustomObject]@{
                Path = "C:\Windows\System32\Tasks"
                Filters = @("*")
                Recurse = $true
            },
            [PSCustomObject]@{
                Path = "C:\Windows\Temp"
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr", "*.tmp")
                Recurse = $true
            },
            [PSCustomObject]@{
                Path = "C:\ProgramData"
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr", "*.lnk")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = "C:\Users\me\AppData\Roaming"
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr", "*.lnk")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = "C:\Users\me\AppData\Local"
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr", "*.lnk")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = "C:\Users\Public"
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr", "*.lnk")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = "C:\Users\me\Downloads"
                Filters = @("*.exe", "*.dll", "*.ps1", "*.vbs", "*.js", "*.jse", "*.hta", "*.bat", "*.cmd", "*.scr", "*.lnk")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
                Filters = @("*")
                Recurse = $false
            },
            [PSCustomObject]@{
                Path = "C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
                Filters = @("*")
                Recurse = $false
            }
        )
    }
}

function Merge-UniqueStringLists {
    param(
        [object[]]$Primary,
        [object[]]$Secondary
    )

    @(
        @($Primary) + @($Secondary) |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } |
            Sort-Object -Unique
    )
}

function Test-ExcludedPath {
    param(
        [string]$Path,
        $Config
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $candidate = $Path.Trim().TrimEnd('\').ToLowerInvariant()
    foreach ($prefix in @($Config.ExcludePathPrefixes)) {
        $value = [string]$prefix
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        $normalized = $value.Trim().TrimEnd('\').ToLowerInvariant()
        if ($candidate -eq $normalized -or $candidate.StartsWith($normalized + "\")) {
            return $true
        }
    }

    return $false
}

function Merge-WatchDirectories {
    param(
        [object[]]$Primary,
        [object[]]$Secondary
    )

    $merged = @()
    foreach ($entry in @($Primary) + @($Secondary)) {
        if ($null -eq $entry) {
            continue
        }

        $path = [string]$entry.Path
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        $filters = @()
        if ($entry.PSObject.Properties.Name -contains "Filters") {
            $filters = @($entry.Filters | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
        } elseif ($entry.PSObject.Properties.Name -contains "Filter" -and -not [string]::IsNullOrWhiteSpace([string]$entry.Filter)) {
            $filters = @([string]$entry.Filter)
        } else {
            $filters = @("*")
        }

        $record = [PSCustomObject]@{
            Path = $path
            Filters = @($filters)
            Recurse = [bool]$entry.Recurse
        }

        $key = "{0}|{1}|{2}" -f $record.Path.ToLowerInvariant(), (($record.Filters | Sort-Object) -join ';').ToLowerInvariant(), $record.Recurse
        if (-not ($merged | Where-Object {
            ("{0}|{1}|{2}" -f $_.Path.ToLowerInvariant(), (($_.Filters | Sort-Object) -join ';').ToLowerInvariant(), $_.Recurse) -eq $key
        })) {
            $merged += $record
        }
    }

    return @($merged)
}

function Get-ExecutableFileRecords {
    param($Config)

    if (-not $Config.PSObject.Properties.Name.Contains('WatchAllExecutables') -or -not [bool]$Config.WatchAllExecutables) {
        return @()
    }

    $roots = @($Config.ExecutableRoots | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $patterns = @($Config.ExecutableExtensions | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

    if (@($roots).Count -eq 0 -or @($patterns).Count -eq 0) {
        return @()
    }

    $records = @()
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath ([string]$root))) {
            continue
        }

        $items = Get-ChildItem -LiteralPath ([string]$root) -Recurse -File -Include $patterns -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            if (Test-ExcludedPath -Path $item.FullName -Config $Config) {
                continue
            }
            $records += Get-FileRecord -Path $item.FullName
        }
    }

    return @($records)
}

function Get-PathExecutableFileRecords {
    param($Config)

    if (-not $Config.PSObject.Properties.Name.Contains('WatchPathExecutables') -or -not [bool]$Config.WatchPathExecutables) {
        return @()
    }

    $patterns = @($Config.ExecutableExtensions | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if (@($patterns).Count -eq 0) {
        return @()
    }

    $pathDirectories = @(
        ($env:Path -split ';') |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim() }
    ) | Sort-Object -Unique

    $records = @()
    foreach ($directoryPath in $pathDirectories) {
        if (-not (Test-Path -LiteralPath $directoryPath)) {
            continue
        }

        foreach ($pattern in $patterns) {
            $items = Get-ChildItem -LiteralPath $directoryPath -File -Filter $pattern -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if (Test-ExcludedPath -Path $item.FullName -Config $Config) {
                    continue
                }
                $records += Get-FileRecord -Path $item.FullName
            }
        }
    }

    return @($records)
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

function Get-IocLocationConfig {
    param([string]$Path)

    if (Test-Path $Path) {
        return (Get-Content $Path -Raw | ConvertFrom-Json)
    }

    $config = Get-DefaultIocLocationConfig
    Write-JsonFile -Path $Path -Object $config
    return $config
}

function Merge-TripwireAndIocConfig {
    param(
        $BaseConfig,
        $IocConfig
    )

    [PSCustomObject]@{
        LocalGroups = @($BaseConfig.LocalGroups)
        WatchAllExecutables = [bool]$BaseConfig.WatchAllExecutables
        WatchPathExecutables = [bool]$BaseConfig.WatchPathExecutables
        ExecutableRoots = @($BaseConfig.ExecutableRoots)
        ExecutableExtensions = @($BaseConfig.ExecutableExtensions)
        WatchFiles = Merge-UniqueStringLists -Primary @($BaseConfig.WatchFiles) -Secondary @($IocConfig.WatchFiles)
        ExcludePathPrefixes = Merge-UniqueStringLists -Primary @($BaseConfig.ExcludePathPrefixes) -Secondary @($IocConfig.ExcludePathPrefixes)
        WatchDirectories = Merge-WatchDirectories -Primary @($BaseConfig.WatchDirectories) -Secondary @($IocConfig.WatchDirectories)
        RecentWindowHours = [int]$BaseConfig.RecentWindowHours
    }
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

    $records += Get-ExecutableFileRecords -Config $Config
    $records += Get-PathExecutableFileRecords -Config $Config

    foreach ($path in @($Config.WatchFiles)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$path)) {
            if (Test-ExcludedPath -Path ([string]$path) -Config $Config) {
                continue
            }
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
                if (Test-ExcludedPath -Path $item.FullName -Config $Config) {
                    continue
                }
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

function Get-TaskRelativePathFromFilePath {
    param([string]$Path)

    $prefix = 'C:\Windows\System32\Tasks\'
    if ([string]::IsNullOrWhiteSpace($Path) -or -not $Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }

    return ('\' + $Path.Substring($prefix.Length).TrimStart('\'))
}

function Get-TaskProvenanceNote {
    param(
        [string]$Path,
        $TaskSnapshot,
        $RecentEvents
    )

    $taskPath = Get-TaskRelativePathFromFilePath -Path $Path
    if ([string]::IsNullOrWhiteSpace($taskPath)) {
        return ""
    }

    $matchingTask = @($TaskSnapshot | Where-Object { ([string]$_.Name) -ieq $taskPath } | Select-Object -First 1)
    $author = ""
    $actions = ""
    if (@($matchingTask).Count -gt 0) {
        $author = [string]$matchingTask[0].Author
        $actions = [string]$matchingTask[0].Actions
    }

    $nearbyEvents = @()
    foreach ($event in @($RecentEvents.TaskSchedulerOperational) + @($RecentEvents.Security4698) + @($RecentEvents.Security4702) + @($RecentEvents.Security4699)) {
        if ($null -eq $event) {
            continue
        }

        $message = [string]$event.Message
        if ($message -like "*$taskPath*") {
            $nearbyEvents += $event
        }
    }

    $eventSummary = @($nearbyEvents | Select-Object -First 3 | ForEach-Object { "{0}:{1}" -f $_.ProviderName, $_.Id }) -join ', '

    if ($taskPath.StartsWith('\Codex ', [System.StringComparison]::OrdinalIgnoreCase)) {
        $details = @()
        if (-not [string]::IsNullOrWhiteSpace($author)) {
            $details += ("author={0}" -f $author)
        }
        if (-not [string]::IsNullOrWhiteSpace($eventSummary)) {
            $details += ("events={0}" -f $eventSummary)
        }
        return "LikelySelfManagedTask: {0}{1}" -f $taskPath, ($(if (@($details).Count -gt 0) { " [" + ($details -join '; ') + "]" } else { "" }))
    }

    $isMicrosoftPath = $taskPath.StartsWith('\Microsoft\Windows\', [System.StringComparison]::OrdinalIgnoreCase)
    $isMicrosoftAuthor = -not [string]::IsNullOrWhiteSpace($author) -and $author.ToLowerInvariant().Contains('microsoft')
    $isWindowsAction = -not [string]::IsNullOrWhiteSpace($actions) -and (
        $actions.ToLowerInvariant().Contains('c:\windows\') -or
        $actions.ToLowerInvariant().Contains('program files\windowsapps')
    )

    if ($isMicrosoftPath -and ($isMicrosoftAuthor -or $isWindowsAction -or @($nearbyEvents).Count -gt 0 -or @($matchingTask).Count -gt 0)) {
        $details = @()
        if (-not [string]::IsNullOrWhiteSpace($author)) {
            $details += ("author={0}" -f $author)
        }
        if (-not [string]::IsNullOrWhiteSpace($eventSummary)) {
            $details += ("events={0}" -f $eventSummary)
        }
        return "LikelySystemManagedTask: {0}{1}" -f $taskPath, ($(if (@($details).Count -gt 0) { " [" + ($details -join '; ') + "]" } else { "" }))
    }

    if (@($nearbyEvents).Count -gt 0) {
        return "TaskFileChangeObserved: {0} [events={1}]" -f $taskPath, $eventSummary
    }

    if (@($matchingTask).Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($author)) {
        return "TaskFileChangeObserved: {0} [author={1}]" -f $taskPath, $author
    }

    return "TaskFileChangeObserved: {0}" -f $taskPath
}

function Add-TaskFileProvenanceAnnotations {
    param(
        $Changes,
        $TaskSnapshot,
        $RecentEvents
    )

    foreach ($change in @($Changes)) {
        if ($change.Category -ne 'WatchedFile') {
            continue
        }

        if ([string]::IsNullOrWhiteSpace([string]$change.Path)) {
            continue
        }

        $note = Get-TaskProvenanceNote -Path ([string]$change.Path) -TaskSnapshot $TaskSnapshot -RecentEvents $RecentEvents
        if (-not [string]::IsNullOrWhiteSpace($note)) {
            $change.Notes = $note
        }
    }

    return @($Changes)
}

function Get-AlertableChanges {
    param($Changes)

    return @(
        @($Changes) | Where-Object {
            (Get-ChangeSeverityRank $_) -ge 3
        }
    )
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

$baseConfig = Get-TripwireConfig -Path $ConfigPath
$iocLocationConfig = Get-IocLocationConfig -Path $IocLocationConfigPath
$config = Merge-TripwireAndIocConfig -BaseConfig $baseConfig -IocConfig $iocLocationConfig
$resolvedStateDbPath = Get-StateDbPath -ConfiguredStateDbPath $StateDbPath -LegacyStatePath $StatePath
$tripwireLockPath = Get-TripwireLockPath -DbPath $resolvedStateDbPath
$tripwireLockAcquired = $false

if ($Mode -eq "Check") {
    $runningBaseline = Test-TripwireBaselineRunning -LockPath $tripwireLockPath
    if ($null -ne $runningBaseline) {
        $message = "Tripwire Check cannot run because a Baseline is currently in progress on {0} (PID {1}, started {2}). Wait for the baseline to finish and run Check again." -f $runningBaseline.ComputerName, $runningBaseline.Pid, $runningBaseline.StartedUtc
        Write-Warning $message
        exit 1
    }
}

if ($Mode -eq "Baseline") {
    Set-TripwireRunLock -LockPath $tripwireLockPath -Mode $Mode
    $tripwireLockAcquired = $true
}

try {
    $tripwireExecutionContext = Get-ExecutionContextInfo
    $snapshot = [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            CollectionTimeUtc = $collectionTimeUtc
            ConfigPath = $ConfigPath
            IocLocationConfigPath = $IocLocationConfigPath
            StateDbPath = $resolvedStateDbPath
            ExecutionContext = $tripwireExecutionContext
        }
        LocalUsers = @(Get-LocalUsersSnapshot)
        LocalGroups = @(Get-LocalGroupMembersSnapshot -Groups @($config.LocalGroups))
        Services = @(Get-ServiceSnapshot)
        ScheduledTasks = @(Get-TaskSnapshot)
        Autoruns = @(Get-RunKeySnapshot)
        WatchedFiles = @(Get-WatchedFilesSnapshot -Config $config)
        RecentEvents = Get-KeyEventSnapshot -RecentWindowHours ([int]$config.RecentWindowHours)
        SecurityControlBaseline = Get-SecurityControlBaselineSnapshot
        TrustedWindowsToolBaseline = Get-TrustedWindowsToolBaselineSnapshot
        LoggingAuditBaseline = Get-LoggingAuditBaselineSnapshot
        AppIntegrityBaseline = Get-AppOwnedFileBaselineSnapshot
    }

    if ($Mode -eq "Baseline") {
        Save-SqliteState -DbPath $resolvedStateDbPath -Namespace "host_tripwire" -Key "baseline" -Object $snapshot
        Write-JsonFile -Path $jsonFile -Object $snapshot
        $baselineHashIndexResult = $null
        try {
            $baselineHashIndexResult = Index-TripwireBaselineInSqlite -DbPath $resolvedStateDbPath -BaselineJsonPath $jsonFile -BaselineMarkdownPath $mdFile
        } catch {
            Write-Warning ("Tripwire baseline hash indexing failed: {0}" -f $_.Exception.Message)
        }

        Set-Content -LiteralPath $mdFile -Value "# Host Tripwire Baseline`r`n"
        Write-MdLine ""
        Write-MdLine "This baseline represents the currently trusted state. Create a new baseline only after reviewing outstanding drift."
        Write-MdLine ""
        Write-MdLine ("CollectionTimeUtc: {0}" -f $collectionTimeUtc)
        Write-MdLine ("StateDbPath: {0}" -f $resolvedStateDbPath)
        Write-MdLine ("ExecutionContext: {0}" -f $tripwireExecutionContext.Scope)
        if (-not [string]::IsNullOrWhiteSpace($CreatedBy)) { Write-MdLine ("CreatedBy: {0}" -f $CreatedBy) }
        if (-not [string]::IsNullOrWhiteSpace($BaselineReason)) { Write-MdLine ("BaselineReason: {0}" -f $BaselineReason) }
        Write-MdLine ("CreatedAfterReview: {0}" -f $CreatedAfterReview)
        Write-MdLine ""
        Write-MdLine ("- Local users: {0}" -f @($snapshot.LocalUsers).Count)
        Write-MdLine ("- Group snapshots: {0}" -f @($snapshot.LocalGroups).Count)
        Write-MdLine ("- Services: {0}" -f @($snapshot.Services).Count)
        Write-MdLine ("- Tasks: {0}" -f @($snapshot.ScheduledTasks).Count)
        Write-MdLine ("- Autoruns: {0}" -f @($snapshot.Autoruns).Count)
        Write-MdLine ("- Watched files: {0}" -f @($snapshot.WatchedFiles).Count)
        Write-MdLine ("- Security controls baselined: {0}" -f @($snapshot.SecurityControlBaseline.Items).Count)
        Write-MdLine ("- Trusted Windows tools baselined: {0}" -f @($snapshot.TrustedWindowsToolBaseline.Tools).Count)
        Write-MdLine ("- Logging/audit items baselined: {0}" -f @($snapshot.LoggingAuditBaseline.Items).Count)
        Write-MdLine ("- App integrity files baselined: {0}" -f @($snapshot.AppIntegrityBaseline.Files).Count)
        if ($null -ne $baselineHashIndexResult) {
            Write-MdLine ("- Indexed baseline hashes: {0}" -f $baselineHashIndexResult.hashed_file_count)
            Write-MdLine ("- Baseline ID: {0}" -f $baselineHashIndexResult.baseline_id)
        }
        Write-MdLine ""
        Write-MdLine "## Posture Baseline Sections"
        Write-MdLine ""
        foreach ($item in @($snapshot.SecurityControlBaseline.Items)) { Write-MdLine ("- [SecurityControlBaseline] {0}: {1}" -f $item.Title, $item.Value) }
        foreach ($item in @($snapshot.LoggingAuditBaseline.Items)) { Write-MdLine ("- [LoggingAuditBaseline] {0}: {1}" -f $item.Title, $item.Value) }
        foreach ($item in @($snapshot.TrustedWindowsToolBaseline.Tools | Select-Object -First 16)) { Write-MdLine ("- [TrustedWindowsToolBaseline] {0}: Exists={1}; Signature={2}" -f $item.Title, $item.Exists, $item.SignatureStatus) }
        foreach ($item in @($snapshot.AppIntegrityBaseline.Files | Select-Object -First 20)) { Write-MdLine ("- [AppIntegrityBaseline] {0}: Exists={1}; SHA256={2}" -f $item.Title, $item.Exists, $item.SHA256) }

        Write-Host ("State written to SQLite: {0}" -f $resolvedStateDbPath)
        Write-Host ("JSON written to: {0}" -f $jsonFile)
        Write-Host ("Markdown written to: {0}" -f $mdFile)
        if ($null -ne $baselineHashIndexResult) {
            Write-Host ("Baseline hash index updated: {0} ({1} hashed files)" -f $baselineHashIndexResult.baseline_id, $baselineHashIndexResult.hashed_file_count)
        }
        exit 0
    }

    $oldState = Get-SqliteState -DbPath $resolvedStateDbPath -Namespace "host_tripwire" -Key "baseline"
    if ($null -eq $oldState) {
        $legacyState = Read-LegacyStateFile -Path $StatePath
        if ($null -ne $legacyState) {
            Save-SqliteState -DbPath $resolvedStateDbPath -Namespace "host_tripwire" -Key "baseline" -Object $legacyState
            $oldState = $legacyState
        }
    }

    if ($null -eq $oldState) {
        throw "Tripwire baseline state not found in SQLite: $resolvedStateDbPath"
    }

    $baselineContext = $null
    if ($oldState.PSObject.Properties.Name -contains 'Metadata' -and $null -ne $oldState.Metadata -and $oldState.Metadata.PSObject.Properties.Name -contains 'ExecutionContext') {
        $baselineContext = $oldState.Metadata.ExecutionContext
    }
    $contextCheck = Test-ExecutionContextCompatible -BaselineContext $baselineContext -CurrentContext $tripwireExecutionContext
    if (-not [bool]$contextCheck.IsCompatible) {
        throw [string]$contextCheck.Message
    }

    $changes = @()
    $changes += Compare-SimpleRecords -Category "LocalUser" -OldItems $oldState.LocalUsers -NewItems $snapshot.LocalUsers -KeySelector { param($item) $item.Name } -PropertyNames @("Enabled", "PasswordRequired", "PasswordExpires", "LastLogon", "PasswordLastSet")
    $changes += Compare-GroupMembership -OldGroups $oldState.LocalGroups -NewGroups $snapshot.LocalGroups
    $changes += Compare-SimpleRecords -Category "Service" -OldItems $oldState.Services -NewItems $snapshot.Services -KeySelector { param($item) $item.Name } -PropertyNames @("StartMode", "StartName", "PathName")
    $changes += Compare-SimpleRecords -Category "ScheduledTask" -OldItems $oldState.ScheduledTasks -NewItems $snapshot.ScheduledTasks -KeySelector { param($item) $item.Name } -PropertyNames @("Author", "Actions", "Triggers")
    $changes += Compare-SimpleRecords -Category "Autorun" -OldItems $oldState.Autoruns -NewItems $snapshot.Autoruns -KeySelector { param($item) "{0}|{1}" -f $item.RegistryPath, $item.Name } -PropertyNames @("Value")
    $changes += Compare-FileRecords -OldFiles $oldState.WatchedFiles -NewFiles $snapshot.WatchedFiles
    $changes += Compare-BaselineValueSection -Category 'SecurityControl' -OldItems $oldState.SecurityControlBaseline.Items -NewItems $snapshot.SecurityControlBaseline.Items -Evaluator ${function:Get-ExpectedSecurityControlSeverity}
    $changes += Compare-TrustedWindowsToolBaseline -OldTools $oldState.TrustedWindowsToolBaseline.Tools -NewTools $snapshot.TrustedWindowsToolBaseline.Tools
    $changes += Compare-LoggingAuditBaseline -OldItems $oldState.LoggingAuditBaseline.Items -NewItems $snapshot.LoggingAuditBaseline.Items
    $changes += Compare-AppIntegrityBaseline -OldFiles $oldState.AppIntegrityBaseline.Files -NewFiles $snapshot.AppIntegrityBaseline.Files
    $changes = Add-TaskFileProvenanceAnnotations -Changes $changes -TaskSnapshot $snapshot.ScheduledTasks -RecentEvents $snapshot.RecentEvents
    $ruleEngineResult = Invoke-TripwirePostureRuleEngine -Changes $changes -Snapshot $snapshot -AcceptedDriftPath $resolvedStateDbPath -AcceptedDriftJsonFallbackPath (Join-Path $PSScriptRoot 'state\accepted-posture-drift.json')
    $changes = @($ruleEngineResult.Changes)
    $tripwirePostureSummary = Get-TripwirePostureSummary -Snapshot $snapshot -Changes $changes -RuleEngineResult $ruleEngineResult

    $report = [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            CollectionTimeUtc = $collectionTimeUtc
            StateDbPath = $resolvedStateDbPath
            ConfigPath = $ConfigPath
            ExecutionContext = $tripwireExecutionContext
            ChangeCount = @($changes).Count
            HighestSeverity = if (@($changes).Count -gt 0) { (@($changes | ForEach-Object { Get-ChangeSeverityRank $_ }) | Measure-Object -Maximum).Maximum } else { 0 }
            HighestSeverityLabel = if (@($changes).Count -gt 0) { ((@($changes) | Sort-Object { Get-ChangeSeverityRank $_ } -Descending | Select-Object -First 1) | ForEach-Object { Get-ChangeSeverity $_ }) } else { 'Info' }
        }
        Summary = $tripwirePostureSummary
        RuleEngine = [PSCustomObject]@{
            RulesFilePath = $ruleEngineResult.RulesFilePath
            RulesFileStatus = $ruleEngineResult.RulesFileStatus
            RulesLoadedCount = $ruleEngineResult.RulesLoadedCount
            RuleMatchesCount = $ruleEngineResult.RuleMatchesCount
            Warning = $ruleEngineResult.Warning
            Source = $ruleEngineResult.Source
            CatalogVersion = $ruleEngineResult.CatalogVersion
        }
        CurrentSnapshotSections = [PSCustomObject]@{
            SecurityControlBaseline = $snapshot.SecurityControlBaseline
            TrustedWindowsToolBaseline = $snapshot.TrustedWindowsToolBaseline
            LoggingAuditBaseline = $snapshot.LoggingAuditBaseline
            AppIntegrityBaseline = $snapshot.AppIntegrityBaseline
        }
        Changes = @($changes)
        RecentEvents = $snapshot.RecentEvents
    }

    $alertableChanges = @(Get-AlertableChanges -Changes $report.Changes)

    Write-JsonFile -Path $jsonFile -Object $report
    Save-SqliteState -DbPath $resolvedStateDbPath -Namespace "host_tripwire" -Key "baseline" -Object $snapshot

    Set-Content -LiteralPath $mdFile -Value "# Host Tripwire Report`r`n"
    Write-MdLine ""
    Write-MdLine ("CollectionTimeUtc: {0}" -f $collectionTimeUtc)
    Write-MdLine ("ChangeCount: {0}" -f $report.Metadata.ChangeCount)
    Write-MdLine ("HighestSeverity: {0}" -f $report.Metadata.HighestSeverityLabel)
    Write-MdLine ""
    Write-MdLine "## Posture Drift Summary"
    Write-MdLine ""
    Write-MdLine ($report.Summary.note)
    Write-MdLine ("- security_controls_checked: {0}" -f $report.Summary.security_controls_checked)
    Write-MdLine ("- trusted_windows_tools_checked: {0}" -f $report.Summary.trusted_windows_tools_checked)
    Write-MdLine ("- logging_audit_items_checked: {0}" -f $report.Summary.logging_audit_items_checked)
    Write-MdLine ("- app_integrity_items_checked: {0}" -f $report.Summary.app_integrity_items_checked)
    Write-MdLine ("- security_control_drift_count: {0}" -f $report.Summary.security_control_drift_count)
    Write-MdLine ("- trusted_tool_drift_count: {0}" -f $report.Summary.trusted_tool_drift_count)
    Write-MdLine ("- logging_audit_drift_count: {0}" -f $report.Summary.logging_audit_drift_count)
    Write-MdLine ("- app_integrity_drift_count: {0}" -f $report.Summary.app_integrity_drift_count)
    Write-MdLine ("- observed_posture_change_count: {0}" -f $report.Summary.observed_posture_change_count)
    Write-MdLine ("- expected_operational_change_count: {0}" -f $report.Summary.expected_operational_change_count)
    Write-MdLine ("- accepted_posture_change_count: {0}" -f $report.Summary.accepted_posture_change_count)
    Write-MdLine ("- posture_review_count: {0}" -f $report.Summary.posture_review_count)
    Write-MdLine ("- response_required_count: {0}" -f $report.Summary.response_required_count)
    Write-MdLine ("- guardrail_protected_count: {0}" -f $report.Summary.guardrail_protected_count)
    Write-MdLine ("- expected_churn_count (legacy): {0}" -f $report.Summary.expected_churn_count)
    Write-MdLine ("- accepted_drift_count (legacy): {0}" -f $report.Summary.accepted_drift_count)
    Write-MdLine ("- unexpected_drift_count (legacy technical total): {0}" -f $report.Summary.unexpected_drift_count)
    Write-MdLine ("- review_drift_count (legacy): {0}" -f $report.Summary.review_drift_count)
    Write-MdLine ("- warning_drift_count (legacy): {0}" -f $report.Summary.warning_drift_count)
    Write-MdLine ("- critical_drift_count (legacy): {0}" -f $report.Summary.critical_drift_count)
    Write-MdLine ("- guardrail_matched_count (legacy): {0}" -f $report.Summary.guardrail_matched_count)
    Write-MdLine ("- suspicious_drift_count (legacy): {0}" -f $report.Summary.suspicious_drift_count)
    Write-MdLine ("- rules_loaded_count: {0}" -f $report.Summary.rules_loaded_count)
    Write-MdLine ("- rule_matches_count: {0}" -f $report.Summary.rule_matches_count)
    Write-MdLine ("- rules_file_status: {0}" -f $report.Summary.rules_file_status)
    Write-MdLine ("- rules_file_path: {0}" -f $report.Summary.rules_file_path)
    Write-MdLine ("- accepted_drift_registry_status: {0}" -f $report.Summary.accepted_drift_registry_status)
    Write-MdLine ("- accepted_drift_registry_path: {0}" -f $report.Summary.accepted_drift_registry_path)
    Write-MdLine ("- accepted_drift_registry_loaded_count: {0}" -f $report.Summary.accepted_drift_registry_loaded_count)
    Write-MdLine ""
    Write-MdLine "## NIST CSF View"
    Write-MdLine ""
    Write-MdLine "Detect records observed posture changes from the trusted baseline. Respond focuses attention on findings that require action. Govern records reviewed and accepted posture changes. Recover may establish a new trusted baseline after review."
    Write-MdLine "Not every observed posture change is an alert. Expected operational changes and accepted posture changes remain in the audit trail, while response-required findings are the subset that should be surfaced for action."
    Write-MdLine ""
    Write-MdLine "## Accepted Drift"
    Write-MdLine ""
    Write-MdLine "Accepted posture changes are specific observed changes that were reviewed and recorded as expected. Accepted drift is stored locally in the SQLite state database and remains part of the audit trail. Acceptance does not disable IOC matching or future drift detection."
    if ([string]$report.Summary.accepted_drift_registry_status -eq "json_fallback") {
        Write-MdLine "JSON fallback was used for accepted drift compatibility."
    }
    Write-MdLine ("- accepted_posture_change_count: {0}" -f $report.Summary.accepted_posture_change_count)
    Write-MdLine ("- response_required_count: {0}" -f $report.Summary.response_required_count)
    Write-MdLine ("- expected_operational_change_count: {0}" -f $report.Summary.expected_operational_change_count)
    Write-MdLine ("- posture_review_count: {0}" -f $report.Summary.posture_review_count)
    Write-MdLine ("- observed_posture_change_count: {0}" -f $report.Summary.observed_posture_change_count)
    Write-MdLine ("- guardrail_protected_count: {0}" -f $report.Summary.guardrail_protected_count)
    Write-MdLine ("- accepted_drift_count: {0}" -f $report.Summary.accepted_drift_count)
    Write-MdLine ("- unexpected_drift_count: {0}" -f $report.Summary.unexpected_drift_count)
    $acceptedChanges = @($report.Changes | Where-Object { [bool]$_.IsAcceptedDrift })
    if (@($acceptedChanges).Count -gt 0) {
        Write-MdLine ""
        foreach ($change in $acceptedChanges) {
            Write-MdLine ("- [{0}] {1}" -f $change.Category, $change.Name)
            if (-not [string]::IsNullOrWhiteSpace([string]$change.AcceptanceId)) { Write-MdLine ("  AcceptanceId: {0}" -f $change.AcceptanceId) }
            if (-not [string]::IsNullOrWhiteSpace([string]$change.MatchedRuleId)) { Write-MdLine ("  MatchedRuleId: {0}" -f $change.MatchedRuleId) }
            if (-not [string]::IsNullOrWhiteSpace([string]$change.AcceptedDriftReason)) { Write-MdLine ("  AcceptedDriftReason: {0}" -f $change.AcceptedDriftReason) }
        }
    }
    Write-MdLine ""
    Write-MdLine "## Changes"
    Write-MdLine ""

    if (@($report.Changes).Count -eq 0) {
        Write-MdLine "_No baseline deviations detected in the monitored categories._"
    } else {
        foreach ($change in $report.Changes) {
            Write-MdLine ("- [{0}] {1} {2} ({3}/{4})" -f $change.Category, $change.Name, $change.ChangeType, (Get-ChangeSeverity $change), $(if ([string]::IsNullOrWhiteSpace([string]$change.Classification)) { 'uncategorized' } else { [string]$change.Classification }))
            if (-not [string]::IsNullOrWhiteSpace($change.Path)) {
                Write-MdLine ("  Path/Field: {0}" -f $change.Path)
            }
            if (-not [string]::IsNullOrWhiteSpace($change.OldValue)) {
                Write-MdLine ("  Old: {0}" -f $change.OldValue)
            }
            if (-not [string]::IsNullOrWhiteSpace($change.NewValue)) {
                Write-MdLine ("  New: {0}" -f $change.NewValue)
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$change.CsfMapping)) {
                Write-MdLine ("  CSF: {0}" -f $change.CsfMapping)
            }
            if (-not [string]::IsNullOrWhiteSpace($change.Notes)) {
                Write-MdLine ("  Notes: {0}" -f $change.Notes)
            }
            if ([bool]$change.GuardrailMatched -and -not [string]::IsNullOrWhiteSpace([string]$change.GuardrailReason)) {
                Write-MdLine ("  Guardrail: {0}" -f $change.GuardrailReason)
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$change.MatchedRuleId)) {
                Write-MdLine ("  MatchedRuleId: {0}" -f $change.MatchedRuleId)
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$change.MatchedRuleDescription)) {
                Write-MdLine ("  Rule: {0}" -f $change.MatchedRuleDescription)
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$change.Interpretation)) {
                Write-MdLine ("  Interpretation: {0}" -f $change.Interpretation)
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$change.RecommendedAction)) {
                Write-MdLine ("  RecommendedAction: {0}" -f $change.RecommendedAction)
            }
            if ([bool]$change.IsAcceptedDrift) {
                Write-MdLine ("  AcceptedDrift: {0}" -f $(if (-not [string]::IsNullOrWhiteSpace([string]$change.AcceptanceId)) { $change.AcceptanceId } else { 'true' }))
                if (-not [string]::IsNullOrWhiteSpace([string]$change.AcceptedDriftReason)) {
                    Write-MdLine ("  AcceptedDriftReason: {0}" -f $change.AcceptedDriftReason)
                }
            } elseif (-not [string]::IsNullOrWhiteSpace([string]$change.AcceptedDriftBlockedReason)) {
                Write-MdLine ("  AcceptedDriftBlockedReason: {0}" -f $change.AcceptedDriftBlockedReason)
            }
        }
    }

    if (@($alertableChanges).Count -gt 0) {
        $topChanges = @($alertableChanges | Select-Object -First 3)
        $headline = Format-ChangeHeadline -Change $topChanges[0]
        $detailLines = @($topChanges | ForEach-Object { Format-ChangeHeadline -Change $_ })
        $alertHighestSeverity = (@($alertableChanges | ForEach-Object { Get-ChangeSeverityRank $_ } | Measure-Object -Maximum).Maximum)
        $alertSeverityLabel = if ($alertHighestSeverity -ge 4) { "High" } elseif ($alertHighestSeverity -ge 3) { "Medium" } else { "Low" }
        $alert = [PSCustomObject]@{
            Metadata = [PSCustomObject]@{
                AlertType = "HostTripwire"
                ComputerName = $env:COMPUTERNAME
                CollectionTimeUtc = $collectionTimeUtc
                Severity = $alertSeverityLabel
                ChangeCount = @($alertableChanges).Count
                SourceReport = $jsonFile
            }
            Summary = [PSCustomObject]@{
                Title = "Codex tripwire: {0}" -f $headline
                Message = "{0} alertable posture-drift change(s) detected. Highest severity: {1}." -f @($alertableChanges).Count, $alertSeverityLabel
                DetailLines = @($detailLines)
            }
            Changes = @($alertableChanges)
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
            Add-Content -LiteralPath $alertMd -Value ("- [{0}] {1} {2} ({3}/{4})" -f $change.Category, $change.Name, $change.ChangeType, (Get-ChangeSeverity $change), $(if ([string]::IsNullOrWhiteSpace([string]$change.Classification)) { 'uncategorized' } else { [string]$change.Classification }))
        }
        Write-Host ("Alert JSON written to: {0}" -f $alertJson)
        Write-Host ("Alert Markdown written to: {0}" -f $alertMd)
    }

    Write-Host ("JSON written to: {0}" -f $jsonFile)
    Write-Host ("Markdown written to: {0}" -f $mdFile)
}
finally {
    if ($tripwireLockAcquired) {
        Clear-TripwireRunLock -LockPath $tripwireLockPath
    }
}

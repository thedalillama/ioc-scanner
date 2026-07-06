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

function Get-BaselineHashStatus {
    param([string]$DbPath)

    if (-not (Test-Path -LiteralPath $DbPath)) {
        return $null
    }

    try {
        $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("baseline-hash-status")
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            return ($raw | ConvertFrom-Json)
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

function Get-LatestTripwireReportSummary {
    $report = Get-LatestFileMetadata -Pattern "HOST_TRIPWIRE_CHECK_*.json"
    if ($null -eq $report -or [string]::IsNullOrWhiteSpace([string]$report.Path) -or -not (Test-Path -LiteralPath ([string]$report.Path))) {
        return $null
    }

    try {
        $payload = Get-Content -LiteralPath ([string]$report.Path) -Raw | ConvertFrom-Json
        return [PSCustomObject]@{
            Path = [string]$report.Path
            LastWriteTimeUtc = [string]$report.LastWriteTimeUtc
            CollectionTimeUtc = if ($payload.Metadata) { [string]$payload.Metadata.CollectionTimeUtc } else { $null }
            ChangeCount = if ($payload.Metadata) { [int]$payload.Metadata.ChangeCount } else { 0 }
            HighestSeverityLabel = if ($payload.Metadata) { [string]$payload.Metadata.HighestSeverityLabel } else { $null }
            Summary = $payload.Summary
        }
    } catch {
        return $null
    }
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

function Get-ProtectionProfiles {
    $path = Join-Path $PSScriptRoot "protection-profiles.json"
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Protection profiles file is missing: $path"
    }

    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Get-LocalPcIdentifyData {
    $data = [ordered]@{
        Hostname = $env:COMPUTERNAME
        Manufacturer = $null
        Model = $null
        WindowsEdition = $null
        WindowsVersion = $null
        WindowsBuild = $null
        CurrentUser = $null
        LocalUserCount = $null
        LocalAdministratorCount = $null
        InstalledSoftwareCount = $null
        RunningServiceCount = $null
        ScheduledTaskCount = $null
        AutorunCount = $null
        NetworkAdapterCount = $null
        ListeningTcpPortCount = $null
        SharedFolderCount = $null
    }

    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $data.Manufacturer = [string]$computerSystem.Manufacturer
        $data.Model = [string]$computerSystem.Model
    } catch {
    }

    try {
        $currentVersion = Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace([string]$currentVersion.ProductName)) {
            $data.WindowsEdition = [string]$currentVersion.ProductName
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$currentVersion.EditionID)) {
            $data.WindowsEdition = [string]$currentVersion.EditionID
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$currentVersion.DisplayVersion)) {
            $data.WindowsVersion = [string]$currentVersion.DisplayVersion
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$currentVersion.ReleaseId)) {
            $data.WindowsVersion = [string]$currentVersion.ReleaseId
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$currentVersion.CurrentBuildNumber)) {
            $data.WindowsBuild = [string]$currentVersion.CurrentBuildNumber
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$currentVersion.CurrentBuild)) {
            $data.WindowsBuild = [string]$currentVersion.CurrentBuild
        }
    } catch {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $data.WindowsEdition = [string]$os.Caption
            $data.WindowsVersion = [string]$os.Version
            $data.WindowsBuild = [string]$os.BuildNumber
        } catch {
        }
    }

    try {
        $data.CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    } catch {
    }

    try {
        $data.LocalUserCount = @((Get-LocalUser -ErrorAction Stop)).Count
    } catch {
    }

    try {
        $data.LocalAdministratorCount = @((Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop)).Count
    } catch {
    }

    try {
        $softwareKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($path in $uninstallPaths) {
            foreach ($item in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
                if ([string]::IsNullOrWhiteSpace([string]$item.DisplayName)) {
                    continue
                }
                $identity = "{0}|{1}|{2}" -f [string]$item.DisplayName, [string]$item.DisplayVersion, [string]$item.Publisher
                [void]$softwareKeys.Add($identity)
            }
        }
        $data.InstalledSoftwareCount = $softwareKeys.Count
    } catch {
    }

    try {
        $data.RunningServiceCount = @((Get-Service -ErrorAction Stop | Where-Object { $_.Status -eq "Running" })).Count
    } catch {
    }

    try {
        $data.ScheduledTaskCount = @((Get-ScheduledTask -ErrorAction Stop)).Count
    } catch {
    }

    try {
        $autorunCount = 0
        $autorunKeys = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($key in $autorunKeys) {
            if (-not (Test-Path -LiteralPath $key)) {
                continue
            }
            $item = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
            if ($null -eq $item) {
                continue
            }
            $autorunCount += @($item.PSObject.Properties | Where-Object {
                $_.MemberType -eq "NoteProperty" -and $_.Name -notlike "PS*"
            }).Count
        }

        $startupFolders = @(
            [Environment]::GetFolderPath("CommonStartup"),
            [Environment]::GetFolderPath("Startup")
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($folder in $startupFolders) {
            if (Test-Path -LiteralPath $folder) {
                $autorunCount += @((Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue)).Count
            }
        }
        $data.AutorunCount = $autorunCount
    } catch {
    }

    try {
        $data.NetworkAdapterCount = @((Get-NetAdapter -ErrorAction Stop)).Count
    } catch {
    }

    try {
        $data.ListeningTcpPortCount = @((Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort -Unique)).Count
    } catch {
    }

    try {
        $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object {
            $_.Name -and $_.Name -notmatch '\$$' -and ($null -eq $_.Special -or -not $_.Special)
        })
        $data.SharedFolderCount = $shares.Count
    } catch {
    }

    return [PSCustomObject]$data
}

function Get-ExecutionPolicyRank {
    param([string]$Policy)

    $policyText = if ($null -eq $Policy) { "" } else { [string]$Policy }
    switch ($policyText.ToLowerInvariant()) {
        "restricted" { return 4 }
        "allsigned" { return 3 }
        "remotesigned" { return 2 }
        "unrestricted" { return 1 }
        "bypass" { return 0 }
        "undefined" { return -1 }
        default { return -1 }
    }
}

function New-ProtectionResult {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Desired,
        [string]$Current,
        [string]$Status,
        [int]$Weight,
        [int]$ScoreAwarded,
        [string]$Message
    )

    return [PSCustomObject]@{
        Id = $Id
        Title = $Title
        Desired = $Desired
        Current = $Current
        Status = $Status
        Weight = $Weight
        ScoreAwarded = $ScoreAwarded
        Message = $Message
    }
}

function Test-ProtectionControl {
    param(
        [pscustomobject]$Control
    )

    $id = [string]$Control.id
    $desired = [string]$Control.desired
    $weight = [int]$Control.weight

    try {
        switch ($id) {
            "firewall_all_profiles" {
                $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
                $enabledProfiles = @($profiles | Where-Object { $_.Enabled })
                $current = (@($profiles | ForEach-Object { "{0}={1}" -f $_.Name, $(if ($_.Enabled) { "On" } else { "Off" }) }) -join ", ")
                if (@($enabledProfiles).Count -eq @($profiles).Count -and @($profiles).Count -gt 0) {
                    return (New-ProtectionResult $id "Firewall profiles" "All profiles enabled" $current "Pass" $weight $weight "All Windows Firewall profiles are enabled.")
                }
                if (@($enabledProfiles).Count -gt 0) {
                    return (New-ProtectionResult $id "Firewall profiles" "All profiles enabled" $current "Partial" $weight ([int][math]::Floor($weight / 2)) "Some Firewall profiles are enabled, but not all.")
                }
                return (New-ProtectionResult $id "Firewall profiles" "All profiles enabled" $current "Fail" $weight 0 "Windows Firewall profiles are disabled.")
            }
            "defender_realtime" {
                $mp = Get-MpComputerStatus -ErrorAction Stop
                $current = if ($mp.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" }
                if ($mp.RealTimeProtectionEnabled) {
                    return (New-ProtectionResult $id "Defender real-time protection" "Enabled" $current "Pass" $weight $weight "Microsoft Defender real-time protection is enabled.")
                }
                return (New-ProtectionResult $id "Defender real-time protection" "Enabled" $current "Fail" $weight 0 "Microsoft Defender real-time protection is disabled.")
            }
            "bitlocker_system_drive" {
                $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
                $isProtected = ($volume.ProtectionStatus -eq "On" -or [int]$volume.ProtectionStatus -eq 1)
                $current = "{0} ({1})" -f $volume.VolumeStatus, $(if ($isProtected) { "Protected" } else { "Unprotected" })
                if ($isProtected) {
                    return (New-ProtectionResult $id "BitLocker system drive" "Enabled" $current "Pass" $weight $weight "The system drive is protected by BitLocker.")
                }
                return (New-ProtectionResult $id "BitLocker system drive" "Enabled" $current "Fail" $weight 0 "The system drive is not protected by BitLocker.")
            }
            "secure_boot" {
                $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
                $current = if ($enabled) { "Enabled" } else { "Disabled" }
                if ($enabled) {
                    return (New-ProtectionResult $id "Secure Boot" "Enabled" $current "Pass" $weight $weight "Secure Boot is enabled.")
                }
                return (New-ProtectionResult $id "Secure Boot" "Enabled" $current "Fail" $weight 0 "Secure Boot is disabled.")
            }
            "rdp" {
                $rdpValue = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop).fDenyTSConnections
                $enabled = ([int]$rdpValue -eq 0)
                $current = if ($enabled) { "Enabled" } else { "Disabled" }
                if (-not $enabled) {
                    return (New-ProtectionResult $id "Remote Desktop" "Disabled" $current "Pass" $weight $weight "Remote Desktop is disabled.")
                }
                return (New-ProtectionResult $id "Remote Desktop" "Disabled" $current "Fail" $weight 0 "Remote Desktop is enabled.")
            }
            "winrm" {
                $service = Get-Service -Name WinRM -ErrorAction Stop
                $serviceCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
                $current = "{0} / {1}" -f $service.Status, $serviceCim.StartMode
                $disabled = ($serviceCim.StartMode -eq "Disabled" -and $service.Status -ne "Running")
                if ($disabled) {
                    return (New-ProtectionResult $id "WinRM service" "Disabled" $current "Pass" $weight $weight "WinRM is disabled.")
                }
                if ($service.Status -ne "Running") {
                    return (New-ProtectionResult $id "WinRM service" "Disabled" $current "Partial" $weight ([int][math]::Floor($weight / 2)) "WinRM is not running, but it is not disabled.")
                }
                return (New-ProtectionResult $id "WinRM service" "Disabled" $current "Fail" $weight 0 "WinRM is enabled and running.")
            }
            "execution_policy" {
                $policy = [string](Get-ExecutionPolicy)
                $rank = Get-ExecutionPolicyRank -Policy $policy
                $pass = $false
                if ($desired -eq "remotesigned_or_stricter") {
                    $pass = ($rank -ge 2)
                } elseif ($desired -eq "allsigned_or_restricted") {
                    $pass = ($rank -ge 3)
                }
                if ($pass) {
                    return (New-ProtectionResult $id "PowerShell execution policy" $desired $policy "Pass" $weight $weight "PowerShell execution policy meets the selected profile.")
                }
                return (New-ProtectionResult $id "PowerShell execution policy" $desired $policy "Fail" $weight 0 "PowerShell execution policy is weaker than the selected profile expects.")
            }
            "defender_signatures" {
                $mp = Get-MpComputerStatus -ErrorAction Stop
                $updated = [datetimeoffset]$mp.AntivirusSignatureLastUpdated
                $ageDays = (New-TimeSpan -Start $updated.UtcDateTime -End (Get-Date).ToUniversalTime()).TotalDays
                $current = "{0} ({1:N1} days old)" -f $updated.ToString("o"), $ageDays
                $limit = if ($desired -eq "fresh_3d") { 3 } else { 7 }
                if ($ageDays -le $limit) {
                    return (New-ProtectionResult $id "Defender signatures" ("Fresh within {0} days" -f $limit) $current "Pass" $weight $weight "Defender signatures are current.")
                }
                return (New-ProtectionResult $id "Defender signatures" ("Fresh within {0} days" -f $limit) $current "Fail" $weight 0 "Defender signatures are older than the selected profile expects.")
            }
            default {
                return (New-ProtectionResult $id $id $desired "Unknown" "Unknown" $weight 0 "This control is not implemented yet.")
            }
        }
    } catch {
        return (New-ProtectionResult $id $id $desired "Unknown" "Unknown" $weight 0 $_.Exception.Message)
    }
}

function Get-ProtectionPosture {
    param(
        $Settings
    )

    $profiles = Get-ProtectionProfiles
    $availableProfiles = @($profiles.profiles)
    $selectedProfileId = [string]$Settings.ProtectionProfile
    if ([string]::IsNullOrWhiteSpace($selectedProfileId)) {
        $selectedProfileId = "microsoft_baseline"
    }

    $selectedProfile = @($availableProfiles | Where-Object { $_.id -eq $selectedProfileId } | Select-Object -First 1)
    if (@($selectedProfile).Count -eq 0) {
        $selectedProfile = @($availableProfiles | Select-Object -First 1)
    }
    $selectedProfile = $selectedProfile[0]

    $results = @($selectedProfile.controls | ForEach-Object { Test-ProtectionControl -Control $_ })
    $totalWeight = [int]((@($selectedProfile.controls) | Measure-Object -Property weight -Sum).Sum)
    $awarded = [int]((@($results) | Measure-Object -Property ScoreAwarded -Sum).Sum)
    $score = if ($totalWeight -gt 0) { [int][math]::Round(($awarded / $totalWeight) * 100) } else { 0 }

    return [PSCustomObject]@{
        SelectedProfile = [PSCustomObject]@{
            Id = [string]$selectedProfile.id
            Name = [string]$selectedProfile.name
            Description = [string]$selectedProfile.description
            Source = [string]$selectedProfile.source
        }
        AvailableProfiles = @($availableProfiles | ForEach-Object {
            [PSCustomObject]@{
                Id = [string]$_.id
                Name = [string]$_.name
                Description = [string]$_.description
                Source = [string]$_.source
            }
        })
        Score = $score
        MaximumScore = 100
        Controls = @($results)
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
$protection = Get-ProtectionPosture -Settings $settings
$identify = Get-LocalPcIdentifyData

$rssState = Get-SqliteState -DbPath $resolvedStateDbPath -Namespace "threat_rss" -Key "feed_state"
$tripwireBaselineMeta = Get-SqliteStateMeta -DbPath $resolvedStateDbPath -Namespace "host_tripwire" -Key "baseline"
$alertHelperState = Get-SqliteState -DbPath $resolvedStateDbPath -Namespace "alert_helper" -Key "seen_alerts"
$baselineHashStatus = Get-BaselineHashStatus -DbPath $resolvedStateDbPath
$latestIocHashCoverage = Get-SqliteState -DbPath $resolvedStateDbPath -Namespace "ioc_scan" -Key "latest_hash_coverage"
$latestTripwireDriftSummary = Get-LatestTripwireReportSummary

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

foreach ($control in @($protection.Controls | Where-Object { $_.Status -eq "Fail" })) {
    Add-HealthFinding -List $healthFindings -Severity "Medium" -Message ("Protection posture drift: {0}." -f $control.Title)
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
    Identify = [PSCustomObject]@{
        Hostname = $identify.Hostname
        Manufacturer = $identify.Manufacturer
        Model = $identify.Model
        WindowsEdition = $identify.WindowsEdition
        WindowsVersion = $identify.WindowsVersion
        WindowsBuild = $identify.WindowsBuild
        CurrentUser = $identify.CurrentUser
        LocalUserCount = $identify.LocalUserCount
        LocalAdministratorCount = $identify.LocalAdministratorCount
        InstalledSoftwareCount = $identify.InstalledSoftwareCount
        RunningServiceCount = $identify.RunningServiceCount
        ScheduledTaskCount = $identify.ScheduledTaskCount
        AutorunCount = $identify.AutorunCount
        NetworkAdapterCount = $identify.NetworkAdapterCount
        ListeningTcpPortCount = $identify.ListeningTcpPortCount
        SharedFolderCount = $identify.SharedFolderCount
        BaselineScope = if ($tripwireBaselineMeta -and $tripwireBaselineMeta.metadata) {
            if ($tripwireBaselineMeta.metadata.ExecutionContext -and $tripwireBaselineMeta.metadata.ExecutionContext.Scope) {
                [string]$tripwireBaselineMeta.metadata.ExecutionContext.Scope
            } else {
                [string]$tripwireBaselineMeta.metadata.ExecutionContext
            }
        } else { $null }
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
        LatestTripwireDriftSummary = if ($latestTripwireDriftSummary) { $latestTripwireDriftSummary.Summary } else { $null }
        LatestTripwireDriftHighestSeverity = if ($latestTripwireDriftSummary) { [string]$latestTripwireDriftSummary.HighestSeverityLabel } else { $null }
    }
    Coverage = [PSCustomObject]@{
        BaselineHashIndexStatus = if ($baselineHashStatus) { [string]$baselineHashStatus.status } else { "unavailable" }
        LatestBaselineId = if ($baselineHashStatus) { [string]$baselineHashStatus.latest_baseline_id } else { $null }
        LatestBaselineHashCount = if ($baselineHashStatus) { [int]$baselineHashStatus.baseline_hash_count } else { 0 }
        LatestBaselineHashTimestamp = if ($baselineHashStatus) { [string]$baselineHashStatus.baseline_timestamp } else { $null }
        LatestIocHashCoverage = $latestIocHashCoverage
        LatestTripwirePostureSummary = if ($latestTripwireDriftSummary) { $latestTripwireDriftSummary.Summary } else { $null }
    }
    LatestArtifacts = [PSCustomObject]@{
        LatestIocReport = Get-LatestFileMetadata -Pattern "HOST_IOC_*.json"
        LatestTripwireReport = Get-LatestFileMetadata -Pattern "HOST_TRIPWIRE_*.json"
        LatestThreatRssReport = Get-LatestFileMetadata -Pattern "THREAT_RSS_*.json"
    }
    Protection = $protection
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
Write-Host ("Protection profile: {0}" -f $status.Protection.SelectedProfile.Name)
Write-Host ("Protection score: {0}/{1}" -f $status.Protection.Score, $status.Protection.MaximumScore)
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

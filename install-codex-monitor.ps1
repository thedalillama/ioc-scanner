# CODEX_MONITOR_SELF_EVENT
param(
    [string]$SourceRoot = $PSScriptRoot,
    [string]$RuntimeRoot = "C:\Program Files\CodexMonitor",
    [string]$DataRoot = "C:\ProgramData\CodexMonitor",
    [string]$SettingsRoot = "",
    [switch]$CreateSystemTasks,
    [switch]$CreateUserNotifierTask,
    [switch]$InitializeProtection,
    [string]$NotifierScriptPath = "",
    [switch]$InstallPythonIfMissing,
    [string]$PythonInstallerPath = "",
    [string]$PythonInstallerArguments = "",
    [string]$PythonWingetId = "Python.Python.3.12"
)

$ErrorActionPreference = "Stop"

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Copy-IfExists {
    param(
        [string]$Path,
        [string]$Destination
    )

    if (Test-Path -LiteralPath $Path) {
        $destinationParent = Split-Path -Parent $Destination
        if (-not [string]::IsNullOrWhiteSpace($destinationParent)) {
            Ensure-Directory -Path $destinationParent
        }
        if (Test-Path -LiteralPath $Destination) {
            $destinationItem = Get-Item -LiteralPath $Destination -Force
            if (-not $destinationItem.PSIsContainer -and $destinationItem.IsReadOnly) {
                $destinationItem.IsReadOnly = $false
            }
            [System.IO.File]::SetAttributes($Destination, [System.IO.FileAttributes]::Normal)
        }
        Copy-Item -LiteralPath $Path -Destination $Destination -Force
        if (Test-Path -LiteralPath $Destination) {
            $copiedItem = Get-Item -LiteralPath $Destination -Force
            if (-not $copiedItem.PSIsContainer -and $copiedItem.IsReadOnly) {
                $copiedItem.IsReadOnly = $false
            }
            [System.IO.File]::SetAttributes($Destination, [System.IO.FileAttributes]::Normal)
        }
    }
}

function Resolve-SourceArtifact {
    param(
        [string]$Root,
        [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        $candidatePath = Join-Path $Root $candidate
        if (Test-Path -LiteralPath $candidatePath) {
            return $candidatePath
        }
    }

    return $null
}

function Test-PythonCommand {
    param(
        [string]$Command,
        [string[]]$Arguments = @()
    )

    try {
        $output = & $Command @Arguments -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $resolved = (@($output) | Select-Object -Last 1).Trim()
            if (-not [string]::IsNullOrWhiteSpace($resolved) -and (Test-Path -LiteralPath $resolved)) {
                return $resolved
            }
        }
    } catch {
    }

    return $null
}

function Resolve-PythonRuntime {
    $candidates = @(
        @{ Command = "python"; Arguments = @() },
        @{ Command = "py"; Arguments = @("-3") }
    )

    foreach ($candidate in $candidates) {
        $resolved = Test-PythonCommand -Command $candidate.Command -Arguments $candidate.Arguments
        if (-not [string]::IsNullOrWhiteSpace($resolved)) {
            return $resolved
        }
    }

    $wellKnownRoots = @()
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $wellKnownRoots += (Join-Path $env:LOCALAPPDATA "Programs\Python")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $wellKnownRoots += (Join-Path $env:ProgramFiles "Python")
    }
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $wellKnownRoots += (Join-Path ${env:ProgramFiles(x86)} "Python")
    }
    $wellKnownRoots = @($wellKnownRoots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) })

    foreach ($root in $wellKnownRoots) {
        $pythonCandidates = Get-ChildItem -Path $root -Filter python.exe -Recurse -ErrorAction SilentlyContinue |
            Sort-Object -Property FullName -Descending
        foreach ($candidate in $pythonCandidates) {
            if (Test-Path -LiteralPath $candidate.FullName) {
                return $candidate.FullName
            }
        }
    }

    return $null
}

function Wait-ForPythonRuntime {
    param(
        [int]$TimeoutSeconds = 300,
        [int]$PollSeconds = 5
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $resolved = Resolve-PythonRuntime
        if (-not [string]::IsNullOrWhiteSpace($resolved)) {
            return $resolved
        }
        Start-Sleep -Seconds $PollSeconds
    } while ((Get-Date) -lt $deadline)

    return $null
}

function Test-IsAdministrator {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-CurrentIdentityName {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($null -ne $currentIdentity -and -not [string]::IsNullOrWhiteSpace($currentIdentity.Name)) {
            return $currentIdentity.Name
        }
    } catch {
    }

    if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN) -and -not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
        return "{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME
    }

    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME) -and -not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
        return "{0}\{1}" -f $env:COMPUTERNAME, $env:USERNAME
    }

    throw "Unable to resolve the current Windows user identity for the notifier task."
}

function Grant-NotifierStateAccess {
    param(
        [string]$Identity,
        [string]$StateDirectory
    )

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        throw "Interactive notifier identity is required to grant SQLite state access."
    }
    & icacls.exe $StateDirectory /grant ("{0}:(OI)(CI)M" -f $Identity) /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to grant notifier Modify access to SQLite state directory: $StateDirectory"
    }
}

function Register-CodexSystemTask {
    param(
        [string]$TaskName,
        [string]$VbsPath,
        [string]$LauncherPath,
        [ValidateSet('Hourly', 'Daily')]
        [string]$Schedule,
        [datetime]$At
    )

    if (-not (Test-IsAdministrator)) {
        throw "Creating SYSTEM scheduled tasks requires an elevated installer session."
    }

    $action = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument ('//B //nologo "{0}" "{1}"' -f $VbsPath, $LauncherPath)
    if ($Schedule -eq 'Hourly') {
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 3650)
    } else {
        $trigger = New-ScheduledTaskTrigger -Daily -At $At
    }

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Write-LauncherScript {
    param(
        [string]$Path,
        [string]$PowerShellCommand
    )

    $content = @(
        '@echo off',
        $PowerShellCommand,
        'exit /b %ERRORLEVEL%'
    )

    if (Test-Path -LiteralPath $Path) {
        $existingItem = Get-Item -LiteralPath $Path -Force
        if (-not $existingItem.PSIsContainer -and $existingItem.IsReadOnly) {
            $existingItem.IsReadOnly = $false
        }
        [System.IO.File]::SetAttributes($Path, [System.IO.FileAttributes]::Normal)
    }

    $content | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Install-PythonRuntime {
    param(
        [string]$InstallerPath,
        [string]$InstallerArguments,
        [string]$WingetId
    )

    if (-not [string]::IsNullOrWhiteSpace($InstallerPath)) {
        if (-not (Test-Path -LiteralPath $InstallerPath)) {
            throw "Python installer path does not exist: $InstallerPath"
        }

        $extension = [IO.Path]::GetExtension($InstallerPath).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($InstallerArguments)) {
            if ($extension -eq ".msi") {
                $InstallerArguments = "/quiet"
            } else {
                $InstallerArguments = "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0"
            }
        }

        $installProcess = Start-Process -FilePath $InstallerPath -ArgumentList $InstallerArguments -Wait -PassThru
        if ($installProcess.ExitCode -ne 0) {
            throw "Python installer exited with code $($installProcess.ExitCode)."
        }
        return
    }

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        throw "Python is missing and winget is not available. Install Python manually or supply -PythonInstallerPath."
    }

    $wingetArgs = @(
        "install",
        "--exact",
        "--id", $WingetId,
        "--accept-package-agreements",
        "--accept-source-agreements"
    )
    $wingetProcess = Start-Process -FilePath $winget.Source -ArgumentList $wingetArgs -Wait -PassThru
    if ($wingetProcess.ExitCode -ne 0) {
        Write-Warning "winget Python installation exited with code $($wingetProcess.ExitCode). Waiting to see whether Python became available anyway."
    }
}

Ensure-Directory -Path $RuntimeRoot
Ensure-Directory -Path $DataRoot

if ([string]::IsNullOrWhiteSpace($SettingsRoot)) {
    $SettingsRoot = $RuntimeRoot
}

Ensure-Directory -Path $SettingsRoot
Ensure-Directory -Path (Join-Path $DataRoot "alerts")
Ensure-Directory -Path (Join-Path $DataRoot "alerts\pending")
Ensure-Directory -Path (Join-Path $DataRoot "alerts\archive")
Ensure-Directory -Path (Join-Path $DataRoot "indicators")
Ensure-Directory -Path (Join-Path $DataRoot "state")

$pythonRuntime = Resolve-PythonRuntime
if ([string]::IsNullOrWhiteSpace($pythonRuntime) -and $InstallPythonIfMissing) {
    Install-PythonRuntime -InstallerPath $PythonInstallerPath -InstallerArguments $PythonInstallerArguments -WingetId $PythonWingetId
    $pythonRuntime = Wait-ForPythonRuntime
}

if ([string]::IsNullOrWhiteSpace($pythonRuntime)) {
    throw "A usable Python runtime was not found. Install Python first, or rerun the installer with -InstallPythonIfMissing."
}

if ([string]::IsNullOrWhiteSpace($NotifierScriptPath)) {
    $NotifierScriptPath = (Join-Path $RuntimeRoot "start-codex-alert-helper.ps1")
}

$runtimeFiles = @(
    @{ Target = "codex_monitor_ui.py"; Candidates = @("codex_monitor_ui.py") },
    @{ Target = "start-codex-monitor-ui.ps1"; Candidates = @("start-codex-monitor-ui.ps1") },
    @{ Target = "invoke-host-ioc.ps1"; Candidates = @("invoke-host-ioc.ps1", "ioc.ps1") },
    @{ Target = "invoke-host-tripwire.ps1"; Candidates = @("invoke-host-tripwire.ps1", "tripwire.ps1") },
    @{ Target = "refresh-tripwire-baseline.ps1"; Candidates = @("refresh-tripwire-baseline.ps1") },
    @{ Target = "monitor-threat-rss.ps1"; Candidates = @("monitor-threat-rss.ps1", "rss.ps1") },
    @{ Target = "start-codex-alert-helper.ps1"; Candidates = @("start-codex-alert-helper.ps1", "alert-helper.ps1") },
    @{ Target = "import-threat-feeds.ps1"; Candidates = @("import-threat-feeds.ps1", "feed-import.ps1") },
    @{ Target = "get-codex-monitor-status.ps1"; Candidates = @("get-codex-monitor-status.ps1", "status.ps1") },
    @{ Target = "ioc_store.py"; Candidates = @("ioc_store.py", "store.py") },
    @{ Target = "host-tripwire-config.json"; Candidates = @("host-tripwire-config.json", "tripwire-config.json") },
    @{ Target = "ioc-monitor-locations.json"; Candidates = @("ioc-monitor-locations.json", "ioc-locations.json") },
    @{ Target = "accept-posture-drift.ps1"; Candidates = @("accept-posture-drift.ps1") },
    @{ Target = "posture-drift-rules.ps1"; Candidates = @("posture-drift-rules.ps1") },
    @{ Target = "tripwire-posture-baseline.ps1"; Candidates = @("tripwire-posture-baseline.ps1") },
    @{ Target = "protection-profiles.json"; Candidates = @("protection-profiles.json") },
    @{ Target = "profiles\persona-profiles.json"; Candidates = @("profiles\persona-profiles.json") },
    @{ Target = "profiles\system-profiles.json"; Candidates = @("profiles\system-profiles.json") },
    @{ Target = "profiles\posture-drift-rules.json"; Candidates = @("profiles\posture-drift-rules.json") },
    @{ Target = "run-hidden.vbs"; Candidates = @("run-hidden.vbs", "hidden.vbs") }
)

$missingRuntimeFiles = New-Object System.Collections.Generic.List[string]
foreach ($file in $runtimeFiles) {
    $sourcePath = Resolve-SourceArtifact -Root $SourceRoot -Candidates $file.Candidates
    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        $missingRuntimeFiles.Add($file.Target)
        continue
    }
    Copy-IfExists -Path $sourcePath -Destination (Join-Path $RuntimeRoot $file.Target)
}

if ($missingRuntimeFiles.Count -gt 0) {
    throw ("The installer media is missing required runtime files: {0}" -f ($missingRuntimeFiles -join ", "))
}

$settings = [PSCustomObject]@{
    RuntimeRoot = $RuntimeRoot
    DataRoot = $DataRoot
    StateDbPath = (Join-Path $DataRoot "state\ioc-store.db")
    IndicatorExportPath = (Join-Path $DataRoot "indicators\feed-indicators-latest.json")
    PythonCommand = $pythonRuntime
    AlertWatchPath = (Join-Path $DataRoot "alerts\pending")
    AlertInboxPath = (Join-Path $DataRoot "alerts\pending")
    AlertArchivePath = (Join-Path $DataRoot "alerts\archive")
}
$settingsPath = Join-Path $SettingsRoot "codex-monitor.settings.json"
if (Test-Path -LiteralPath $settingsPath) {
    $settingsItem = Get-Item -LiteralPath $settingsPath -Force
    if (-not $settingsItem.PSIsContainer -and $settingsItem.IsReadOnly) {
        $settingsItem.IsReadOnly = $false
    }
    [System.IO.File]::SetAttributes($settingsPath, [System.IO.FileAttributes]::Normal)
}
$settings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $settingsPath -Encoding UTF8

$runtimeRootTaskPath = $RuntimeRoot
$dataRootTaskPath = $DataRoot

$iocStoreRuntimePath = Join-Path $RuntimeRoot "ioc_store.py"
if (Test-Path -LiteralPath $iocStoreRuntimePath) {
    & $pythonRuntime $iocStoreRuntimePath --db (Join-Path $DataRoot "state\ioc-store.db") init | Out-Null
}

if ($CreateSystemTasks) {
    $vbsRuntimePath = (Join-Path $runtimeRootTaskPath "run-hidden.vbs")
    $tripwireLauncher = Join-Path $RuntimeRoot "codex-host-tripwire.cmd"
    $rssLauncher = Join-Path $RuntimeRoot "codex-threat-rss.cmd"
    $feedImportLauncher = Join-Path $RuntimeRoot "codex-feed-import.cmd"
    $iocScanLauncher = Join-Path $RuntimeRoot "codex-ioc-scan.cmd"

    Write-LauncherScript -Path $tripwireLauncher -PowerShellCommand ("powershell.exe -ExecutionPolicy Bypass -File ""{0}\invoke-host-tripwire.ps1"" -Mode Check -StateDbPath ""{1}\state\ioc-store.db""" -f $RuntimeRoot, $DataRoot)
    Write-LauncherScript -Path $rssLauncher -PowerShellCommand ("powershell.exe -ExecutionPolicy Bypass -File ""{0}\monitor-threat-rss.ps1"" -StateDbPath ""{1}\state\ioc-store.db"" -RunTripwireCheckOnMatch" -f $RuntimeRoot, $DataRoot)
    Write-LauncherScript -Path $feedImportLauncher -PowerShellCommand ("powershell.exe -ExecutionPolicy Bypass -File ""{0}\import-threat-feeds.ps1""" -f $RuntimeRoot)
    Write-LauncherScript -Path $iocScanLauncher -PowerShellCommand ("powershell.exe -ExecutionPolicy Bypass -File ""{0}\invoke-host-ioc.ps1"" -Mode IOC" -f $RuntimeRoot)

    Register-CodexSystemTask -TaskName 'Codex Host Tripwire' -VbsPath $vbsRuntimePath -LauncherPath $tripwireLauncher -Schedule Hourly
    Register-CodexSystemTask -TaskName 'Codex Threat RSS Monitor' -VbsPath $vbsRuntimePath -LauncherPath $rssLauncher -Schedule Hourly
    Register-CodexSystemTask -TaskName 'Codex Threat Feed Import' -VbsPath $vbsRuntimePath -LauncherPath $feedImportLauncher -Schedule Daily -At (Get-Date -Hour 2 -Minute 0 -Second 0)
    Register-CodexSystemTask -TaskName 'Codex IOC Daily Scan' -VbsPath $vbsRuntimePath -LauncherPath $iocScanLauncher -Schedule Daily -At (Get-Date -Hour 3 -Minute 0 -Second 0)
}

if ($CreateUserNotifierTask) {
    $notifierUser = Get-CurrentIdentityName
    Grant-NotifierStateAccess -Identity $notifierUser -StateDirectory (Join-Path $DataRoot "state")
    $notifierRuntimePath = $NotifierScriptPath
    if ($notifierRuntimePath -like "C:\Program Files\*") {
        $notifierRuntimePath = $notifierRuntimePath -replace '^C:\\Program Files', 'C:\Progra~1'
    }
    $vbsRuntimePath = (Join-Path $runtimeRootTaskPath "run-hidden.vbs")
    $notifierStateDbTaskPath = Join-Path $dataRootTaskPath "state\ioc-store.db"
    $notifierLauncher = Join-Path $RuntimeRoot "codex-alert-notifier.cmd"
    Write-LauncherScript -Path $notifierLauncher -PowerShellCommand ("powershell.exe -ExecutionPolicy Bypass -File ""{0}"" -StateDbPath ""{1}""" -f $NotifierScriptPath, (Join-Path $DataRoot "state\ioc-store.db"))
    $notifierLauncherTaskPath = $notifierLauncher -replace '\\', '\'
    $xmlPath = Join-Path $env:TEMP "CodexAlertNotifierTask.generated.xml"
    $startBoundary = (Get-Date).AddMinutes(1).ToString("s")
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Codex</Author>
    <Description>Runs the Codex alert notifier once per minute without flashing a PowerShell console window.</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>$startBoundary</StartBoundary>
      <Enabled>true</Enabled>
      <Repetition>
        <Interval>PT1M</Interval>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$notifierUser</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>wscript.exe</Command>
      <Arguments>//B //nologo "$vbsRuntimePath" "$notifierLauncherTaskPath"</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    $utf16 = New-Object System.Text.UnicodeEncoding($false, $true)
    [System.IO.File]::WriteAllText($xmlPath, $xml, $utf16)
    schtasks /Create /TN "Codex Alert Notifier" /XML $xmlPath /F | Out-Null
}

if ($InitializeProtection) {
    & (Join-Path $RuntimeRoot "import-threat-feeds.ps1")
    & (Join-Path $RuntimeRoot "invoke-host-tripwire.ps1") -Mode Baseline -StateDbPath (Join-Path $DataRoot "state\ioc-store.db")
    & (Join-Path $RuntimeRoot "monitor-threat-rss.ps1") -StateDbPath (Join-Path $DataRoot "state\ioc-store.db")
}

Write-Host ("Runtime root: {0}" -f $RuntimeRoot)
Write-Host ("Data root: {0}" -f $DataRoot)
Write-Host ("Settings file: {0}" -f $settingsPath)
Write-Host ("Python runtime: {0}" -f $pythonRuntime)
if ($CreateSystemTasks) {
    Write-Host "Created system scheduled tasks."
}
if ($CreateUserNotifierTask) {
    Write-Host "Created user notifier task."
}

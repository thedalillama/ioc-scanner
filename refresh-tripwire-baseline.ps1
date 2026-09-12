# CODEX_MONITOR_SELF_EVENT
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Reason,
    [string]$CreatedBy = $env:USERNAME,
    [string]$StateDbPath = "",
    [ValidateRange(30, 3600)]
    [int]$WaitSeconds = 900
)

$ErrorActionPreference = "Stop"
$refreshTaskName = "Codex Tripwire Baseline Refresh"
$refreshTaskPath = "\$refreshTaskName"
$tripwireScriptPath = Join-Path $PSScriptRoot "invoke-host-tripwire.ps1"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-StateDbPath {
    param([string]$ConfiguredPath)

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        return [IO.Path]::GetFullPath($ConfiguredPath)
    }

    $settingsPath = Join-Path $PSScriptRoot "codex-monitor.settings.json"
    if (Test-Path -LiteralPath $settingsPath) {
        $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
        if (-not [string]::IsNullOrWhiteSpace([string]$settings.StateDbPath)) {
            $settingsDirectory = Split-Path -Parent $settingsPath
            $configuredStateDbPath = [string]$settings.StateDbPath
            if ([IO.Path]::IsPathRooted($configuredStateDbPath)) {
                return [IO.Path]::GetFullPath($configuredStateDbPath)
            }
            return [IO.Path]::GetFullPath((Join-Path $settingsDirectory $configuredStateDbPath))
        }
    }

    return (Join-Path $PSScriptRoot "state\ioc-store.db")
}

if (-not (Test-IsAdministrator)) {
    throw "Tripwire baseline refresh requires an elevated administrator session to create its one-shot SYSTEM task."
}
if (-not (Test-Path -LiteralPath $tripwireScriptPath)) {
    throw "Tripwire collector was not found: $tripwireScriptPath"
}
if (Get-ScheduledTask -TaskName $refreshTaskName -ErrorAction SilentlyContinue) {
    throw "Refusing to reuse existing task $refreshTaskPath. Review and remove it before starting a baseline refresh."
}

$resolvedStateDbPath = Resolve-StateDbPath -ConfiguredPath $StateDbPath
$argumentList = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode Baseline -StateDbPath "{1}" -BaselineReason "{2}" -CreatedBy "{3}" -ExcludeTransientBaselineRefreshTask' -f $tripwireScriptPath, $resolvedStateDbPath, $Reason.Replace('"', '""'), $CreatedBy.Replace('"', '""')
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argumentList
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(1)
$createdTask = $false

try {
    Register-ScheduledTask -TaskName $refreshTaskName -Action $action -Principal $principal -Trigger $trigger -Force | Out-Null
    $createdTask = $true
    Start-ScheduledTask -TaskName $refreshTaskName

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    do {
        Start-Sleep -Seconds 2
        $task = Get-ScheduledTask -TaskName $refreshTaskName -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskName $refreshTaskName -ErrorAction Stop
        if ($task.State -ne "Running" -and $info.LastRunTime -gt [datetime]::MinValue) {
            if ($info.LastTaskResult -ne 0) {
                throw "SYSTEM Tripwire baseline refresh failed with task result $($info.LastTaskResult)."
            }
            Write-Output "Tripwire baseline refresh completed as SYSTEM."
            break
        }
    } while ((Get-Date) -lt $deadline)

    if ((Get-Date) -ge $deadline) {
        throw "SYSTEM Tripwire baseline refresh did not complete within $WaitSeconds seconds. The task was retained for investigation."
    }
} finally {
    if ($createdTask) {
        $task = Get-ScheduledTask -TaskName $refreshTaskName -ErrorAction SilentlyContinue
        if ($null -ne $task -and $task.State -ne "Running") {
            Unregister-ScheduledTask -TaskName $refreshTaskName -Confirm:$false
        }
    }
}

function Get-StringSha256 {
    param([string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($(if ($null -eq $Text) { '' } else { [string]$Text }))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '') } finally { $sha.Dispose() }
}

function ConvertTo-NormalizedListValue {
    param([object[]]$Items)
    return ((@($Items) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ } | Sort-Object -Unique) -join '|')
}

function Get-RegistryValueSafe {
    param([string]$Path,[string]$Name,$Default = $null)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $Default }
}

function Get-CommandPathSafe {
    param([string]$Name)
    try {
        $command = Get-Command -Name $Name -ErrorAction Stop | Select-Object -First 1
        foreach ($property in 'Source', 'Definition', 'Path') {
            $value = [string]$command.$property
            if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
        }
    } catch {}
    return $null
}

function Get-AuthenticodeMetadata {
    param([string]$Path)
    $result = [ordered]@{ SignatureStatus = 'Unavailable'; Publisher = $null; IsMicrosoftSigned = $false }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return [pscustomobject]$result }
    try {
        $signature = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $result.SignatureStatus = [string]$signature.Status
        if ($signature.SignerCertificate) {
            $result.Publisher = [string]$signature.SignerCertificate.Subject
            if ($result.Publisher.ToLowerInvariant().Contains('microsoft')) { $result.IsMicrosoftSigned = $true }
        }
    } catch {}
    return [pscustomobject]$result
}

function Get-IntegrityFileRecord {
    param([string]$Id,[string]$Title,[string]$Path,[bool]$Optional = $false,[bool]$IncludeSignature = $false,[string]$CsfMapping = 'ID.AM')
    $record = [ordered]@{ Id = $Id; Title = $Title; Path = $Path; Exists = $false; Optional = $Optional; Length = $null; LastWriteTimeUtc = $null; SHA256 = $null; FileVersion = $null; SignatureStatus = $null; Publisher = $null; IsMicrosoftSigned = $null; CsfMapping = $CsfMapping }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return [pscustomobject]$record }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return [pscustomobject]$record }
    $record.Exists = $true
    if (-not $item.PSIsContainer) {
        $record.Length = [int64]$item.Length
        $record.LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
        try { $record.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
        try { $record.FileVersion = [string]$item.VersionInfo.FileVersion } catch {}
    }
    if ($IncludeSignature) {
        $signature = Get-AuthenticodeMetadata -Path $Path
        $record.SignatureStatus = [string]$signature.SignatureStatus
        $record.Publisher = [string]$signature.Publisher
        $record.IsMicrosoftSigned = [bool]$signature.IsMicrosoftSigned
    }
    return [pscustomobject]$record
}

function New-BaselineValueRecord {
    param([string]$Id,[string]$Title,[string]$Value,[string]$Availability = 'available',[string]$Details = '',[string]$CsfMapping = 'DE.CM')
    return [pscustomobject]@{ Id = $Id; Title = $Title; Value = $(if ($null -eq $Value) { '' } else { [string]$Value }); Availability = $(if ([string]::IsNullOrWhiteSpace($Availability)) { 'available' } else { [string]$Availability }); Details = $(if ($null -eq $Details) { '' } else { [string]$Details }); CsfMapping = $CsfMapping }
}

function Resolve-ControlledFolderAccessState { param($Value) switch ([string]$Value) { '0' { 'Disabled' } '1' { 'Enabled' } '2' { 'AuditMode' } default { if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { 'Unavailable' } else { [string]$Value } } } }
function Resolve-SmartAppControlState { param($Value) switch ([string]$Value) { '0' { 'Off' } '1' { 'Eval' } '2' { 'On' } default { if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { 'Unavailable' } else { [string]$Value } } } }

function Get-SecurityControlBaselineSnapshot {
    $items = [System.Collections.ArrayList]::new(); $mpStatus = $null; $mpPreference = $null
    try { $mpStatus = Get-MpComputerStatus -ErrorAction Stop } catch {}
    try { $mpPreference = Get-MpPreference -ErrorAction Stop } catch {}
    if ($null -ne $mpStatus) {
        [void]$items.Add((New-BaselineValueRecord 'DefenderRealTime' 'Microsoft Defender real-time protection' $(if ($mpStatus.RealTimeProtectionEnabled) { 'Enabled' } else { 'Disabled' }) 'available' 'Expected state is enabled.' 'PR.PS / DE.CM'))
        $cloudState = 'Unknown'; if ($null -ne $mpPreference) { if ([string]$mpPreference.MAPSReporting -in @('0', 'Disabled')) { $cloudState = 'Disabled' } else { $cloudState = 'Enabled' } }
        [void]$items.Add((New-BaselineValueRecord 'DefenderCloudProtection' 'Defender cloud protection' $cloudState 'available' 'Derived from MAPS reporting preference when available.' 'PR.PS / DE.CM'))
        [void]$items.Add((New-BaselineValueRecord 'DefenderVersions' 'Defender engine/platform/security intelligence versions' ("Engine={0};Platform={1};SecurityIntelligence={2}" -f [string]$mpStatus.AMEngineVersion, [string]$mpStatus.AMProductVersion, [string]$mpStatus.AntivirusSignatureVersion) 'available' ("Security intelligence updated {0}" -f (ConvertTo-StableDateString $mpStatus.AntivirusSignatureLastUpdated)) 'PR.PS / DE.CM'))
    } else {
        [void]$items.Add((New-BaselineValueRecord 'DefenderRealTime' 'Microsoft Defender real-time protection' 'Unavailable' 'unavailable' 'Get-MpComputerStatus was not available.' 'PR.PS / DE.CM'))
        [void]$items.Add((New-BaselineValueRecord 'DefenderCloudProtection' 'Defender cloud protection' 'Unavailable' 'unavailable' 'Get-MpPreference was not available.' 'PR.PS / DE.CM'))
        [void]$items.Add((New-BaselineValueRecord 'DefenderVersions' 'Defender engine/platform/security intelligence versions' 'Unavailable' 'unavailable' 'Defender status could not be collected.' 'PR.PS / DE.CM'))
    }
    if ($null -ne $mpPreference) {
        $exclusions = @(); $exclusions += @($mpPreference.ExclusionPath | ForEach-Object { "Path:{0}" -f [string]$_ }); $exclusions += @($mpPreference.ExclusionExtension | ForEach-Object { "Extension:{0}" -f [string]$_ }); $exclusions += @($mpPreference.ExclusionProcess | ForEach-Object { "Process:{0}" -f [string]$_ }); $exclusions += @($mpPreference.ExclusionIpAddress | ForEach-Object { "IP:{0}" -f [string]$_ })
        [void]$items.Add((New-BaselineValueRecord 'DefenderExclusions' 'Defender exclusions' (ConvertTo-NormalizedListValue -Items $exclusions) 'available' ("Exclusion count: {0}" -f @($exclusions).Count) 'PR.PS / GV.OV'))
        [void]$items.Add((New-BaselineValueRecord 'ControlledFolderAccess' 'Controlled Folder Access' (Resolve-ControlledFolderAccessState -Value $mpPreference.EnableControlledFolderAccess) 'available' 'Read-only policy state from Defender preferences.' 'PR.PS'))
    } else {
        [void]$items.Add((New-BaselineValueRecord 'DefenderExclusions' 'Defender exclusions' 'Unavailable' 'unavailable' 'Defender preferences could not be collected.' 'PR.PS / GV.OV'))
        [void]$items.Add((New-BaselineValueRecord 'ControlledFolderAccess' 'Controlled Folder Access' 'Unavailable' 'unavailable' 'Defender preferences could not be collected.' 'PR.PS'))
    }
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Sort-Object Name)
        [void]$items.Add((New-BaselineValueRecord 'FirewallProfiles' 'Firewall profile states' (ConvertTo-NormalizedListValue -Items @($profiles | ForEach-Object { '{0}={1}' -f $_.Name, $(if ($_.Enabled) { 'On' } else { 'Off' }) })) 'available' 'Domain, Private, and Public profile enablement.' 'PR.PS'))
        [void]$items.Add((New-BaselineValueRecord 'FirewallDefaultPolicy' 'Firewall default inbound/outbound policy' (ConvertTo-NormalizedListValue -Items @($profiles | ForEach-Object { '{0}=Inbound:{1};Outbound:{2}' -f $_.Name, [string]$_.DefaultInboundAction, [string]$_.DefaultOutboundAction })) 'available' 'Default policy by profile.' 'PR.PS'))
    } catch {
        [void]$items.Add((New-BaselineValueRecord 'FirewallProfiles' 'Firewall profile states' 'Unavailable' 'unavailable' $_.Exception.Message 'PR.PS'))
        [void]$items.Add((New-BaselineValueRecord 'FirewallDefaultPolicy' 'Firewall default inbound/outbound policy' 'Unavailable' 'unavailable' $_.Exception.Message 'PR.PS'))
    }
    try {
        $service = Get-Service -Name wuauserv -ErrorAction Stop; $serviceCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='wuauserv'" -ErrorAction Stop
        $wuValue = 'Status={0};StartMode={1};AUOptions={2};NoAutoUpdate={3};PauseExpiry={4}' -f [string]$service.Status, [string]$serviceCim.StartMode, [string](Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'AUOptions'), [string](Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'NoAutoUpdate'), [string](Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesExpiryTime')
        [void]$items.Add((New-BaselineValueRecord 'WindowsUpdatePosture' 'Windows Update posture' $wuValue 'available' 'Service state and local policy posture.' 'PR.PS / GV.PO'))
    } catch { [void]$items.Add((New-BaselineValueRecord 'WindowsUpdatePosture' 'Windows Update posture' 'Unavailable' 'unavailable' $_.Exception.Message 'PR.PS / GV.PO')) }
    $pendingSignals = @(); if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pendingSignals += 'CBS' }; if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pendingSignals += 'WindowsUpdate' }; if ($null -ne (Get-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')) { $pendingSignals += 'PendingFileRenameOperations' }
    [void]$items.Add((New-BaselineValueRecord 'PendingReboot' 'Pending reboot state' $(if (@($pendingSignals).Count -gt 0) { 'Pending' } else { 'NotPending' }) 'available' (ConvertTo-NormalizedListValue -Items $pendingSignals) 'RC.RP / DE.CM'))
    if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) { try { $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; [void]$items.Add((New-BaselineValueRecord 'BitLockerSystemDrive' 'BitLocker status' ('ProtectionStatus={0};VolumeStatus={1};EncryptionPercentage={2}' -f [string]$volume.ProtectionStatus, [string]$volume.VolumeStatus, [string]$volume.EncryptionPercentage) 'available' ('System drive {0}' -f $env:SystemDrive) 'PR.PS / RC.RP')) } catch { [void]$items.Add((New-BaselineValueRecord 'BitLockerSystemDrive' 'BitLocker status' 'Unavailable' 'unavailable' $_.Exception.Message 'PR.PS / RC.RP')) } } else { [void]$items.Add((New-BaselineValueRecord 'BitLockerSystemDrive' 'BitLocker status' 'Unavailable' 'unavailable' 'Get-BitLockerVolume is not available.' 'PR.PS / RC.RP')) }
    if (Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) { try { [void]$items.Add((New-BaselineValueRecord 'SecureBoot' 'Secure Boot status' $(if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'Enabled' } else { 'Disabled' }) 'available' 'Collected from Confirm-SecureBootUEFI.' 'PR.PS')) } catch { [void]$items.Add((New-BaselineValueRecord 'SecureBoot' 'Secure Boot status' 'Unavailable' $(if ($_.Exception.Message -match 'supported on this platform') { 'not_applicable' } else { 'unavailable' }) $_.Exception.Message 'PR.PS')) } } else { [void]$items.Add((New-BaselineValueRecord 'SecureBoot' 'Secure Boot status' 'Unavailable' 'unavailable' 'Confirm-SecureBootUEFI is not available.' 'PR.PS')) }
    if (Get-Command -Name Get-Tpm -ErrorAction SilentlyContinue) { try { $tpm = Get-Tpm -ErrorAction Stop; [void]$items.Add((New-BaselineValueRecord 'TPM' 'TPM status' ('Present={0};Ready={1};Enabled={2};Activated={3}' -f [string]$tpm.TpmPresent, [string]$tpm.TpmReady, [string]$tpm.TpmEnabled, [string]$tpm.TpmActivated) 'available' 'Collected from Get-Tpm.' 'PR.PS / ID.AM')) } catch { [void]$items.Add((New-BaselineValueRecord 'TPM' 'TPM status' 'Unavailable' 'unavailable' $_.Exception.Message 'PR.PS / ID.AM')) } } else { [void]$items.Add((New-BaselineValueRecord 'TPM' 'TPM status' 'Unavailable' 'unavailable' 'Get-Tpm is not available.' 'PR.PS / ID.AM')) }
    [void]$items.Add((New-BaselineValueRecord 'SmartAppControl' 'Smart App Control status' (Resolve-SmartAppControlState -Value (Get-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState')) $(if ($null -eq (Get-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState')) { 'unavailable' } else { 'available' }) 'Derived from Code Integrity policy state when present.' 'PR.PS'))
    try { [void]$items.Add((New-BaselineValueRecord 'UAC' 'User Account Control setting' ('EnableLUA={0};ConsentPromptBehaviorAdmin={1};PromptOnSecureDesktop={2}' -f [int](Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 0), [string](Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' ''), [string](Get-RegistryValueSafe 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' '')) 'available' 'Registry-backed UAC posture.' 'PR.PS / GV.PO')) } catch { [void]$items.Add((New-BaselineValueRecord 'UAC' 'User Account Control setting' 'Unavailable' 'unavailable' $_.Exception.Message 'PR.PS / GV.PO')) }
    try { [void]$items.Add((New-BaselineValueRecord 'RemoteDesktop' 'Remote Desktop status' $(if ([int](Get-RegistryValueSafe 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1) -eq 0) { 'Enabled' } else { 'Disabled' }) 'available' 'Registry-backed Terminal Server setting.' 'PR.IR / PR.PS')) } catch { [void]$items.Add((New-BaselineValueRecord 'RemoteDesktop' 'Remote Desktop status' 'Unavailable' 'unavailable' $_.Exception.Message 'PR.IR / PR.PS')) }
    try { $adminMembers = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Sort-Object Name | ForEach-Object { [string]$_.Name }); [void]$items.Add((New-BaselineValueRecord 'LocalAdministrators' 'Local administrators' (ConvertTo-NormalizedListValue -Items $adminMembers) 'available' ('Member count: {0}' -f @($adminMembers).Count) 'ID.AM / PR.PS')) } catch { [void]$items.Add((New-BaselineValueRecord 'LocalAdministrators' 'Local administrators' 'Unavailable' 'unavailable' $_.Exception.Message 'ID.AM / PR.PS')) }
    if (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue) { try { $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -and $_.Name -notmatch '\$$' -and ($null -eq $_.Special -or -not $_.Special) } | Sort-Object Name); [void]$items.Add((New-BaselineValueRecord 'SharedFolders' 'Shared folders' (ConvertTo-NormalizedListValue -Items @($shares | ForEach-Object { '{0}={1}' -f [string]$_.Name, [string]$_.Path })) 'available' ('Share count: {0}' -f @($shares).Count) 'ID.AM / PR.IR')) } catch { [void]$items.Add((New-BaselineValueRecord 'SharedFolders' 'Shared folders' 'Unavailable' 'unavailable' $_.Exception.Message 'ID.AM / PR.IR')) } } else { [void]$items.Add((New-BaselineValueRecord 'SharedFolders' 'Shared folders' 'Unavailable' 'unavailable' 'Get-SmbShare is not available.' 'ID.AM / PR.IR')) }
    return [pscustomobject]@{ CsfMapping = 'GV.PO / GV.OV / PR.PS / PR.IR / DE.CM / RC.RP'; Items = @($items) }
}

function Get-TrustedWindowsToolBaselineSnapshot {
    $defs = @(
        @{ Id = 'powershell_exe'; Title = 'powershell.exe'; Path = (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'); Optional = $false }, @{ Id = 'pwsh_exe'; Title = 'pwsh.exe'; Path = (Get-CommandPathSafe 'pwsh.exe'); Optional = $true },
        @{ Id = 'msinfo32_exe'; Title = 'msinfo32.exe'; Path = (Join-Path $env:WINDIR 'System32\msinfo32.exe'); Optional = $false }, @{ Id = 'systeminfo_exe'; Title = 'systeminfo.exe'; Path = (Join-Path $env:WINDIR 'System32\systeminfo.exe'); Optional = $false },
        @{ Id = 'driverquery_exe'; Title = 'driverquery.exe'; Path = (Join-Path $env:WINDIR 'System32\driverquery.exe'); Optional = $false }, @{ Id = 'wevtutil_exe'; Title = 'wevtutil.exe'; Path = (Join-Path $env:WINDIR 'System32\wevtutil.exe'); Optional = $false },
        @{ Id = 'auditpol_exe'; Title = 'auditpol.exe'; Path = (Join-Path $env:WINDIR 'System32\auditpol.exe'); Optional = $false }, @{ Id = 'gpresult_exe'; Title = 'gpresult.exe'; Path = (Join-Path $env:WINDIR 'System32\gpresult.exe'); Optional = $false },
        @{ Id = 'netsh_exe'; Title = 'netsh.exe'; Path = (Join-Path $env:WINDIR 'System32\netsh.exe'); Optional = $false }, @{ Id = 'schtasks_exe'; Title = 'schtasks.exe'; Path = (Join-Path $env:WINDIR 'System32\schtasks.exe'); Optional = $false },
        @{ Id = 'sc_exe'; Title = 'sc.exe'; Path = (Join-Path $env:WINDIR 'System32\sc.exe'); Optional = $false }, @{ Id = 'reg_exe'; Title = 'reg.exe'; Path = (Join-Path $env:WINDIR 'System32\reg.exe'); Optional = $false },
        @{ Id = 'whoami_exe'; Title = 'whoami.exe'; Path = (Join-Path $env:WINDIR 'System32\whoami.exe'); Optional = $false }, @{ Id = 'certutil_exe'; Title = 'certutil.exe'; Path = (Join-Path $env:WINDIR 'System32\certutil.exe'); Optional = $false },
        @{ Id = 'reagentc_exe'; Title = 'reagentc.exe'; Path = (Join-Path $env:WINDIR 'System32\reagentc.exe'); Optional = $false }, @{ Id = 'vssadmin_exe'; Title = 'vssadmin.exe'; Path = (Join-Path $env:WINDIR 'System32\vssadmin.exe'); Optional = $false }
    )
    return [pscustomobject]@{ CsfMapping = 'ID.AM / PR.PS / DE.CM'; Tools = @($defs | ForEach-Object { Get-IntegrityFileRecord -Id ([string]$_.Id) -Title ([string]$_.Title) -Path $(if ([string]::IsNullOrWhiteSpace([string]$_.Path)) { Join-Path $env:WINDIR ('System32\' + [string]$_.Title) } else { [string]$_.Path }) -Optional ([bool]$_.Optional) -IncludeSignature $true -CsfMapping 'ID.AM / PR.PS / DE.CM' }) }
}

function Get-EventLogBaselineRecord {
    param([string]$Id,[string]$Title,[string]$LogName,[string]$CsfMapping = 'DE.CM')
    try { $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop; return (New-BaselineValueRecord $Id $Title ('Available={0};Enabled={1};Mode={2};MaxSizeBytes={3}' -f 'True', [string]$log.IsEnabled, [string]$log.LogMode, [string]$log.MaximumSizeInBytes) 'available' ('Record count {0}' -f [string]$log.RecordCount) $CsfMapping) } catch { return (New-BaselineValueRecord $Id $Title 'Unavailable' 'unavailable' $_.Exception.Message $CsfMapping) }
}

function Get-LoggingAuditBaselineSnapshot {
    $items = [System.Collections.ArrayList]::new(); foreach ($entry in @(@{ Id = 'SecurityLog'; Title = 'Security log availability'; LogName = 'Security' }, @{ Id = 'SystemLog'; Title = 'System log availability'; LogName = 'System' }, @{ Id = 'ApplicationLog'; Title = 'Application log availability'; LogName = 'Application' }, @{ Id = 'DefenderOperationalLog'; Title = 'Defender operational log availability'; LogName = 'Microsoft-Windows-Windows Defender/Operational' }, @{ Id = 'PowerShellOperationalLog'; Title = 'PowerShell operational log availability'; LogName = 'Microsoft-Windows-PowerShell/Operational' }, @{ Id = 'TaskSchedulerOperationalLog'; Title = 'Task Scheduler operational log availability'; LogName = 'Microsoft-Windows-TaskScheduler/Operational' })) { [void]$items.Add((Get-EventLogBaselineRecord -Id ([string]$entry.Id) -Title ([string]$entry.Title) -LogName ([string]$entry.LogName) -CsfMapping 'DE.CM / DE.AE')) }
    $auditpolPath = Join-Path $env:WINDIR 'System32\auditpol.exe'; if (Test-Path -LiteralPath $auditpolPath) { try { $auditText = (& $auditpolPath /get /category:* 2>$null | Out-String).Trim(); [void]$items.Add((New-BaselineValueRecord 'AuditPolicySummary' 'Audit policy summary' (Get-StringSha256 -Text $auditText) 'available' ('Captured auditpol summary hash over {0} characters.' -f $auditText.Length) 'GV.OV / DE.CM')) } catch { [void]$items.Add((New-BaselineValueRecord 'AuditPolicySummary' 'Audit policy summary' 'Unavailable' 'unavailable' $_.Exception.Message 'GV.OV / DE.CM')) } } else { [void]$items.Add((New-BaselineValueRecord 'AuditPolicySummary' 'Audit policy summary' 'Unavailable' 'unavailable' 'auditpol.exe was not found.' 'GV.OV / DE.CM')) }
    $sbl = Get-RegistryValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'; [void]$items.Add((New-BaselineValueRecord 'PowerShellScriptBlockLogging' 'PowerShell script block logging state' $(if ($null -eq $sbl) { 'NotConfigured' } elseif ([int]$sbl -eq 1) { 'Enabled' } else { 'Disabled' }) 'available' 'Policy registry state.' 'DE.CM / DE.AE'))
    $ml = Get-RegistryValueSafe 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'; $moduleNames = @(); try { $moduleNames = @(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -ErrorAction Stop | Select-Object -ExpandProperty PSObject | Select-Object -ExpandProperty Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notlike 'PS*' } | ForEach-Object { [string]$_.Name }) } catch {}
    [void]$items.Add((New-BaselineValueRecord 'PowerShellModuleLogging' 'PowerShell module logging state' $(if ($null -eq $ml) { 'NotConfigured' } elseif ([int]$ml -eq 1) { 'Enabled' } else { 'Disabled' }) 'available' ('Configured module names: {0}' -f (ConvertTo-NormalizedListValue -Items $moduleNames)) 'DE.CM / DE.AE'))
    return [pscustomobject]@{ CsfMapping = 'GV.OV / DE.CM / DE.AE'; Items = @($items) }
}

function Get-AppOwnedFileBaselineSnapshot {
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($relative in @('codex_monitor_ui.py','ioc_store.py','get-codex-monitor-status.ps1','invoke-host-ioc.ps1','invoke-host-tripwire.ps1','import-threat-feeds.ps1','monitor-threat-rss.ps1','protection-profiles.json','profiles\persona-profiles.json','profiles\system-profiles.json','codex-monitor.settings.json','host-tripwire-config.json','ioc-monitor-locations.json')) { [void]$paths.Add((Join-Path $PSScriptRoot $relative)) }
    foreach ($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.json' -File -ErrorAction SilentlyContinue)) { if ($file.Name -notlike 'HOST_*' -and $file.Name -notlike 'THREAT_*' -and $file.Name -notlike 'ALERT_*') { [void]$paths.Add($file.FullName) } }
    $profilesRoot = Join-Path $PSScriptRoot 'profiles'; if (Test-Path -LiteralPath $profilesRoot) { foreach ($file in @(Get-ChildItem -LiteralPath $profilesRoot -Filter '*.json' -File -ErrorAction SilentlyContinue)) { [void]$paths.Add($file.FullName) } }
    return [pscustomobject]@{ CsfMapping = 'GV.PO / DE.CM / RC.RP'; Files = @(@($paths | Sort-Object) | ForEach-Object { $title = Split-Path -Path $_ -Leaf; Get-IntegrityFileRecord -Id ([IO.Path]::GetFileNameWithoutExtension($title).Replace('.', '_').Replace('-', '_').ToLowerInvariant()) -Title $title -Path $_ -Optional $false -IncludeSignature $false -CsfMapping 'GV.PO / DE.CM / RC.RP' }) }
}
function Get-ExpectedSecurityControlSeverity {
    param([string]$Id,[string]$OldValue,[string]$NewValue,$OldItem,$NewItem)
    $classification = 'review'; $severity = 'Review'; $interpretation = 'This reflects posture drift from the saved baseline, not proof of compromise.'; $notes = ''
    switch ($Id) {
        'DefenderRealTime' { if ($NewValue -eq 'Disabled') { $severity = 'Warning'; $classification = 'warning'; $interpretation = 'Required Windows malware protection is no longer in the expected state.' } }
        'DefenderCloudProtection' { if ($NewValue -eq 'Disabled') { $severity = 'Warning'; $classification = 'warning' } }
        'DefenderExclusions' { $oldSet = @(($OldValue -split '\|') | Where-Object { $_ }); $newSet = @(($NewValue -split '\|') | Where-Object { $_ }); $added = @($newSet | Where-Object { $_ -notin $oldSet }); $removed = @($oldSet | Where-Object { $_ -notin $newSet }); if (@($added).Count -gt 0) { $severity = 'Warning'; $classification = 'warning'; $notes = 'Added exclusions: ' + ($added -join ', ') } elseif (@($removed).Count -gt 0) { $severity = 'Review'; $classification = 'review'; $notes = 'Removed exclusions: ' + ($removed -join ', ') } }
        'DefenderVersions' { $severity = 'Info'; $classification = 'info'; $notes = 'Version drift can reflect normal product updates.' }
        'FirewallProfiles' { if ($NewValue -match '=Off') { $severity = 'Warning'; $classification = 'warning' } }
        'FirewallDefaultPolicy' { if ($NewValue -match 'Inbound:Allow') { $severity = 'Warning'; $classification = 'warning' } }
        'WindowsUpdatePosture' { $severity = 'Review'; $classification = 'review' }
        'PendingReboot' { $severity = 'Info'; $classification = 'info'; if ($NewValue -eq 'Pending') { $notes = 'A pending reboot can follow normal patching.' } }
        'BitLockerSystemDrive' { if ($NewValue -notmatch 'ProtectionStatus=On|ProtectionStatus=1') { $severity = 'Warning'; $classification = 'warning' } }
        'SecureBoot' { if ($NewValue -eq 'Disabled') { $severity = 'Warning'; $classification = 'warning' } elseif (($NewItem.Availability -as [string]) -eq 'not_applicable') { $severity = 'Info'; $classification = 'info' } }
        'TPM' { if ($NewValue -match 'Present=False|Ready=False|Enabled=False|Activated=False') { $severity = 'Review'; $classification = 'review' } }
        'ControlledFolderAccess' { if ($NewValue -eq 'Disabled') { $severity = 'Review'; $classification = 'review' } }
        'SmartAppControl' { if ($NewValue -eq 'Off') { $severity = 'Review'; $classification = 'review' } else { $severity = 'Info'; $classification = 'info' } }
        'UAC' { if ($NewValue -match 'EnableLUA=0') { $severity = 'Warning'; $classification = 'warning' } }
        'RemoteDesktop' { if ($NewValue -eq 'Enabled') { $severity = 'Warning'; $classification = 'warning'; $interpretation = 'Remote Desktop is enabled and should be reviewed for this local PC baseline.' } }
        'LocalAdministrators' { $oldSet = @(($OldValue -split '\|') | Where-Object { $_ }); $newSet = @(($NewValue -split '\|') | Where-Object { $_ }); $added = @($newSet | Where-Object { $_ -notin $oldSet }); $removed = @($oldSet | Where-Object { $_ -notin $newSet }); if (@($added).Count -gt 0) { $severity = 'Warning'; $classification = 'warning'; $notes = 'Added local administrators: ' + ($added -join ', ') } elseif (@($removed).Count -gt 0) { $notes = 'Removed local administrators: ' + ($removed -join ', ') } }
        'SharedFolders' { $oldSet = @(($OldValue -split '\|') | Where-Object { $_ }); $newSet = @(($NewValue -split '\|') | Where-Object { $_ }); $added = @($newSet | Where-Object { $_ -notin $oldSet }); $removed = @($oldSet | Where-Object { $_ -notin $newSet }); if (@($added).Count -gt 0) { $notes = 'Added shared folders: ' + ($added -join ', ') } elseif (@($removed).Count -gt 0) { $severity = 'Info'; $classification = 'info'; $notes = 'Removed shared folders: ' + ($removed -join ', ') } }
    }
    return [pscustomobject]@{ Severity = $severity; Classification = $classification; Notes = $notes; Interpretation = $interpretation }
}

function Compare-BaselineValueSection {
    param([string]$Category,$OldItems,$NewItems,[scriptblock]$Evaluator)
    $changes = @(); $oldMap = ConvertTo-Map -Items $OldItems -KeySelector { param($item) $item.Id }; $newMap = ConvertTo-Map -Items $NewItems -KeySelector { param($item) $item.Id }; $ids = @($oldMap.Keys + $newMap.Keys | Sort-Object -Unique)
    foreach ($id in $ids) {
        $oldItem = $oldMap[$id]; $newItem = $newMap[$id]; if ($null -eq $oldItem -and $null -eq $newItem) { continue }
        $title = if ($null -ne $newItem -and -not [string]::IsNullOrWhiteSpace([string]$newItem.Title)) { [string]$newItem.Title } else { [string]$oldItem.Title }
        $oldValue = if ($null -ne $oldItem) { [string]$oldItem.Value } else { '' }; $newValue = if ($null -ne $newItem) { [string]$newItem.Value } else { '' }
        $oldAvailability = if ($null -ne $oldItem) { [string]$oldItem.Availability } else { '' }; $newAvailability = if ($null -ne $newItem) { [string]$newItem.Availability } else { '' }
        if ($null -ne $oldItem -and $null -ne $newItem -and $oldValue -ceq $newValue -and $oldAvailability -ceq $newAvailability) { continue }
        $assessment = & $Evaluator $id $oldValue $newValue $oldItem $newItem; $changeType = if ($null -eq $oldItem) { 'Added' } elseif ($null -eq $newItem) { 'Removed' } else { 'Modified' }
        $csfMapping = if ($null -ne $newItem -and -not [string]::IsNullOrWhiteSpace([string]$newItem.CsfMapping)) { [string]$newItem.CsfMapping } else { [string]$oldItem.CsfMapping }
        $notes = @([string]$assessment.Notes, ('Baseline availability={0}; Current availability={1}' -f $oldAvailability, $newAvailability)) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
        $changes += New-ChangeRecord -Category $Category -Name $title -ChangeType $changeType -Path $id -OldValue $oldValue -NewValue $newValue -Notes ($notes -join ' | ') -Severity ([string]$assessment.Severity) -Classification ([string]$assessment.Classification) -CsfMapping $csfMapping -Interpretation ([string]$assessment.Interpretation)
    }
    return @($changes)
}

function Compare-LoggingAuditBaseline {
    param($OldItems,$NewItems)
    return Compare-BaselineValueSection -Category 'LoggingAudit' -OldItems $OldItems -NewItems $NewItems -Evaluator {
        param($id, $oldValue, $newValue, $oldItem, $newItem)
        $severity = 'Review'; $classification = 'review'; $interpretation = 'Logging and audit drift affects evidence collection coverage, not proof of compromise.'
        if ($id -in @('SecurityLog','SystemLog','ApplicationLog') -and ($newValue -eq 'Unavailable' -or $newValue -match 'Enabled=False')) { $severity = 'Warning'; $classification = 'warning' }
        elseif ($id -in @('DefenderOperationalLog','PowerShellOperationalLog','TaskSchedulerOperationalLog') -and ($newValue -eq 'Unavailable' -or $newValue -match 'Enabled=False')) { $severity = 'Review'; $classification = 'review' }
        elseif ($id -in @('PowerShellScriptBlockLogging','PowerShellModuleLogging') -and $newValue -eq 'Disabled') { $severity = 'Warning'; $classification = 'warning' }
        [pscustomobject]@{ Severity = $severity; Classification = $classification; Notes = ''; Interpretation = $interpretation }
    }
}

function Compare-TrustedWindowsToolBaseline {
    param($OldTools,$NewTools)
    $changes = @(); $oldMap = ConvertTo-Map -Items $OldTools -KeySelector { param($item) $item.Id }; $newMap = ConvertTo-Map -Items $NewTools -KeySelector { param($item) $item.Id }; $ids = @($oldMap.Keys + $newMap.Keys | Sort-Object -Unique)
    foreach ($id in $ids) {
        $oldItem = $oldMap[$id]; $newItem = $newMap[$id]; if ($null -eq $oldItem -and $null -eq $newItem) { continue }
        $oldFingerprint = if ($null -ne $oldItem) { ('{0}|{1}|{2}|{3}|{4}|{5}' -f [string]$oldItem.Path, [string]$oldItem.Exists, [string]$oldItem.SHA256, [string]$oldItem.FileVersion, [string]$oldItem.SignatureStatus, [string]$oldItem.Publisher) } else { '' }
        $newFingerprint = if ($null -ne $newItem) { ('{0}|{1}|{2}|{3}|{4}|{5}' -f [string]$newItem.Path, [string]$newItem.Exists, [string]$newItem.SHA256, [string]$newItem.FileVersion, [string]$newItem.SignatureStatus, [string]$newItem.Publisher) } else { '' }
        if ($oldFingerprint -ceq $newFingerprint) { continue }
        $title = if ($null -ne $newItem) { [string]$newItem.Title } else { [string]$oldItem.Title }; $optional = if ($null -ne $newItem) { [bool]$newItem.Optional } else { [bool]$oldItem.Optional }
        $severity = 'Review'; $classification = 'review'; $interpretation = 'Trusted Windows tool drift should be reviewed, but it is not by itself proof of compromise.'
        if ($null -ne $newItem -and -not [bool]$newItem.Exists) { $severity = if ($optional) { 'Review' } else { 'Critical' }; $classification = if ($optional) { 'review' } else { 'critical' }; $interpretation = 'A Windows tool the product depends on is missing from the expected path.' }
        elseif ($null -ne $newItem -and [string]$newItem.SignatureStatus -eq 'NotSigned') { $severity = 'Warning'; $classification = 'warning' }
        elseif ($null -ne $newItem -and [string]$newItem.SignatureStatus -notin @('Valid','NotSigned') -and -not [bool]$newItem.IsMicrosoftSigned) { $severity = 'Critical'; $classification = 'critical'; $interpretation = 'A trusted Windows tool changed and is no longer clearly Microsoft-signed.' }
        $changes += New-ChangeRecord -Category 'TrustedWindowsTool' -Name $title -ChangeType 'Modified' -Path ([string]$newItem.Path) -OldValue $oldFingerprint -NewValue $newFingerprint -Notes ('Signature={0}; Publisher={1}; Optional={2}' -f [string]$newItem.SignatureStatus, [string]$newItem.Publisher, $optional) -Severity $severity -Classification $classification -CsfMapping 'ID.AM / PR.PS / DE.CM' -Interpretation $interpretation
    }
    return @($changes)
}

function Compare-AppIntegrityBaseline {
    param($OldFiles,$NewFiles)
    $changes = @(); $oldMap = ConvertTo-Map -Items $OldFiles -KeySelector { param($item) $item.Path }; $newMap = ConvertTo-Map -Items $NewFiles -KeySelector { param($item) $item.Path }; $paths = @($oldMap.Keys + $newMap.Keys | Sort-Object -Unique)
    foreach ($path in $paths) {
        $oldItem = $oldMap[$path]; $newItem = $newMap[$path]; if ($null -eq $oldItem -and $null -eq $newItem) { continue }
        $oldFingerprint = if ($null -ne $oldItem) { ('{0}|{1}|{2}|{3}' -f [string]$oldItem.Exists, [string]$oldItem.SHA256, [string]$oldItem.Length, [string]$oldItem.LastWriteTimeUtc) } else { '' }
        $newFingerprint = if ($null -ne $newItem) { ('{0}|{1}|{2}|{3}' -f [string]$newItem.Exists, [string]$newItem.SHA256, [string]$newItem.Length, [string]$newItem.LastWriteTimeUtc) } else { '' }
        if ($oldFingerprint -ceq $newFingerprint) { continue }
        $title = if ($null -ne $newItem) { [string]$newItem.Title } else { [string]$oldItem.Title }; $extension = [IO.Path]::GetExtension($title).ToLowerInvariant(); $severity = 'Review'; $classification = 'review'; $interpretation = 'App-owned file drift should be reviewed because collectors and local policy artifacts changed.'
        if ($extension -in @('.ps1','.py')) { $severity = 'Warning'; $classification = 'warning'; $interpretation = 'A collector or core app file changed unexpectedly.' }
        if ($null -ne $newItem -and -not [bool]$newItem.Exists) { $severity = if ($extension -in @('.ps1','.py')) { 'Critical' } else { 'Warning' }; $classification = if ($extension -in @('.ps1','.py')) { 'critical' } else { 'warning' } }
        $changes += New-ChangeRecord -Category 'AppIntegrity' -Name $title -ChangeType 'Modified' -Path ([string]$path) -OldValue $oldFingerprint -NewValue $newFingerprint -Notes 'App-owned collector/config integrity metadata changed.' -Severity $severity -Classification $classification -CsfMapping 'GV.PO / DE.CM / RC.RP' -Interpretation $interpretation
    }
    return @($changes)
}


function Get-TaskRelativePathFromFilePath {

    param([string]$Path)



    $prefix = 'C:\Windows\System32\Tasks\'

    if ([string]::IsNullOrWhiteSpace($Path) -or -not $Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {

        return $null

    }



    return ('\' + $Path.Substring($prefix.Length).TrimStart('\'))

}



function Get-ServiceExecutablePath {
    param([string]$Value)
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    if ($text.StartsWith('"')) {
        $match = [regex]::Match($text, '"([^"]+)"')
        if ($match.Success) { return $match.Groups[1].Value }
    }
    $exeMatch = [regex]::Match($text, '^[^\r\n]+?\.exe', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($exeMatch.Success) { return $exeMatch.Value.Trim() }
    return $text.Trim()
}

function Test-SuspiciousCommandLine {

    param([string]$Text)

    $value = ([string]$Text).ToLowerInvariant()

    if ([string]::IsNullOrWhiteSpace($value)) { return $false }



    $patterns = @(

        '-encodedcommand',

        ' frombase64string(',

        'iex ',

        'invoke-expression',

        'http://',

        'https://',

        'ftp://',

        'mshta',

        'wscript',

        'cscript',

        'rundll32',

        'regsvr32',

        'invoke-webrequest',

        'iwr ',

        'curl ',

        'wget ',

        'bitsadmin',

        'downloadfile(',

        'start-bitstransfer',

        'certutil -urlcache',

        'certutil.exe -urlcache',

        'cmd /c',

        '\downloads\',

        '\temp\',

        '\appdata\local\temp\',


        '\\'

    )

    foreach ($pattern in $patterns) {

        if ($value.Contains($pattern)) { return $true }

    }

    return $false

}



function Get-CommandFilePath {

    param([string]$Text)

    $value = [string]$Text

    if ([string]::IsNullOrWhiteSpace($value)) { return $null }



    $quotedMatch = [regex]::Match($value, '"([^"]+\.(?:exe|dll|sys|drv|com|bat|cmd|ps1|psm1|psd1|vbs|js|jse|hta|scr))"', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($quotedMatch.Success) { return $quotedMatch.Groups[1].Value }



    $bareMatch = [regex]::Match($value, '([A-Za-z]:\[^\r\n"]+?\.(?:exe|dll|sys|drv|com|bat|cmd|ps1|psm1|psd1|vbs|js|jse|hta|scr))', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($bareMatch.Success) { return $bareMatch.Groups[1].Value.Trim() }



    return $null

}



function Test-SuspiciousWritablePath {

    param([string]$Text)

    $value = ([string]$Text).ToLowerInvariant()

    if ([string]::IsNullOrWhiteSpace($value)) { return $false }

    if ($value.Contains('\downloads\')) { return $true }

    if ($value.Contains('\temp\')) { return $true }

    if ($value.Contains('\appdata\local\temp\')) { return $true }

    if ($value.Contains('\appdata\roaming\') -and -not ($value.Contains('\zoom\') -or $value.Contains('\google\') -or $value.Contains('\chrome\') -or $value.Contains('\mozilla\') -or $value.Contains('\firefox\') -or $value.Contains('\microsoft\edge'))) { return $true }

    return $false

}



function Test-UntrustedPersistenceCommand {

    param([string]$Text)

    $value = [string]$Text

    if ([string]::IsNullOrWhiteSpace($value)) { return $false }

    if (Test-SuspiciousCommandLine -Text $value) { return $true }

    if (Test-SuspiciousWritablePath -Text $value) { return $true }



    $path = Get-CommandFilePath -Text $value

    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return $false }



    $signature = Get-AuthenticodeMetadata -Path $path

    $status = [string]$signature.SignatureStatus

    $isExecutable = ([IO.Path]::GetExtension($path).ToLowerInvariant() -in @('.exe','.dll','.sys','.drv','.com','.scr'))

    if ($isExecutable -and $status -in @('NotSigned','HashMismatch','NotTrusted','UnknownError','PublisherMismatch')) { return $true }

    return $false

}



function Test-NormalGoogleTask {
    param($TaskRecord)
    if ($null -eq $TaskRecord) { return $false }
    $combined = ('{0} {1} {2}' -f [string]$TaskRecord.Name, [string]$TaskRecord.Author, [string]$TaskRecord.Actions).ToLowerInvariant()
    if (Test-SuspiciousCommandLine -Text $combined) { return $false }
    return ($combined.Contains('google') -or $combined.Contains('chrome'))
}

function Test-NormalZoomTask {
    param($TaskRecord)
    if ($null -eq $TaskRecord) { return $false }
    $actions = [string]$TaskRecord.Actions
    $combined = ('{0} {1} {2}' -f [string]$TaskRecord.Name, [string]$TaskRecord.Author, $actions).ToLowerInvariant()
    if (Test-SuspiciousCommandLine -Text $combined) { return $false }
    if (-not $combined.Contains('zoom')) { return $false }
    if ($combined.Contains('downloads') -or $combined.Contains('\\temp\\')) { return $false }
    return $true
}

function Test-NormalBrowserUpdaterTask {
    param($TaskRecord)
    if ($null -eq $TaskRecord) { return $false }
    $combined = ('{0} {1} {2}' -f [string]$TaskRecord.Name, [string]$TaskRecord.Author, [string]$TaskRecord.Actions).ToLowerInvariant()
    if (Test-SuspiciousCommandLine -Text $combined) { return $false }
    return ($combined.Contains('google') -or $combined.Contains('chrome') -or $combined.Contains('edge') -or $combined.Contains('mozilla') -or $combined.Contains('firefox'))
}

function Test-NormalBrowserUpdaterServiceChange {
    param($Change)
    $combined = ('{0} {1} {2}' -f [string]$Change.Name, [string]$Change.OldValue, [string]$Change.NewValue).ToLowerInvariant()
    if (Test-SuspiciousCommandLine -Text $combined) { return $false }
    $path = Get-ServiceExecutablePath -Value ([string]$Change.NewValue)
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return $false }
    $signature = Get-AuthenticodeMetadata -Path $path
    $lowerPath = $path.ToLowerInvariant()
    if ($Change.Name -like 'GoogleChromeElevationService' -and $lowerPath.Contains('program files (x86)\\google\\chrome\\application\\') -and [string]$signature.SignatureStatus -eq 'Valid' -and ([string]$signature.Publisher).ToLowerInvariant().Contains('google')) { return $true }
    if ($Change.Name -like 'MicrosoftEdge*' -and $lowerPath.Contains('program files (x86)\\microsoft\\edge') -and [string]$signature.SignatureStatus -eq 'Valid' -and ([string]$signature.Publisher).ToLowerInvariant().Contains('microsoft')) { return $true }
    if (($Change.Name -like 'Mozilla*' -or $Change.Name -like '*Firefox*') -and $lowerPath.Contains('mozilla') -and [string]$signature.SignatureStatus -eq 'Valid') { return $true }
    return $false
}

function Test-ExpectedPerUserServiceName {
    param([string]$Name)
    $patterns = @('AarSvc_*','BcastDVRUserService_*','BluetoothUserService_*','CaptureService_*','cbdhsvc_*','CDPUserSvc_*','ConsentUxUserSvc_*','DeviceAssociationBrokerSvc_*','DevicesFlowUserSvc_*','OneSyncSvc_*','PimIndexMaintenanceSvc_*','UdkUserSvc_*','UnistoreSvc_*','UserDataSvc_*','WpnUserService_*')
    foreach ($pattern in $patterns) { if ($Name -like $pattern) { return $true } }
    return $false
}

function Test-ExpectedPerUserServiceChange {
    param($Change)
    if (-not (Test-ExpectedPerUserServiceName -Name ([string]$Change.Name))) { return $false }
    $combined = ('{0} {1} {2} {3}' -f [string]$Change.Name, [string]$Change.Path, [string]$Change.OldValue, [string]$Change.NewValue).ToLowerInvariant()
    if (Test-SuspiciousCommandLine -Text $combined) { return $false }
    if ($combined.Contains('svchost.exe') -or $combined.Contains('windows\\system32')) { return $true }
    if ($combined.Contains('localservice') -or $combined.Contains('localsystem')) { return $true }
    return $false
}

function Test-NormalTempOrCachePath {
    param([string]$Path)
    $value = ([string]$Path).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($value)) { return $false }
    if ($value.StartsWith('c:\windows\temp\')) { return $true }
    if ($value.StartsWith('c:\windows\softwaredistribution\download\')) { return $true }
    if ($value.Contains('\appdata\local\temp\')) { return $true }
    if ($value.Contains('\cache\') -and ($value.Contains('chrome') -or $value.Contains('edge') -or $value.Contains('firefox') -or $value.Contains('mozilla'))) { return $true }
    return $false
}

function Test-ScriptOrExecutablePath {
    param([string]$Path)
    $extension = [IO.Path]::GetExtension([string]$Path).ToLowerInvariant()
    return $extension -in @('.exe','.dll','.sys','.drv','.com','.bat','.cmd','.ps1','.psm1','.psd1','.vbs','.js','.jse','.hta','.scr')
}

function Set-ExpectedChurnClassification {
# CODEX_MONITOR_SELF_EVENT
param(
        $Change,
        [string]$Interpretation,
        [string]$ExtraNote = ''
    )
    $Change.Severity = 'Info'
    $Change.Classification = 'expected'
    $Change.Interpretation = $Interpretation
    $notes = @([string]$Change.Notes, $ExtraNote) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    $Change.Notes = ($notes -join ' | ')
}

function Set-ReviewClassification {

    param(

        $Change,

        [string]$Interpretation,

        [string]$ExtraNote = ''

    )

    $Change.Severity = 'Review'

    $Change.Classification = 'review'

    $Change.Interpretation = $Interpretation

    $notes = @([string]$Change.Notes, $ExtraNote) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    $Change.Notes = ($notes -join ' | ')

}



function Set-GuardrailClassification {

    param(

        $Change,

        [string]$Severity,

        [string]$Classification,

        [string]$Interpretation,

        [string]$Reason,

        [string]$ExtraNote = ''

    )

    $Change.Severity = $Severity

    $Change.Classification = $Classification

    $Change.Interpretation = $Interpretation

    $Change.GuardrailMatched = $true

    $Change.GuardrailReason = $Reason

    $notes = @([string]$Change.Notes, $ExtraNote) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    $Change.Notes = ($notes -join ' | ')

}



function Test-NeverDowngradeDrift {

    param(

        $Change,

        $Snapshot

    )



    if ($null -eq $Change) { return $null }



    $name = [string]$Change.Name

    $path = [string]$Change.Path

    $oldValue = [string]$Change.OldValue

    $newValue = [string]$Change.NewValue

    $combined = ('{0} {1} {2} {3} {4}' -f [string]$Change.Category, $name, $path, $oldValue, $newValue).ToLowerInvariant()



    switch ([string]$Change.Category) {

        'SecurityControl' {

            switch ($path) {

                'DefenderExclusions' { if ($Change.Notes -like '*Added exclusions:*') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Defender exclusion added'; Interpretation='Microsoft Defender exclusions changed from the trusted baseline. Guardrails keep this security drift at warning severity.' } } }

                'DefenderRealTime' { if ($newValue -eq 'Disabled') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Defender real-time protection disabled'; Interpretation='Real-time malware protection is disabled relative to the trusted baseline.' } } }

                'DefenderCloudProtection' { if ($newValue -eq 'Disabled') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Defender cloud protection disabled'; Interpretation='Cloud-assisted Defender protection is disabled relative to the trusted baseline.' } } }

                'FirewallProfiles' { if ($newValue -match '=Off') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Firewall profile disabled'; Interpretation='One or more Windows Firewall profiles are now off relative to the trusted baseline.' } } }

                'UAC' { if ($newValue -match 'EnableLUA=0') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='UAC weakened'; Interpretation='User Account Control is weaker than the trusted baseline.' } } }

                'RemoteDesktop' { if ($oldValue -eq 'Disabled' -and $newValue -eq 'Enabled') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Remote Desktop enabled'; Interpretation='Remote Desktop was enabled after the baseline and should not be downgraded as normal churn.' } } }

                'LocalAdministrators' { if ($Change.Notes -like '*Added local administrators:*') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Local administrator added'; Interpretation='A new local administrator was added after the baseline and should be reviewed.' } } }

                'SharedFolders' { if ($Change.Notes -like '*Added shared folders:*') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Shared folder added'; Interpretation='A new shared folder was added after the baseline and should be reviewed before any churn downgrade.' } } }

                'BitLockerSystemDrive' { if ($oldValue -match 'ProtectionStatus=On|ProtectionStatus=1' -and $newValue -notmatch 'ProtectionStatus=On|ProtectionStatus=1') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='BitLocker protection disabled'; Interpretation='System drive BitLocker protection is weaker than the trusted baseline.' } } }

                'SecureBoot' { if ($oldValue -eq 'Enabled' -and $newValue -eq 'Disabled') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Secure Boot disabled'; Interpretation='Secure Boot is disabled relative to the trusted baseline.' } } }

                'TPM' { if (($oldValue -match 'Present=True|Ready=True|Enabled=True|Activated=True') -and ($newValue -match 'Present=False|Ready=False|Enabled=False|Activated=False')) { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='TPM became unavailable'; Interpretation='TPM state is weaker than the trusted baseline and should not be downgraded.' } } }

            }

        }

        'LoggingAudit' {

            switch ($path) {

                'SecurityLog' { if ($newValue -eq 'Unavailable' -or $newValue -match 'Enabled=False') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Security log unavailable'; Interpretation='The Security event log is no longer available for evidence collection.' } } }

                'DefenderOperationalLog' { if ($newValue -eq 'Unavailable' -or $newValue -match 'Enabled=False') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Defender operational log unavailable'; Interpretation='The Defender operational log is unavailable and should not be downgraded.' } } }

                'PowerShellOperationalLog' { if ($newValue -eq 'Unavailable' -or $newValue -match 'Enabled=False') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='PowerShell operational log unavailable'; Interpretation='The PowerShell operational log is unavailable and weakens detection evidence.' } } }

                'PowerShellScriptBlockLogging' { if ($newValue -eq 'Disabled') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='PowerShell script block logging disabled'; Interpretation='PowerShell script block logging is disabled relative to the trusted baseline.' } } }

                'PowerShellModuleLogging' { if ($newValue -eq 'Disabled') { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='PowerShell module logging disabled'; Interpretation='PowerShell module logging is disabled relative to the trusted baseline.' } } }

                'AuditPolicySummary' { if ($oldValue -and $newValue -and $oldValue -cne $newValue) { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Audit policy changed'; Interpretation='Audit policy summary changed from the trusted baseline and should be reviewed before any churn downgrade.' } } }

                'SecurityLogRetention' { if ($oldValue -and $newValue -and $oldValue -cne $newValue) { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Security log retention changed'; Interpretation='Security log retention changed from the trusted baseline and reduces evidence retention assumptions.' } } }

                'PowerShellOperationalLogRetention' { if ($oldValue -and $newValue -and $oldValue -cne $newValue) { return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='PowerShell log retention changed'; Interpretation='PowerShell log retention changed from the trusted baseline and should not be downgraded.' } } }

            }

        }

        'TrustedWindowsTool' {

            if ($newValue -match '\|False\|') {

                return [pscustomobject]@{ Severity='Critical'; Classification='critical'; Reason='Trusted Windows tool missing'; Interpretation='A trusted Windows tool the product depends on is missing from the expected path.' }

            }

            if ($newValue -match '\|(NotSigned|HashMismatch|NotTrusted|UnknownError|PublisherMismatch)\|') {

                return [pscustomobject]@{ Severity='Critical'; Classification='critical'; Reason='Trusted Windows tool signature invalid'; Interpretation='A trusted Windows tool changed and no longer has a clearly valid trusted signature.' }

            }

            if ($oldValue -and $newValue -and $oldValue -cne $newValue -and $newValue -notmatch '\|Valid\|') {

                return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='Trusted Windows tool changed without valid signature'; Interpretation='A trusted Windows tool changed and is not clearly Microsoft-signed in the current snapshot.' }

            }

        }

        'AppIntegrity' {

            $lowerPath = $path.ToLowerInvariant()

            if ($newValue -match '^False\|' -or $newValue -match '\|False\|') {

                return [pscustomobject]@{ Severity='Critical'; Classification='critical'; Reason='Required app file missing'; Interpretation='An app-owned collector or profile file is missing relative to the trusted baseline.' }

            }

            if ($lowerPath.EndsWith('.ps1') -or $lowerPath.EndsWith('.py')) {

                return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='App collector script changed'; Interpretation='A collector or core app script changed after the trusted baseline and should not be downgraded.' }

            }

            if ($lowerPath.EndsWith('.json')) {

                return [pscustomobject]@{ Severity='Warning'; Classification='warning'; Reason='App config or profile changed'; Interpretation='An app-owned config or profile JSON changed after the trusted baseline.' }

            }

        }

        'ScheduledTask' {

            if (Test-UntrustedPersistenceCommand -Text $combined) {

                return [pscustomobject]@{ Severity='Critical'; Classification='critical'; Reason='Scheduled task uses suspicious command or writable path'; Interpretation='This scheduled-task drift points to a suspicious command, download path, temp path, or untrusted executable and must not be downgraded.' }

            }

        }

        'Service' {

            if (Test-UntrustedPersistenceCommand -Text $combined) {

                return [pscustomobject]@{ Severity='Critical'; Classification='critical'; Reason='Service uses suspicious command or writable path'; Interpretation='This service drift points to a suspicious command, writable path, or untrusted executable and must not be downgraded.' }

            }

        }

        'Autorun' {

            if (Test-UntrustedPersistenceCommand -Text $combined) {

                return [pscustomobject]@{ Severity='Critical'; Classification='critical'; Reason='Autorun uses suspicious command or writable path'; Interpretation='This autorun drift points to a suspicious command, writable path, or untrusted executable and must not be downgraded.' }

            }

        }

        'WatchedFile' {

            if ($path -and $path.ToLowerInvariant().StartsWith('c:\windows\system32\tasks\') -and (Test-UntrustedPersistenceCommand -Text $combined)) {

                return [pscustomobject]@{ Severity='Critical'; Classification='critical'; Reason='Task file drift references suspicious persistence'; Interpretation='This task-file drift points to suspicious persistence evidence and must not be downgraded.' }

            }

        }

    }



    return $null

}



function Apply-TripwireGuardrails {

    param(

        $Changes,

        $Snapshot

    )



    foreach ($change in @($Changes)) {

        if ($null -eq $change) { continue }

        $guardrail = Test-NeverDowngradeDrift -Change $change -Snapshot $Snapshot

        if ($null -ne $guardrail) {

            Set-GuardrailClassification -Change $change -Severity ([string]$guardrail.Severity) -Classification ([string]$guardrail.Classification) -Interpretation ([string]$guardrail.Interpretation) -Reason ([string]$guardrail.Reason) -ExtraNote 'Phase 2 guardrail prevented expected-churn downgrade.'

        }

    }



    return @($Changes)

}



function Classify-ExpectedTripwireChurn {
    param(
        $Changes,
        $Snapshot
    )

    $taskMap = @{}
    foreach ($task in @($Snapshot.ScheduledTasks)) { $taskMap[[string]$task.Name] = $task }

    foreach ($change in @($Changes)) {
        if ($null -eq $change) { continue }

        if ($change.Category -eq 'WatchedFile' -and -not [string]::IsNullOrWhiteSpace([string]$change.Path) -and ([string]$change.Path).ToLowerInvariant().StartsWith('c:\windows\system32\tasks\')) {
            $taskPath = Get-TaskRelativePathFromFilePath -Path ([string]$change.Path)
            $taskRecord = if (-not [string]::IsNullOrWhiteSpace($taskPath) -and $taskMap.ContainsKey($taskPath)) { $taskMap[$taskPath] } else { $null }
            $taskIdentity = ('{0} {1}' -f [string]$change.Name, [string]$taskPath).ToLowerInvariant()

            if ($taskIdentity.Contains('googleuserpeh') -or $taskIdentity.Contains('runplatformexperiencehelper_metrics')) {
                if (Test-NormalGoogleTask -TaskRecord $taskRecord) {
                    Set-ExpectedChurnClassification -Change $change -Interpretation 'Expected churn: this task drift matches normal Google or Chrome updater/telemetry maintenance.' -ExtraNote 'Matched Phase 1 GoogleUserPEH churn rule.'
                } else {
                    Set-ReviewClassification -Change $change -Interpretation 'This task drift matches a common GoogleUserPEH pattern, but the command or author context was incomplete or not clearly trusted.' -ExtraNote 'Matched Phase 1 GoogleUserPEH review rule.'
                }
                continue
            }

            if ([string]$change.Name -like 'ZoomUpdateTaskUser-*' -or $taskIdentity.Contains('zoomupdatetaskuser-')) {
                if (Test-NormalZoomTask -TaskRecord $taskRecord) {
                    Set-ExpectedChurnClassification -Change $change -Interpretation 'Expected churn: this drift matches a normal Zoom updater task refresh.' -ExtraNote 'Matched Phase 1 Zoom updater churn rule.'
                } else {
                    Set-ReviewClassification -Change $change -Interpretation 'This task drift resembles a Zoom updater refresh, but the command or path was not clearly normal.' -ExtraNote 'Matched Phase 1 Zoom updater review rule.'
                }
                continue
            }

            if ($taskIdentity.Contains('google') -or $taskIdentity.Contains('chrome') -or $taskIdentity.Contains('edge') -or $taskIdentity.Contains('mozilla') -or $taskIdentity.Contains('firefox')) {
                if (Test-NormalBrowserUpdaterTask -TaskRecord $taskRecord) {
                    Set-ExpectedChurnClassification -Change $change -Interpretation 'Expected churn: this task drift matches a normal browser updater task change.' -ExtraNote 'Matched Phase 1 browser updater task churn rule.'
                } else {
                    Set-ReviewClassification -Change $change -Interpretation 'This task drift resembles browser updater churn, but the command or author context was not clearly trusted.' -ExtraNote 'Matched Phase 1 browser updater review rule.'
                }
                continue
            }
        }

        if ($change.Category -eq 'Service') {
            if ((Test-NormalBrowserUpdaterServiceChange -Change $change)) {
                Set-ExpectedChurnClassification -Change $change -Interpretation 'Expected churn: this service path drift matches a normal trusted browser updater version change.' -ExtraNote 'Matched Phase 1 browser updater service churn rule.'
                continue
            }
            if (Test-ExpectedPerUserServiceChange -Change $change) {
                Set-ExpectedChurnClassification -Change $change -Interpretation 'Expected churn: this drift matches normal Windows per-user service suffix rotation.' -ExtraNote 'Matched Phase 1 per-user service churn rule.'
                continue
            }
        }

        if ($change.Category -eq 'WatchedFile' -and -not [string]::IsNullOrWhiteSpace([string]$change.Path) -and (Test-NormalTempOrCachePath -Path ([string]$change.Path))) {
            if ($change.ChangeType -in @('Removed','Modified') -and -not (Test-ScriptOrExecutablePath -Path ([string]$change.Path))) {
                Set-ExpectedChurnClassification -Change $change -Interpretation 'Expected churn: this file drift matches normal temp, cache, or update cleanup activity.' -ExtraNote 'Matched Phase 1 temp/cache churn rule.'
                continue
            }
        }
    }

    return @($Changes)
}

function Get-TripwirePostureSummary {
    param($Snapshot,$Changes)
    return [pscustomobject]@{
        security_controls_checked = @($Snapshot.SecurityControlBaseline.Items).Count
        trusted_windows_tools_checked = @($Snapshot.TrustedWindowsToolBaseline.Tools).Count
        logging_audit_items_checked = @($Snapshot.LoggingAuditBaseline.Items).Count
        app_integrity_items_checked = @($Snapshot.AppIntegrityBaseline.Files).Count
        security_control_drift_count = @(@($Changes) | Where-Object { $_.Category -eq 'SecurityControl' }).Count
        trusted_tool_drift_count = @(@($Changes) | Where-Object { $_.Category -eq 'TrustedWindowsTool' }).Count
        logging_audit_drift_count = @(@($Changes) | Where-Object { $_.Category -eq 'LoggingAudit' }).Count
        app_integrity_drift_count = @(@($Changes) | Where-Object { $_.Category -eq 'AppIntegrity' }).Count
        expected_churn_count = @(@($Changes) | Where-Object { ([string]$_.Classification).ToLowerInvariant() -eq 'expected' }).Count
        review_drift_count = @(@($Changes) | Where-Object { (Get-ChangeSeverity $_) -eq 'Review' }).Count
        warning_drift_count = @(@($Changes) | Where-Object { (Get-ChangeSeverity $_) -in @('Warning','Medium') }).Count
        critical_drift_count = @(@($Changes) | Where-Object { (Get-ChangeSeverity $_) -in @('Critical','High') }).Count
        guardrail_matched_count = @(@($Changes) | Where-Object { [bool]$_.GuardrailMatched }).Count
        suspicious_drift_count = @(@($Changes) | Where-Object { [bool]$_.GuardrailMatched -and (Get-ChangeSeverityRank $_) -ge 3 }).Count
        note = 'These findings describe posture drift from the saved baseline. They are not, by themselves, proof of compromise. Expected churn means the change matched a known normal operating-system or trusted application update pattern only after guardrails verified that the drift was not security-relevant. It is still recorded for auditability.'
    }
}

. (Join-Path $PSScriptRoot 'posture-drift-rules.ps1')


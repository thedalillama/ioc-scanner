function New-PostureDriftRule {
    param(
        [string]$RuleId,
        [bool]$Enabled,
        [int]$Priority,
        [string]$Description,
        [string]$RuleType,
        [string]$SectionPattern,
        [string]$ItemTypePattern,
        [string]$Classification,
        [string]$Severity,
        [string]$CsfMapping,
        [string]$Interpretation,
        [string]$RecommendedAction,
        [string]$GuardrailReason = '',
        [hashtable]$Extra = @{}
    )
    $rule = [ordered]@{
        rule_id = $RuleId
        enabled = $Enabled
        priority = $Priority
        description = $Description
        rule_type = $RuleType
        section_pattern = $SectionPattern
        item_type_pattern = $ItemTypePattern
        classification = $Classification
        severity = $Severity
        csf_mapping = $CsfMapping
        interpretation = $Interpretation
        recommended_action = $RecommendedAction
        guardrail_reason = $GuardrailReason
    }
    foreach ($key in $Extra.Keys) { $rule[$key] = $Extra[$key] }
    return [pscustomobject]$rule
}

function Add-RuleSpec {
    param([System.Collections.ArrayList]$Rules,[hashtable]$Spec)
    $extra = @{}
    foreach ($key in @('name','path','cmd','pub','signer','change','notes','old','new','cond','reqsig','block')) {
        if ($Spec.ContainsKey($key) -and $null -ne $Spec[$key] -and -not [string]::IsNullOrWhiteSpace([string]$Spec[$key])) {
            switch ($key) {
                'name' { $extra['item_name_pattern'] = $Spec[$key] }
                'path' { $extra['path_pattern'] = $Spec[$key] }
                'cmd' { $extra['command_line_pattern'] = $Spec[$key] }
                'pub' { $extra['publisher_pattern'] = $Spec[$key] }
                'signer' { $extra['signer_pattern'] = $Spec[$key] }
                'change' { $extra['change_type_pattern'] = $Spec[$key] }
                'notes' { $extra['notes_pattern'] = $Spec[$key] }
                'old' { $extra['old_value_pattern'] = $Spec[$key] }
                'new' { $extra['new_value_pattern'] = $Spec[$key] }
                'cond' { $extra['condition_id'] = $Spec[$key] }
                'reqsig' { $extra['requires_signature_status'] = $Spec[$key] }
                'block' { $extra['blocks_if_suspicious_command_line'] = [bool]$Spec[$key] }
            }
        }
    }
    [void]$Rules.Add((New-PostureDriftRule -RuleId $Spec.id -Enabled $Spec.en -Priority $Spec.p -Description $Spec.d -RuleType $Spec.rt -SectionPattern $Spec.sec -ItemTypePattern $Spec.it -Classification $Spec.cls -Severity $Spec.sev -CsfMapping $Spec.csf -Interpretation $Spec.interp -RecommendedAction $Spec.act -GuardrailReason $(if ($Spec.ContainsKey('reason')) { [string]$Spec.reason } else { '' }) -Extra $extra))
}

function Get-BuiltInPostureDriftRulesPayload {
    $rules = [System.Collections.ArrayList]::new()

    foreach ($spec in @(
        @{id='guardrail-defender-exclusion-added';en=$true;p=900;d='Never downgrade newly added Microsoft Defender exclusions.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='DefenderExclusions';notes='*Added exclusions:*';cls='warning';sev='Warning';csf='PR.PS / DE.CM';interp='Microsoft Defender exclusions changed from the trusted baseline. Guardrails keep this security drift at warning severity.';act='Review the newly added exclusion and confirm it was intentionally approved.';reason='Defender exclusion added'},
        @{id='guardrail-defender-realtime-disabled';en=$true;p=890;d='Never downgrade disabled Defender real-time protection.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='DefenderRealTime';new='Disabled';cls='warning';sev='Warning';csf='PR.PS / DE.CM';interp='Real-time malware protection is disabled relative to the trusted baseline.';act='Verify why Defender real-time protection changed and restore the expected posture if appropriate.';reason='Defender real-time protection disabled'},
        @{id='guardrail-defender-cloud-disabled';en=$true;p=885;d='Never downgrade disabled Defender cloud protection.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='DefenderCloudProtection';new='Disabled';cls='warning';sev='Warning';csf='PR.PS / DE.CM';interp='Cloud-assisted Defender protection is disabled relative to the trusted baseline.';act='Review why cloud protection changed and confirm whether this reduction was intended.';reason='Defender cloud protection disabled'},
        @{id='guardrail-firewall-disabled';en=$true;p=880;d='Never downgrade disabled firewall profiles.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='FirewallProfiles';new='*=Off*';cls='warning';sev='Warning';csf='PR.PS / DE.CM';interp='One or more Windows Firewall profiles are now off relative to the trusted baseline.';act='Check whether the firewall profile change was intentional before treating it as normal churn.';reason='Firewall profile disabled'},
        @{id='guardrail-uac-weakened';en=$true;p=875;d='Never downgrade weakened UAC posture.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='UAC';new='*EnableLUA=0*';cls='warning';sev='Warning';csf='PR.PS';interp='User Account Control is weaker than the trusted baseline.';act='Review why UAC changed and confirm whether the weaker posture is approved.';reason='UAC weakened'},
        @{id='guardrail-remote-desktop-enabled';en=$true;p=870;d='Never downgrade Remote Desktop being enabled after the baseline.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='RemoteDesktop';old='Disabled';new='Enabled';cls='warning';sev='Warning';csf='PR.IR / DE.CM';interp='Remote Desktop was enabled after the baseline and should not be downgraded as normal churn.';act='Confirm whether Remote Desktop should be enabled on this PC and review network exposure.';reason='Remote Desktop enabled'},
        @{id='guardrail-local-admin-added';en=$true;p=865;d='Never downgrade newly added local administrators.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='LocalAdministrators';notes='*Added local administrators:*';cls='warning';sev='Warning';csf='ID.AM / PR.PS';interp='A new local administrator was added after the baseline and should be reviewed.';act='Review the added administrator and confirm it was intentionally granted elevated rights.';reason='Local administrator added'},
        @{id='guardrail-shared-folder-added';en=$true;p=860;d='Never downgrade newly added shared folders.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='SharedFolders';notes='*Added shared folders:*';cls='warning';sev='Warning';csf='ID.AM / PR.IR';interp='A new shared folder was added after the baseline and should be reviewed before any churn downgrade.';act='Confirm whether the new share was intentionally created and whether its permissions are expected.';reason='Shared folder added'},
        @{id='guardrail-bitlocker-weakened';en=$true;p=855;d='Never downgrade BitLocker posture weakening.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='BitLockerSystemDrive';cond='bitlocker_weakened';cls='warning';sev='Warning';csf='PR.PS';interp='System drive BitLocker protection is weaker than the trusted baseline.';act='Review why BitLocker protection changed and whether recovery-key handling or encryption posture was altered.';reason='BitLocker protection disabled'},
        @{id='guardrail-secureboot-weakened';en=$true;p=850;d='Never downgrade Secure Boot being disabled after the baseline.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='SecureBoot';old='Enabled';new='Disabled';cls='warning';sev='Warning';csf='PR.PS';interp='Secure Boot is disabled relative to the trusted baseline.';act='Confirm whether firmware settings were intentionally changed and whether boot trust assumptions still hold.';reason='Secure Boot disabled'},
        @{id='guardrail-tpm-weakened';en=$true;p=845;d='Never downgrade TPM availability weakening.';rt='guardrail';sec='SecurityControlBaseline';it='SecurityControl';path='TPM';cond='tpm_weakened';cls='warning';sev='Warning';csf='PR.PS';interp='TPM state is weaker than the trusted baseline and should not be downgraded.';act='Review whether TPM state changed because of firmware, hardware, or platform configuration drift.';reason='TPM became unavailable'}
    )) { Add-RuleSpec -Rules $rules -Spec $spec }
    foreach ($spec in @(
        @{id='guardrail-security-log-unavailable';en=$true;p=840;d='Never downgrade Security log availability loss.';rt='guardrail';sec='LoggingAuditBaseline';it='LoggingAudit';path='SecurityLog';cond='log_unavailable_or_disabled';cls='warning';sev='Warning';csf='DE.CM / DE.AE';interp='The Security event log is no longer available for evidence collection.';act='Check why the Security event log became unavailable before treating related churn as benign.';reason='Security log unavailable'},
        @{id='guardrail-defender-log-unavailable';en=$true;p=838;d='Never downgrade Defender operational log availability loss.';rt='guardrail';sec='LoggingAuditBaseline';it='LoggingAudit';path='DefenderOperationalLog';cond='log_unavailable_or_disabled';cls='warning';sev='Warning';csf='DE.CM';interp='The Defender operational log is unavailable and should not be downgraded.';act='Review why Defender telemetry coverage changed before assuming normal maintenance.';reason='Defender operational log unavailable'},
        @{id='guardrail-powershell-log-unavailable';en=$true;p=836;d='Never downgrade PowerShell operational log availability loss.';rt='guardrail';sec='LoggingAuditBaseline';it='LoggingAudit';path='PowerShellOperationalLog';cond='log_unavailable_or_disabled';cls='warning';sev='Warning';csf='DE.CM';interp='The PowerShell operational log is unavailable and weakens detection evidence.';act='Review why PowerShell logging coverage changed before dismissing related drift as benign.';reason='PowerShell operational log unavailable'},
        @{id='guardrail-powershell-script-block-disabled';en=$true;p=834;d='Never downgrade PowerShell script block logging being disabled.';rt='guardrail';sec='LoggingAuditBaseline';it='LoggingAudit';path='PowerShellScriptBlockLogging';new='Disabled';cls='warning';sev='Warning';csf='DE.CM / DE.AE';interp='PowerShell script block logging is disabled relative to the trusted baseline.';act='Review why script block logging changed because it directly reduces evidence quality.';reason='PowerShell script block logging disabled'},
        @{id='guardrail-powershell-module-disabled';en=$true;p=832;d='Never downgrade PowerShell module logging being disabled.';rt='guardrail';sec='LoggingAuditBaseline';it='LoggingAudit';path='PowerShellModuleLogging';new='Disabled';cls='warning';sev='Warning';csf='DE.CM / DE.AE';interp='PowerShell module logging is disabled relative to the trusted baseline.';act='Review why module logging changed because it reduces PowerShell evidence fidelity.';reason='PowerShell module logging disabled'},
        @{id='guardrail-audit-policy-changed';en=$true;p=830;d='Never downgrade audit policy drift.';rt='guardrail';sec='LoggingAuditBaseline';it='LoggingAudit';path='AuditPolicySummary';cond='old_and_new_differ';cls='warning';sev='Warning';csf='GV.OV / DE.CM';interp='Audit policy summary changed from the trusted baseline and should be reviewed before any churn downgrade.';act='Review the audit-policy change to confirm whether event collection breadth was intentionally altered.';reason='Audit policy changed'},
        @{id='guardrail-log-retention-changed';en=$true;p=828;d='Never downgrade meaningful event-log retention drift.';rt='guardrail';sec='LoggingAuditBaseline';it='LoggingAudit';path='*Retention';cond='old_and_new_differ';cls='warning';sev='Warning';csf='DE.CM / RC.RP';interp='Event-log retention changed from the trusted baseline and reduces evidence retention assumptions.';act='Review why log retention changed and whether evidence history is still sufficient.';reason='Event log retention changed'},
        @{id='guardrail-trusted-tool-missing';en=$true;p=820;d='Never downgrade a missing trusted Windows tool.';rt='guardrail';sec='TrustedWindowsToolBaseline';it='TrustedWindowsTool';cond='trusted_windows_tool_missing';cls='critical';sev='Critical';csf='ID.AM / PR.PS / DE.CM';interp='A trusted Windows tool the product depends on is missing from the expected path.';act='Verify whether the tool was removed intentionally or whether the expected system path is no longer trustworthy.';reason='Trusted Windows tool missing'},
        @{id='guardrail-trusted-tool-invalid-signature';en=$true;p=818;d='Never downgrade a trusted Windows tool with an invalid or missing signature.';rt='guardrail';sec='TrustedWindowsToolBaseline';it='TrustedWindowsTool';cond='trusted_windows_tool_invalid_signature';cls='critical';sev='Critical';csf='ID.AM / PR.PS / DE.CM';interp='A trusted Windows tool changed and no longer has a clearly valid trusted signature.';act='Review the file path, signature state, and provenance before trusting the changed tool.';reason='Trusted Windows tool signature invalid'},
        @{id='guardrail-trusted-tool-changed-without-valid-signature';en=$true;p=816;d='Never downgrade a changed trusted Windows tool that is not clearly validly signed.';rt='guardrail';sec='TrustedWindowsToolBaseline';it='TrustedWindowsTool';cond='trusted_windows_tool_changed_without_valid_signature';cls='warning';sev='Warning';csf='ID.AM / PR.PS / DE.CM';interp='A trusted Windows tool changed and is not clearly Microsoft-signed in the current snapshot.';act='Review the tool path and signature state before treating the drift as routine servicing.';reason='Trusted Windows tool changed without valid signature'},
        @{id='guardrail-app-file-missing';en=$true;p=810;d='Never downgrade missing app-owned collector or profile files.';rt='guardrail';sec='AppIntegrityBaseline';it='AppIntegrity';cond='app_required_file_missing';cls='critical';sev='Critical';csf='GV.PO / DE.CM / RC.RP';interp='An app-owned collector or profile file is missing relative to the trusted baseline.';act='Verify whether the file was intentionally removed and whether monitoring coverage is now incomplete.';reason='Required app file missing'},
        @{id='guardrail-app-script-changed';en=$true;p=808;d='Never downgrade drift in app-owned PowerShell collector files.';rt='guardrail';sec='AppIntegrityBaseline';it='AppIntegrity';path='*.ps1';cond='app_integrity_script_changed';cls='warning';sev='Warning';csf='GV.PO / DE.CM / RC.RP';interp='A collector or core app script changed after the trusted baseline and should not be downgraded.';act='Review the script change and confirm it matches expected product maintenance.';reason='App collector script changed'},
        @{id='guardrail-app-python-changed';en=$true;p=806;d='Never downgrade drift in app-owned Python files.';rt='guardrail';sec='AppIntegrityBaseline';it='AppIntegrity';path='*.py';cond='app_integrity_script_changed';cls='warning';sev='Warning';csf='GV.PO / DE.CM / RC.RP';interp='A collector or core app script changed after the trusted baseline and should not be downgraded.';act='Review the script change and confirm it matches expected product maintenance.';reason='App collector script changed'},
        @{id='guardrail-app-json-changed';en=$true;p=804;d='Never downgrade drift in app-owned JSON profiles and config.';rt='guardrail';sec='AppIntegrityBaseline';it='AppIntegrity';path='*.json';cond='app_integrity_json_changed';cls='warning';sev='Warning';csf='GV.PO / DE.CM / RC.RP';interp='An app-owned config or profile JSON changed after the trusted baseline.';act='Review the JSON change and confirm it reflects intended local configuration maintenance.';reason='App config or profile changed'},
        @{id='guardrail-scheduled-task-suspicious';en=$true;p=800;d='Never downgrade scheduled-task drift that points to suspicious persistence.';rt='guardrail';sec='RuntimeDrift';it='ScheduledTask';cond='suspicious_persistence_command';cls='critical';sev='Critical';csf='DE.CM / DE.AE';interp='This scheduled-task drift points to a suspicious command, download path, temp path, or untrusted executable and must not be downgraded.';act='Inspect the task action, file path, and signature before trusting the persistence change.';reason='Scheduled task uses suspicious command or writable path'},
        @{id='guardrail-service-suspicious';en=$true;p=798;d='Never downgrade service drift that points to suspicious persistence.';rt='guardrail';sec='RuntimeDrift';it='Service';cond='suspicious_persistence_command';cls='critical';sev='Critical';csf='DE.CM / DE.AE';interp='This service drift points to a suspicious command, writable path, or untrusted executable and must not be downgraded.';act='Inspect the service image path and signer before trusting the service change.';reason='Service uses suspicious command or writable path'},
        @{id='guardrail-autorun-suspicious';en=$true;p=796;d='Never downgrade autorun drift that points to suspicious persistence.';rt='guardrail';sec='RuntimeDrift';it='Autorun';cond='suspicious_persistence_command';cls='critical';sev='Critical';csf='DE.CM / DE.AE';interp='This autorun drift points to a suspicious command, writable path, or untrusted executable and must not be downgraded.';act='Inspect the autorun command and executable provenance before trusting the persistence change.';reason='Autorun uses suspicious command or writable path'},
        @{id='guardrail-task-file-suspicious';en=$true;p=794;d='Never downgrade watched task-file drift that points to suspicious persistence.';rt='guardrail';sec='RuntimeDrift';it='WatchedFile';path='C:\Windows\System32\Tasks\*';cond='suspicious_persistence_command';cls='critical';sev='Critical';csf='DE.CM / DE.AE';interp='This task-file drift points to suspicious persistence evidence and must not be downgraded.';act='Inspect the matching task definition and action path before trusting the drift as routine.';reason='Task file drift references suspicious persistence'}
    )) { Add-RuleSpec -Rules $rules -Spec $spec }

    foreach ($spec in @(
        @{id='churn-googleuserpeh-expected';en=$true;p=500;d='Downgrade normal GoogleUserPEH and RunPlatformExperienceHelper metrics churn.';rt='churn';sec='RuntimeDrift';it='WatchedFile';path='C:\Windows\System32\Tasks\*';name='*RunPlatformExperienceHelper_Metrics*';cond='normal_google_task';block=$true;cls='expected';sev='Info';csf='DE.CM';interp='Expected churn: this task drift matches normal Google or Chrome updater/telemetry maintenance.';act='No immediate action is required. Retain the evidence for auditability.'},
        @{id='review-googleuserpeh-ambiguous';en=$true;p=490;d='Keep ambiguous GoogleUserPEH churn at review when the trusted context is incomplete.';rt='review';sec='RuntimeDrift';it='WatchedFile';path='C:\Windows\System32\Tasks\*';cond='google_task_pattern_only';cls='review';sev='Review';csf='DE.CM';interp='This task drift matches a common GoogleUserPEH pattern, but the command or author context was incomplete or not clearly trusted.';act='Review the task author and action path before treating the drift as expected.'},
        @{id='churn-zoom-updater-expected';en=$true;p=480;d='Downgrade normal Zoom updater task churn.';rt='churn';sec='RuntimeDrift';it='WatchedFile';path='C:\Windows\System32\Tasks\*';name='*ZoomUpdateTaskUser-*';cond='normal_zoom_task';block=$true;cls='expected';sev='Info';csf='DE.CM';interp='Expected churn: this drift matches a normal Zoom updater task refresh.';act='No immediate action is required. Retain the evidence for auditability.'},
        @{id='review-zoom-updater-ambiguous';en=$true;p=470;d='Keep ambiguous Zoom updater task churn at review.';rt='review';sec='RuntimeDrift';it='WatchedFile';path='C:\Windows\System32\Tasks\*';cond='zoom_task_pattern_only';cls='review';sev='Review';csf='DE.CM';interp='This task drift resembles a Zoom updater refresh, but the command or path was not clearly normal.';act='Review the updater path and signer before treating the churn as expected.'},
        @{id='churn-browser-task-expected';en=$true;p=460;d='Downgrade normal browser updater task churn for Chrome, Edge, and Firefox.';rt='churn';sec='RuntimeDrift';it='WatchedFile';path='C:\Windows\System32\Tasks\*';cond='normal_browser_updater_task';block=$true;cls='expected';sev='Info';csf='DE.CM';interp='Expected churn: this task drift matches a normal browser updater task change.';act='No immediate action is required. Retain the evidence for auditability.'},
        @{id='review-browser-task-ambiguous';en=$true;p=450;d='Keep ambiguous browser updater task churn at review.';rt='review';sec='RuntimeDrift';it='WatchedFile';path='C:\Windows\System32\Tasks\*';cond='browser_updater_task_pattern_only';cls='review';sev='Review';csf='DE.CM';interp='This task drift resembles browser updater churn, but the command or author context was not clearly trusted.';act='Review the task author and action path before treating the churn as expected.'},
        @{id='churn-browser-service-expected';en=$true;p=440;d='Downgrade trusted browser updater service version churn.';rt='churn';sec='RuntimeDrift';it='Service';cond='normal_browser_updater_service';block=$true;cls='expected';sev='Info';csf='DE.CM';interp='Expected churn: this service path drift matches a normal trusted browser updater version change.';act='No immediate action is required. Retain the evidence for auditability.'},
        @{id='churn-per-user-service-expected';en=$true;p=430;d='Downgrade expected Windows per-user service suffix rotation.';rt='churn';sec='RuntimeDrift';it='Service';cond='expected_per_user_service';block=$true;cls='expected';sev='Info';csf='DE.CM';interp='Expected churn: this drift matches normal Windows per-user service suffix rotation.';act='No immediate action is required. Retain the evidence for auditability.'},
        @{id='churn-temp-cache-cleanup';en=$true;p=420;d='Downgrade normal temp, cache, and update cleanup file drift.';rt='churn';sec='RuntimeDrift';it='WatchedFile';cond='normal_temp_cache_cleanup';cls='expected';sev='Info';csf='DE.CM';interp='Expected churn: this file drift matches normal temp, cache, or update cleanup activity.';act='No immediate action is required. Retain the evidence for auditability.'}
    )) { Add-RuleSpec -Rules $rules -Spec $spec }

    return [pscustomobject]@{ schema_version = 1; description = 'Local explainable posture drift rules for Codex tripwire classification.'; rules = @($rules) }
}

function Get-DefaultPostureDriftRulesPath { return (Join-Path $PSScriptRoot 'profiles\posture-drift-rules.json') }

function ConvertTo-PostureDriftRuleList {
    param($Payload)
    if ($null -eq $Payload) { return @() }
    $rules = if ($Payload.PSObject.Properties.Name -contains 'rules') { @($Payload.rules) } else { @($Payload) }
    return @($rules | Where-Object { $null -ne $_ -and ($_.enabled -eq $null -or [bool]$_.enabled) })
}

function Load-PostureDriftRuleCatalog {
    param([string]$RulesPath = '')
    $resolvedPath = if ([string]::IsNullOrWhiteSpace($RulesPath)) { Get-DefaultPostureDriftRulesPath } else { $RulesPath }
    $fileStatus = 'external'; $warning = ''; $payload = $null; $source = 'external'
    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        $payload = Get-BuiltInPostureDriftRulesPayload; $fileStatus = 'missing_builtin_fallback'; $warning = ('Posture drift rule file not found: {0}. Built-in defaults were used.' -f $resolvedPath); $source = 'builtin'
    } else {
        try { $jsonText = Get-Content -LiteralPath $resolvedPath -Raw -Encoding UTF8; if ($jsonText.Length -gt 0 -and $jsonText[0] -eq [char]0xFEFF) { $jsonText = $jsonText.TrimStart([char]0xFEFF) }; $payload = ($jsonText | ConvertFrom-Json) }
        catch { $payload = Get-BuiltInPostureDriftRulesPayload; $fileStatus = 'invalid_builtin_fallback'; $warning = ('Posture drift rule file is invalid: {0}. Built-in defaults were used. Error: {1}' -f $resolvedPath, $_.Exception.Message); $source = 'builtin' }
    }
    $rules = ConvertTo-PostureDriftRuleList -Payload $payload
    $catalogVersion = if ($null -ne $payload -and $payload.PSObject.Properties.Name -contains 'schema_version') { [string]$payload.schema_version } else { '1' }
    return [pscustomobject]@{ Rules = @($rules); RulesFilePath = $resolvedPath; RulesFileStatus = $fileStatus; RulesLoadedCount = @($rules).Count; Warning = $warning; Source = $source; CatalogVersion = $catalogVersion }
}

function Get-DefaultAcceptedPostureDriftJsonPath {
    return (Join-Path $PSScriptRoot 'state\accepted-posture-drift.json')
}

function ConvertTo-PostureDriftAcceptedEntryList {
    param($Payload)
    if ($null -eq $Payload) { return @() }
    $entries = if ($Payload.PSObject.Properties.Name -contains 'entries') { @($Payload.entries) } else { @($Payload) }
    return @($entries | Where-Object { $null -ne $_ -and ($_.Enabled -eq $null -or [bool]$_.Enabled) })
}

function Get-PostureDriftCurrentValue {
    param($Change)
    $values = @(
        [string]$Change.CurrentValue,
        [string]$Change.NewValue,
        [string]$Change.New,
        [string]$Change.Value,
        [string]$Change.SHA256
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
    if ($null -ne $values) { return [string]$values }
    return ''
}

function Invoke-PostureDriftStateStore {
    param(
        [string]$DbPath,
        [string[]]$Arguments
    )
    if (Get-Command -Name Invoke-StateStore -ErrorAction SilentlyContinue) {
        return Invoke-StateStore -DbPath $DbPath -Arguments $Arguments
    }
    $pythonCommand = $null
    foreach ($candidate in @('python','python3')) {
        if (Get-Command -Name $candidate -ErrorAction SilentlyContinue) { $pythonCommand = $candidate; break }
    }
    if ($null -eq $pythonCommand) { throw 'Python command not available for accepted drift registry access.' }
    $scriptPath = Join-Path $PSScriptRoot 'ioc_store.py'
    $output = & $pythonCommand $scriptPath --db $DbPath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("Accepted drift registry command failed: {0} {1} --db {2} {3}`n{4}" -f $pythonCommand, $scriptPath, $DbPath, ($Arguments -join ' '), (@($output) -join [Environment]::NewLine))
    }
    return (@($output) -join [Environment]::NewLine)
}

function Test-PostureDriftAcceptedEntryMatch {
    param($Entry, $Change, $Context)
    if ($null -eq $Entry -or $null -eq $Change -or $null -eq $Context) { return $false }
    if ([string]::IsNullOrWhiteSpace([string]$Entry.Section) -or ([string]$Context.SectionName -ine [string]$Entry.Section)) { return $false }
    if (-not [string]::IsNullOrWhiteSpace([string]$Entry.ItemName) -and ([string]$Change.Name -ine [string]$Entry.ItemName)) { return $false }
    if (-not [string]::IsNullOrWhiteSpace([string]$Entry.ItemType) -and ([string]$Context.Change.Category -ine [string]$Entry.ItemType)) { return $false }
    if (-not [string]::IsNullOrWhiteSpace([string]$Entry.Field)) {
        $candidateField = [string]$Change.Field
        if ([string]::IsNullOrWhiteSpace($candidateField)) { $candidateField = [string]$Context.Change.Field }
        if ([string]::IsNullOrWhiteSpace($candidateField)) { $candidateField = 'CurrentValue' }
        if ([string]$candidateField -ine [string]$Entry.Field) { return $false }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Entry.AcceptedCurrentValue)) {
        $currentValue = Get-PostureDriftCurrentValue -Change $Change
        if ([string]::IsNullOrWhiteSpace($currentValue) -or ([string]$currentValue -ine [string]$Entry.AcceptedCurrentValue)) { return $false }
    }
    return $true
}

function Load-AcceptedPostureDriftRegistry {
    param(
        [string]$DbPath = '',
        [string]$JsonFallbackPath = ''
    )
    $resolvedDbPath = if ([string]::IsNullOrWhiteSpace($DbPath)) { Join-Path $PSScriptRoot 'state\ioc-store.db' } else { $DbPath }
    $fallbackPath = if ([string]::IsNullOrWhiteSpace($JsonFallbackPath)) { Get-DefaultAcceptedPostureDriftJsonPath } else { $JsonFallbackPath }
    $result = [pscustomobject]@{ RegistryPath = $resolvedDbPath; RegistryStatus = 'missing'; RegistryLoadedCount = 0; Warning = ''; Entries = @() }
    try {
        $raw = Invoke-PostureDriftStateStore -DbPath $resolvedDbPath -Arguments @('accepted-drift-get', '--json-fallback', $fallbackPath)
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $payload = $raw | ConvertFrom-Json
            $result.RegistryStatus = [string]$payload.registry_status
            $result.RegistryPath = if (-not [string]::IsNullOrWhiteSpace([string]$payload.registry_path)) { [string]$payload.registry_path } else { $resolvedDbPath }
            $result.RegistryLoadedCount = if ($null -ne $payload.loaded_count) { [int]$payload.loaded_count } else { 0 }
            $result.Warning = if ($payload.PSObject.Properties.Name -contains 'warning') { [string]$payload.warning } else { '' }
            $entries = @()
            if ($payload.PSObject.Properties.Name -contains 'entries' -and $null -ne $payload.entries) { $entries = @($payload.entries) }
            $result.Entries = @($entries | Where-Object {
                $enabled = if ($_.PSObject.Properties.Name -contains 'Enabled') { [bool]$_.Enabled } else { $true }
                if (-not $enabled) { return $false }
                if ($_.PSObject.Properties.Name -contains 'ExpiresUtc' -and -not [string]::IsNullOrWhiteSpace([string]$_.ExpiresUtc)) {
                    try {
                        $expires = [DateTime]::Parse([string]$_.ExpiresUtc).ToUniversalTime()
                        if ($expires -lt [DateTime]::UtcNow) { return $false }
                    } catch {
                        return $false
                    }
                }
                return $true
            })
        }
    } catch {
        $result.RegistryStatus = 'sqlite_error'
        $result.Warning = $_.Exception.Message
        if (Test-Path -LiteralPath $fallbackPath) {
            try {
                $jsonText = Get-Content -LiteralPath $fallbackPath -Raw -Encoding UTF8
                if ($jsonText.Length -gt 0 -and $jsonText[0] -eq [char]0xFEFF) { $jsonText = $jsonText.TrimStart([char]0xFEFF) }
                $payload = ($jsonText | ConvertFrom-Json)
                $entries = if ($payload.PSObject.Properties.Name -contains 'entries') { @($payload.entries) } else { @($payload) }
                $result.RegistryStatus = 'json_fallback'
                $result.RegistryPath = $fallbackPath
                $result.RegistryLoadedCount = @($entries).Count
                $result.Entries = @($entries | Where-Object {
                    $enabled = if ($_.PSObject.Properties.Name -contains 'Enabled') { [bool]$_.Enabled } else { $true }
                    if (-not $enabled) { return $false }
                    if ($_.PSObject.Properties.Name -contains 'ExpiresUtc' -and -not [string]::IsNullOrWhiteSpace([string]$_.ExpiresUtc)) {
                        try {
                            $expires = [DateTime]::Parse([string]$_.ExpiresUtc).ToUniversalTime()
                            if ($expires -lt [DateTime]::UtcNow) { return $false }
                        } catch {
                            return $false
                        }
                    }
                    return $true
                })
            } catch {
                $result.Warning = ('{0} | JSON fallback failed: {1}' -f $result.Warning, $_.Exception.Message)
            }
        }
    }
    return $result
}

function Test-PostureDriftAcceptedFindingBlocked {
    param($Change)
    $blockedRuleIds = @(
        'guardrail-defender-exclusion-added',
        'guardrail-defender-realtime-disabled',
        'guardrail-defender-cloud-disabled',
        'guardrail-firewall-disabled',
        'guardrail-security-log-unavailable',
        'guardrail-powershell-log-unavailable',
        'guardrail-powershell-script-block-disabled',
        'guardrail-powershell-module-disabled',
        'guardrail-trusted-tool-missing',
        'guardrail-trusted-tool-invalid-signature',
        'guardrail-trusted-tool-changed-without-valid-signature',
        'guardrail-scheduled-task-suspicious',
        'guardrail-service-suspicious',
        'guardrail-autorun-suspicious',
        'guardrail-task-file-suspicious'
    )
    return ($blockedRuleIds -contains [string]$Change.MatchedRuleId)
}

function Apply-AcceptedPostureDrift {
    param($Changes, $Snapshot, [string]$RegistryPath = '', [string]$JsonFallbackPath = '')
    $registry = Load-AcceptedPostureDriftRegistry -DbPath $RegistryPath -JsonFallbackPath $JsonFallbackPath
    $taskMap = @{}; foreach ($task in @($Snapshot.ScheduledTasks)) { $taskMap[[string]$task.Name] = $task }
    $activeEntries = @($registry.Entries)
    $matches = 0
    foreach ($change in @($Changes)) {
        if ($null -eq $change) { continue }
        $context = Get-PostureDriftRuleContext -Change $change -Snapshot $Snapshot -TaskMap $taskMap
        foreach ($entry in $activeEntries) {
            if (Test-PostureDriftAcceptedEntryMatch -Entry $entry -Change $change -Context $context) {
                $matches += 1
                if (-not (Test-PostureDriftAcceptedFindingBlocked -Change $change)) {
                    $change | Add-Member -NotePropertyName IsAcceptedDrift -NotePropertyValue $true -Force
                    $change | Add-Member -NotePropertyName AcceptanceId -NotePropertyValue ([string]$entry.AcceptanceId) -Force
                    $change | Add-Member -NotePropertyName AcceptedDriftReason -NotePropertyValue ([string]$entry.Reason) -Force
                    $change | Add-Member -NotePropertyName AcceptedDriftBlocked -NotePropertyValue $false -Force
                    $change | Add-Member -NotePropertyName AcceptedDriftBlockedReason -NotePropertyValue '' -Force
                    $change.Classification = 'accepted'
                    $change.Severity = 'Info'
                    if ([string]::IsNullOrWhiteSpace([string]$change.Interpretation)) {
                        $change.Interpretation = 'This change was reviewed and recorded as accepted drift. The evidence remains in the audit trail and future drift detection continues to run.'
                    } else {
                        $change.Interpretation = ('{0} This change was reviewed and recorded as accepted drift. The evidence remains in the audit trail and future drift detection continues to run.' -f [string]$change.Interpretation)
                    }
                    if (-not [string]::IsNullOrWhiteSpace([string]$entry.CsfMapping)) { $change.CsfMapping = [string]$entry.CsfMapping }
                    if (-not [string]::IsNullOrWhiteSpace([string]$entry.RecommendedAction) -and [string]::IsNullOrWhiteSpace([string]$change.RecommendedAction)) { $change.RecommendedAction = [string]$entry.RecommendedAction }
                    $change.Notes = (@([string]$change.Notes, ('Accepted drift recorded: {0}' -f [string]$entry.Reason)) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique) -join ' | '
                } else {
                    $blockedReason = if (-not [string]::IsNullOrWhiteSpace([string]$entry.GuardrailReason)) { [string]$entry.GuardrailReason } else { 'Accepted drift was blocked by a dangerous security guardrail.' }
                    $change | Add-Member -NotePropertyName IsAcceptedDrift -NotePropertyValue $false -Force
                    $change | Add-Member -NotePropertyName AcceptanceId -NotePropertyValue ([string]$entry.AcceptanceId) -Force
                    $change | Add-Member -NotePropertyName AcceptedDriftReason -NotePropertyValue ([string]$entry.Reason) -Force
                    $change | Add-Member -NotePropertyName AcceptedDriftBlocked -NotePropertyValue $true -Force
                    $change | Add-Member -NotePropertyName AcceptedDriftBlockedReason -NotePropertyValue $blockedReason -Force
                    if ([string]::IsNullOrWhiteSpace([string]$change.Interpretation)) {
                        $change.Interpretation = ('Accepted drift entry matched but was blocked because the finding is security-relevant: {0}' -f $blockedReason)
                    } else {
                        $change.Interpretation = ('{0} Accepted drift entry matched but was blocked because the finding is security-relevant: {1}' -f [string]$change.Interpretation, $blockedReason)
                    }
                }
                break
            }
        }
    }
    return [pscustomobject]@{
        Changes = @($Changes)
        RegistryPath = $registry.RegistryPath
        RegistryStatus = $registry.RegistryStatus
        RegistryLoadedCount = $registry.RegistryLoadedCount
        Warning = $registry.Warning
        MatchCount = $matches
    }
}

function Get-ChangeSectionName {
    param($Change)
    switch ([string]$Change.Category) {
        'SecurityControl' { 'SecurityControlBaseline' }
        'LoggingAudit' { 'LoggingAuditBaseline' }
        'TrustedWindowsTool' { 'TrustedWindowsToolBaseline' }
        'AppIntegrity' { 'AppIntegrityBaseline' }
        default { 'RuntimeDrift' }
    }
}

function Test-WildcardPatternValue {
    param($Pattern, [string]$Value)
    if ($null -eq $Pattern -or [string]::IsNullOrWhiteSpace([string]$Pattern)) { return $true }
    $patterns = if ($Pattern -is [System.Collections.IEnumerable] -and -not ($Pattern -is [string])) { @($Pattern) } else { @([string]$Pattern) }
    foreach ($entry in $patterns) { if (-not [string]::IsNullOrWhiteSpace([string]$entry) -and $Value -like [string]$entry) { return $true } }
    return $false
}

function Get-RuleCommandFilePath {
    param($Change, $TaskRecord)
    if ([string]$Change.Category -eq 'Service') {
        $path = Get-ServiceExecutablePath -Value ([string]$Change.NewValue)
        if ([string]::IsNullOrWhiteSpace($path)) { $path = Get-ServiceExecutablePath -Value ([string]$Change.OldValue) }
        return $path
    }
    $commandLine = ('{0} {1} {2} {3}' -f [string]$Change.Name, [string]$Change.Path, [string]$Change.OldValue, [string]$Change.NewValue)
    if ($null -ne $TaskRecord) { $commandLine = ('{0} {1} {2}' -f $commandLine, [string]$TaskRecord.Author, [string]$TaskRecord.Actions) }
    return (Get-CommandFilePath -Text $commandLine)
}

function Get-PostureDriftRuleContext {
    param($Change,$Snapshot,[hashtable]$TaskMap)
    $path = [string]$Change.Path; $taskPath = $null; $taskRecord = $null
    if (-not [string]::IsNullOrWhiteSpace($path) -and $path.StartsWith('C:\Windows\System32\Tasks\', [System.StringComparison]::OrdinalIgnoreCase)) {
        $taskPath = Get-TaskRelativePathFromFilePath -Path $path
        if (-not [string]::IsNullOrWhiteSpace($taskPath) -and $TaskMap.ContainsKey($taskPath)) { $taskRecord = $TaskMap[$taskPath] }
    } elseif ([string]$Change.Category -eq 'ScheduledTask' -and $TaskMap.ContainsKey([string]$Change.Name)) {
        $taskRecord = $TaskMap[[string]$Change.Name]; $taskPath = [string]$Change.Name
    }
    $commandPath = Get-RuleCommandFilePath -Change $Change -TaskRecord $taskRecord
    $signature = if (-not [string]::IsNullOrWhiteSpace($commandPath) -and (Test-Path -LiteralPath $commandPath)) { Get-AuthenticodeMetadata -Path $commandPath } else { [pscustomobject]@{ SignatureStatus=''; Publisher=''; IsMicrosoftSigned=$false } }
    $author = if ($null -ne $taskRecord) { [string]$taskRecord.Author } else { '' }
    $actions = if ($null -ne $taskRecord) { [string]$taskRecord.Actions } else { '' }
    $combined = @([string]$Change.Name,[string]$Change.Path,[string]$Change.OldValue,[string]$Change.NewValue,$author,$actions,$commandPath) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    return [pscustomobject]@{ Change = $Change; Snapshot = $Snapshot; SectionName = Get-ChangeSectionName -Change $Change; TaskPath = $taskPath; TaskRecord = $taskRecord; TaskAuthor = $author; TaskActions = $actions; ResolvedCommandPath = $commandPath; CombinedText = ($combined -join ' '); SignatureStatus = [string]$signature.SignatureStatus; Publisher = if (-not [string]::IsNullOrWhiteSpace($author)) { $author } elseif (-not [string]::IsNullOrWhiteSpace([string]$signature.Publisher)) { [string]$signature.Publisher } else { '' }; Signer = if (-not [string]::IsNullOrWhiteSpace([string]$signature.Publisher)) { [string]$signature.Publisher } else { '' }; IsMicrosoftSigned = [bool]$signature.IsMicrosoftSigned }
}

function Test-PostureDriftRuleCondition {
    param($Rule, $Context)
    $change = $Context.Change; $oldValue = [string]$change.OldValue; $newValue = [string]$change.NewValue; $conditionId = [string]$Rule.condition_id
    if ([string]::IsNullOrWhiteSpace($conditionId)) { return $true }
    switch ($conditionId) {
        'bitlocker_weakened' { ($oldValue -match 'ProtectionStatus=On|ProtectionStatus=1') -and ($newValue -notmatch 'ProtectionStatus=On|ProtectionStatus=1') }
        'tpm_weakened' { ($oldValue -match 'Present=True|Ready=True|Enabled=True|Activated=True') -and ($newValue -match 'Present=False|Ready=False|Enabled=False|Activated=False') }
        'log_unavailable_or_disabled' { ($newValue -eq 'Unavailable' -or $newValue -match 'Enabled=False') }
        'old_and_new_differ' { (-not [string]::IsNullOrWhiteSpace($oldValue)) -and (-not [string]::IsNullOrWhiteSpace($newValue)) -and ($oldValue -cne $newValue) }
        'trusted_windows_tool_missing' { $newValue -match '\|False\|' }
        'trusted_windows_tool_invalid_signature' { $newValue -match '\|(NotSigned|HashMismatch|NotTrusted|UnknownError|PublisherMismatch)\|' }
        'trusted_windows_tool_changed_without_valid_signature' { (-not [string]::IsNullOrWhiteSpace($oldValue)) -and (-not [string]::IsNullOrWhiteSpace($newValue)) -and ($oldValue -cne $newValue) -and ($newValue -notmatch '\|Valid\|') }
        'app_required_file_missing' { $newValue -match '^False\|' -or $newValue -match '\|False\|' }
        'app_integrity_script_changed' { $lower = ([string]$change.Path).ToLowerInvariant(); $lower.EndsWith('.ps1') -or $lower.EndsWith('.py') }
        'app_integrity_json_changed' { ([string]$change.Path).ToLowerInvariant().EndsWith('.json') }
        'suspicious_persistence_command' { Test-UntrustedPersistenceCommand -Text ([string]$Context.CombinedText) }
        'google_task_pattern_only' { $identity = ('{0} {1}' -f [string]$change.Name, [string]$Context.TaskPath).ToLowerInvariant(); $identity.Contains('googleuserpeh') -or $identity.Contains('runplatformexperiencehelper_metrics') }
        'normal_google_task' { (Test-PostureDriftRuleCondition -Rule ([pscustomobject]@{ condition_id = 'google_task_pattern_only' }) -Context $Context) -and (Test-NormalGoogleTask -TaskRecord $Context.TaskRecord) }
        'zoom_task_pattern_only' { $identity = ('{0} {1}' -f [string]$change.Name, [string]$Context.TaskPath).ToLowerInvariant(); ([string]$change.Name -like 'ZoomUpdateTaskUser-*') -or $identity.Contains('zoomupdatetaskuser-') }
        'normal_zoom_task' { (Test-PostureDriftRuleCondition -Rule ([pscustomobject]@{ condition_id = 'zoom_task_pattern_only' }) -Context $Context) -and (Test-NormalZoomTask -TaskRecord $Context.TaskRecord) }
        'browser_updater_task_pattern_only' { $identity = ('{0} {1}' -f [string]$change.Name, [string]$Context.TaskPath).ToLowerInvariant(); $identity.Contains('google') -or $identity.Contains('chrome') -or $identity.Contains('edge') -or $identity.Contains('mozilla') -or $identity.Contains('firefox') }
        'normal_browser_updater_task' { (Test-PostureDriftRuleCondition -Rule ([pscustomobject]@{ condition_id = 'browser_updater_task_pattern_only' }) -Context $Context) -and (Test-NormalBrowserUpdaterTask -TaskRecord $Context.TaskRecord) }
        'normal_browser_updater_service' { Test-NormalBrowserUpdaterServiceChange -Change $change }
        'expected_per_user_service' { Test-ExpectedPerUserServiceChange -Change $change }
        'normal_temp_cache_cleanup' { ($change.ChangeType -in @('Removed','Modified')) -and (Test-NormalTempOrCachePath -Path ([string]$change.Path)) -and (-not (Test-ScriptOrExecutablePath -Path ([string]$change.Path))) }
        default { $true }
    }
}

function Test-PostureDriftRuleMatch {
    param($Rule, $Context)
    if ($null -eq $Rule -or $null -eq $Context) { return $false }
    if ($Rule.enabled -ne $null -and -not [bool]$Rule.enabled) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.section_pattern -Value ([string]$Context.SectionName))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.item_type_pattern -Value ([string]$Context.Change.Category))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.item_name_pattern -Value ([string]$Context.Change.Name))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.path_pattern -Value ([string]$Context.Change.Path))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.change_type_pattern -Value ([string]$Context.Change.ChangeType))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.old_value_pattern -Value ([string]$Context.Change.OldValue))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.new_value_pattern -Value ([string]$Context.Change.NewValue))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.notes_pattern -Value ([string]$Context.Change.Notes))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.command_line_pattern -Value ([string]$Context.CombinedText))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.publisher_pattern -Value ([string]$Context.Publisher))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.signer_pattern -Value ([string]$Context.Signer))) { return $false }
    if (-not (Test-WildcardPatternValue -Pattern $Rule.requires_signature_status -Value ([string]$Context.SignatureStatus))) { return $false }
    if ([bool]$Rule.blocks_if_suspicious_command_line -and (Test-SuspiciousCommandLine -Text ([string]$Context.CombinedText))) { return $false }
    return (Test-PostureDriftRuleCondition -Rule $Rule -Context $Context)
}
function Get-SeverityRankFromLabel {
    param([string]$Severity)
    switch (([string]$Severity).ToLowerInvariant()) {
        'critical' { 4 }
        'high' { 4 }
        'warning' { 3 }
        'medium' { 3 }
        'review' { 2 }
        'low' { 1 }
        'info' { 1 }
        default { 0 }
    }
}

function Get-DefaultClassificationForSeverity {
    param([string]$Severity)
    switch (([string]$Severity).ToLowerInvariant()) {
        'critical' { 'critical' }
        'high' { 'critical' }
        'warning' { 'warning' }
        'medium' { 'warning' }
        'review' { 'review' }
        'low' { 'info' }
        'info' { 'info' }
        default { 'review' }
    }
}

function Ensure-ChangeRuleFields {
    param($Change)
    foreach ($property in @('MatchedRuleId','MatchedRuleDescription','RecommendedAction')) {
        if ($Change.PSObject.Properties.Name -notcontains $property) { $Change | Add-Member -NotePropertyName $property -NotePropertyValue '' }
    }
    foreach ($property in @('GuardrailMatched','GuardrailReason')) {
        if ($Change.PSObject.Properties.Name -notcontains $property) { $Change | Add-Member -NotePropertyName $property -NotePropertyValue $(if ($property -eq 'GuardrailMatched') { $false } else { '' }) }
    }
}

function Apply-PostureDriftRuleToChange {
    param($Change, $Rule, [bool]$IsGuardrail)
    Ensure-ChangeRuleFields -Change $Change
    $ruleSeverity = if ([string]::IsNullOrWhiteSpace([string]$Rule.severity)) { [string]$Change.Severity } else { [string]$Rule.severity }
    $ruleClassification = if ([string]::IsNullOrWhiteSpace([string]$Rule.classification)) { [string]$Change.Classification } else { [string]$Rule.classification }
    if ($IsGuardrail) {
        $currentRank = Get-SeverityRankFromLabel -Severity ([string]$Change.Severity)
        $ruleRank = Get-SeverityRankFromLabel -Severity $ruleSeverity
        if ($ruleRank -gt $currentRank -or [string]::IsNullOrWhiteSpace([string]$Change.Severity)) { $Change.Severity = $ruleSeverity; $Change.Classification = $ruleClassification }
        elseif ([string]::IsNullOrWhiteSpace([string]$Change.Classification)) { $Change.Classification = Get-DefaultClassificationForSeverity -Severity ([string]$Change.Severity) }
        $Change.GuardrailMatched = $true; $Change.GuardrailReason = [string]$Rule.guardrail_reason
    } else {
        if (-not [string]::IsNullOrWhiteSpace($ruleSeverity)) { $Change.Severity = $ruleSeverity }
        if (-not [string]::IsNullOrWhiteSpace($ruleClassification)) { $Change.Classification = $ruleClassification }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Rule.csf_mapping)) { $Change.CsfMapping = [string]$Rule.csf_mapping }
    if (-not [string]::IsNullOrWhiteSpace([string]$Rule.interpretation)) { $Change.Interpretation = [string]$Rule.interpretation }
    if (-not [string]::IsNullOrWhiteSpace([string]$Rule.recommended_action)) { $Change.RecommendedAction = [string]$Rule.recommended_action }
    $Change.MatchedRuleId = [string]$Rule.rule_id; $Change.MatchedRuleDescription = [string]$Rule.description
    $extraNotes = @([string]$Change.Notes, ('Matched posture drift rule: {0}' -f [string]$Rule.rule_id), $(if ($IsGuardrail) { 'Rule engine guardrail blocked churn downgrade.' } else { '' })) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    $Change.Notes = ($extraNotes -join ' | ')
}

function Invoke-TripwirePostureRuleEngine {
    param($Changes,$Snapshot,[string]$RulesPath = '', [string]$AcceptedDriftPath = '', [string]$AcceptedDriftJsonFallbackPath = '')
    $catalog = Load-PostureDriftRuleCatalog -RulesPath $RulesPath
    $taskMap = @{}; foreach ($task in @($Snapshot.ScheduledTasks)) { $taskMap[[string]$task.Name] = $task }
    $rules = @($catalog.Rules | Sort-Object { [int]$_.priority } -Descending)
    $guardrailRules = @($rules | Where-Object { ([string]$_.rule_type).ToLowerInvariant() -eq 'guardrail' })
    $otherRules = @($rules | Where-Object { ([string]$_.rule_type).ToLowerInvariant() -ne 'guardrail' })
    $ruleMatches = 0
    foreach ($change in @($Changes)) {
        if ($null -eq $change) { continue }
        Ensure-ChangeRuleFields -Change $change
        $context = Get-PostureDriftRuleContext -Change $change -Snapshot $Snapshot -TaskMap $taskMap
        $matched = $false
        foreach ($rule in $guardrailRules) {
            if (Test-PostureDriftRuleMatch -Rule $rule -Context $context) { Apply-PostureDriftRuleToChange -Change $change -Rule $rule -IsGuardrail $true; $ruleMatches += 1; $matched = $true; break }
        }
        if ($matched) { continue }
        foreach ($rule in $otherRules) {
            if (Test-PostureDriftRuleMatch -Rule $rule -Context $context) { Apply-PostureDriftRuleToChange -Change $change -Rule $rule -IsGuardrail $false; $ruleMatches += 1; break }
        }
    }
    $acceptedResult = Apply-AcceptedPostureDrift -Changes $Changes -Snapshot $Snapshot -RegistryPath $AcceptedDriftPath -JsonFallbackPath $AcceptedDriftJsonFallbackPath
    $combinedWarning = @($catalog.Warning, $acceptedResult.Warning) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    [pscustomobject]@{ Changes = @($acceptedResult.Changes); RulesFilePath = $catalog.RulesFilePath; RulesFileStatus = $catalog.RulesFileStatus; RulesLoadedCount = $catalog.RulesLoadedCount; RuleMatchesCount = $ruleMatches; AcceptedDriftPath = $acceptedResult.RegistryPath; AcceptedDriftStatus = $acceptedResult.RegistryStatus; AcceptedDriftLoadedCount = $acceptedResult.RegistryLoadedCount; AcceptedDriftMatchCount = $acceptedResult.MatchCount; AcceptedDriftWarning = $acceptedResult.Warning; Warning = ($combinedWarning -join ' '); Source = $catalog.Source; CatalogVersion = $catalog.CatalogVersion }
}

function Get-TripwirePostureSummary {
    param($Snapshot,$Changes,$RuleEngineResult)
    $changesList = @($Changes)
    $ruleWarning = if ($null -ne $RuleEngineResult) { [string]$RuleEngineResult.Warning } else { '' }
    $acceptedWarning = if ($null -ne $RuleEngineResult -and $RuleEngineResult.PSObject.Properties.Name -contains 'AcceptedDriftWarning') { [string]$RuleEngineResult.AcceptedDriftWarning } else { '' }
    $baseNote = 'These findings describe observed posture changes from the saved baseline, not proof of compromise. NIST CSF view: Detect records observed posture changes from the trusted baseline, Respond focuses attention on findings that require action, Govern records reviewed and accepted posture changes, and Recover may establish a new trusted baseline after review. Not every observed posture change is an alert. Expected operational changes and accepted posture changes remain in the audit trail, while response-required findings are the subset that should be surfaced for action. Drift classification used local explainable posture rules.'
    if (-not [string]::IsNullOrWhiteSpace($ruleWarning)) { $baseNote = ('{0} Rule catalog warning: {1}' -f $baseNote, $ruleWarning) }
    if (-not [string]::IsNullOrWhiteSpace($acceptedWarning)) { $baseNote = ('{0} Accepted drift registry warning: {1}' -f $baseNote, $acceptedWarning) }
    $observedCount = @($changesList).Count
    $expectedOperationalCount = @($changesList | Where-Object { ([string]$_.Classification).ToLowerInvariant() -eq 'expected' }).Count
    $acceptedCount = @($changesList | Where-Object { [bool]$_.IsAcceptedDrift }).Count
    $reviewCount = @($changesList | Where-Object { -not [bool]$_.IsAcceptedDrift -and ([string]$_.Severity).ToLowerInvariant() -eq 'review' }).Count
    $warningCount = @($changesList | Where-Object { ([string]$_.Severity).ToLowerInvariant() -in @('warning','medium') }).Count
    $criticalCount = @($changesList | Where-Object { ([string]$_.Severity).ToLowerInvariant() -in @('critical','high') }).Count
    $responseRequiredCount = $warningCount + $criticalCount
    $guardrailCount = @($changesList | Where-Object { [bool]$_.GuardrailMatched }).Count
    [pscustomobject]@{
        observed_posture_change_count = $observedCount
        expected_operational_change_count = $expectedOperationalCount
        accepted_posture_change_count = $acceptedCount
        posture_review_count = $reviewCount
        response_required_count = $responseRequiredCount
        guardrail_protected_count = $guardrailCount
        security_controls_checked = @($Snapshot.SecurityControlBaseline.Items).Count
        trusted_windows_tools_checked = @($Snapshot.TrustedWindowsToolBaseline.Tools).Count
        logging_audit_items_checked = @($Snapshot.LoggingAuditBaseline.Items).Count
        app_integrity_items_checked = @($Snapshot.AppIntegrityBaseline.Files).Count
        security_control_drift_count = @($changesList | Where-Object { $_.Category -eq 'SecurityControl' }).Count
        trusted_tool_drift_count = @($changesList | Where-Object { $_.Category -eq 'TrustedWindowsTool' }).Count
        logging_audit_drift_count = @($changesList | Where-Object { $_.Category -eq 'LoggingAudit' }).Count
        app_integrity_drift_count = @($changesList | Where-Object { $_.Category -eq 'AppIntegrity' }).Count
        expected_churn_count = $expectedOperationalCount
        accepted_drift_count = $acceptedCount
        unexpected_drift_count = @($changesList | Where-Object { -not [bool]$_.IsAcceptedDrift -and ([string]$_.Classification).ToLowerInvariant() -ne 'expected' }).Count
        review_drift_count = $reviewCount
        warning_drift_count = $warningCount
        critical_drift_count = $criticalCount
        guardrail_matched_count = $guardrailCount
        suspicious_drift_count = @($changesList | Where-Object { [bool]$_.GuardrailMatched -and (([string]$_.Severity).ToLowerInvariant() -in @('critical','high')) }).Count
        rules_loaded_count = if ($null -ne $RuleEngineResult) { [int]$RuleEngineResult.RulesLoadedCount } else { 0 }
        rule_matches_count = if ($null -ne $RuleEngineResult) { [int]$RuleEngineResult.RuleMatchesCount } else { 0 }
        rules_file_status = if ($null -ne $RuleEngineResult) { [string]$RuleEngineResult.RulesFileStatus } else { 'unavailable' }
        rules_file_path = if ($null -ne $RuleEngineResult) { [string]$RuleEngineResult.RulesFilePath } else { '' }
        accepted_drift_registry_status = if ($null -ne $RuleEngineResult -and $RuleEngineResult.PSObject.Properties.Name -contains 'AcceptedDriftStatus') { [string]$RuleEngineResult.AcceptedDriftStatus } else { 'unavailable' }
        accepted_drift_registry_path = if ($null -ne $RuleEngineResult -and $RuleEngineResult.PSObject.Properties.Name -contains 'AcceptedDriftPath') { [string]$RuleEngineResult.AcceptedDriftPath } else { '' }
        accepted_drift_registry_loaded_count = if ($null -ne $RuleEngineResult -and $RuleEngineResult.PSObject.Properties.Name -contains 'AcceptedDriftLoadedCount') { [int]$RuleEngineResult.AcceptedDriftLoadedCount } else { 0 }
        note = $baseNote
    }
}

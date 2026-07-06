param(
    [string]$WatchPath = "",
    [string]$StatePath = "",
    [string]$StateDbPath = "",
    [int]$PollSeconds = 30,
    [int]$RepeatSuppressHours = 24,
    [switch]$Watch
)

$ErrorActionPreference = "Stop"

function Get-SettingsPath {
    return (Join-Path $PSScriptRoot "codex-monitor.settings.json")
}

function Get-HelperWatchPath {
    param([string]$ConfiguredWatchPath)

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredWatchPath)) {
        $resolvedConfiguredPath = $ConfiguredWatchPath
        if (Test-Path -LiteralPath (Join-Path $resolvedConfiguredPath "alerts\pending")) {
            return (Join-Path $resolvedConfiguredPath "alerts\pending")
        }
        return $resolvedConfiguredPath
    }

    if (-not [string]::IsNullOrWhiteSpace($env:CODEX_MONITOR_WATCHPATH)) {
        return $env:CODEX_MONITOR_WATCHPATH
    }

    $settingsPath = Get-SettingsPath
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.AlertInboxPath)) {
                return [string]$settings.AlertInboxPath
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.AlertWatchPath)) {
                return [string]$settings.AlertWatchPath
            }
        } catch {
        }
    }

    $defaultInbox = Join-Path $PSScriptRoot "alerts\pending"
    if (Test-Path -LiteralPath $defaultInbox) {
        return $defaultInbox
    }
    return $PSScriptRoot
}

function Get-StateStoreScriptPath {
    $path = Join-Path $PSScriptRoot "ioc_store.py"
    if (-not (Test-Path -LiteralPath $path)) {
        throw "SQLite state helper not found: $path"
    }
    return $path
}

function Get-PythonCommand {
    $settingsPath = Get-SettingsPath
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

function Get-HelperStateDbPath {
    param(
        [string]$ConfiguredStateDbPath,
        [string]$ConfiguredStatePath
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredStateDbPath)) {
        return $ConfiguredStateDbPath
    }

    if (-not [string]::IsNullOrWhiteSpace($env:CODEX_MONITOR_STATEDBPATH)) {
        return $env:CODEX_MONITOR_STATEDBPATH
    }

    $settingsPath = Get-SettingsPath
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.StateDbPath)) {
                return [string]$settings.StateDbPath
            }
        } catch {
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredStatePath)) {
        $legacyParent = Split-Path -Path $ConfiguredStatePath -Parent
        if (-not [string]::IsNullOrWhiteSpace($legacyParent)) {
            return (Join-Path $legacyParent "ioc-store.db")
        }
    }

    return (Join-Path $PSScriptRoot "state\ioc-store.db")
}

function Get-ArchivePath {
    param([string]$CurrentWatchPath)

    $settingsPath = Get-SettingsPath
    if (Test-Path -LiteralPath $settingsPath) {
        try {
            $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace([string]$settings.AlertArchivePath)) {
                return [string]$settings.AlertArchivePath
            }
        } catch {
        }
    }

    $parent = Split-Path -Path $CurrentWatchPath -Parent
    if ((Split-Path -Leaf $CurrentWatchPath) -ieq "pending" -and -not [string]::IsNullOrWhiteSpace($parent)) {
        return (Join-Path $parent "archive")
    }

    return (Join-Path $CurrentWatchPath "archive")
}

function Ensure-ParentDirectory {
    param([string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

function Write-JsonFile {
    param(
        [string]$Path,
        $Object,
        [int]$Depth = 8
    )

    Ensure-ParentDirectory -Path $Path
    $json = ConvertTo-Json -InputObject $Object -Depth $Depth
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function Read-LegacyStateFile {
    param([string]$Path)

    if (Test-Path -LiteralPath $Path) {
        try {
            return (Get-Content $Path -Raw | ConvertFrom-Json)
        } catch {
        }
    }

    return [PSCustomObject]@{
        SeenAlerts = @()
        AlertFingerprintLastShownUtc = @{}
        LastRunUtc = $null
    }
}

function Get-State {
    param(
        [string]$DbPath,
        [string]$LegacyPath
    )

    try {
        $raw = Invoke-StateStore -DbPath $DbPath -Arguments @("state-get", "--namespace", "alert_helper", "--key", "seen_alerts")
        $payload = $raw | ConvertFrom-Json
        if ($payload.found) {
            return $payload.value
        }
    } catch {
    }

    $legacyState = Read-LegacyStateFile -Path $LegacyPath
    $legacySeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($legacyState.SeenAlerts)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$entry)) {
            [void]$legacySeen.Add([string]$entry)
        }
    }
    $legacyFingerprints = @{}
    foreach ($property in @(($legacyState.PSObject.Properties | Where-Object { $_.Name -eq 'AlertFingerprintLastShownUtc' }))) {
        foreach ($entry in @($property.Value.PSObject.Properties)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$entry.Name) -and -not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
                $legacyFingerprints[[string]$entry.Name] = [string]$entry.Value
            }
        }
    }
    Save-State -DbPath $DbPath -SeenAlerts $legacySeen -AlertFingerprintLastShownUtc $legacyFingerprints -LastRunUtc ([string]$legacyState.LastRunUtc)
    return [PSCustomObject]@{
        SeenAlerts = @($legacySeen)
        AlertFingerprintLastShownUtc = $legacyFingerprints
        LastRunUtc = [string]$legacyState.LastRunUtc
    }
}

function Save-State {
    param(
        [string]$DbPath,
        [System.Collections.Generic.HashSet[string]]$SeenAlerts,
        [hashtable]$AlertFingerprintLastShownUtc = @{},
        [string]$LastRunUtc = ""
    )

    $state = [PSCustomObject]@{
        SeenAlerts = @($SeenAlerts)
        AlertFingerprintLastShownUtc = $AlertFingerprintLastShownUtc
        LastRunUtc = if ([string]::IsNullOrWhiteSpace($LastRunUtc)) { (Get-Date).ToUniversalTime().ToString("o") } else { $LastRunUtc }
    }

    $json = ConvertTo-Json -InputObject $state -Depth 8
    $tempPath = [System.IO.Path]::GetTempFileName()
    try {
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)
        [void](Invoke-StateStore -DbPath $DbPath -Arguments @("state-put", "--namespace", "alert_helper", "--key", "seen_alerts", "--input", $tempPath))
    } finally {
        if (Test-Path -LiteralPath $tempPath) {
            [System.IO.File]::Delete($tempPath)
        }
    }
}

function Show-AlertPopup {
    param(
        [string]$Title,
        [string]$Message,
        [string[]]$DetailLines = @(),
        [string]$AlertMarkdownPath = "",
        [string]$AlertFolderPath = ""
    )

    try {
        Add-Type -AssemblyName PresentationFramework
        Add-Type -AssemblyName PresentationCore

        $safeDetailLines = @($DetailLines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -First 3)
        $detailText = ($safeDetailLines -join [Environment]::NewLine)

        $window = New-Object System.Windows.Window
        $window.Title = $Title
        $window.Width = 520
        $window.SizeToContent = 'Height'
        $window.WindowStartupLocation = 'CenterScreen'
        $window.Topmost = $true
        $window.ResizeMode = 'NoResize'
        $window.Background = [System.Windows.Media.Brushes]::WhiteSmoke

        $outer = New-Object System.Windows.Controls.Grid
        $outer.Margin = '18'
        $outer.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
        $outer.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
        $outer.RowDefinitions[1].Height = 'Auto'

        $contentStack = New-Object System.Windows.Controls.StackPanel
        $contentStack.Orientation = 'Vertical'

        $titleBlock = New-Object System.Windows.Controls.TextBlock
        $titleBlock.Text = $Title
        $titleBlock.FontSize = 20
        $titleBlock.FontWeight = 'Bold'
        $titleBlock.TextWrapping = 'Wrap'
        $titleBlock.Margin = '0,0,0,10'
        [void]$contentStack.Children.Add($titleBlock)

        $messageBlock = New-Object System.Windows.Controls.TextBlock
        $messageBlock.Text = $Message
        $messageBlock.FontSize = 14
        $messageBlock.TextWrapping = 'Wrap'
        $messageBlock.Margin = '0,0,0,10'
        [void]$contentStack.Children.Add($messageBlock)

        if (-not [string]::IsNullOrWhiteSpace($detailText)) {
            $detailsBorder = New-Object System.Windows.Controls.Border
            $detailsBorder.Background = [System.Windows.Media.Brushes]::White
            $detailsBorder.BorderBrush = [System.Windows.Media.Brushes]::LightGray
            $detailsBorder.BorderThickness = '1'
            $detailsBorder.Padding = '10'
            $detailsBorder.Margin = '0,0,0,12'

            $detailsBlock = New-Object System.Windows.Controls.TextBlock
            $detailsBlock.Text = $detailText
            $detailsBlock.TextWrapping = 'Wrap'
            $detailsBlock.FontFamily = 'Consolas'
            $detailsBorder.Child = $detailsBlock
            [void]$contentStack.Children.Add($detailsBorder)
        }

        $hintBlock = New-Object System.Windows.Controls.TextBlock
        $hintBlock.Text = 'Use Open Alert to inspect the report, or Dismiss to acknowledge.'
        $hintBlock.FontStyle = 'Italic'
        $hintBlock.Foreground = [System.Windows.Media.Brushes]::DimGray
        $hintBlock.TextWrapping = 'Wrap'
        [void]$contentStack.Children.Add($hintBlock)

        [System.Windows.Controls.Grid]::SetRow($contentStack, 0)
        [void]$outer.Children.Add($contentStack)

        $buttonPanel = New-Object System.Windows.Controls.StackPanel
        $buttonPanel.Orientation = 'Horizontal'
        $buttonPanel.HorizontalAlignment = 'Right'
        $buttonPanel.Margin = '0,14,0,0'

        $openAlertButton = New-Object System.Windows.Controls.Button
        $openAlertButton.Content = 'Open Alert'
        $openAlertButton.MinWidth = 90
        $openAlertButton.Margin = '0,0,8,0'
        $openAlertButton.IsEnabled = -not [string]::IsNullOrWhiteSpace($AlertMarkdownPath)
        $openAlertButton.Add_Click({
            if (-not [string]::IsNullOrWhiteSpace($AlertMarkdownPath) -and (Test-Path -LiteralPath $AlertMarkdownPath)) {
                Start-Process -FilePath $AlertMarkdownPath | Out-Null
            }
        })
        [void]$buttonPanel.Children.Add($openAlertButton)

        $openFolderButton = New-Object System.Windows.Controls.Button
        $openFolderButton.Content = 'Open Folder'
        $openFolderButton.MinWidth = 90
        $openFolderButton.Margin = '0,0,8,0'
        $openFolderButton.IsEnabled = -not [string]::IsNullOrWhiteSpace($AlertFolderPath)
        $openFolderButton.Add_Click({
            if (-not [string]::IsNullOrWhiteSpace($AlertFolderPath) -and (Test-Path -LiteralPath $AlertFolderPath)) {
                Start-Process explorer.exe -ArgumentList $AlertFolderPath | Out-Null
            }
        })
        [void]$buttonPanel.Children.Add($openFolderButton)

        $dismissButton = New-Object System.Windows.Controls.Button
        $dismissButton.Content = 'Dismiss'
        $dismissButton.MinWidth = 90
        $dismissButton.IsDefault = $true
        $dismissButton.Add_Click({ $window.Close() })
        [void]$buttonPanel.Children.Add($dismissButton)

        [System.Windows.Controls.Grid]::SetRow($buttonPanel, 1)
        [void]$outer.Children.Add($buttonPanel)

        $window.Content = $outer
        [void]$window.ShowDialog()
        return $true
    } catch {
    }

    try {
        $wshShell = New-Object -ComObject WScript.Shell
        [void]$wshShell.Popup($Message, 10, $Title, 64)
        return $true
    } catch {
    }

    return $false
}

function Get-AlertIdentity {
    param($Alert)

    $sourceReport = [string]$Alert.Metadata.SourceReport
    $collectionTimeUtc = [string]$Alert.Metadata.CollectionTimeUtc
    $alertType = [string]$Alert.Metadata.AlertType
    return "{0}|{1}|{2}" -f $alertType, $collectionTimeUtc, $sourceReport
}

function Get-AlertFingerprint {
    param($Alert)

    $meta = $Alert.Metadata
    $summary = $Alert.Summary
    $changes = @($Alert.Changes)
    $changeTokens = foreach ($change in ($changes | Select-Object -First 6)) {
        "{0}|{1}|{2}|{3}" -f ([string]$change.Category), ([string]$change.Name), ([string]$change.ChangeType), ([string]$change.Path)
    }
    if (@($changeTokens).Count -eq 0) {
        $changeTokens = @(@($summary.DetailLines | Select-Object -First 6 | ForEach-Object { [string]$_ }))
    }
    $basis = @(
        [string]$meta.AlertType,
        [string]$summary.Title,
        [string]$summary.Message,
        ($changeTokens -join '||')
    ) -join "`n"

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($basis)
        $hash = $sha.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Should-NotifyAlert {
    param(
        [hashtable]$LastShownByFingerprint,
        [string]$Fingerprint,
        [int]$SuppressHours
    )

    if ([string]::IsNullOrWhiteSpace($Fingerprint)) {
        return $true
    }
    if (-not $LastShownByFingerprint.ContainsKey($Fingerprint)) {
        return $true
    }

    $lastShownText = [string]$LastShownByFingerprint[$Fingerprint]
    $lastShown = [datetime]::MinValue
    if (-not [datetime]::TryParse($lastShownText, [ref]$lastShown)) {
        return $true
    }

    return $lastShown.ToUniversalTime() -le (Get-Date).ToUniversalTime().AddHours(-1 * [math]::Abs($SuppressHours))
}

function Move-AlertArtifactsToArchive {
    param(
        [System.IO.FileInfo]$JsonFile,
        [string]$MarkdownPath,
        [string]$ArchivePath
    )

    $archiveJsonPath = Join-Path $ArchivePath $JsonFile.Name
    Move-Item -LiteralPath $JsonFile.FullName -Destination $archiveJsonPath -Force

    $archiveMarkdownPath = ""
    if (-not [string]::IsNullOrWhiteSpace($MarkdownPath) -and (Test-Path -LiteralPath $MarkdownPath)) {
        $archiveMarkdownPath = Join-Path $ArchivePath ([IO.Path]::GetFileName($MarkdownPath))
        Move-Item -LiteralPath $MarkdownPath -Destination $archiveMarkdownPath -Force
    }

    return [PSCustomObject]@{
        ArchiveJsonPath = $archiveJsonPath
        ArchiveMarkdownPath = $archiveMarkdownPath
    }
}

function New-QueuedAlertRecord {
    param(
        [System.IO.FileInfo]$JsonFile,
        $AlertPayload
    )

    $title = [string]$AlertPayload.Summary.Title
    $message = [string]$AlertPayload.Summary.Message
    $detailLines = @($AlertPayload.Summary.DetailLines)
    if ([string]::IsNullOrWhiteSpace($title)) {
        $title = 'Codex monitor alert'
    }
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = [string]$JsonFile.Name
    }

    return [PSCustomObject]@{
        File = $JsonFile
        Alert = $AlertPayload
        Identity = Get-AlertIdentity -Alert $AlertPayload
        Fingerprint = Get-AlertFingerprint -Alert $AlertPayload
        Title = $title
        Message = $message
        DetailLines = $detailLines
        MarkdownPath = [IO.Path]::ChangeExtension($JsonFile.FullName, '.md')
        JsonPath = $JsonFile.FullName
    }
}

function Convert-ToArchivedAlertRecord {
    param(
        $QueuedAlert,
        $ArchiveMoveResult
    )

    return [PSCustomObject]@{
        File = $QueuedAlert.File
        Alert = $QueuedAlert.Alert
        Identity = $QueuedAlert.Identity
        Fingerprint = $QueuedAlert.Fingerprint
        Title = $QueuedAlert.Title
        Message = $QueuedAlert.Message
        DetailLines = $QueuedAlert.DetailLines
        MarkdownPath = if ($ArchiveMoveResult -and $ArchiveMoveResult.ArchiveMarkdownPath) { [string]$ArchiveMoveResult.ArchiveMarkdownPath } else { [string]$QueuedAlert.MarkdownPath }
        JsonPath = if ($ArchiveMoveResult -and $ArchiveMoveResult.ArchiveJsonPath) { [string]$ArchiveMoveResult.ArchiveJsonPath } else { [string]$QueuedAlert.JsonPath }
    }
}

function Show-QueuedAlerts {
    param(
        [object[]]$QueuedAlerts,
        [string]$AlertFolderPath
    )

    if (@($QueuedAlerts).Count -le 0) {
        return $false
    }

    if (@($QueuedAlerts).Count -eq 1) {
        $item = $QueuedAlerts[0]
        return Show-AlertPopup -Title $item.Title -Message $item.Message -DetailLines $item.DetailLines -AlertMarkdownPath $item.MarkdownPath -AlertFolderPath $AlertFolderPath
    }

    $latest = $QueuedAlerts[-1]
    $detailLines = @()
    foreach ($item in @($QueuedAlerts | Select-Object -First 3)) {
        $detailLines += ('- {0}: {1}' -f $item.Title, $item.Message)
    }
    if (@($QueuedAlerts).Count -gt 3) {
        $detailLines += ('- Plus {0} more queued alerts' -f (@($QueuedAlerts).Count - 3))
    }

    return Show-AlertPopup `
        -Title ('Codex monitor alerts ({0})' -f @($QueuedAlerts).Count) `
        -Message ('{0} new alerts queued while you were away. Dismiss once to archive this batch.' -f @($QueuedAlerts).Count) `
        -DetailLines $detailLines `
        -AlertMarkdownPath $latest.MarkdownPath `
        -AlertFolderPath $AlertFolderPath
}

$WatchPath = Get-HelperWatchPath -ConfiguredWatchPath $WatchPath
$StateDbPath = Get-HelperStateDbPath -ConfiguredStateDbPath $StateDbPath -ConfiguredStatePath $StatePath
$ArchivePath = Get-ArchivePath -CurrentWatchPath $WatchPath
Ensure-ParentDirectory -Path (Join-Path $ArchivePath "placeholder.txt")

if (-not (Test-Path -LiteralPath $WatchPath)) {
    throw "Watch path not found: $WatchPath"
}

$state = Get-State -DbPath $StateDbPath -LegacyPath $StatePath
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in @($state.SeenAlerts)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$entry)) {
        [void]$seen.Add([string]$entry)
    }
}
$lastShownByFingerprint = @{}
foreach ($property in @(($state.PSObject.Properties | Where-Object { $_.Name -eq 'AlertFingerprintLastShownUtc' }))) {
    foreach ($entry in @($property.Value.PSObject.Properties)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$entry.Name) -and -not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            $lastShownByFingerprint[[string]$entry.Name] = [string]$entry.Value
        }
    }
}

do {
    $alerts = @(Get-ChildItem -LiteralPath $WatchPath -Filter "ALERT_*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    $queuedAlerts = @()
    $notifyAlerts = @()
    $batchFingerprints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $alerts) {
        try {
            $alert = Get-Content $file.FullName -Raw | ConvertFrom-Json
        } catch {
            continue
        }

        $queued = New-QueuedAlertRecord -JsonFile $file -AlertPayload $alert
        if ($seen.Contains($queued.Identity)) {
            continue
        }
        $queuedAlerts += $queued
        if ((-not $batchFingerprints.Contains($queued.Fingerprint)) -and (Should-NotifyAlert -LastShownByFingerprint $lastShownByFingerprint -Fingerprint $queued.Fingerprint -SuppressHours $RepeatSuppressHours)) {
            [void]$batchFingerprints.Add($queued.Fingerprint)
            $notifyAlerts += $queued
        }
    }

    if (@($queuedAlerts).Count -gt 0) {
        $notifyByIdentity = @{}
        foreach ($queued in $notifyAlerts) {
            $notifyByIdentity[[string]$queued.Identity] = $true
        }

        $archivedNotifyAlerts = @()
        $shownAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        foreach ($queued in $queuedAlerts) {
            [void]$seen.Add($queued.Identity)
            $archiveMove = Move-AlertArtifactsToArchive -JsonFile $queued.File -MarkdownPath $queued.MarkdownPath -ArchivePath $ArchivePath
            if ($notifyByIdentity.ContainsKey([string]$queued.Identity)) {
                $archivedNotifyAlerts += (Convert-ToArchivedAlertRecord -QueuedAlert $queued -ArchiveMoveResult $archiveMove)
                if (-not [string]::IsNullOrWhiteSpace($queued.Fingerprint)) {
                    $lastShownByFingerprint[$queued.Fingerprint] = $shownAtUtc
                }
            }
        }
        Save-State -DbPath $StateDbPath -SeenAlerts $seen -AlertFingerprintLastShownUtc $lastShownByFingerprint
        if (@($archivedNotifyAlerts).Count -gt 0) {
            [void](Show-QueuedAlerts -QueuedAlerts $archivedNotifyAlerts -AlertFolderPath $ArchivePath)
        }
    }

    if ($Watch) {
        Start-Sleep -Seconds $PollSeconds
    }
} while ($Watch)

param(
    [string]$WatchPath = "",
    [string]$StatePath = "",
    [string]$StateDbPath = "",
    [int]$PollSeconds = 30,
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
    Save-State -DbPath $DbPath -SeenAlerts $legacySeen -LastRunUtc ([string]$legacyState.LastRunUtc)
    return $legacyState
}

function Save-State {
    param(
        [string]$DbPath,
        [System.Collections.Generic.HashSet[string]]$SeenAlerts,
        [string]$LastRunUtc = ""
    )

    $state = [PSCustomObject]@{
        SeenAlerts = @($SeenAlerts)
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

do {
    $alerts = @(Get-ChildItem -LiteralPath $WatchPath -Filter "ALERT_*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    foreach ($file in $alerts) {
        try {
            $alert = Get-Content $file.FullName -Raw | ConvertFrom-Json
        } catch {
            continue
        }

        $identity = Get-AlertIdentity -Alert $alert
        if ($seen.Contains($identity)) {
            continue
        }

        $title = [string]$alert.Summary.Title
        $message = [string]$alert.Summary.Message
        $detailLines = @($alert.Summary.DetailLines)
        if ([string]::IsNullOrWhiteSpace($title)) {
            $title = "Codex monitor alert"
        }
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = [string]$file.Name
        }

        $pairedMarkdownPath = [IO.Path]::ChangeExtension($file.FullName, ".md")
        [void](Show-AlertPopup -Title $title -Message $message -DetailLines $detailLines -AlertMarkdownPath $pairedMarkdownPath -AlertFolderPath $WatchPath)
        [void]$seen.Add($identity)
        Save-State -DbPath $StateDbPath -SeenAlerts $seen

        $archiveJsonPath = Join-Path $ArchivePath $file.Name
        Move-Item -LiteralPath $file.FullName -Destination $archiveJsonPath -Force

        if (Test-Path -LiteralPath $pairedMarkdownPath) {
            Move-Item -LiteralPath $pairedMarkdownPath -Destination (Join-Path $ArchivePath ([IO.Path]::GetFileName($pairedMarkdownPath))) -Force
        }
    }

    if ($Watch) {
        Start-Sleep -Seconds $PollSeconds
    }
} while ($Watch)

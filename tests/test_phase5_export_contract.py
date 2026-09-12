import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PhaseFiveExportContractTests(unittest.TestCase):
    def read_script(self, name: str) -> str:
        return (ROOT / name).read_text(encoding="utf-8")

    def test_collectors_expose_opt_in_export_switches(self) -> None:
        for script_name in (
            "invoke-host-ioc.ps1",
            "invoke-host-tripwire.ps1",
            "monitor-threat-rss.ps1",
            "import-threat-feeds.ps1",
        ):
            self.assertIn("[switch]$Export", self.read_script(script_name), script_name)

    def test_ioc_and_rss_reports_write_only_when_export_requested(self) -> None:
        ioc = self.read_script("invoke-host-ioc.ps1")
        rss = self.read_script("monitor-threat-rss.ps1")
        self.assertIn("if ($Export) {\n    Write-JsonFile -Path $jsonFile -Object $data", ioc)
        self.assertIn("if ($Export) {\nWrite-JsonFile -Path $jsonFile -Object $report", rss)
        self.assertIn("if ($Export -and [int]$report.Metadata.RelevantItemCount -gt 0)", rss)

    def test_tripwire_uses_deleted_temporary_baseline_serialization_without_export(self) -> None:
        tripwire = self.read_script("invoke-host-tripwire.ps1")
        self.assertIn("$temporaryBaselineSerializationPath = [IO.Path]::GetTempFileName()", tripwire)
        self.assertIn("Index-TripwireBaselineInSqlite -DbPath $resolvedStateDbPath -BaselineJsonPath $baselineSerializationPath", tripwire)
        self.assertIn("[IO.File]::Delete($temporaryBaselineSerializationPath)", tripwire)
        self.assertIn("if ($Export) {\n            Write-JsonFile -Path $alertJson -Object $alert", tripwire)

    def test_feed_import_uses_temporary_serialization_and_always_cleans_it_up(self) -> None:
        feed_import = self.read_script("import-threat-feeds.ps1")
        self.assertIn("$emitExport = $Export -or -not [string]::IsNullOrWhiteSpace($OutputPath)", feed_import)
        self.assertIn("$temporaryBundlePath = [IO.Path]::GetTempFileName()", feed_import)
        self.assertIn("} finally {\n    if (-not [string]::IsNullOrWhiteSpace($temporaryBundlePath)", feed_import)
        self.assertIn("[IO.File]::Delete($temporaryBundlePath)", feed_import)

    def test_ui_alert_surface_uses_sqlite_ids_and_has_no_alert_file_route(self) -> None:
        ui_source = self.read_script("codex_monitor_ui.py")
        self.assertIn("def list_sqlite_alerts", ui_source)
        self.assertIn("def get_sqlite_alert_detail", ui_source)
        self.assertIn('params.get("id", [""])[0]', ui_source)
        self.assertIn('export-alert --alert-id', ui_source)
        self.assertNotIn("def list_alert_records", ui_source)
        self.assertNotIn('params.get("path", [""])[0]\n                alert_path', ui_source)
        self.assertNotIn("alert_inbox_path", ui_source)
        self.assertNotIn("alert_archive_path", ui_source)

    def test_notifier_opens_sqlite_alert_detail_and_data_root(self) -> None:
        notifier_source = self.read_script("start-codex-alert-helper.ps1")
        ui_launcher_source = self.read_script("start-codex-monitor-ui.ps1")
        self.assertIn("function Get-HelperDataRoot", notifier_source)
        self.assertIn("function Open-AlertInUi", notifier_source)
        self.assertIn("$launchArguments = '-NoProfile -ExecutionPolicy Bypass -File", notifier_source)
        self.assertIn('Start-Process -FilePath "powershell.exe" -ArgumentList $launchArguments -WindowStyle Hidden', notifier_source)
        self.assertIn("AlertId = [string]$_.alert_id", notifier_source)
        self.assertIn("Show-QueuedAlerts -QueuedAlerts $popupAlerts -AlertFolderPath $dataRoot", notifier_source)
        self.assertNotIn("MarkdownPath = [string]$_.export_markdown_path", notifier_source)
        self.assertIn('[string]$OpenPath = "/"', ui_launcher_source)
        self.assertIn('@("--open-browser", "--open-path", $OpenPath)', ui_launcher_source)

    def test_notifier_preserves_sqlite_presentation_suppression(self) -> None:
        notifier_source = self.read_script("start-codex-alert-helper.ps1")
        self.assertIn("function Get-DeliveryPresentationState", notifier_source)
        self.assertIn("function Save-DeliveryPresentationState", notifier_source)
        self.assertIn('"--key", "delivery_presentations"', notifier_source)
        self.assertIn("Get-DeliveryPresentationState -DbPath $StateDbPath -SuppressHours $RepeatSuppressHours", notifier_source)
        self.assertIn("$presentationState.ContainsKey($alertId)", notifier_source)
        self.assertIn("Save-DeliveryPresentationState -DbPath $StateDbPath -PresentationState $presentationState", notifier_source)

    def test_ioc_excludes_only_exact_monitor_marked_powershell_events(self) -> None:
        ioc = self.read_script("invoke-host-ioc.ps1")
        self.assertIn('$MonitorSelfEventMarker = "CODEX_MONITOR_SELF_EVENT"', ioc)
        self.assertIn(
            '([string]$Event.Message).IndexOf($MonitorSelfEventMarker, [System.StringComparison]::Ordinal) -ge 0',
            ioc,
        )
        self.assertIn('Get-MonitorRelevantPowerShellEvents -Start $Start -EventId 4103', ioc)
        self.assertIn('Get-MonitorRelevantPowerShellEvents -Start $Start -EventId 4104', ioc)
        self.assertIn(' -MaxEvents 200 |', ioc)
        self.assertIn('Where-Object { -not (Test-IsMonitorOwnedPowerShellEvent -Event $_) }', ioc)
        self.assertIn('Select-Object -First 40', ioc)

    def test_runtime_powershell_scripts_carry_the_self_event_marker(self) -> None:
        for script_name in (
            "accept-posture-drift.ps1",
            "collect-security-baseline.ps1",
            "get-codex-monitor-status.ps1",
            "import-threat-feeds.ps1",
            "install-codex-monitor.ps1",
            "invoke-host-ioc.ps1",
            "invoke-host-tripwire.ps1",
            "monitor-threat-rss.ps1",
            "posture-drift-rules.ps1",
            "start-codex-alert-helper.ps1",
            "start-codex-monitor-ui.ps1",
            "tripwire-posture-baseline.ps1",
        ):
            self.assertIn("# CODEX_MONITOR_SELF_EVENT", self.read_script(script_name), script_name)


if __name__ == "__main__":
    unittest.main()

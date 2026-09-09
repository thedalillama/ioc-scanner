import json
import tempfile
import unittest
from pathlib import Path

import codex_monitor_ui as ui


class CodexMonitorUiTests(unittest.TestCase):
    def make_config(self, root: Path, ui_persona: str = "user") -> ui.AppConfig:
        return ui.AppConfig(
            settings_path=root / "codex-monitor.settings.json",
            runtime_root=root,
            data_root=root,
            state_db_path=root / "state" / "ioc-store.db",
            alert_inbox_path=root / "alerts" / "pending",
            alert_archive_path=root / "alerts" / "archive",
            indicator_export_path=root / "indicators" / "feed-indicators-latest.json",
            protection_profile="microsoft_baseline",
            ui_persona=ui_persona,
            repo_root=Path(__file__).resolve().parent.parent,
        )

    def make_tripwire_report(self, root: Path) -> Path:
        report_path = root / "HOST_TRIPWIRE_CHECK_2026-07-19_12-00-00.json"
        payload = {
            "Metadata": {
                "CollectionTimeUtc": "2026-07-19T12:00:00Z",
                "OverallStatus": "Review",
            },
            "Summary": {
                "observed_posture_change_count": 4,
                "expected_operational_change_count": 1,
                "accepted_posture_change_count": 1,
                "posture_review_count": 1,
                "response_required_count": 1,
                "guardrail_protected_count": 1,
                "accepted_drift_registry_status": "sqlite",
                "note": "Observed changes are posture drift, not proof of compromise.",
            },
            "Changes": [
                {
                    "Category": "SecurityControlBaseline",
                    "Section": "SecurityControlBaseline",
                    "ItemType": "SecurityControl",
                    "Name": "Windows Firewall",
                    "Field": "Enabled",
                    "OldValue": "Enabled",
                    "NewValue": "Disabled",
                    "Severity": "Critical",
                    "Classification": "critical",
                    "GuardrailMatched": True,
                    "GuardrailReason": "Firewall disabled is protected by a security guardrail.",
                    "MatchedRuleId": "guardrail-firewall-disabled",
                    "MatchedRuleDescription": "Firewall disabled should remain response-required.",
                    "RecommendedAction": "Restore Firewall after verifying the evidence.",
                    "CsfMapping": "PR.PS / DE.CM",
                    "Interpretation": "Firewall protection appears weaker than the trusted baseline.",
                },
                {
                    "Category": "AppIntegrity",
                    "Section": "AppIntegrity",
                    "ItemType": "AppFile",
                    "Name": "profiles\\posture-drift-rules.json",
                    "Path": "C:\\CodexTest\\profiles\\posture-drift-rules.json",
                    "Field": "Sha256",
                    "OldValue": "OLDHASH",
                    "NewValue": "NEWHASH",
                    "Severity": "Review",
                    "Classification": "review",
                    "MatchedRuleId": "app-profile-reviewed",
                    "MatchedRuleDescription": "App-owned profile drift should be reviewed before acceptance.",
                    "RecommendedAction": "Review the profile update and record an exact acceptance if it was intentional.",
                    "CsfMapping": "GV.OV / DE.CM",
                    "Interpretation": "An app-owned posture rules file changed from the trusted baseline.",
                },
                {
                    "Category": "ScheduledTask",
                    "Section": "ScheduledTasks",
                    "ItemType": "ScheduledTask",
                    "Name": "ZoomUpdateTaskUser-12345",
                    "ChangeType": "Modified",
                    "Severity": "Info",
                    "Classification": "expected",
                    "CsfMapping": "DE.CM",
                    "Interpretation": "This matched a known updater churn pattern.",
                },
                {
                    "Category": "AppIntegrity",
                    "Section": "AppIntegrity",
                    "ItemType": "AppFile",
                    "Name": "codex-monitor.settings.json",
                    "Field": "Sha256",
                    "OldValue": "OLDER",
                    "NewValue": "NEWER",
                    "Severity": "Info",
                    "Classification": "accepted",
                    "IsAcceptedDrift": True,
                    "AcceptanceId": "ACC-TEST-001",
                    "AcceptedDriftReason": "Reviewed local settings update.",
                    "CsfMapping": "GV.OV / DE.CM",
                },
            ],
        }
        report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return report_path

    def make_snapshot(self, root: Path, report_path: Path | None = None) -> dict:
        summary = {
            "observed_posture_change_count": 4,
            "expected_operational_change_count": 1,
            "accepted_posture_change_count": 1,
            "posture_review_count": 1,
            "response_required_count": 1,
            "guardrail_protected_count": 1,
            "accepted_drift_registry_status": "sqlite",
            "note": "Observed changes are posture drift, not proof of compromise.",
        }
        latest_tripwire = {
            "Path": str(report_path) if report_path else "",
            "LastWriteTimeUtc": "2026-07-19T12:00:00Z" if report_path else "",
        }
        recent_reports = []
        if report_path:
            recent_reports.append(
                {
                    "name": report_path.name,
                    "path": str(report_path),
                    "report_type": "Check",
                    "collection_time": "2026-07-19T12:00:00Z",
                    "summary": {"ChangeCount": 4},
                }
            )
        return {
            "status": {
                "Metadata": {"OverallStatus": "Review", "ComputerName": "TEST-PC"},
                "Identify": {
                    "Hostname": "TEST-PC",
                    "Manufacturer": "Contoso",
                    "Model": "Test Model",
                    "WindowsEdition": "Windows 11 Pro",
                    "WindowsVersion": "11",
                    "WindowsBuild": "26100",
                    "CurrentUser": "tester",
                    "BaselineScope": "Local PC",
                    "LocalUserCount": 9,
                    "LocalAdministratorCount": 3,
                    "InstalledSoftwareCount": 42,
                    "RunningServiceCount": 100,
                    "ScheduledTaskCount": 261,
                    "AutorunCount": 15,
                    "NetworkAdapterCount": 4,
                    "ListeningTcpPortCount": 12,
                    "SharedFolderCount": 1,
                },
                "Protection": {
                    "Score": 88,
                    "SelectedProfile": {"Id": "microsoft_baseline", "Name": "Microsoft baseline", "Description": "Test profile."},
                    "AvailableProfiles": [{"Id": "microsoft_baseline", "Name": "Microsoft baseline"}],
                    "Controls": [],
                },
                "HealthFindings": [],
                "State": {
                    "PendingAlertCount": 0,
                    "ThreatRssLastRunUtc": "2026-07-19T11:30:00Z",
                    "TripwireBaselineCollectionTimeUtc": "2026-07-18T00:00:00Z",
                    "LatestTripwireDriftSummary": summary,
                },
                "LatestArtifacts": {
                    "LatestIocReport": {"Path": "", "LastWriteTimeUtc": "2026-07-19T11:00:00Z"},
                    "LatestTripwireReport": latest_tripwire,
                    "LatestThreatRssReport": {"Path": "", "LastWriteTimeUtc": "2026-07-19T11:10:00Z"},
                },
                "Coverage": {
                    "LatestIocHashCoverage": {},
                    "LatestTripwirePostureSummary": summary,
                    "BaselineHashIndexStatus": "unavailable",
                },
                "ScheduledTasks": [],
            },
            "task_details": [
                {
                    "Name": "Codex Alert Notifier",
                    "Installed": True,
                    "State": "Ready",
                    "Enabled": True,
                    "Author": "Codex",
                    "Description": "Notifier",
                    "Principal": "tester",
                    "RunLevel": "Limited",
                    "LastRunTime": "2026-07-19T11:59:00Z",
                    "NextRunTime": "2026-07-19T12:00:00Z",
                    "LastTaskResult": "0",
                    "Actions": [],
                    "Triggers": [],
                }
            ],
            "indicators": {"indicator_count": 0, "ingest_runs": [], "by_type": [], "by_source": [], "app_state": []},
            "pending_alerts": [],
            "archive_alerts": [],
            "recent_reports": recent_reports,
        }

    def test_load_settings_uses_configured_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            settings_path = root / "codex-monitor.settings.json"
            payload = {
                "RuntimeRoot": str(root / "runtime"),
                "DataRoot": str(root / "data"),
                "StateDbPath": str(root / "data" / "state" / "ioc-store.db"),
                "AlertInboxPath": str(root / "data" / "alerts" / "pending"),
                "AlertArchivePath": str(root / "data" / "alerts" / "archive"),
                "IndicatorExportPath": str(root / "data" / "indicators" / "feed-indicators-latest.json"),
            }
            settings_path.write_text(json.dumps(payload), encoding="utf-8")

            config = ui.load_settings(settings_path)

            self.assertEqual(config.runtime_root, Path(payload["RuntimeRoot"]).resolve())
            self.assertEqual(config.data_root, Path(payload["DataRoot"]).resolve())
            self.assertEqual(config.state_db_path, Path(payload["StateDbPath"]).resolve())
            self.assertEqual(config.alert_inbox_path, Path(payload["AlertInboxPath"]).resolve())
            self.assertEqual(config.alert_archive_path, Path(payload["AlertArchivePath"]).resolve())

    def test_load_settings_resolves_relative_paths_from_settings_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            settings_dir = root / "runtime"
            settings_dir.mkdir()
            settings_path = settings_dir / "codex-monitor.settings.json"
            payload = {
                "RuntimeRoot": ".",
                "DataRoot": ".",
                "StateDbPath": "./state/ioc-store.db",
                "AlertInboxPath": "./alerts/pending",
                "AlertArchivePath": "./alerts/archive",
                "IndicatorExportPath": "./indicators/feed-indicators-latest.json",
            }
            settings_path.write_text(json.dumps(payload), encoding="utf-8")

            config = ui.load_settings(settings_path)

            self.assertEqual(config.runtime_root, settings_dir.resolve())
            self.assertEqual(config.data_root, settings_dir.resolve())
            self.assertEqual(config.state_db_path, (settings_dir / "state" / "ioc-store.db").resolve())
            self.assertEqual(config.alert_inbox_path, (settings_dir / "alerts" / "pending").resolve())
            self.assertEqual(config.alert_archive_path, (settings_dir / "alerts" / "archive").resolve())
            self.assertEqual(config.indicator_export_path, (settings_dir / "indicators" / "feed-indicators-latest.json").resolve())

    def test_safe_path_accepts_only_whitelisted_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            allowed = root / "allowed"
            allowed.mkdir()
            good_file = allowed / "sample.txt"
            good_file.write_text("ok", encoding="utf-8")
            bad_file = root / "outside.txt"
            bad_file.write_text("no", encoding="utf-8")

            self.assertEqual(ui.safe_path(str(good_file), [allowed]), good_file.resolve())
            self.assertIsNone(ui.safe_path(str(bad_file), [allowed]))

    def test_list_alert_records_parses_summary_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bucket = Path(temp_dir)
            alert_json = bucket / "ALERT_SAMPLE.json"
            alert_md = bucket / "ALERT_SAMPLE.md"
            alert_json.write_text(
                json.dumps(
                    {
                        "Metadata": {
                            "AlertType": "HostTripwire",
                            "Severity": "High",
                            "ChangeCount": 3,
                            "CollectionTimeUtc": "2026-06-17T00:00:00Z",
                            "SourceReport": "C:\\Report.json",
                        },
                        "Summary": {
                            "Title": "Sample Alert",
                            "Message": "Three changes detected.",
                            "DetailLines": ["A", "B"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            alert_md.write_text("# Sample", encoding="utf-8")

            records = ui.list_alert_records(bucket, "pending")

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["title"], "Sample Alert")
            self.assertEqual(records[0]["severity"], "High")
            self.assertEqual(records[0]["change_count"], 3)
            self.assertEqual(records[0]["markdown_path"], str(alert_md))

    def test_checked_in_wrappers_use_dynamic_app_root_resolution(self) -> None:
        wrapper_names = [
            "codex-alert-notifier.cmd",
            "codex-feed-import.cmd",
            "codex-host-tripwire-baseline-ui.cmd",
            "codex-host-tripwire-baseline.cmd",
            "codex-host-tripwire.cmd",
            "codex-ioc-scan.cmd",
            "codex-threat-rss.cmd",
        ]
        repo_root = Path(__file__).resolve().parent.parent
        for wrapper_name in wrapper_names:
            wrapper_text = (repo_root / wrapper_name).read_text(encoding="utf-8")
            self.assertIn("%~dp0", wrapper_text, wrapper_name)
            self.assertNotIn("C:\\CodexTest", wrapper_text, wrapper_name)

    def test_build_respond_queue_uses_latest_tripwire_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = self.make_tripwire_report(root)
            config = self.make_config(root, "advanced_user")
            snapshot = self.make_snapshot(root, report_path)

            queue = ui.build_respond_queue_data(config, snapshot)

            self.assertEqual(queue["queue_state"], "active")
            self.assertEqual(queue["latest_report_name"], report_path.name)
            self.assertEqual(len(queue["active_findings"]), 2)
            self.assertEqual(len(queue["recorded_findings"]), 2)
            self.assertEqual(queue["active_findings"][0]["title"], "Windows Firewall")
            self.assertEqual(queue["summary_cards"][0]["label"], "Response required")

    def test_build_respond_queue_handles_missing_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = self.make_config(root)
            snapshot = self.make_snapshot(root, None)

            queue = ui.build_respond_queue_data(config, snapshot)

            self.assertEqual(queue["queue_state"], "missing_report")
            self.assertIn("No posture check report is available yet", queue["queue_message"])

    def test_guardrail_finding_does_not_offer_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = self.make_tripwire_report(root)
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            guardrail_change = payload["Changes"][0]
            finding = ui.build_respond_finding(guardrail_change, 1, report_path)
            card = ui.render_respond_finding_card(finding, ui.coerce_persona_profile("tech"))
            self.assertIn("Acceptance blocked", card)
            self.assertNotIn(".\\accept-posture-drift.ps1", card)

    def test_safe_app_finding_shows_acceptance_guidance_for_advanced_user(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = self.make_tripwire_report(root)
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            safe_change = payload["Changes"][1]
            finding = ui.build_respond_finding(safe_change, 2, report_path)
            card = ui.render_respond_finding_card(finding, ui.coerce_persona_profile("advanced_user"))
            self.assertIn("Accept exact reviewed change", card)
            self.assertIn(".\\accept-posture-drift.ps1", card)

    def test_safe_app_finding_shows_home_user_guidance_without_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = self.make_tripwire_report(root)
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            safe_change = payload["Changes"][1]
            finding = ui.build_respond_finding(safe_change, 2, report_path)
            card = ui.render_respond_finding_card(finding, ui.coerce_persona_profile("user"))
            self.assertIn("Switch to Advanced User or Technician mode", card)
            self.assertNotIn(".\\accept-posture-drift.ps1", card)

    def test_respond_page_renders_with_csf_aligned_terms(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = self.make_tripwire_report(root)
            config = self.make_config(root, "csf_native")
            snapshot = self.make_snapshot(root, report_path)

            page = ui.render_respond_page(config, snapshot)

            self.assertIn("Respond to findings", page)
            self.assertIn("Observed posture changes", page)
            self.assertIn("Response required", page)
            self.assertIn("Detect records observed configuration drift. Respond handles findings. Recover confirms trusted operation after response.", page)

    def test_render_routes_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = self.make_tripwire_report(root)
            config = self.make_config(root, "advanced_user")
            snapshot = self.make_snapshot(root, report_path)

            self.assertIn("Today", ui.render_dashboard(config, snapshot))
            self.assertIn("What the app is watching", ui.render_detect_page(config, snapshot))
            self.assertIn("Respond to findings", ui.render_respond_page(config, snapshot))
            self.assertIn("Recover", ui.render_recover_page(config, snapshot))
            self.assertIn("Records of care", ui.render_reports_page(config, snapshot))


class PersonaConsistencyTests(unittest.TestCase):
    def test_persona_catalog_order_and_labels(self) -> None:
        personas = [ui.coerce_persona_profile(pid) for pid in ["user", "advanced_user", "csf_native", "analyst", "tech"]]
        self.assertEqual([p["persona_id"] for p in personas], ["user", "advanced_user", "csf_native", "analyst", "tech"])
        self.assertEqual([p["display_name"] for p in personas], ["Home User", "Advanced User", "NIST CSF Native", "Analyst", "Technician"])

    def test_primary_nav_hides_diagnostics_for_home_user(self) -> None:
        home = ui.coerce_persona_profile("user")
        nav = ui.render_primary_nav("/", persona_profile=home, show_technical=True)
        self.assertNotIn("Diagnostics", nav)
        self.assertNotIn("Reports", nav)

    def test_primary_nav_shows_diagnostics_for_technician(self) -> None:
        tech = ui.coerce_persona_profile("tech")
        nav = ui.render_primary_nav("/", persona_profile=tech, show_technical=True)
        self.assertIn("Diagnostics", nav)

    def test_persona_selector_and_csf_language(self) -> None:
        persona_ids = ["user", "advanced_user", "csf_native", "analyst", "tech"]
        personas = [ui.coerce_persona_profile(pid) for pid in persona_ids]
        model = {
            "app": {
                "message": "",
                "ui_persona": "csf_native",
                "persona_profile": ui.coerce_persona_profile("csf_native"),
                "available_personas": personas,
            },
            "alerts": {"pending": [], "archived": []},
            "protection_controls": {"score": 90},
            "task_job_health": {"attention_tasks": 0},
            "recommended_responses": [{"title": "Review what changed", "summary": "Open the latest summary for this PC."}],
        }
        page = ui.render_page_shell(model, "/", "Dashboard", "lede", "<div>body</div>")
        labels = __import__("re").findall(r'<option value="[^"]*"[^>]*>([^<]+)</option>', page)
        self.assertEqual(labels[:5], ["Home User", "Advanced User", "NIST CSF Native", "Analyst", "Technician"])
        self.assertIn("GV / Govern", ui.friendly_function_label("govern", "csf_native"))
        self.assertIn("DE / Detect", ui.friendly_function_label("detect", "csf_native"))


if __name__ == "__main__":
    unittest.main()

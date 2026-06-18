import json
import tempfile
import unittest
from pathlib import Path

import codex_monitor_ui as ui


class CodexMonitorUiTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

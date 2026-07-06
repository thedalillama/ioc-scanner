import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import ioc_store


class IocStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.db_path = self.root / "ioc-store.db"
        self.conn = ioc_store.connect_db(self.db_path)
        self.addCleanup(self.conn.close)
        ioc_store.init_db(self.conn)

    def test_init_creates_indicator_and_app_state_tables(self) -> None:
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('indicators', 'ingest_runs', 'app_state')"
        ).fetchall()
        self.assertEqual({"indicators", "ingest_runs", "app_state"}, {row["name"] for row in rows})

    def test_normalize_indicators_accepts_bundle_object(self) -> None:
        fixture_path = Path(__file__).parent / "fixtures" / "normalized-indicators.min.json"
        document = ioc_store.load_json(fixture_path)
        indicators, source_name = ioc_store.normalize_indicators(document)
        self.assertEqual(2, len(indicators))
        self.assertEqual("normalized-indicator-set", source_name)

    def test_import_and_export_round_trip(self) -> None:
        fixture_path = Path(__file__).parent / "fixtures" / "normalized-indicators.min.json"
        document = ioc_store.load_json(fixture_path)
        indicators, source_name = ioc_store.normalize_indicators(document)
        run_id = ioc_store.begin_ingest_run(self.conn, source_name, fixture_path)
        imported = ioc_store.upsert_indicators(self.conn, run_id, indicators)
        ioc_store.finish_ingest_run(self.conn, run_id, "success", imported)

        self.assertEqual(2, imported)

        exported = ioc_store.export_indicators(self.conn)
        self.assertEqual(2, exported["Metadata"]["IndicatorCount"])
        self.assertEqual({"sha256", "url"}, {item["type"] for item in exported["Indicators"]})

    def test_upsert_deduplicates_by_type_value_source(self) -> None:
        indicator = {
            "indicator_id": "one",
            "type": "sha256",
            "value": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "source": "UnitTest",
            "confidence": 50,
            "severity": "medium",
            "raw_source_record": {"version": 1},
        }
        run_id = ioc_store.begin_ingest_run(self.conn, "unit", self.root / "input.json")
        ioc_store.upsert_indicators(self.conn, run_id, [indicator])

        indicator["confidence"] = 95
        indicator["severity"] = "high"
        indicator["raw_source_record"] = {"version": 2}
        ioc_store.upsert_indicators(self.conn, run_id, [indicator])

        row = self.conn.execute(
            "SELECT COUNT(*) AS count, confidence, severity, raw_source_record_json FROM indicators WHERE type = ? AND value = ? AND source = ?",
            ("sha256", indicator["value"], indicator["source"]),
        ).fetchone()
        self.assertEqual(1, row["count"])
        self.assertEqual(95, row["confidence"])
        self.assertEqual("high", row["severity"])
        self.assertEqual({"version": 2}, json.loads(row["raw_source_record_json"]))

    def test_app_state_put_and_get_round_trip(self) -> None:
        payload = {
            "SeenAlerts": ["a", "b"],
            "LastRunUtc": "2026-06-10T00:00:00Z",
        }
        ioc_store.put_app_state(self.conn, "alert_helper", "seen_alerts", payload)
        loaded = ioc_store.get_app_state(self.conn, "alert_helper", "seen_alerts")

        self.assertTrue(loaded["found"])
        self.assertEqual(payload, loaded["value"])

    def test_stats_reports_app_state_count(self) -> None:
        ioc_store.put_app_state(self.conn, "alert_helper", "seen_alerts", {"SeenAlerts": []})
        values = ioc_store.stats(self.conn)
        self.assertIn("app_state_count", values)
        self.assertEqual(1, values["app_state_count"])

    def assert_snapshot_match_shape(self, match: dict, *, expected_source: str, expected_field: str, expected_observation_type: str) -> None:
        self.assertEqual(expected_source, match["match_source"])
        self.assertEqual("sqlite_evidence_join", match["match_method"])
        self.assertEqual("snapshot-one", match["snapshot_id"])
        self.assertEqual("current_scan", match["snapshot_type"])
        self.assertEqual("2026-06-20T12:00:00+00:00", match["snapshot_time"])
        self.assertEqual(expected_field, match["matched_field"])
        self.assertTrue(match["matched_value"])
        self.assertEqual(expected_observation_type, match["matched_observation_type"])
        self.assertTrue(match["evidence_strength"])
        self.assertTrue(match["false_positive_risk"])
        self.assertTrue(match["interpretation"])
        self.assertTrue(match["scope_note"])

    def test_import_evidence_snapshot_and_positive_snapshot_matches(self) -> None:
        snapshot_doc = {
            "Metadata": {
                "ComputerName": "UNIT-TEST-PC",
                "CollectionTimeUtc": "2026-06-20T12:00:00Z",
                "Mode": "Deep",
            },
            "NormalizedIOCRecords": [
                {
                    "Category": "Process",
                    "Name": "proc.exe",
                    "Path": r"C:\Tools\proc.exe",
                    "Hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "HashAlgorithm": "SHA256",
                    "Timestamp": "2026-06-20T12:00:00Z",
                    "Owner": "UNIT\\user",
                    "PID": 111,
                    "ParentPID": 1,
                    "CommandLine": r'"C:\Tools\proc.exe" --connect https://example.test/run',
                    "RegistryPath": "",
                    "Source": ["UnitTest"],
                },
                {
                    "Category": "Service",
                    "Name": "UnitService",
                    "Value": "Unit Service",
                    "Path": r"C:\Services\unitservice.exe",
                    "Owner": "LocalSystem",
                    "PID": 222,
                    "CommandLine": r"C:\Services\unitservice.exe",
                    "RegistryPath": r"HKLM:\SYSTEM\CurrentControlSet\Services\UnitService",
                    "Notes": "Running",
                    "Source": ["UnitTest"],
                },
                {
                    "Category": "ScheduledTask",
                    "Name": r"\Unit\Test Task",
                    "Value": "Test Task",
                    "Path": r"\Unit\Test Task",
                    "Timestamp": "2026-06-20T12:00:00Z",
                    "Owner": "UnitAuthor",
                    "CommandLine": r"C:\Scripts\test-task.ps1",
                    "Notes": "NextRun=2026-06-21T00:00:00Z; Result=0",
                    "Source": ["UnitTest"],
                },
                {
                    "Category": "DnsCache",
                    "Name": "example.test",
                    "Value": "example.test",
                    "CommandLine": "Type=A; Data=203.0.113.10; TTL=60",
                    "Source": ["UnitTest"],
                },
                {
                    "Category": "NetworkConnection",
                    "Name": "203.0.113.10",
                    "Value": "203.0.113.10",
                    "Timestamp": "2026-06-20T12:00:00Z",
                    "PID": 111,
                    "CommandLine": "10.0.0.5:51515->203.0.113.10:443 [Established]",
                    "Source": ["UnitTest"],
                },
                {
                    "Category": "NetworkConnection",
                    "Name": "2001:db8::25",
                    "Value": "2001:db8::25",
                    "Timestamp": "2026-06-20T12:00:30Z",
                    "PID": 111,
                    "CommandLine": "",
                    "Source": ["UnitTest"],
                },
                {
                    "Category": "PowerShellLog",
                    "Name": "4104",
                    "Timestamp": "2026-06-20T12:01:00Z",
                    "CommandLine": "Invoke-WebRequest https://example.test/run",
                    "Source": ["PowerShell/Operational"],
                },
            ],
        }

        snapshot_path = self.root / "snapshot.json"
        snapshot_path.write_text(json.dumps(snapshot_doc), encoding="utf-8")

        result = ioc_store.index_evidence_snapshot(
            self.conn,
            snapshot_path,
            snapshot_id="snapshot-one",
            snapshot_type="current_scan",
            source_json_path=str(snapshot_path),
            source_markdown_path="",
            collector_version="unit-test",
            trust_label="unknown",
        )
        self.assertEqual("snapshot-one", result["snapshot_id"])
        self.assertEqual(1, ioc_store.stats(self.conn)["evidence_snapshot_count"])

        indicators = [
            {
                "indicator_id": "test-sha256",
                "type": "sha256",
                "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "source": "LOCAL_TEST_DO_NOT_ALERT",
                "confidence": 1,
                "severity": "informational",
                "raw_source_record": {"kind": "test"},
            },
            {
                "indicator_id": "test-service",
                "type": "service_name",
                "value": "UnitService",
                "source": "LOCAL_TEST_DO_NOT_ALERT",
                "confidence": 1,
                "severity": "informational",
                "raw_source_record": {"kind": "test"},
            },
            {
                "indicator_id": "test-task",
                "type": "scheduled_task",
                "value": r"\Unit\Test Task",
                "source": "LOCAL_TEST_DO_NOT_ALERT",
                "confidence": 1,
                "severity": "informational",
                "raw_source_record": {"kind": "test"},
            },
            {
                "indicator_id": "test-domain",
                "type": "domain",
                "value": "example.test",
                "source": "LOCAL_TEST_DO_NOT_ALERT",
                "confidence": 1,
                "severity": "informational",
                "raw_source_record": {"kind": "test"},
            },
            {
                "indicator_id": "test-cmd",
                "type": "command_line_pattern",
                "value": r"Invoke-WebRequest\s+https://example\.test/run",
                "source": "LOCAL_TEST_DO_NOT_ALERT",
                "confidence": 1,
                "severity": "informational",
                "raw_source_record": {"kind": "test"},
            },
            {
                "indicator_id": "test-ipv4",
                "type": "ipv4",
                "value": "203.0.113.10",
                "source": "LOCAL_TEST_DO_NOT_ALERT",
                "confidence": 1,
                "severity": "informational",
                "raw_source_record": {"kind": "test"},
            },
            {
                "indicator_id": "test-ipv6",
                "type": "ipv6",
                "value": "2001:db8::25",
                "source": "LOCAL_TEST_DO_NOT_ALERT",
                "confidence": 1,
                "severity": "informational",
                "raw_source_record": {"kind": "test"},
            },
        ]
        run_id = ioc_store.begin_ingest_run(self.conn, "unit", self.root / "indicators.json")
        ioc_store.upsert_indicators(self.conn, run_id, indicators)
        ioc_store.finish_ingest_run(self.conn, run_id, "success", len(indicators))

        matches = ioc_store.match_indicators_against_evidence_snapshots(self.conn, "snapshot-one")
        self.assertTrue(matches["snapshot_available"])
        self.assertEqual("snapshot-one", matches["current_snapshot_id"])
        self.assertGreaterEqual(matches["match_count"], 7)

        by_type = {}
        for match in matches["current_matches"]:
            by_type.setdefault(match["indicator_type"], []).append(match)

        self.assert_snapshot_match_shape(
            by_type["sha256"][0],
            expected_source="file_observations",
            expected_field="sha256",
            expected_observation_type="FileObservation",
        )
        self.assert_snapshot_match_shape(
            by_type["service_name"][0],
            expected_source="service_observations",
            expected_field="service_name",
            expected_observation_type="ServiceObservation",
        )
        self.assert_snapshot_match_shape(
            by_type["scheduled_task"][0],
            expected_source="scheduled_task_observations",
            expected_field="task_path",
            expected_observation_type="ScheduledTaskObservation",
        )
        self.assert_snapshot_match_shape(
            by_type["domain"][0],
            expected_source="dns_cache_observations",
            expected_field="name",
            expected_observation_type="DnsCacheEntry",
        )
        self.assertIn(by_type["command_line_pattern"][0]["match_source"], {"powershell_event_observations", "process_observations"})
        self.assert_snapshot_match_shape(
            by_type["ipv4"][0],
            expected_source="network_connection_observations",
            expected_field="remote_address",
            expected_observation_type="NetworkConnection",
        )
        self.assertEqual("203.0.113.10", by_type["ipv4"][0]["matched_value"])
        self.assert_snapshot_match_shape(
            by_type["ipv6"][0],
            expected_source="network_connection_observations",
            expected_field="remote_address",
            expected_observation_type="NetworkConnection",
        )
        self.assertEqual("2001:db8::25", by_type["ipv6"][0]["matched_value"])


if __name__ == "__main__":
    unittest.main()

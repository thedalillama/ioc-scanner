import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
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

    def test_init_creates_additive_phase_two_schema(self) -> None:
        expected_tables = {
            "schema_migrations",
            "collector_runs",
            "reports",
            "findings",
            "alerts",
            "alert_deliveries",
        }
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ({0})".format(
                ", ".join("?" for _ in expected_tables)
            ),
            tuple(sorted(expected_tables)),
        ).fetchall()
        self.assertEqual(expected_tables, {row["name"] for row in rows})

        migrations = self.conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        self.assertEqual([1, 2], [row["version"] for row in migrations])

        indexes = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name IN "
            "('idx_reports_type_collected', 'idx_findings_report_severity', "
            "'idx_alerts_lifecycle_severity', 'idx_alert_deliveries_pending')"
        ).fetchall()
        self.assertEqual(
            {
                "idx_reports_type_collected",
                "idx_findings_report_severity",
                "idx_alerts_lifecycle_severity",
                "idx_alert_deliveries_pending",
            },
            {row["name"] for row in indexes},
        )

    def test_persist_collector_run_report_findings_is_atomic_and_normalized(self) -> None:
        saved = ioc_store.persist_collector_run_report_findings(
            self.conn,
            {
                "collector_run_id": "run-one",
                "collector_name": "tripwire",
                "collector_version": "test-version",
                "started_at": "2026-09-09T03:00:00Z",
                "completed_at": "2026-09-09T03:01:00Z",
                "outcome": "success",
                "summary": {"change_count": 1},
            },
            {
                "report_id": "report-one",
                "collector_run_id": "run-one",
                "report_type": "tripwire_check",
                "collection_time_utc": "2026-09-09T03:01:00Z",
                "overall_status": "attention",
                "severity": "high",
                "summary": {"ChangeCount": 1},
                "export_json_path": "C:/exports/report-one.json",
            },
            [
                {
                    "finding_id": "finding-one",
                    "finding_sequence": 0,
                    "category": "ScheduledTask",
                    "severity": "high",
                    "classification": "persistence",
                    "title": "Unexpected task",
                    "summary": "Review the task.",
                    "evidence": {"task": "\\Unit\\Task"},
                    "csf_mapping": "DE.CM",
                    "guardrail_state": "protected",
                }
            ],
        )

        self.assertEqual({"collector_run_id": "run-one", "report_id": "report-one", "finding_count": 1}, saved)
        row = self.conn.execute(
            """
            SELECT cr.collector_name, r.report_type, r.summary_json, f.finding_id,
                   f.evidence_json, f.response_state
            FROM collector_runs cr
            JOIN reports r ON r.collector_run_id = cr.collector_run_id
            JOIN findings f ON f.report_id = r.report_id
            """
        ).fetchone()
        self.assertEqual("tripwire", row["collector_name"])
        self.assertEqual("tripwire_check", row["report_type"])
        self.assertEqual({"ChangeCount": 1}, json.loads(row["summary_json"]))
        self.assertEqual("finding-one", row["finding_id"])
        self.assertEqual({"task": "\\Unit\\Task"}, json.loads(row["evidence_json"]))
        self.assertEqual("open", row["response_state"])

    def test_alert_delivery_claim_is_atomic_and_failed_delivery_is_retryable(self) -> None:
        saved = ioc_store.persist_collector_run_report_findings(
            self.conn,
            {"collector_run_id": "alert-run", "collector_name": "tripwire", "started_at": "2026-09-11T01:00:00Z", "outcome": "success"},
            {"report_id": "alert-report", "collector_run_id": "alert-run", "report_type": "tripwire_check", "collection_time_utc": "2026-09-11T01:00:00Z", "summary": {}},
            [{"finding_id": "alert-finding", "finding_sequence": 0, "severity": "high", "evidence": {}}],
            [{"alert_id": "alert-one", "finding_id": "alert-finding", "severity": "high", "summary": "Unexpected task", "delivery_channel": "interactive_popup", "recipient": "interactive-user"}],
        )
        self.assertEqual(1, saved["alert_count"])
        claimed = ioc_store.claim_alert_deliveries(self.conn, "interactive_popup", "interactive-user")
        self.assertEqual(1, len(claimed))
        self.assertEqual("alert-report", claimed[0]["report_id"])
        self.assertEqual("alert-finding", claimed[0]["finding_id"])
        self.assertEqual("high", claimed[0]["severity"])
        self.assertEqual([], ioc_store.claim_alert_deliveries(self.conn, "interactive_popup", "interactive-user"))

        ioc_store.complete_alert_delivery(self.conn, claimed[0]["alert_delivery_id"], "failed", "popup unavailable")
        retried = ioc_store.claim_alert_deliveries(self.conn, "interactive_popup", "interactive-user")
        self.assertEqual(1, len(retried))
        self.assertEqual(2, retried[0]["attempt_count"])
        ioc_store.complete_alert_delivery(self.conn, retried[0]["alert_delivery_id"], "delivered")
        self.assertEqual([], ioc_store.claim_alert_deliveries(self.conn, "interactive_popup", "interactive-user"))
        lifecycle = self.conn.execute("SELECT lifecycle_state, acknowledged_at FROM alerts WHERE alert_id='alert-one'").fetchone()
        self.assertEqual("acknowledged", lifecycle["lifecycle_state"])
        self.assertTrue(lifecycle["acknowledged_at"])

    def test_alert_with_unknown_finding_rolls_back_report_transaction(self) -> None:
        with self.assertRaisesRegex(ValueError, "alert.finding_id"):
            ioc_store.persist_collector_run_report_findings(
                self.conn,
                {"collector_run_id": "bad-alert-run", "collector_name": "tripwire", "started_at": "2026-09-11T01:00:00Z", "outcome": "success"},
                {"report_id": "bad-alert-report", "collector_run_id": "bad-alert-run", "report_type": "tripwire_check", "collection_time_utc": "2026-09-11T01:00:00Z", "summary": {}},
                [],
                [{"alert_id": "bad-alert", "finding_id": "missing", "severity": "high", "summary": "bad"}],
            )
        self.assertIsNone(self.conn.execute("SELECT 1 FROM reports WHERE report_id='bad-alert-report'").fetchone())

    def test_interrupted_alert_claim_is_recovered_only_after_lease(self) -> None:
        ioc_store.persist_collector_run_report_findings(
            self.conn,
            {"collector_run_id": "lease-run", "collector_name": "tripwire", "started_at": "2026-09-11T01:00:00Z", "outcome": "success"},
            {"report_id": "lease-report", "collector_run_id": "lease-run", "report_type": "tripwire_check", "collection_time_utc": "2026-09-11T01:00:00Z", "summary": {}},
            [{"finding_id": "lease-finding", "finding_sequence": 0, "severity": "medium", "evidence": {}}],
            [{"alert_id": "lease-alert", "finding_id": "lease-finding", "severity": "medium", "summary": "Interrupted popup"}],
        )
        claimed = ioc_store.claim_alert_deliveries(self.conn, "interactive_popup", "interactive-user", claim_lease_seconds=300)
        self.assertEqual(1, len(claimed))
        self.assertEqual([], ioc_store.claim_alert_deliveries(self.conn, "interactive_popup", "interactive-user", claim_lease_seconds=300))
        self.conn.execute("UPDATE alert_deliveries SET claimed_at='2000-01-01T00:00:00+00:00' WHERE alert_delivery_id=?", (claimed[0]["alert_delivery_id"],))
        self.conn.commit()
        self.assertEqual(1, len(ioc_store.claim_alert_deliveries(self.conn, "interactive_popup", "interactive-user", claim_lease_seconds=300)))

    def test_persist_collector_run_report_findings_rolls_back_on_invalid_finding(self) -> None:
        collector_run = {
            "collector_run_id": "rollback-run",
            "collector_name": "ioc",
            "started_at": "2026-09-09T03:00:00Z",
            "outcome": "success",
        }
        report = {
            "report_id": "rollback-report",
            "collector_run_id": "rollback-run",
            "report_type": "ioc",
            "collection_time_utc": "2026-09-09T03:01:00Z",
        }
        duplicate_sequences = [
            {"finding_id": "rollback-one", "finding_sequence": 0},
            {"finding_id": "rollback-two", "finding_sequence": 0},
        ]

        with self.assertRaises(sqlite3.IntegrityError):
            ioc_store.persist_collector_run_report_findings(self.conn, collector_run, report, duplicate_sequences)

        self.assertEqual(0, self.conn.execute("SELECT COUNT(*) FROM collector_runs").fetchone()[0])
        self.assertEqual(0, self.conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0])
        self.assertEqual(0, self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])

    def test_persisted_report_queries_provide_ui_ready_list_and_detail(self) -> None:
        for suffix, collected_at in (("old", "2026-09-09T02:00:00Z"), ("new", "2026-09-09T03:00:00Z")):
            ioc_store.persist_collector_run_report_findings(
                self.conn,
                {
                    "collector_run_id": f"run-{suffix}",
                    "collector_name": "ioc",
                    "started_at": collected_at,
                    "outcome": "success",
                    "summary": {"run": suffix},
                },
                {
                    "report_id": f"report-{suffix}",
                    "collector_run_id": f"run-{suffix}",
                    "report_type": "ioc",
                    "collection_time_utc": collected_at,
                    "summary": {"MatchCount": 1 if suffix == "new" else 0},
                },
                [
                    {
                        "finding_id": f"finding-{suffix}-second",
                        "finding_sequence": 1,
                        "title": "Second finding",
                        "evidence": {"position": 2},
                    },
                    {
                        "finding_id": f"finding-{suffix}-first",
                        "finding_sequence": 0,
                        "title": "First finding",
                        "evidence": {"position": 1},
                    },
                ],
            )

        reports = ioc_store.list_persisted_reports(self.conn)
        self.assertEqual(["report-new", "report-old"], [item["report_id"] for item in reports])
        self.assertEqual({"MatchCount": 1}, reports[0]["summary"])

        detail = ioc_store.get_persisted_report(self.conn, "report-new")
        self.assertTrue(detail["found"])
        self.assertEqual("ioc", detail["report"]["collector"]["name"])
        self.assertEqual(
            ["finding-new-first", "finding-new-second"],
            [item["finding_id"] for item in detail["findings"]],
        )
        self.assertEqual({"position": 1}, detail["findings"][0]["evidence"])
        self.assertEqual({"run": "new"}, detail["report"]["collector"]["summary"])
        self.assertEqual({"found": False, "report": None, "findings": []}, ioc_store.get_persisted_report(self.conn, "missing"))

    def test_persist_collector_report_command_accepts_json_envelope(self) -> None:
        envelope_path = self.root / "collector-report.json"
        envelope_path.write_text(
            json.dumps(
                {
                    "collector_run": {
                        "collector_run_id": "cli-run",
                        "collector_name": "ioc",
                        "started_at": "2026-09-09T03:00:00Z",
                        "outcome": "success",
                    },
                    "report": {
                        "report_id": "cli-report",
                        "collector_run_id": "cli-run",
                        "report_type": "ioc",
                        "collection_time_utc": "2026-09-09T03:00:01Z",
                    },
                    "findings": [{"finding_id": "cli-finding", "title": "CLI finding"}],
                }
            ),
            encoding="utf-8",
        )
        self.conn.close()
        completed = subprocess.run(
            [sys.executable, str(Path(ioc_store.__file__).resolve()), "--db", str(self.db_path), "persist-collector-report", "--input", str(envelope_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            {"collector_run_id": "cli-run", "report_id": "cli-report", "finding_count": 1},
            json.loads(completed.stdout),
        )
        check_connection = ioc_store.connect_db(self.db_path)
        self.addCleanup(check_connection.close)
        self.assertTrue(ioc_store.get_persisted_report(check_connection, "cli-report")["found"])

    def test_explicit_export_commands_write_only_requested_sqlite_records(self) -> None:
        ioc_store.persist_collector_run_report_findings(
            self.conn,
            {
                "collector_run_id": "export-run",
                "collector_name": "tripwire",
                "started_at": "2026-09-11T12:00:00Z",
                "outcome": "success",
            },
            {
                "report_id": "export-report-id",
                "collector_run_id": "export-run",
                "report_type": "tripwire_check",
                "collection_time_utc": "2026-09-11T12:00:01Z",
                "summary": {"ChangeCount": 1},
            },
            [{"finding_id": "export-finding-id", "finding_sequence": 0, "severity": "high", "evidence": {"task": "Unit Test"}}],
            [{"alert_id": "export-alert-id", "finding_id": "export-finding-id", "severity": "high", "summary": "Unit-test alert"}],
        )
        indicator_run = ioc_store.begin_ingest_run(self.conn, "unit", self.root / "indicators.json")
        ioc_store.upsert_indicators(
            self.conn,
            indicator_run,
            [{"indicator_id": "export-indicator-id", "type": "url", "value": "https://unit.test", "source": "UnitTest"}],
        )

        self.conn.close()
        commands = [
            ("export-report", "--report-id", "export-report-id", "report-export.json"),
            ("export-alert", "--alert-id", "export-alert-id", "alert-export.json"),
            ("export-indicators", None, None, "indicator-export.json"),
        ]
        for command, id_argument, identifier, filename in commands:
            output_path = self.root / filename
            invocation = [sys.executable, str(Path(ioc_store.__file__).resolve()), "--db", str(self.db_path), command]
            if id_argument:
                invocation.extend([id_argument, identifier])
            invocation.extend(["--output", str(output_path)])
            subprocess.run(invocation, check=True, capture_output=True, text=True)

        report_export = json.loads((self.root / "report-export.json").read_text(encoding="utf-8"))
        alert_export = json.loads((self.root / "alert-export.json").read_text(encoding="utf-8"))
        indicator_export = json.loads((self.root / "indicator-export.json").read_text(encoding="utf-8"))
        self.assertEqual("export-report-id", report_export["report"]["report_id"])
        self.assertEqual(["export-finding-id"], [finding["finding_id"] for finding in report_export["findings"]])
        self.assertEqual("export-alert-id", alert_export["alert"]["alert_id"])
        self.assertEqual("export-report-id", alert_export["alert"]["report_id"])
        self.assertEqual(["export-indicator-id"], [indicator["indicator_id"] for indicator in indicator_export["Indicators"]])

    def test_collector_report_parity_fixtures_cover_all_phase_two_report_types(self) -> None:
        fixtures = [
            ("ioc", "ioc", [{"finding_id": "ioc-finding", "title": "IOC"}]),
            ("tripwire_check", "tripwire", [{"finding_id": "tripwire-finding", "title": "Tripwire", "guardrail_state": "protected"}]),
            ("tripwire_baseline", "tripwire", []),
            ("threat_rss", "threat_rss", [{"finding_id": "rss-finding", "title": "RSS"}]),
            ("threat_feed_import", "threat_feed_import", []),
        ]
        for index, (report_type, collector_name, findings) in enumerate(fixtures):
            report_id = f"parity-{report_type}"
            ioc_store.persist_collector_run_report_findings(self.conn, {"collector_run_id": f"{report_id}-run", "collector_name": collector_name, "started_at": f"2026-09-09T0{index}:00:00Z", "outcome": "success"}, {"report_id": report_id, "collector_run_id": f"{report_id}-run", "report_type": report_type, "collection_time_utc": f"2026-09-09T0{index}:00:01Z", "summary": {"fixture": report_type}}, findings)
        reports = ioc_store.list_persisted_reports(self.conn)
        self.assertEqual({item[0] for item in fixtures}, {item["report_type"] for item in reports})
        self.assertEqual("protected", ioc_store.get_persisted_report(self.conn, "parity-tripwire_check")["findings"][0]["guardrail_state"])

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

    def test_query_active_indicators_filters_expired_and_types(self) -> None:
        indicators = [
            {"indicator_id": "active-sha", "type": "sha256", "value": "a" * 64, "source": "UnitTest", "confidence": 90, "severity": "high", "valid_until": "2099-01-01T00:00:00Z", "raw_source_record": {"state": "active"}},
            {"indicator_id": "expired-url", "type": "url", "value": "https://expired.test", "source": "UnitTest", "confidence": 50, "severity": "medium", "valid_until": "2000-01-01T00:00:00Z", "raw_source_record": {"state": "expired"}},
            {"indicator_id": "invalid-expiry", "type": "url", "value": "https://invalid-expiry.test", "source": "UnitTest", "confidence": 50, "severity": "medium", "valid_until": "not-a-date", "raw_source_record": {"state": "invalid"}},
            {"indicator_id": "active-url", "type": "url", "value": "https://active.test", "source": "UnitTest", "confidence": 50, "severity": "medium", "raw_source_record": {"state": "active"}},
        ]
        run_id = ioc_store.begin_ingest_run(self.conn, "unit", self.root / "indicators.json")
        ioc_store.upsert_indicators(self.conn, run_id, indicators)

        active = ioc_store.query_active_indicators(self.conn, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(["active-sha", "active-url"], [item["indicator_id"] for item in active["Indicators"]])
        self.assertEqual("sqlite-active-indicator-set", active["Metadata"]["Format"])
        self.assertEqual({"state": "active"}, active["Indicators"][0]["raw_source_record"])

        urls = ioc_store.query_active_indicators(self.conn, indicator_types=["URL"], now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(["active-url"], [item["indicator_id"] for item in urls["Indicators"]])

        all_urls = ioc_store.query_active_indicators(self.conn, indicator_types=["url"], include_expired=True, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(["active-url", "expired-url", "invalid-expiry"], [item["indicator_id"] for item in all_urls["Indicators"]])

    def test_query_active_indicators_command_returns_filtered_json(self) -> None:
        run_id = ioc_store.begin_ingest_run(self.conn, "unit", self.root / "indicators.json")
        ioc_store.upsert_indicators(self.conn, run_id, [
            {"indicator_id": "cli-url", "type": "url", "value": "https://cli.test", "source": "UnitTest", "confidence": 50, "severity": "medium"},
            {"indicator_id": "cli-hash", "type": "sha256", "value": "b" * 64, "source": "UnitTest", "confidence": 50, "severity": "medium"},
        ])
        self.conn.close()
        completed = subprocess.run(
            [sys.executable, str(Path(ioc_store.__file__).resolve()), "--db", str(self.db_path), "query-active-indicators", "--type", "url"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)
        self.assertEqual("sqlite-active-indicator-set", payload["Metadata"]["Format"])
        self.assertEqual(["cli-url"], [item["indicator_id"] for item in payload["Indicators"]])

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
            {
                "indicator_id": "expired-sha256",
                "type": "sha256",
                "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "source": "EXPIRED_TEST_DO_NOT_MATCH",
                "confidence": 1,
                "severity": "informational",
                "valid_until": "2000-01-01T00:00:00Z",
                "raw_source_record": {"kind": "expired-test"},
            },
        ]
        run_id = ioc_store.begin_ingest_run(self.conn, "unit", self.root / "indicators.json")
        ioc_store.upsert_indicators(self.conn, run_id, indicators)
        ioc_store.finish_ingest_run(self.conn, run_id, "success", len(indicators))

        matches = ioc_store.match_indicators_against_evidence_snapshots(self.conn, "snapshot-one")
        self.assertTrue(matches["snapshot_available"])
        self.assertEqual("snapshot-one", matches["current_snapshot_id"])
        self.assertGreaterEqual(matches["match_count"], 7)
        self.assertNotIn(
            "EXPIRED_TEST_DO_NOT_MATCH",
            {match["indicator_source"] for match in matches["current_matches"]},
        )

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

    def test_baseline_hash_join_excludes_expired_indicators(self) -> None:
        sha256 = "c" * 64
        baseline_path = self.root / "baseline.json"
        baseline_path.write_text(
            json.dumps(
                {
                    "Metadata": {
                        "BaselineId": "baseline-one",
                        "CollectionTimeUtc": "2026-01-01T00:00:00Z",
                    },
                    "WatchedFiles": [
                        {
                            "Path": r"C:\\Unit\\file.exe",
                            "SHA256": sha256,
                            "Exists": True,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        ioc_store.index_tripwire_baseline(self.conn, baseline_path)
        run_id = ioc_store.begin_ingest_run(self.conn, "unit", self.root / "indicators.json")
        ioc_store.upsert_indicators(
            self.conn,
            run_id,
            [
                {"indicator_id": "active-hash", "type": "sha256", "value": sha256, "source": "ACTIVE_TEST", "confidence": 50, "severity": "medium"},
                {"indicator_id": "expired-hash", "type": "sha256", "value": sha256, "source": "EXPIRED_TEST", "confidence": 50, "severity": "medium", "valid_until": "2000-01-01T00:00:00Z"},
            ],
        )

        matches = ioc_store.match_sha256_indicators_against_baseline_hashes(self.conn)
        self.assertEqual("available", matches["baseline_hash_index_status"])
        self.assertEqual(["ACTIVE_TEST"], [item["source"] for item in matches["matches"]])


if __name__ == "__main__":
    unittest.main()

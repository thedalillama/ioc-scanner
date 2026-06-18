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


if __name__ == "__main__":
    unittest.main()

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import codex_monitor_store as ioc_store
from csf_capability_dependencies import CAPABILITY_DEPENDENCIES
from csf_control_mapping_relationships import CONTROL_MAPPING_RELATIONSHIPS


class IocStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.db_path = self.root / "ioc-store.db"
        self.conn = ioc_store.connect_db(self.db_path)
        self.addCleanup(self.conn.close)
        ioc_store.init_db(self.conn)
        self.profile_id = ioc_store.get_active_csf_profile(self.conn)["profile_id"]

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
            "local_csf_categories",
            "local_csf_outcomes",
            "csf_subcategory_guidance",
            "csf_subcategory_profile_metadata",
            "csf_outcome_audit_events",
            "csf_current_assessments",
            "csf_profile_definitions",
            "csf_active_profile",
            "csf_community_profile_catalog",
            "csf_profile_community_profile_sources",
            "csf_community_profile_frozen_sources",
            "csf_community_profile_outcome_facets",
            "csf_profile_audit_events",
            "csf_profiles",
            "csf_profile_action_guidance",
            "csf_supporting_basis",
            "csf_evidence_outcome_links",
            "csf_reviewed_actions",
            "csf_reviewed_action_updates",
            "csf_reviewed_action_basis_links",
            "csf_reviewed_action_update_basis_links",
            "csf_reference_frameworks",
            "csf_control_catalogs",
            "csf_profile_control_catalogs",
            "csf_reference_controls",
            "csf_subcategory_control_mappings",
            "csf_control_mapping_relationships",
            "csf_reviewed_action_control_links",
            "csf_information_items",
            "csf_subcategory_information_sources",
            "csf_subcategory_information_uses",
            "csf_subcategory_capability_dependencies",
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
        self.assertEqual(list(range(1, 45)), [row["version"] for row in migrations])
        self.assertEqual("Single-PC baseline", ioc_store.get_active_csf_profile(self.conn)["profile_name"])
        profile_columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(csf_profiles)").fetchall()}
        self.assertTrue({
            "profile_name", "outcome_id", "outcome_type", "outcome_description", "included_in_profile",
            "rationale", "current_priority", "current_status", "current_policies_processes_procedures",
            "current_internal_practices", "current_roles_responsibilities", "current_selected_informative_references",
            "current_artifacts_evidence", "target_priority", "target_csf_tier",
            "target_policies_processes_procedures", "target_internal_practices",
            "target_roles_responsibilities", "target_selected_informative_references",
            "community_priority", "community_risk_rationale", "community_supporting_references",
            "community_other_guidance", "community_source_locator", "notes", "considerations",
        }.issubset(profile_columns))
        catalogs = ioc_store.list_csf_control_catalogs(self.conn)
        self.assertEqual(1, len(catalogs))
        self.assertEqual("nist-sp-800-53-r5.2.0", catalogs[0]["framework_id"])
        self.assertEqual(1, catalogs[0]["is_enabled"])
        community_profiles = ioc_store.list_csf_community_profiles(self.conn)
        self.assertEqual(1, len(community_profiles))
        self.assertEqual("nist-ransomware", community_profiles[0]["community_profile_id"])

    def test_active_csf_profile_must_be_a_defined_profile(self) -> None:
        with self.assertRaisesRegex(ValueError, "not defined"):
            ioc_store.set_active_csf_profile(self.conn, "Missing profile")
        selected = ioc_store.create_csf_profile_definition(
            self.conn, "Customer-data handling", "PC use involving customer data.",
            community_profile_id="nist-ransomware",
        )
        self.assertEqual("Customer-data handling", selected["profile_name"])
        self.assertEqual(
            128,
            self.conn.execute(
                "SELECT COUNT(*) FROM csf_profiles WHERE profile_name = 'Customer-data handling'"
            ).fetchone()[0],
        )
        self.assertEqual(
            22,
            self.conn.execute(
                "SELECT COUNT(*) FROM csf_profiles WHERE profile_name = 'Customer-data handling' AND outcome_type = 'category'"
            ).fetchone()[0],
        )
        self.assertEqual(
            106,
            self.conn.execute(
                "SELECT COUNT(*) FROM csf_profiles WHERE profile_name = 'Customer-data handling' AND outcome_type = 'subcategory'"
            ).fetchone()[0],
        )
        self.assertEqual(
            "nist-ransomware",
            self.conn.execute(
                "SELECT community_profile_id FROM csf_profile_community_profile_sources WHERE profile_name = 'Customer-data handling'"
            ).fetchone()[0],
        )
        self.assertEqual(
            43,
            self.conn.execute(
                "SELECT COUNT(*) FROM csf_profiles WHERE profile_name = 'Customer-data handling' AND outcome_type = 'subcategory' AND profile_status = 'inherited'"
            ).fetchone()[0],
        )
        frozen = self.conn.execute(
            "SELECT profile_id FROM csf_community_profile_frozen_sources WHERE community_profile_id = 'nist-ransomware'"
        ).fetchone()
        self.assertIsNotNone(frozen)
        self.assertIn(
            frozen["profile_id"],
            [profile["profile_id"] for profile in ioc_store.list_csf_profile_definitions(self.conn)],
        )
        self.assertNotIn(
            "single_pc_scope_note",
            {row["name"] for row in self.conn.execute("PRAGMA table_info(csf_subcategory_guidance)").fetchall()},
        )
        self.assertEqual(106, self.conn.execute("SELECT COUNT(*) FROM csf_subcategory_guidance WHERE language_code = 'en-US'").fetchone()[0])
        self.assertEqual(106, self.conn.execute("SELECT COUNT(*) FROM csf_subcategory_guidance WHERE language_code = 'en-US' AND examples_json <> '[]'").fetchone()[0])
        self.assertEqual(106, self.conn.execute("SELECT COUNT(*) FROM csf_subcategory_profile_metadata WHERE language_code = 'en-US'").fetchone()[0])
        self.assertGreaterEqual(self.conn.execute("SELECT COUNT(*) FROM csf_information_items").fetchone()[0], 15)
        self.assertGreaterEqual(self.conn.execute("SELECT COUNT(*) FROM csf_subcategory_information_uses").fetchone()[0], 50)
        stakeholder_purchase_use = self.conn.execute(
            """SELECT dependency_kind, use_reason
            FROM csf_subcategory_information_uses
            WHERE information_id = 'stakeholder_cybersecurity_needs' AND consumer_subcategory_id = 'GV.SC-05'"""
        ).fetchone()
        self.assertEqual("required_input", stakeholder_purchase_use["dependency_kind"])
        self.assertIn("supplier and purchasing requirements", stakeholder_purchase_use["use_reason"])
        capability_count = self.conn.execute("SELECT COUNT(*) FROM csf_subcategory_capability_dependencies").fetchone()[0]
        self.assertEqual(len(CAPABILITY_DEPENDENCIES), capability_count)
        authentication_gate = self.conn.execute(
            """SELECT dependency_strength FROM csf_subcategory_capability_dependencies
            WHERE prerequisite_subcategory_id = 'PR.AA-03' AND dependent_subcategory_id = 'PR.AA-05'"""
        ).fetchone()
        self.assertEqual("hard_gate", authentication_gate["dependency_strength"])

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

    def test_imports_oran_workbook_as_frozen_community_profile(self) -> None:
        workbook = Path(__file__).resolve().parents[1] / "output" / "nist-ir-8623-oran-community-profile.intermediate.xlsx"
        result = ioc_store.import_frozen_community_profile_from_workbook(
            self.conn,
            workbook=workbook,
            sheet_name="Profile outcomes",
            community_profile_id="nist-oran-2026-draft",
            profile_name="Federal Agency Open Radio Access Network (O-RAN) Deployment",
            publisher="NIST",
            publication_status="Initial Public Draft",
            focus="Federal agency O-RAN deployment",
            source_url="https://csrc.nist.gov/pubs/ir/8623/ipd",
        )
        self.assertTrue(result["imported"])
        self.assertEqual(93, result["source_outcome_count"])
        profile = self.conn.execute(
            "SELECT profile_kind FROM csf_profile_definitions WHERE profile_id = ?", (result["profile_id"],)
        ).fetchone()
        self.assertEqual("frozen_community", profile["profile_kind"])
        outcome = self.conn.execute(
            """SELECT profile_status, community_priority, community_risk_rationale,
                      community_supporting_references, community_other_guidance, notes
            FROM csf_profiles WHERE profile_name = ? AND outcome_id = 'GV.OC-01'""",
            ("Federal Agency Open Radio Access Network (O-RAN) Deployment",),
        ).fetchone()
        self.assertEqual("included", outcome["profile_status"])
        self.assertEqual("N/A", outcome["community_priority"])
        self.assertEqual("OutOfScope", outcome["community_risk_rationale"])
        self.assertIn("O-RAN ALLIANCE Threat Analysis", outcome["community_supporting_references"])
        self.assertIn("Program Management", outcome["community_other_guidance"])
        self.assertIn("Low for O-RAN deployment", outcome["notes"])

    def test_imports_cyber_ai_workbook_with_distinct_focus_area_records(self) -> None:
        workbook = Path(__file__).resolve().parents[1] / "output" / "nist-ir-8596-cyber-ai-community-profile.intermediate.xlsx"
        result = ioc_store.import_frozen_community_profile_from_workbook(
            self.conn,
            workbook=workbook,
            sheet_name="Profile outcomes",
            community_profile_id="nist-cyber-ai",
            profile_name="NIST IR 8596 Cyber AI Profile",
            publisher="NIST",
            publication_status="Initial Preliminary Draft",
            focus="Cybersecurity of AI and AI for cybersecurity",
            source_url="https://csrc.nist.gov/pubs/ir/8596/iprd",
        )
        self.assertTrue(result["imported"])
        self.assertEqual(106, result["source_outcome_count"])
        self.assertEqual(318, result["focus_area_record_count"])
        self.assertEqual(
            318,
            self.conn.execute(
                "SELECT COUNT(*) FROM csf_community_profile_outcome_facets WHERE profile_id = ?", (result["profile_id"],)
            ).fetchone()[0],
        )
        outcome = self.conn.execute(
            """SELECT profile_status, community_priority, community_supporting_references, notes
            FROM csf_profiles WHERE profile_name = ? AND outcome_id = 'GV.OC-02'""",
            ("NIST IR 8596 Cyber AI Profile",),
        ).fetchone()
        self.assertEqual("included", outcome["profile_status"])
        self.assertEqual("Secure: 3; Defend: 2; Thwart: 2", outcome["community_priority"])
        self.assertIn("Collaboration across these areas", outcome["notes"])
        self.assertIn("PM-09", outcome["community_supporting_references"])
        defend = self.conn.execute(
            """SELECT proposed_priority, considerations, source_text
            FROM csf_community_profile_outcome_facets
            WHERE profile_id = ? AND outcome_id = 'GV.OC-02' AND facet_id = 'defend'""",
            (result["profile_id"],),
        ).fetchone()
        self.assertEqual("2", defend["proposed_priority"])
        self.assertTrue(defend["source_text"].startswith("Proposed Priority: 2"))

    def test_imports_cyber_ai_as_three_focus_profiles_with_base_guidance_fallback(self) -> None:
        workbook = Path(__file__).resolve().parents[1] / "output" / "nist-ir-8596-cyber-ai-community-profile.intermediate.xlsx"
        result = ioc_store.import_frozen_cyber_ai_focus_profiles_from_workbook(
            self.conn, workbook=workbook, sheet_name="Profile outcomes", publisher="NIST",
            publication_status="Initial Preliminary Draft", source_url="https://csrc.nist.gov/pubs/ir/8596/iprd",
        )
        self.assertFalse(result["legacy_combined_profile_archived"])
        self.assertEqual(["Secure", "Defend", "Thwart"], [profile["focus_area"] for profile in result["profiles"]])
        self.assertEqual(
            3,
            self.conn.execute(
                """SELECT COUNT(1) FROM csf_profile_definitions
                WHERE profile_name IN ('Cyber AI - Secure', 'Cyber AI - Defend', 'Cyber AI - Thwart')
                  AND profile_kind = 'frozen_community'"""
            ).fetchone()[0],
        )
        secure_standard = self.conn.execute(
            """SELECT notes, community_priority, community_supporting_references
            FROM csf_profiles WHERE profile_name = 'Cyber AI - Secure' AND outcome_id = 'GV.OC-01'"""
        ).fetchone()
        self.assertEqual("", secure_standard["notes"])
        self.assertEqual("3", secure_standard["community_priority"])
        self.assertIn("OWASP", secure_standard["community_supporting_references"])
        secure_specific = self.conn.execute(
            "SELECT notes FROM csf_profiles WHERE profile_name = 'Cyber AI - Secure' AND outcome_id = 'GV.OC-03'"
        ).fetchone()
        self.assertNotEqual("", secure_specific["notes"])
        self.assertEqual(
            106,
            self.conn.execute(
                """SELECT COUNT(1) FROM csf_community_profile_outcome_facets AS facet
                JOIN csf_profile_definitions AS definition ON definition.profile_id = facet.profile_id
                WHERE definition.profile_name = 'Cyber AI - Thwart' AND facet.facet_id = 'thwart'"""
            ).fetchone()[0],
        )

    def test_profile_action_guidance_is_scoped_by_profile_uuid(self) -> None:
        ioc_store.upsert_csf_profile_action_guidance(
            self.conn,
            profile_id=self.profile_id,
            subcategory_id="GV.OC-01",
            action_title_example="Confirm the mission statement",
            action_details_example="Review the mission statement and record the current approved version.",
            action_rationale_example="This keeps cybersecurity decisions connected to the mission.",
            source_kind="community_sample_opportunity",
            prompt_version="pending-batch-v1",
        )
        stored = ioc_store.list_csf_profile_action_guidance(self.conn, self.profile_id)["GV.OC-01"]
        self.assertEqual("Confirm the mission statement", stored["title"])
        self.assertEqual("community_sample_opportunity", stored["source_kind"])
        another_profile = ioc_store.create_csf_profile_definition(
            self.conn, "Separate action templates", "A separate profile for action-template scoping.",
        )
        self.assertNotIn(
            "GV.OC-01",
            ioc_store.list_csf_profile_action_guidance(self.conn, another_profile["profile_id"]),
        )

    def test_import_profile_action_guidance_uses_later_retry(self) -> None:
        def batch_envelope(prompt_version: str, title: str) -> dict:
            return {
                "custom_id": f"{self.profile_id}|GV.OC-01|{prompt_version}",
                "response": {
                    "body": {
                        "status": "completed",
                        "output": [{
                            "type": "message",
                            "content": [{
                                "type": "output_text",
                                "text": json.dumps({
                                    "action_title_example": title,
                                    "action_details_example": "Review the mission statement and identify any security risk to its work.",
                                    "action_rationale_example": "This connects security work on the PC to the organization’s mission.",
                                }),
                            }],
                        }],
                    },
                },
            }

        original = self.root / "original.jsonl"
        retry = self.root / "retry.jsonl"
        original.write_text(json.dumps(batch_envelope("v1", "Review the mission")) + "\n", encoding="utf-8")
        retry.write_text(json.dumps(batch_envelope("v2", "Review the current mission")) + "\n", encoding="utf-8")
        result = ioc_store.import_csf_profile_action_guidance_outputs(
            self.conn, [original, retry], self.profile_id,
        )
        self.assertEqual(2, result["completed_rows"])
        self.assertEqual(1, result["unique_outcomes_imported"])
        stored = ioc_store.list_csf_profile_action_guidance(self.conn, self.profile_id)["GV.OC-01"]
        self.assertEqual("Review the current mission", stored["title"])
        self.assertEqual("v2", stored["prompt_version"])

    def test_import_nist_sp800_53_final_csf_mappings_is_idempotent(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        payload = ioc_store.import_nist_sp800_53_csf_2_mappings(
            self.conn,
            project_root / "reference-data" / "NIST" / "csf-2.0-informative-references.xlsx",
            project_root / "reference-data" / "NIST" / "NIST_SP-800-53_rev5_catalog.json",
        )
        self.assertEqual("nist-sp-800-53-r5.2.0", payload["framework_id"])
        self.assertEqual("5.2.0", payload["catalog_version"])
        self.assertEqual(1196, payload["control_count"])
        self.assertEqual(210, payload["mapped_control_count"])
        self.assertEqual(737, payload["mapping_count"])
        self.assertEqual(["CP", "IR", "PT"], payload["skipped_reference_values"])
        self.assertEqual(
            "Identify Critical Assets",
            self.conn.execute(
                "SELECT title FROM csf_reference_controls WHERE framework_id = ? AND control_id = ?",
                ("nist-sp-800-53-r5.2.0", "CP-02(08)"),
            ).fetchone()[0],
        )
        self.assertIn(
            "Define organizational mission and business processes",
            self.conn.execute(
                "SELECT statement_text FROM csf_reference_controls WHERE framework_id = ? AND control_id = ?",
                ("nist-sp-800-53-r5.2.0", "PM-11"),
            ).fetchone()[0],
        )
        self.assertEqual(
            ["PM-11"],
            [row[0] for row in self.conn.execute(
                "SELECT control_id FROM csf_subcategory_control_mappings WHERE subcategory_id = ? ORDER BY control_id",
                ("GV.OC-01",),
            ).fetchall()],
        )
        mapping_description = self.conn.execute(
            """SELECT interpretation_text, suggested_action_text, action_title_example,
            action_rationale_example, interpretation_source
            FROM csf_subcategory_control_mappings
            WHERE framework_id = ? AND control_id = ? AND subcategory_id = ?""",
            ("nist-sp-800-53-r5.2.0", "PM-11", "GV.OC-01"),
        ).fetchone()
        self.assertEqual("product-generated-v1", mapping_description["interpretation_source"])
        self.assertIn("mission clear, shared, and current", mapping_description["interpretation_text"])
        self.assertIn("Document the current mission statement", mapping_description["suggested_action_text"])
        self.assertEqual("Document and share the current mission statement", mapping_description["action_title_example"])
        self.assertIn("mission statement current", mapping_description["action_rationale_example"])
        repeated = ioc_store.import_nist_sp800_53_csf_2_mappings(
            self.conn,
            project_root / "reference-data" / "NIST" / "csf-2.0-informative-references.xlsx",
            project_root / "reference-data" / "NIST" / "NIST_SP-800-53_rev5_catalog.json",
        )
        self.assertEqual(payload["mapping_count"], repeated["mapping_count"])
        self.assertEqual(737, self.conn.execute("SELECT COUNT(*) FROM csf_subcategory_control_mappings").fetchone()[0])
        relationship_count = self.conn.execute("SELECT COUNT(*) FROM csf_control_mapping_relationships").fetchone()[0]
        self.assertEqual(len(CONTROL_MAPPING_RELATIONSHIPS), relationship_count)
        notification_relationship = self.conn.execute(
            """SELECT relationship_role, information_id, relationship_scope, rationale, review_status
            FROM csf_control_mapping_relationships
            WHERE framework_id = ? AND control_id = ? AND subcategory_id = ?""",
            ("nist-sp-800-53-r5.2.0", "SR-08", "GV.OC-02"),
        ).fetchone()
        self.assertEqual("context_only", notification_relationship["relationship_role"])
        self.assertEqual("", notification_relationship["information_id"])
        self.assertEqual("indirect", notification_relationship["relationship_scope"])
        self.assertEqual("reviewed", notification_relationship["review_status"])
        self.assertIn("does not expressly require", notification_relationship["rationale"])

        action = ioc_store.create_csf_reviewed_action(
            self.conn,
            profile_id=self.profile_id,
            subcategory_id="GV.OC-01",
            title="Address PM-11 — Mission and Business Process Definition",
            action_status="planned",
            control_id="PM-11",
        )
        controls = ioc_store.list_csf_mapped_controls_for_subcategory(self.conn, self.profile_id, "GV.OC-01")
        self.assertEqual("PM-11", controls[0]["control_id"])
        self.assertEqual(action["action_id"], controls[0]["action_id"])
        with self.assertRaisesRegex(ValueError, "already has an action"):
            ioc_store.create_csf_reviewed_action(
                self.conn,
                profile_id=self.profile_id,
                subcategory_id="GV.OC-01",
                title="Duplicate PM-11 action",
                action_status="planned",
                control_id="PM-11",
            )
        ioc_store.delete_csf_reviewed_action(self.conn, action["action_id"])
        self.assertIsNone(ioc_store.list_csf_mapped_controls_for_subcategory(self.conn, self.profile_id, "GV.OC-01")[0]["action_id"])
        ioc_store.set_csf_profile_control_catalog_enabled(
            self.conn, self.profile_id, "nist-sp-800-53-r5.2.0", False
        )
        self.assertEqual([], ioc_store.list_csf_mapped_controls_for_subcategory(self.conn, self.profile_id, "GV.OC-01"))
        ioc_store.set_csf_profile_control_catalog_enabled(
            self.conn, self.profile_id, "nist-sp-800-53-r5.2.0", True
        )
        self.assertEqual("PM-11", ioc_store.list_csf_mapped_controls_for_subcategory(self.conn, self.profile_id, "GV.OC-01")[0]["control_id"])

    def test_csf_outcome_audit_events_are_append_only_and_preserve_assessment_context(self) -> None:
        recorded = ioc_store.record_csf_outcome_audit_event(
            self.conn,
            audit_event_id="audit-gv-oc-01",
            subcategory_id="gv.oc-01",
            event_type="assessment_recorded",
            assessment_method="review",
            profile_id="single-pc",
            profile_version="2026.09",
            target_assessment_level="fully_implemented",
            current_assessment_level="partly_implemented",
            related_record_type="supporting_evidence",
            related_record_id="evidence-001",
            rationale_note="One required artifact remains to be reviewed.",
            payload={"source": "user-entry"},
            recorded_by="local-user",
            recorded_at="2026-09-19T12:00:00+00:00",
        )

        self.assertEqual("GV.OC-01", recorded["subcategory_id"])
        self.assertEqual("assessment_recorded", recorded["event_type"])
        self.assertEqual("partly_implemented", recorded["current_assessment_level"])
        self.assertEqual({"source": "user-entry"}, json.loads(recorded["payload_json"]))
        self.assertEqual(
            ["audit-gv-oc-01"],
            [item["audit_event_id"] for item in ioc_store.list_csf_outcome_audit_events(self.conn, "GV.OC-01")],
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.conn.execute(
                "UPDATE csf_outcome_audit_events SET rationale_note = 'changed' WHERE audit_event_id = ?",
                (recorded["audit_event_id"],),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.conn.execute(
                "DELETE FROM csf_outcome_audit_events WHERE audit_event_id = ?",
                (recorded["audit_event_id"],),
            )
        with self.assertRaisesRegex(ValueError, "current_assessment_level"):
            ioc_store.record_csf_outcome_audit_event(
                self.conn,
                subcategory_id="GV.OC-01",
                event_type="assessment_recorded",
                current_assessment_level="undecided",
            )

    def test_init_removes_legacy_scope_note_column_without_losing_guidance(self) -> None:
        self.conn.execute("ALTER TABLE csf_subcategory_guidance ADD COLUMN single_pc_scope_note TEXT NOT NULL DEFAULT ''")
        self.conn.execute(
            "UPDATE csf_subcategory_guidance SET single_pc_scope_note = 'Legacy product note' WHERE subcategory_id = 'GV.OC-01'"
        )
        self.conn.commit()

        ioc_store.init_db(self.conn)

        columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(csf_subcategory_guidance)").fetchall()}
        guidance = self.conn.execute(
            "SELECT plain_english_text, examples_json FROM csf_subcategory_guidance WHERE subcategory_id = 'GV.OC-01'"
        ).fetchone()
        self.assertNotIn("single_pc_scope_note", columns)
        self.assertTrue(guidance["plain_english_text"])
        self.assertNotEqual("[]", guidance["examples_json"])

    def test_current_csf_assessment_changes_are_append_only_audit_events(self) -> None:
        saved = ioc_store.set_current_csf_assessment(
            self.conn, self.profile_id, "gv.oc-01", "partly_implemented", "local-user"
        )
        updated = ioc_store.set_current_csf_assessment(
            self.conn, self.profile_id, "GV.OC-01", "fully_implemented", "local-user"
        )

        self.assertEqual("partly_implemented", saved["assessment_level"])
        self.assertEqual("fully_implemented", updated["assessment_level"])
        self.assertEqual(
            "fully_implemented",
            ioc_store.list_current_csf_assessments(self.conn, self.profile_id)["GV.OC-01"]["assessment_level"],
        )
        events = ioc_store.list_csf_outcome_audit_events(self.conn, "GV.OC-01")
        self.assertEqual(["assessment_recorded", "assessment_superseded"], [event["event_type"] for event in events])
        self.assertEqual("partly_implemented", json.loads(events[1]["payload_json"])["previous_current_assessment_level"])
        self.assertEqual("fully_implemented", events[1]["current_assessment_level"])
        with self.assertRaisesRegex(ValueError, "assessment_level"):
            ioc_store.set_current_csf_assessment(self.conn, self.profile_id, "GV.OC-01", "undecided")

    def test_evidence_can_support_multiple_outcomes_and_actions_within_a_profile(self) -> None:
        basis = ioc_store.create_csf_supporting_basis(
            self.conn,
            profile_id=self.profile_id,
            basis_id="basis-001",
            subcategory_id="gv.oc-01",
            basis_type="document",
            title="Mission statement",
            details="Reviewed the current organization mission statement.",
            reference_location="C:/evidence/mission.pdf",
            created_by="local-user",
        )
        action = ioc_store.create_csf_reviewed_action(
            self.conn,
            profile_id=self.profile_id,
            action_id="action-001",
            subcategory_id="GV.OC-01",
            title="Share the mission statement with staff",
            action_status="in_progress",
            basis_ids=[basis["basis_id"]],
            created_by="local-user",
        )

        self.assertEqual("GV.OC-01", basis["subcategory_id"])
        evidence_events = [
            event for event in ioc_store.list_csf_outcome_audit_events(self.conn, "GV.OC-01")
            if event["event_type"] == "evidence_linked"
        ]
        self.assertEqual(1, len(evidence_events))
        self.assertEqual("evidence", evidence_events[0]["related_record_type"])
        self.assertEqual("basis-001", evidence_events[0]["related_record_id"])
        self.assertEqual(["basis-001"], [item["basis_id"] for item in ioc_store.list_csf_supporting_basis(self.conn, self.profile_id, "GV.OC-01")])
        self.assertEqual("in_progress", action["action_status"])
        self.assertEqual(
            ["basis-001"],
            ioc_store.list_csf_reviewed_actions(self.conn, self.profile_id, "GV.OC-01")[0]["basis_ids"],
        )
        outcome_link = ioc_store.link_csf_evidence_to_outcome(
            self.conn,
            basis_id=basis["basis_id"],
            profile_id=self.profile_id,
            subcategory_id="GV.OV-01",
            assertion_text="The mission statement identifies the accountable owner.",
            linked_by="local-user",
        )
        cross_outcome_action = ioc_store.create_csf_reviewed_action(
            self.conn,
            profile_id=self.profile_id,
            subcategory_id="GV.OV-01",
            title="Use the accountable owner in governance review",
            action_status="planned",
            basis_ids=[basis["basis_id"]],
        )
        initial_update = ioc_store.list_csf_reviewed_action_updates(self.conn, action["action_id"])[0]
        update_link = ioc_store.link_csf_evidence_to_action_update(
            self.conn,
            action_update_id=initial_update["action_update_id"],
            basis_id=basis["basis_id"],
            assertion_text="This evidence supports the recorded action status.",
        )
        self.assertEqual("GV.OV-01", outcome_link["subcategory_id"])
        self.assertEqual(["basis-001"], [item["basis_id"] for item in ioc_store.list_csf_supporting_basis(self.conn, self.profile_id, "GV.OV-01")])
        self.assertEqual(["basis-001"], ioc_store.list_csf_reviewed_actions(self.conn, self.profile_id, "GV.OV-01")[0]["basis_ids"])
        self.assertEqual(initial_update["action_update_id"], update_link["action_update_id"])
        library = ioc_store.list_csf_evidence_library(self.conn, self.profile_id)
        self.assertEqual(2, library[0]["outcome_link_count"])
        self.assertEqual(2, library[0]["action_link_count"])
        self.assertEqual(1, library[0]["action_update_link_count"])
        detail = ioc_store.get_csf_evidence_detail(self.conn, self.profile_id, basis["basis_id"])
        self.assertEqual("Mission statement", detail["evidence"]["title"])
        self.assertEqual({"GV.OC-01", "GV.OV-01"}, {item["subcategory_id"] for item in detail["outcome_uses"]})
        self.assertEqual(2, len(detail["action_uses"]))
        self.assertEqual(1, len(detail["action_update_uses"]))

    def test_tile_three_records_are_isolated_by_profile_uuid(self) -> None:
        other_profile = ioc_store.create_csf_profile_definition(
            self.conn, "Second profile", "A separate test context."
        )
        other_profile_id = other_profile["profile_id"]
        ioc_store.set_current_csf_assessment(
            self.conn, self.profile_id, "GV.OC-01", "fully_implemented", "local-user"
        )
        ioc_store.set_current_csf_assessment(
            self.conn, other_profile_id, "GV.OC-01", "not_implemented", "local-user"
        )
        base_basis = ioc_store.create_csf_supporting_basis(
            self.conn, profile_id=self.profile_id, subcategory_id="GV.OC-01",
            basis_type="document", title="Base evidence",
        )
        other_basis = ioc_store.create_csf_supporting_basis(
            self.conn, profile_id=other_profile_id, subcategory_id="GV.OC-01",
            basis_type="document", title="Other evidence",
        )
        self.assertEqual(
            "fully_implemented",
            ioc_store.list_current_csf_assessments(self.conn, self.profile_id)["GV.OC-01"]["assessment_level"],
        )
        self.assertEqual(
            "not_implemented",
            ioc_store.list_current_csf_assessments(self.conn, other_profile_id)["GV.OC-01"]["assessment_level"],
        )
        self.assertEqual([base_basis["basis_id"]], [row["basis_id"] for row in ioc_store.list_csf_supporting_basis(self.conn, self.profile_id, "GV.OC-01")])
        self.assertEqual([other_basis["basis_id"]], [row["basis_id"] for row in ioc_store.list_csf_supporting_basis(self.conn, other_profile_id, "GV.OC-01")])

    def test_action_evidence_checklist_reconciles_links(self) -> None:
        evidence = ioc_store.create_csf_supporting_basis(
            self.conn, profile_id=self.profile_id, subcategory_id="GV.OC-01",
            basis_type="document", title="Mission approval",
        )
        action = ioc_store.create_csf_reviewed_action(
            self.conn, profile_id=self.profile_id, subcategory_id="GV.OC-01",
            title="Document mission", action_status="planned", basis_ids=[evidence["basis_id"]],
        )
        self.assertEqual([evidence["basis_id"]], ioc_store.list_csf_reviewed_actions(
            self.conn, self.profile_id, "GV.OC-01"
        )[0]["basis_ids"])
        ioc_store.update_csf_reviewed_action(
            self.conn, action_id=action["action_id"], title="Document mission",
            details="", rationale="", action_status="planned", basis_ids=[],
        )
        self.assertEqual([], ioc_store.list_csf_reviewed_actions(
            self.conn, self.profile_id, "GV.OC-01"
        )[0]["basis_ids"])
        events = ioc_store.list_csf_evidence_link_audit_events(
            self.conn, self.profile_id, target_type="action", target_id=action["action_id"]
        )
        self.assertEqual(["unlinked", "linked"], [event["event_type"] for event in events])

    def test_profile_target_change_requires_a_rationale_and_is_audited(self) -> None:
        with self.assertRaisesRegex(ValueError, "Target rationale"):
            ioc_store.set_csf_profile_outcome_target(
                self.conn, "Single-PC baseline", "GV.OC-01", "partly_implemented", ""
            )
        ioc_store.set_csf_profile_outcome_target(
            self.conn, "Single-PC baseline", "GV.OC-01", "partly_implemented",
            "The PC is being transitioned in two phases.", "local-user", "Transition plan v2",
        )
        self.assertEqual(
            "partly_implemented",
            ioc_store.list_csf_profile_outcome_targets(self.conn, self.profile_id)["GV.OC-01"]["target_assessment_level"],
        )
        events = ioc_store.list_csf_profile_audit_events(self.conn, "Single-PC baseline")
        self.assertEqual("The PC is being transitioned in two phases.", events[-1]["rationale"])
        self.assertEqual("local-user", events[-1]["recorded_by"])
        self.assertEqual("Transition plan v2", events[-1]["supporting_evidence_reference"])
        self.assertEqual(
            "The PC is being transitioned in two phases.",
            self.conn.execute(
                "SELECT rationale FROM csf_profiles WHERE profile_name = ? AND outcome_id = ?",
                ("Single-PC baseline", "GV.OC-01"),
            ).fetchone()["rationale"],
        )
        ioc_store.set_csf_profile_outcome_target(
            self.conn, "Single-PC baseline", "GV.OC-01", "partly_implemented",
            "The phased target remains appropriate after review.", "local-user",
        )
        events = ioc_store.list_csf_profile_audit_events(self.conn, "Single-PC baseline")
        self.assertEqual("outcome_target_rationale_recorded", events[-1]["event_type"])
        self.assertEqual("The phased target remains appropriate after review.", events[-1]["rationale"])
        self.assertEqual(
            "The phased target remains appropriate after review.",
            ioc_store.list_csf_profile_outcome_targets(self.conn, self.profile_id)["GV.OC-01"]["target_reason"],
        )

    def test_profile_inclusion_precedes_its_automatic_target_event(self) -> None:
        ioc_store.set_csf_profile_outcome_status(
            self.conn, "Single-PC baseline", "GV.OC-01", "not_selected", "local-user"
        )
        ioc_store.set_csf_profile_outcome_status(
            self.conn, "Single-PC baseline", "GV.OC-01", "included", "local-user"
        )
        events = [
            event for event in ioc_store.list_csf_profile_audit_events(self.conn, "Single-PC baseline")
            if event["outcome_id"] == "GV.OC-01"
        ]
        self.assertEqual(
            ["outcome_status_changed", "outcome_target_cleared", "outcome_status_changed", "outcome_target_initialized"],
            [event["event_type"] for event in events],
        )

    def test_reviewed_action_updates_are_append_only_and_set_first_completion_time(self) -> None:
        action = ioc_store.create_csf_reviewed_action(
            self.conn,
            profile_id=self.profile_id,
            action_id="action-update-001",
            subcategory_id="GV.OC-01",
            title="Share the mission statement with staff",
            action_status="planned",
            progress_note="Scheduled the staff meeting.",
            created_by="local-user",
        )
        updated = ioc_store.update_csf_reviewed_action(
            self.conn,
            action_id=action["action_id"],
            title=action["title"],
            details="Reviewed the statement with staff.",
            rationale="Staff need the context to make risk decisions.",
            action_status="completed",
            progress_note="Meeting completed and statement shared.",
            updated_by="local-user",
        )

        history = ioc_store.list_csf_reviewed_action_updates(self.conn, action["action_id"])
        self.assertEqual("completed", updated["action_status"])
        self.assertTrue(updated["completed_at"])
        self.assertNotEqual(action["updated_at"], updated["updated_at"])
        self.assertEqual(["completed", "planned"], [item["action_status"] for item in history])
        self.assertEqual("Meeting completed and statement shared.", history[0]["progress_note"])
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.conn.execute(
                "UPDATE csf_reviewed_action_updates SET progress_note = 'changed' WHERE action_update_id = ?",
                (history[0]["action_update_id"],),
            )
        deleted = ioc_store.delete_csf_reviewed_action(self.conn, action["action_id"])
        self.assertEqual(action["action_id"], deleted["action_id"])
        self.assertEqual([], ioc_store.list_csf_reviewed_action_updates(self.conn, action["action_id"]))
        self.assertEqual([], ioc_store.list_csf_reviewed_actions(self.conn, self.profile_id, "GV.OC-01"))

    def test_local_csf_extensions_are_scoped_and_advisory_only(self) -> None:
        category = ioc_store.create_local_csf_category(
            self.conn,
            "DE",
            "Local monitoring practice",
            "Document the monitoring practice used in this environment.",
            "Review the documented local evidence.",
            "Discuss the next human step with the system owner.",
        )
        outcome = ioc_store.create_local_csf_outcome(
            self.conn,
            category["local_category_id"],
            "Review cadence",
            "Keep the documented review cadence current.",
        )
        self.assertEqual("LOCAL.DE.01", category["local_category_id"])
        self.assertEqual("LOCAL.DE.01.01", outcome["local_outcome_id"])
        self.assertEqual(["LOCAL.DE.01"], [item["local_category_id"] for item in ioc_store.list_local_csf_categories(self.conn, "DE")])
        self.assertEqual(["LOCAL.DE.01.01"], [item["local_outcome_id"] for item in ioc_store.list_local_csf_outcomes(self.conn, "LOCAL.DE.01")])
        self.assertNotIn("command", category)
        self.assertNotIn("script", outcome)
        with self.assertRaisesRegex(ValueError, "official CSF Function"):
            ioc_store.create_local_csf_category(self.conn, "LOCAL", "Title", "Objective")
        with self.assertRaisesRegex(ValueError, "existing local Category"):
            ioc_store.create_local_csf_outcome(self.conn, "LOCAL.DE.99", "Title", "Objective")

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

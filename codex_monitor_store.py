import argparse
import hashlib
import json
import re
import sqlite3
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree

from csf_guidance import GENERIC_ACTION_DETAILS_EN_US, GENERIC_ACTION_RATIONALE_EN_US, GENERIC_ACTION_TITLE_EN_US, PLAIN_ENGLISH_GUIDANCE_EN_US, PRODUCT_EXAMPLES_EN_US
from csf_capability_dependencies import CAPABILITY_DEPENDENCIES
from csf_control_mapping_relationships import CONTROL_MAPPING_RELATIONSHIPS
from csf_information_flows import INFORMATION_ITEMS, INFORMATION_SOURCES, INFORMATION_USES
from csf_profile import SUBCATEGORY_PROFILE_METADATA_EN_US
import csf_catalog


# Inventory copied from NIST's CSF 2.0 Profiles catalog.  It is deliberately
# only metadata: each Community Profile keeps its own publication and update
# lifecycle, and its detailed outcome selections must be imported explicitly.
NIST_CSF_COMMUNITY_PROFILE_CATALOG_URL = "https://www.nist.gov/cyberframework/profiles"
NIST_CSF_COMMUNITY_PROFILES = [
    ("nist-oran-2026-draft", "Federal Agency Open Radio Access Network (O-RAN) Deployment", "NIST", "Draft / public comment", "Federal agency O-RAN deployment"),
    ("nist-cyber-ai", "Cyber AI Profile", "NIST", "Reviewing comments", "Cybersecurity of AI and AI for cybersecurity"),
    ("nist-transit", "Transit Community CSF Profile", "NIST", "Finalized", "Public transit operations"),
    ("nist-manufacturing", "Manufacturing CSF Profile", "NIST", "Draft / reviewing comments", "Manufacturing"),
    ("nist-foundational-pnt", "Foundational PNT CSF Profile", "NIST", "Draft / reviewing comments", "Positioning, navigation, and timing services"),
    ("nist-incident-response", "Incident Response CSF Profile", "NIST", "Final", "Cybersecurity incident response"),
    ("nist-semiconductor", "Semiconductor Community Profile", "NIST", "Draft / reviewing comments", "Semiconductor manufacturing"),
    ("nist-ransomware", "Ransomware Risk Management CSF Profile", "NIST", "Final", "Ransomware risk management"),
    ("nist-genomic-data", "Genomic Data CSF Profile", "NIST", "Draft", "Genomic data cybersecurity and privacy"),
    ("csa-cloud-security", "Cloud Security Community Profile", "Cloud Security Alliance", "See source", "Cloud security"),
    ("cablelabs-internet-routing", "Internet Routing CSF Profile", "CableLabs", "See source", "Internet routing"),
    ("cri-financial-cloud", "Financial Sector Cloud Services Community Profile", "Cyber Risk Institute", "See source", "Financial-sector cloud services"),
    ("cri-financial-sector", "Financial Sector CSF Profile", "Cyber Risk Institute", "See source", "Financial services"),
    ("seemless-telco-v1", "Telecommunications Sector CSF Profile Version 1.0", "Seemless Transition", "See source", "Telecommunications"),
    ("tca-telco-v2", "Telecommunications Sector CSF Profile Version 2.0", "Trusted Cyber Annex", "See source", "Telecommunications"),
]



def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: Any) -> None:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=True)


def indicator_key(indicator_type: str, value: str, source: str) -> str:
    return f"{indicator_type.strip().lower()}|{value.strip().lower()}|{source.strip().lower()}"


def connect_db(db_path: Path) -> sqlite3.Connection:
    if db_path.exists() and db_path.is_dir():
        raise IsADirectoryError(f"SQLite database path points to a directory: {db_path}")
    ensure_parent(db_path)
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def init_db(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS ingest_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            source_name TEXT NOT NULL,
            input_path TEXT NOT NULL,
            status TEXT NOT NULL,
            indicator_count INTEGER NOT NULL DEFAULT 0,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_key TEXT NOT NULL UNIQUE,
            indicator_id TEXT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence INTEGER NOT NULL DEFAULT 50,
            severity TEXT NOT NULL DEFAULT 'medium',
            first_seen TEXT,
            last_seen TEXT,
            valid_from TEXT,
            valid_until TEXT,
            tlp TEXT,
            malware_family TEXT,
            campaign TEXT,
            threat_actor TEXT,
            attack_technique TEXT,
            reference_url TEXT,
            raw_source_record_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_ingest_run_id INTEGER,
            FOREIGN KEY(last_ingest_run_id) REFERENCES ingest_runs(id)
        );

        CREATE INDEX IF NOT EXISTS idx_indicators_type_value ON indicators(type, value);
        CREATE INDEX IF NOT EXISTS idx_indicators_source ON indicators(source);
        CREATE INDEX IF NOT EXISTS idx_indicators_valid_until ON indicators(valid_until);

        CREATE TABLE IF NOT EXISTS app_state (
            namespace TEXT NOT NULL,
            state_key TEXT NOT NULL,
            value_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(namespace, state_key)
        );

        CREATE INDEX IF NOT EXISTS idx_app_state_updated_at ON app_state(updated_at);

        CREATE TABLE IF NOT EXISTS accepted_posture_drift (
            acceptance_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            scope TEXT NOT NULL DEFAULT 'exact',
            section TEXT NOT NULL,
            item_name TEXT NOT NULL,
            item_type TEXT,
            field TEXT,
            accepted_current_value TEXT,
            baseline_value TEXT,
            matched_rule_id TEXT,
            matched_rule_description TEXT,
            reason TEXT NOT NULL,
            accepted_by TEXT,
            accepted_utc TEXT NOT NULL,
            expires_utc TEXT,
            source_report_id TEXT,
            source_report_path TEXT,
            csf_mapping TEXT,
            created_by_app_version TEXT,
            created_utc TEXT NOT NULL,
            updated_utc TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_accepted_posture_drift_lookup ON accepted_posture_drift(enabled, section, item_name, item_type, field, accepted_current_value);
        CREATE INDEX IF NOT EXISTS idx_accepted_posture_drift_expiry ON accepted_posture_drift(enabled, expires_utc);
        CREATE INDEX IF NOT EXISTS idx_accepted_posture_drift_rule ON accepted_posture_drift(matched_rule_id);

        CREATE TABLE IF NOT EXISTS baseline_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            baseline_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            host TEXT,
            scope TEXT,
            watched_file_count INTEGER,
            hashed_file_count INTEGER,
            source_json_path TEXT,
            source_markdown_path TEXT
        );

        CREATE TABLE IF NOT EXISTS baseline_file_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            baseline_id TEXT NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT,
            size_bytes INTEGER,
            last_write_time_utc TEXT,
            exists_at_baseline INTEGER,
            source_json_path TEXT,
            FOREIGN KEY(baseline_id) REFERENCES baseline_runs(baseline_id)
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_file_hashes_baseline_path ON baseline_file_hashes(baseline_id, path);
        CREATE INDEX IF NOT EXISTS idx_baseline_file_hashes_sha256 ON baseline_file_hashes(sha256);
        CREATE INDEX IF NOT EXISTS idx_baseline_file_hashes_path ON baseline_file_hashes(path);
        CREATE INDEX IF NOT EXISTS idx_baseline_file_hashes_baseline_id ON baseline_file_hashes(baseline_id);

        CREATE TABLE IF NOT EXISTS evidence_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            snapshot_type TEXT,
            created_at TEXT,
            host TEXT,
            source_json_path TEXT,
            source_markdown_path TEXT,
            collector_version TEXT,
            trust_label TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_snapshots_created_at ON evidence_snapshots(created_at);
        CREATE INDEX IF NOT EXISTS idx_evidence_snapshots_snapshot_type ON evidence_snapshots(snapshot_type);

        CREATE TABLE IF NOT EXISTS network_connection_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            local_address TEXT,
            local_port INTEGER,
            remote_address TEXT,
            remote_port INTEGER,
            state TEXT,
            owning_process INTEGER,
            command_line TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_network_connection_observations_snapshot_id ON network_connection_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_network_connection_observations_remote_address ON network_connection_observations(remote_address);

        CREATE TABLE IF NOT EXISTS dns_cache_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            entry TEXT,
            name TEXT,
            data TEXT,
            record_type TEXT,
            time_to_live TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_dns_cache_observations_snapshot_id ON dns_cache_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_dns_cache_observations_name ON dns_cache_observations(name);
        CREATE INDEX IF NOT EXISTS idx_dns_cache_observations_data ON dns_cache_observations(data);

        CREATE TABLE IF NOT EXISTS powershell_event_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            event_id INTEGER,
            command_line TEXT,
            script_block_text TEXT,
            provider_name TEXT,
            message TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_powershell_event_observations_snapshot_id ON powershell_event_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_powershell_event_observations_command_line ON powershell_event_observations(command_line);
        CREATE INDEX IF NOT EXISTS idx_powershell_event_observations_script_block_text ON powershell_event_observations(script_block_text);

        CREATE TABLE IF NOT EXISTS windows_event_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            event_id INTEGER,
            provider_name TEXT,
            channel TEXT,
            message TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_windows_event_observations_snapshot_id ON windows_event_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_windows_event_observations_event_id ON windows_event_observations(event_id);

        CREATE TABLE IF NOT EXISTS registry_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            key_path TEXT,
            value_name TEXT,
            value_data TEXT,
            source_type TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_registry_observations_snapshot_id ON registry_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_registry_observations_key_path ON registry_observations(key_path);
        CREATE INDEX IF NOT EXISTS idx_registry_observations_value_name ON registry_observations(value_name);
        CREATE INDEX IF NOT EXISTS idx_registry_observations_value_data ON registry_observations(value_data);

        CREATE TABLE IF NOT EXISTS service_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            service_name TEXT,
            display_name TEXT,
            image_path TEXT,
            start_name TEXT,
            state TEXT,
            start_mode TEXT,
            registry_path TEXT,
            process_id INTEGER,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_service_observations_snapshot_id ON service_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_service_observations_service_name ON service_observations(service_name);
        CREATE INDEX IF NOT EXISTS idx_service_observations_image_path ON service_observations(image_path);

        CREATE TABLE IF NOT EXISTS scheduled_task_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            task_name TEXT,
            task_path TEXT,
            author TEXT,
            state TEXT,
            last_run_time TEXT,
            next_run_time TEXT,
            last_task_result TEXT,
            action TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_scheduled_task_observations_snapshot_id ON scheduled_task_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_scheduled_task_observations_task_name ON scheduled_task_observations(task_name);
        CREATE INDEX IF NOT EXISTS idx_scheduled_task_observations_action ON scheduled_task_observations(action);

        CREATE TABLE IF NOT EXISTS autorun_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            name TEXT,
            path TEXT,
            command_line TEXT,
            registry_path TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_autorun_observations_snapshot_id ON autorun_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_autorun_observations_path ON autorun_observations(path);

        CREATE TABLE IF NOT EXISTS process_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            name TEXT,
            path TEXT,
            sha256 TEXT,
            command_line TEXT,
            owner TEXT,
            process_id INTEGER,
            parent_process_id INTEGER,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_process_observations_snapshot_id ON process_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_process_observations_name ON process_observations(name);
        CREATE INDEX IF NOT EXISTS idx_process_observations_command_line ON process_observations(command_line);
        CREATE INDEX IF NOT EXISTS idx_process_observations_path ON process_observations(path);

        CREATE TABLE IF NOT EXISTS file_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            observed_at TEXT,
            observation_type TEXT,
            path TEXT,
            filename TEXT,
            sha256 TEXT,
            size_bytes INTEGER,
            last_write_time_utc TEXT,
            source_note TEXT,
            FOREIGN KEY(snapshot_id) REFERENCES evidence_snapshots(snapshot_id)
        );

        CREATE INDEX IF NOT EXISTS idx_file_observations_snapshot_id ON file_observations(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_file_observations_path ON file_observations(path);
        CREATE INDEX IF NOT EXISTS idx_file_observations_filename ON file_observations(filename);
        CREATE INDEX IF NOT EXISTS idx_file_observations_sha256 ON file_observations(sha256);

        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL,
            description TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS collector_runs (
            collector_run_id TEXT PRIMARY KEY,
            collector_name TEXT NOT NULL,
            collector_version TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            outcome TEXT NOT NULL,
            summary_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_collector_runs_name_started ON collector_runs(collector_name, started_at DESC);
        CREATE INDEX IF NOT EXISTS idx_collector_runs_outcome_started ON collector_runs(outcome, started_at DESC);

        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            collector_run_id TEXT NOT NULL,
            report_type TEXT NOT NULL,
            collection_time_utc TEXT NOT NULL,
            overall_status TEXT,
            severity TEXT,
            summary_json TEXT NOT NULL DEFAULT '{}',
            export_json_path TEXT,
            export_markdown_path TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(collector_run_id) REFERENCES collector_runs(collector_run_id)
        );

        CREATE INDEX IF NOT EXISTS idx_reports_type_collected ON reports(report_type, collection_time_utc DESC);
        CREATE INDEX IF NOT EXISTS idx_reports_collector_run ON reports(collector_run_id);

        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL,
            finding_sequence INTEGER NOT NULL,
            category TEXT,
            severity TEXT,
            classification TEXT,
            title TEXT,
            summary TEXT,
            evidence_json TEXT NOT NULL DEFAULT '{}',
            csf_mapping TEXT,
            guardrail_state TEXT,
            response_state TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            FOREIGN KEY(report_id) REFERENCES reports(report_id),
            UNIQUE(report_id, finding_sequence)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_report_severity ON findings(report_id, severity);
        CREATE INDEX IF NOT EXISTS idx_findings_classification_response ON findings(classification, response_state);

        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            report_id TEXT,
            finding_id TEXT,
            severity TEXT NOT NULL,
            summary TEXT NOT NULL,
            lifecycle_state TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            acknowledged_at TEXT,
            closed_at TEXT,
            FOREIGN KEY(report_id) REFERENCES reports(report_id),
            FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_lifecycle_severity ON alerts(lifecycle_state, severity, created_at DESC);

        CREATE TABLE IF NOT EXISTS alert_deliveries (
            alert_delivery_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL,
            delivery_channel TEXT NOT NULL,
            recipient TEXT,
            delivery_state TEXT NOT NULL DEFAULT 'pending',
            claimed_at TEXT,
            delivered_at TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(alert_id) REFERENCES alerts(alert_id),
            UNIQUE(alert_id, delivery_channel, recipient)
        );

        CREATE INDEX IF NOT EXISTS idx_alert_deliveries_pending ON alert_deliveries(delivery_state, created_at);

        CREATE TABLE IF NOT EXISTS local_csf_categories (
            local_category_id TEXT PRIMARY KEY,
            function_id TEXT NOT NULL CHECK(function_id IN ('GV', 'ID', 'PR', 'DE', 'RS', 'RC')),
            title TEXT NOT NULL,
            objective TEXT NOT NULL,
            advisory_evidence_text TEXT,
            advisory_action_text TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_local_csf_categories_function ON local_csf_categories(function_id, local_category_id);

        CREATE TABLE IF NOT EXISTS local_csf_outcomes (
            local_outcome_id TEXT PRIMARY KEY,
            local_category_id TEXT NOT NULL,
            title TEXT NOT NULL,
            objective TEXT NOT NULL,
            advisory_evidence_text TEXT,
            advisory_action_text TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(local_category_id) REFERENCES local_csf_categories(local_category_id)
        );

        CREATE INDEX IF NOT EXISTS idx_local_csf_outcomes_category ON local_csf_outcomes(local_category_id, local_outcome_id);

        CREATE TABLE IF NOT EXISTS csf_subcategory_guidance (
            subcategory_id TEXT NOT NULL,
            language_code TEXT NOT NULL,
            plain_english_text TEXT NOT NULL CHECK(length(trim(plain_english_text)) > 0),
            examples_json TEXT NOT NULL DEFAULT '[]',
            generic_action_title TEXT NOT NULL DEFAULT '',
            generic_action_details TEXT NOT NULL DEFAULT '',
            generic_action_rationale TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(subcategory_id, language_code)
        );

        CREATE TABLE IF NOT EXISTS csf_subcategory_profile_metadata (
            subcategory_id TEXT NOT NULL,
            language_code TEXT NOT NULL,
            assessment_method TEXT NOT NULL CHECK(assessment_method IN ('evidence', 'attestation', 'review', 'hybrid')),
            research_guidance TEXT NOT NULL CHECK(length(trim(research_guidance)) > 0),
            supporting_note_required INTEGER NOT NULL CHECK(supporting_note_required IN (0, 1)),
            PRIMARY KEY(subcategory_id, language_code)
        );

        CREATE TABLE IF NOT EXISTS csf_outcome_audit_events (
            audit_event_id TEXT PRIMARY KEY,
            subcategory_id TEXT NOT NULL CHECK(length(trim(subcategory_id)) > 0),
            event_type TEXT NOT NULL CHECK(event_type IN (
                'evidence_linked', 'evidence_unlinked', 'note_recorded',
                'action_linked', 'action_unlinked', 'assessment_drafted',
                'assessment_recorded', 'assessment_superseded'
            )),
            assessment_method TEXT CHECK(assessment_method IS NULL OR assessment_method IN ('evidence', 'attestation', 'review', 'hybrid')),
            profile_id TEXT,
            profile_version TEXT,
            target_assessment_level TEXT CHECK(target_assessment_level IS NULL OR target_assessment_level IN ('fully_implemented', 'partly_implemented', 'not_implemented', 'not_applicable')),
            current_assessment_level TEXT CHECK(current_assessment_level IS NULL OR current_assessment_level IN ('fully_implemented', 'partly_implemented', 'not_implemented', 'not_applicable')),
            related_record_type TEXT,
            related_record_id TEXT,
            rationale_note TEXT,
            payload_json TEXT NOT NULL DEFAULT '{}',
            recorded_by TEXT,
            recorded_at TEXT NOT NULL,
            supersedes_audit_event_id TEXT,
            FOREIGN KEY(supersedes_audit_event_id) REFERENCES csf_outcome_audit_events(audit_event_id)
        );

        CREATE INDEX IF NOT EXISTS idx_csf_outcome_audit_events_timeline
            ON csf_outcome_audit_events(subcategory_id, recorded_at, audit_event_id);
        CREATE INDEX IF NOT EXISTS idx_csf_outcome_audit_events_type
            ON csf_outcome_audit_events(event_type, recorded_at);
        CREATE INDEX IF NOT EXISTS idx_csf_outcome_audit_events_supersedes
            ON csf_outcome_audit_events(supersedes_audit_event_id);

        CREATE TRIGGER IF NOT EXISTS prevent_csf_outcome_audit_event_update
        BEFORE UPDATE ON csf_outcome_audit_events
        BEGIN
            SELECT RAISE(ABORT, 'CSF outcome audit events are append-only.');
        END;

        CREATE TRIGGER IF NOT EXISTS prevent_csf_outcome_audit_event_delete
        BEFORE DELETE ON csf_outcome_audit_events
        BEGIN
            SELECT RAISE(ABORT, 'CSF outcome audit events are append-only.');
        END;

        CREATE TABLE IF NOT EXISTS csf_current_assessments (
            subcategory_id TEXT PRIMARY KEY CHECK(length(trim(subcategory_id)) > 0),
            assessment_level TEXT NOT NULL CHECK(assessment_level IN ('fully_implemented', 'partly_implemented', 'not_implemented', 'not_applicable')),
            updated_by TEXT,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_csf_current_assessments_level
            ON csf_current_assessments(assessment_level, updated_at);

        -- Profile-scoped replacement for the original, single-context working
        -- assessment table.  The legacy table is retained only for migration.
        CREATE TABLE IF NOT EXISTS csf_profile_current_assessments (
            profile_id TEXT NOT NULL CHECK(length(trim(profile_id)) > 0),
            subcategory_id TEXT NOT NULL CHECK(length(trim(subcategory_id)) > 0),
            assessment_level TEXT NOT NULL CHECK(assessment_level IN ('fully_implemented', 'partly_implemented', 'not_implemented', 'not_applicable')),
            updated_by TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(profile_id, subcategory_id)
        );
        CREATE INDEX IF NOT EXISTS idx_csf_profile_current_assessments_level
            ON csf_profile_current_assessments(profile_id, assessment_level, updated_at);

        -- The desired Tile 3 assessment is an Organizational Profile choice,
        -- keyed by the profile's UUID rather than its display name.
        CREATE TABLE IF NOT EXISTS csf_profile_outcome_targets (
            profile_id TEXT NOT NULL CHECK(length(trim(profile_id)) > 0),
            subcategory_id TEXT NOT NULL CHECK(length(trim(subcategory_id)) > 0),
            target_assessment_level TEXT NOT NULL CHECK(target_assessment_level IN ('fully_implemented', 'partly_implemented', 'not_implemented', 'not_applicable')),
            updated_by TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(profile_id, subcategory_id)
        );
        CREATE INDEX IF NOT EXISTS idx_csf_profile_outcome_targets_profile
            ON csf_profile_outcome_targets(profile_id, target_assessment_level, updated_at);

        CREATE TABLE IF NOT EXISTS csf_profile_definitions (
            profile_id TEXT NOT NULL UNIQUE,
            profile_name TEXT PRIMARY KEY CHECK(length(trim(profile_name)) > 0),
            profile_kind TEXT NOT NULL DEFAULT 'organizational',
            context_summary TEXT NOT NULL DEFAULT '',
            community_profile_source TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            archived_at TEXT
        );

        CREATE TABLE IF NOT EXISTS csf_active_profile (
            selection_id INTEGER PRIMARY KEY CHECK(selection_id = 1),
            profile_name TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(profile_name) REFERENCES csf_profile_definitions(profile_name) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS csf_community_profile_catalog (
            community_profile_id TEXT PRIMARY KEY,
            profile_name TEXT NOT NULL,
            publisher TEXT NOT NULL,
            publication_status TEXT NOT NULL,
            focus TEXT NOT NULL,
            source_url TEXT NOT NULL,
            catalog_source_url TEXT NOT NULL,
            catalog_checked_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS csf_profile_community_profile_sources (
            profile_name TEXT NOT NULL,
            community_profile_id TEXT NOT NULL,
            selected_at TEXT NOT NULL,
            PRIMARY KEY(profile_name, community_profile_id),
            FOREIGN KEY(profile_name) REFERENCES csf_profile_definitions(profile_name) ON DELETE CASCADE,
            FOREIGN KEY(community_profile_id) REFERENCES csf_community_profile_catalog(community_profile_id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS csf_community_profile_frozen_sources (
            community_profile_id TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL UNIQUE,
            source_workbook_path TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,
            source_version TEXT NOT NULL DEFAULT '',
            source_published_at TEXT,
            source_reviewed_at TEXT,
            next_source_review_at TEXT,
            imported_at TEXT NOT NULL,
            FOREIGN KEY(community_profile_id) REFERENCES csf_community_profile_catalog(community_profile_id) ON DELETE RESTRICT,
            FOREIGN KEY(profile_id) REFERENCES csf_profile_definitions(profile_id) ON DELETE RESTRICT
        );

        -- Some Community Profiles express separate source guidance for more
        -- than one focus area (for example, Secure, Defend, and Thwart in
        -- NIST IR 8596).  Keep those source records independent instead of
        -- flattening them into the outcome's general community guidance.
        CREATE TABLE IF NOT EXISTS csf_community_profile_outcome_facets (
            profile_id TEXT NOT NULL,
            outcome_id TEXT NOT NULL,
            facet_id TEXT NOT NULL,
            facet_label TEXT NOT NULL,
            proposed_priority TEXT NOT NULL DEFAULT '',
            considerations TEXT NOT NULL DEFAULT '',
            opportunities TEXT NOT NULL DEFAULT '',
            informative_references TEXT NOT NULL DEFAULT '',
            source_text TEXT NOT NULL DEFAULT '',
            source_locator TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(profile_id, outcome_id, facet_id),
            FOREIGN KEY(profile_id) REFERENCES csf_profile_definitions(profile_id) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_csf_community_profile_outcome_facets_outcome
            ON csf_community_profile_outcome_facets(profile_id, outcome_id, facet_id);

        CREATE TABLE IF NOT EXISTS csf_profile_source_lineage (
            profile_id TEXT NOT NULL,
            source_profile_id TEXT NOT NULL,
            source_role TEXT NOT NULL,
            copied_at TEXT NOT NULL,
            PRIMARY KEY(profile_id, source_profile_id),
            FOREIGN KEY(profile_id) REFERENCES csf_profile_definitions(profile_id) ON DELETE RESTRICT,
            FOREIGN KEY(source_profile_id) REFERENCES csf_profile_definitions(profile_id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS csf_profile_audit_events (
            profile_audit_event_id TEXT PRIMARY KEY,
            profile_name TEXT NOT NULL,
            event_type TEXT NOT NULL,
            outcome_id TEXT,
            field_name TEXT,
            old_value_json TEXT,
            new_value_json TEXT NOT NULL,
            rationale TEXT NOT NULL DEFAULT '',
            recorded_by TEXT,
            supporting_evidence_reference TEXT NOT NULL DEFAULT '',
            recorded_at TEXT NOT NULL,
            FOREIGN KEY(profile_name) REFERENCES csf_profile_definitions(profile_name) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_csf_profile_audit_events_timeline
            ON csf_profile_audit_events(profile_name, recorded_at, profile_audit_event_id);
        CREATE TRIGGER IF NOT EXISTS prevent_csf_profile_audit_event_update
        BEFORE UPDATE ON csf_profile_audit_events BEGIN SELECT RAISE(ABORT, 'CSF profile audit events are append-only.'); END;
        CREATE TRIGGER IF NOT EXISTS prevent_csf_profile_audit_event_delete
        BEFORE DELETE ON csf_profile_audit_events BEGIN SELECT RAISE(ABORT, 'CSF profile audit events are append-only.'); END;

        -- Each row represents one official CSF Category or Subcategory in a
        -- named Organizational Profile. Field names mirror NIST's CSF 2.0
        -- Organizational Profile Template; no profile is seeded by default.
        CREATE TABLE IF NOT EXISTS csf_profiles (
            profile_name TEXT NOT NULL CHECK(length(trim(profile_name)) > 0),
            outcome_id TEXT NOT NULL CHECK(length(trim(outcome_id)) > 0),
            outcome_type TEXT NOT NULL CHECK(outcome_type IN ('category', 'subcategory')),
            outcome_description TEXT NOT NULL CHECK(length(trim(outcome_description)) > 0),
            included_in_profile INTEGER NOT NULL DEFAULT 0 CHECK(included_in_profile IN (0, 1)),
            profile_status TEXT NOT NULL DEFAULT 'not_selected' CHECK(profile_status IN ('not_selected', 'included', 'inherited', 'out_of_scope')),
            rationale TEXT NOT NULL DEFAULT '',
            current_priority TEXT NOT NULL DEFAULT '',
            current_status TEXT NOT NULL DEFAULT '',
            current_policies_processes_procedures TEXT NOT NULL DEFAULT '',
            current_internal_practices TEXT NOT NULL DEFAULT '',
            current_roles_responsibilities TEXT NOT NULL DEFAULT '',
            current_selected_informative_references TEXT NOT NULL DEFAULT '',
            current_artifacts_evidence TEXT NOT NULL DEFAULT '',
            target_priority TEXT NOT NULL DEFAULT '',
            target_csf_tier TEXT NOT NULL DEFAULT '',
            target_policies_processes_procedures TEXT NOT NULL DEFAULT '',
            target_internal_practices TEXT NOT NULL DEFAULT '',
            target_roles_responsibilities TEXT NOT NULL DEFAULT '',
            target_selected_informative_references TEXT NOT NULL DEFAULT '',
            community_priority TEXT NOT NULL DEFAULT '',
            community_risk_rationale TEXT NOT NULL DEFAULT '',
            community_supporting_references TEXT NOT NULL DEFAULT '',
            community_other_guidance TEXT NOT NULL DEFAULT '',
            community_source_locator TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            considerations TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(profile_name, outcome_id)
        );

        CREATE INDEX IF NOT EXISTS idx_csf_profiles_name_outcome_type
            ON csf_profiles(profile_name, outcome_type, outcome_id);

        -- Profile source material can produce action examples that differ
        -- from the generic CSF wording.  These are examples only; the action
        -- records themselves remain separately profile-scoped.
        CREATE TABLE IF NOT EXISTS csf_profile_action_guidance (
            profile_id TEXT NOT NULL,
            subcategory_id TEXT NOT NULL CHECK(length(trim(subcategory_id)) > 0),
            action_title_example TEXT NOT NULL DEFAULT '',
            action_details_example TEXT NOT NULL DEFAULT '',
            action_rationale_example TEXT NOT NULL DEFAULT '',
            source_kind TEXT NOT NULL DEFAULT '',
            prompt_version TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(profile_id, subcategory_id),
            FOREIGN KEY(profile_id) REFERENCES csf_profile_definitions(profile_id) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_csf_profile_action_guidance_profile
            ON csf_profile_action_guidance(profile_id, subcategory_id);

        CREATE TABLE IF NOT EXISTS csf_supporting_basis (
            basis_id TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL,
            subcategory_id TEXT NOT NULL CHECK(length(trim(subcategory_id)) > 0),
            basis_type TEXT NOT NULL CHECK(basis_type IN ('local_evidence', 'document', 'attestation', 'decision_note', 'other')),
            title TEXT NOT NULL CHECK(length(trim(title)) > 0),
            details TEXT,
            reference_location TEXT,
            recorded_on TEXT,
            review_on TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_csf_supporting_basis_subcategory
            ON csf_supporting_basis(subcategory_id, updated_at, basis_id);

        -- A Supporting Basis record is the durable, Profile-scoped evidence
        -- artifact.  Its original Subcategory remains its primary context;
        -- these links record every additional claim that the same artifact
        -- supports without copying the evidence.
        CREATE TABLE IF NOT EXISTS csf_evidence_outcome_links (
            evidence_outcome_link_id TEXT PRIMARY KEY,
            basis_id TEXT NOT NULL,
            profile_id TEXT NOT NULL,
            subcategory_id TEXT NOT NULL CHECK(length(trim(subcategory_id)) > 0),
            link_role TEXT NOT NULL CHECK(link_role IN ('supports_outcome', 'supports_current_assessment', 'supports_target_rationale')),
            assertion_text TEXT NOT NULL DEFAULT '',
            applicability_note TEXT NOT NULL DEFAULT '',
            linked_by TEXT,
            linked_at TEXT NOT NULL,
            reviewed_at TEXT,
            review_note TEXT NOT NULL DEFAULT '',
            UNIQUE(basis_id, subcategory_id, link_role),
            FOREIGN KEY(basis_id) REFERENCES csf_supporting_basis(basis_id) ON DELETE CASCADE,
            FOREIGN KEY(profile_id) REFERENCES csf_profile_definitions(profile_id) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_csf_evidence_outcome_links_profile_outcome
            ON csf_evidence_outcome_links(profile_id, subcategory_id, linked_at, basis_id);

        CREATE TABLE IF NOT EXISTS csf_reviewed_actions (
            action_id TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL,
            subcategory_id TEXT NOT NULL CHECK(length(trim(subcategory_id)) > 0),
            title TEXT NOT NULL CHECK(length(trim(title)) > 0),
            details TEXT,
            rationale TEXT,
            action_status TEXT NOT NULL CHECK(action_status IN ('planned', 'in_progress', 'completed', 'not_proceeding')),
            completed_at TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_csf_reviewed_actions_subcategory
            ON csf_reviewed_actions(subcategory_id, action_status, updated_at, action_id);

        CREATE TABLE IF NOT EXISTS csf_reviewed_action_updates (
            action_update_id TEXT PRIMARY KEY,
            action_id TEXT NOT NULL,
            action_status TEXT NOT NULL CHECK(action_status IN ('planned', 'in_progress', 'completed', 'not_proceeding')),
            progress_note TEXT,
            recorded_by TEXT,
            recorded_at TEXT NOT NULL,
            FOREIGN KEY(action_id) REFERENCES csf_reviewed_actions(action_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_csf_reviewed_action_updates_timeline
            ON csf_reviewed_action_updates(action_id, recorded_at, action_update_id);

        CREATE TRIGGER IF NOT EXISTS prevent_csf_reviewed_action_update_change
        BEFORE UPDATE ON csf_reviewed_action_updates
        BEGIN
            SELECT RAISE(ABORT, 'CSF reviewed-action updates are append-only.');
        END;

        CREATE TABLE IF NOT EXISTS csf_reviewed_action_basis_links (
            action_id TEXT NOT NULL,
            basis_id TEXT NOT NULL,
            link_role TEXT NOT NULL DEFAULT 'supports_action' CHECK(link_role IN ('supports_action', 'supports_progress', 'supports_completion')),
            assertion_text TEXT NOT NULL DEFAULT '',
            applicability_note TEXT NOT NULL DEFAULT '',
            linked_by TEXT,
            linked_at TEXT NOT NULL,
            reviewed_at TEXT,
            review_note TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(action_id, basis_id),
            FOREIGN KEY(action_id) REFERENCES csf_reviewed_actions(action_id) ON DELETE CASCADE,
            FOREIGN KEY(basis_id) REFERENCES csf_supporting_basis(basis_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_csf_reviewed_action_basis_links_basis
            ON csf_reviewed_action_basis_links(basis_id, action_id);

        CREATE TABLE IF NOT EXISTS csf_reviewed_action_update_basis_links (
            action_update_id TEXT NOT NULL,
            basis_id TEXT NOT NULL,
            assertion_text TEXT NOT NULL DEFAULT '',
            applicability_note TEXT NOT NULL DEFAULT '',
            linked_by TEXT,
            linked_at TEXT NOT NULL,
            reviewed_at TEXT,
            review_note TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(action_update_id, basis_id),
            FOREIGN KEY(action_update_id) REFERENCES csf_reviewed_action_updates(action_update_id) ON DELETE CASCADE,
            FOREIGN KEY(basis_id) REFERENCES csf_supporting_basis(basis_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_csf_reviewed_action_update_basis_links_basis
            ON csf_reviewed_action_update_basis_links(basis_id, action_update_id);

        CREATE TABLE IF NOT EXISTS csf_evidence_link_audit_events (
            evidence_link_audit_event_id TEXT PRIMARY KEY,
            profile_id TEXT NOT NULL,
            basis_id TEXT NOT NULL,
            target_type TEXT NOT NULL CHECK(target_type IN ('outcome', 'action', 'action_update')),
            target_id TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK(event_type IN ('linked', 'unlinked', 'updated')),
            link_role TEXT NOT NULL DEFAULT '',
            assertion_text TEXT NOT NULL DEFAULT '',
            applicability_note TEXT NOT NULL DEFAULT '',
            recorded_by TEXT,
            recorded_at TEXT NOT NULL,
            FOREIGN KEY(basis_id) REFERENCES csf_supporting_basis(basis_id) ON DELETE RESTRICT,
            FOREIGN KEY(profile_id) REFERENCES csf_profile_definitions(profile_id) ON DELETE RESTRICT
        );

        CREATE INDEX IF NOT EXISTS idx_csf_evidence_link_audit_events_target
            ON csf_evidence_link_audit_events(profile_id, target_type, target_id, recorded_at);

        CREATE TABLE IF NOT EXISTS csf_reference_frameworks (
            framework_id TEXT PRIMARY KEY,
            framework_name TEXT NOT NULL,
            publisher TEXT NOT NULL,
            version TEXT NOT NULL,
            mapping_name TEXT NOT NULL,
            mapping_reference_id TEXT,
            mapping_status TEXT NOT NULL,
            mapping_source_path TEXT NOT NULL,
            mapping_source_sha256 TEXT NOT NULL,
            catalog_source_path TEXT NOT NULL,
            catalog_source_sha256 TEXT NOT NULL,
            imported_at TEXT NOT NULL
        );

        -- A selectable catalog is a product setting, separate from the
        -- imported framework and its official controls/mappings.  Disabling a
        -- catalog only removes it from the action picker; it never removes
        -- reference data or an action already linked to a control.
        CREATE TABLE IF NOT EXISTS csf_control_catalogs (
            framework_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL CHECK(length(trim(display_name)) > 0),
            version TEXT NOT NULL DEFAULT '',
            source_label TEXT NOT NULL DEFAULT '',
            source_path TEXT NOT NULL DEFAULT '',
            is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
            registered_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS csf_profile_control_catalogs (
            profile_id TEXT NOT NULL,
            framework_id TEXT NOT NULL,
            is_enabled INTEGER NOT NULL DEFAULT 1 CHECK(is_enabled IN (0, 1)),
            configured_by TEXT,
            configured_at TEXT NOT NULL,
            PRIMARY KEY(profile_id, framework_id),
            FOREIGN KEY(profile_id) REFERENCES csf_profile_definitions(profile_id) ON DELETE RESTRICT,
            FOREIGN KEY(framework_id) REFERENCES csf_control_catalogs(framework_id) ON DELETE RESTRICT
        );

        CREATE INDEX IF NOT EXISTS idx_csf_profile_control_catalogs_enabled
            ON csf_profile_control_catalogs(profile_id, is_enabled, framework_id);

        CREATE TABLE IF NOT EXISTS csf_reference_controls (
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            title TEXT NOT NULL,
            statement_text TEXT,
            catalog_control_id TEXT NOT NULL,
            source_catalog_uuid TEXT,
            PRIMARY KEY(framework_id, control_id),
            FOREIGN KEY(framework_id) REFERENCES csf_reference_frameworks(framework_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_csf_reference_controls_title
            ON csf_reference_controls(framework_id, title, control_id);

        CREATE TABLE IF NOT EXISTS csf_subcategory_control_mappings (
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            subcategory_id TEXT NOT NULL,
            interpretation_text TEXT NOT NULL DEFAULT '',
            suggested_action_text TEXT NOT NULL DEFAULT '',
            action_title_example TEXT NOT NULL DEFAULT '',
            action_details_example TEXT NOT NULL DEFAULT '',
            action_rationale_example TEXT NOT NULL DEFAULT '',
            confidence_note TEXT NOT NULL DEFAULT '',
            interpretation_source TEXT NOT NULL DEFAULT 'product-generated-v1',
            interpretation_updated_at TEXT,
            PRIMARY KEY(framework_id, control_id, subcategory_id),
            FOREIGN KEY(framework_id, control_id)
                REFERENCES csf_reference_controls(framework_id, control_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_csf_subcategory_control_mappings_subcategory
            ON csf_subcategory_control_mappings(subcategory_id, framework_id, control_id);

        CREATE TABLE IF NOT EXISTS csf_control_mapping_relationships (
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            subcategory_id TEXT NOT NULL,
            relationship_role TEXT NOT NULL CHECK(relationship_role IN (
                'produces_outcome_information', 'consumes_outcome_information',
                'enables_outcome_capability', 'context_only'
            )),
            information_id TEXT NOT NULL DEFAULT '',
            relationship_scope TEXT NOT NULL CHECK(relationship_scope IN ('direct', 'partial', 'indirect')),
            rationale TEXT NOT NULL CHECK(length(trim(rationale)) > 0),
            review_status TEXT NOT NULL CHECK(review_status IN ('draft', 'reviewed', 'rejected')),
            source_label TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(framework_id, control_id, subcategory_id, relationship_role, information_id),
            FOREIGN KEY(framework_id, control_id, subcategory_id)
                REFERENCES csf_subcategory_control_mappings(framework_id, control_id, subcategory_id)
                ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_csf_control_mapping_relationships_subcategory
            ON csf_control_mapping_relationships(subcategory_id, framework_id, control_id, review_status);

        CREATE TABLE IF NOT EXISTS csf_control_mapping_relationship_sources (
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            subcategory_id TEXT NOT NULL,
            source_artifact TEXT NOT NULL,
            request_custom_id TEXT NOT NULL,
            model_name TEXT NOT NULL,
            prompt_version TEXT NOT NULL,
            source_kind TEXT NOT NULL CHECK(source_kind IN ('ai_assisted_draft', 'human_reviewed_decision')),
            response_json TEXT NOT NULL,
            imported_at TEXT NOT NULL,
            PRIMARY KEY(framework_id, control_id, subcategory_id, source_artifact),
            FOREIGN KEY(framework_id, control_id, subcategory_id)
                REFERENCES csf_subcategory_control_mappings(framework_id, control_id, subcategory_id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS csf_reviewed_action_control_links (
            action_id TEXT PRIMARY KEY,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            subcategory_id TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            FOREIGN KEY(action_id) REFERENCES csf_reviewed_actions(action_id) ON DELETE CASCADE,
            FOREIGN KEY(framework_id, control_id, subcategory_id)
                REFERENCES csf_subcategory_control_mappings(framework_id, control_id, subcategory_id) ON DELETE RESTRICT,
            UNIQUE(framework_id, control_id, subcategory_id)
        );

        CREATE INDEX IF NOT EXISTS idx_csf_reviewed_action_control_links_subcategory
            ON csf_reviewed_action_control_links(subcategory_id, framework_id, control_id);

        CREATE TABLE IF NOT EXISTS csf_information_items (
            information_id TEXT PRIMARY KEY,
            title TEXT NOT NULL CHECK(length(trim(title)) > 0),
            description TEXT NOT NULL CHECK(length(trim(description)) > 0),
            source_label TEXT NOT NULL DEFAULT 'product-authored-v1',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS csf_subcategory_information_sources (
            information_id TEXT NOT NULL,
            source_subcategory_id TEXT NOT NULL CHECK(length(trim(source_subcategory_id)) > 0),
            source_guidance TEXT NOT NULL CHECK(length(trim(source_guidance)) > 0),
            PRIMARY KEY(information_id, source_subcategory_id),
            FOREIGN KEY(information_id) REFERENCES csf_information_items(information_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_csf_information_sources_subcategory
            ON csf_subcategory_information_sources(source_subcategory_id, information_id);

        CREATE TABLE IF NOT EXISTS csf_subcategory_information_uses (
            information_id TEXT NOT NULL,
            consumer_subcategory_id TEXT NOT NULL CHECK(length(trim(consumer_subcategory_id)) > 0),
            dependency_kind TEXT NOT NULL CHECK(dependency_kind IN ('required_input', 'planning_input', 'event_input')),
            use_reason TEXT NOT NULL CHECK(length(trim(use_reason)) > 0),
            PRIMARY KEY(information_id, consumer_subcategory_id),
            FOREIGN KEY(information_id) REFERENCES csf_information_items(information_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_csf_information_uses_subcategory
            ON csf_subcategory_information_uses(consumer_subcategory_id, dependency_kind, information_id);

        CREATE TABLE IF NOT EXISTS csf_subcategory_capability_dependencies (
            prerequisite_subcategory_id TEXT NOT NULL CHECK(length(trim(prerequisite_subcategory_id)) > 0),
            dependent_subcategory_id TEXT NOT NULL CHECK(length(trim(dependent_subcategory_id)) > 0),
            dependency_strength TEXT NOT NULL CHECK(dependency_strength IN ('hard_gate', 'partial_gate', 'supporting_capability')),
            rationale TEXT NOT NULL CHECK(length(trim(rationale)) > 0),
            source_label TEXT NOT NULL DEFAULT 'product-authored-v1',
            updated_at TEXT NOT NULL,
            PRIMARY KEY(prerequisite_subcategory_id, dependent_subcategory_id)
        );

        CREATE INDEX IF NOT EXISTS idx_csf_capability_dependencies_dependent
            ON csf_subcategory_capability_dependencies(dependent_subcategory_id, dependency_strength, prerequisite_subcategory_id);

        """
    )
    guidance_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(csf_subcategory_guidance)").fetchall()
    }
    if "single_pc_scope_note" in guidance_columns:
        with connection:
            connection.execute(
                """
                CREATE TABLE csf_subcategory_guidance_without_scope_note (
                    subcategory_id TEXT NOT NULL,
                    language_code TEXT NOT NULL,
                    plain_english_text TEXT NOT NULL CHECK(length(trim(plain_english_text)) > 0),
                    examples_json TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY(subcategory_id, language_code)
                )
                """
            )
            connection.execute(
                """
                INSERT INTO csf_subcategory_guidance_without_scope_note (
                    subcategory_id, language_code, plain_english_text, examples_json
                )
                SELECT subcategory_id, language_code, plain_english_text, examples_json
                FROM csf_subcategory_guidance
                """
            )
            connection.execute("DROP TABLE csf_subcategory_guidance")
            connection.execute(
                "ALTER TABLE csf_subcategory_guidance_without_scope_note RENAME TO csf_subcategory_guidance"
            )
        guidance_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(csf_subcategory_guidance)").fetchall()
        }
    basis_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(csf_supporting_basis)").fetchall()}
    action_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(csf_reviewed_actions)").fetchall()}
    action_basis_link_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(csf_reviewed_action_basis_links)").fetchall()
    }
    reference_control_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(csf_reference_controls)").fetchall()}
    mapping_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(csf_subcategory_control_mappings)").fetchall()}
    profile_outcome_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(csf_profiles)").fetchall()}
    profile_definition_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(csf_profile_definitions)").fetchall()}
    profile_audit_columns = {str(row["name"]) for row in connection.execute("PRAGMA table_info(csf_profile_audit_events)").fetchall()}
    frozen_source_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(csf_community_profile_frozen_sources)").fetchall()
    }
    with connection:
        if "recorded_on" not in basis_columns:
            connection.execute("ALTER TABLE csf_supporting_basis ADD COLUMN recorded_on TEXT")
        if "review_on" not in basis_columns:
            connection.execute("ALTER TABLE csf_supporting_basis ADD COLUMN review_on TEXT")
        if "profile_id" not in basis_columns:
            connection.execute("ALTER TABLE csf_supporting_basis ADD COLUMN profile_id TEXT")
        # Existing links predate the evidence library. Preserve them as
        # supports-action assertions and add context for each evidence use.
        if "link_role" not in action_basis_link_columns:
            connection.execute("ALTER TABLE csf_reviewed_action_basis_links ADD COLUMN link_role TEXT NOT NULL DEFAULT 'supports_action'")
        if "assertion_text" not in action_basis_link_columns:
            connection.execute("ALTER TABLE csf_reviewed_action_basis_links ADD COLUMN assertion_text TEXT NOT NULL DEFAULT ''")
        if "applicability_note" not in action_basis_link_columns:
            connection.execute("ALTER TABLE csf_reviewed_action_basis_links ADD COLUMN applicability_note TEXT NOT NULL DEFAULT ''")
        if "linked_by" not in action_basis_link_columns:
            connection.execute("ALTER TABLE csf_reviewed_action_basis_links ADD COLUMN linked_by TEXT")
        if "reviewed_at" not in action_basis_link_columns:
            connection.execute("ALTER TABLE csf_reviewed_action_basis_links ADD COLUMN reviewed_at TEXT")
        if "review_note" not in action_basis_link_columns:
            connection.execute("ALTER TABLE csf_reviewed_action_basis_links ADD COLUMN review_note TEXT NOT NULL DEFAULT ''")
        if "rationale" not in action_columns:
            connection.execute("ALTER TABLE csf_reviewed_actions ADD COLUMN rationale TEXT")
        if "profile_id" not in action_columns:
            connection.execute("ALTER TABLE csf_reviewed_actions ADD COLUMN profile_id TEXT")
        connection.execute(
            """CREATE INDEX IF NOT EXISTS idx_csf_supporting_basis_profile_subcategory
            ON csf_supporting_basis(profile_id, subcategory_id, updated_at, basis_id)"""
        )
        connection.execute(
            """CREATE INDEX IF NOT EXISTS idx_csf_reviewed_actions_profile_subcategory
            ON csf_reviewed_actions(profile_id, subcategory_id, action_status, updated_at, action_id)"""
        )
        if "statement_text" not in reference_control_columns:
            connection.execute("ALTER TABLE csf_reference_controls ADD COLUMN statement_text TEXT")
        if "interpretation_text" not in mapping_columns:
            connection.execute("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN interpretation_text TEXT NOT NULL DEFAULT ''")
        if "suggested_action_text" not in mapping_columns:
            connection.execute("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN suggested_action_text TEXT NOT NULL DEFAULT ''")
        if "action_title_example" not in mapping_columns:
            connection.execute("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN action_title_example TEXT NOT NULL DEFAULT ''")
        if "action_details_example" not in mapping_columns:
            connection.execute("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN action_details_example TEXT NOT NULL DEFAULT ''")
        if "action_rationale_example" not in mapping_columns:
            connection.execute("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN action_rationale_example TEXT NOT NULL DEFAULT ''")
        if "confidence_note" not in mapping_columns:
            connection.execute("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN confidence_note TEXT NOT NULL DEFAULT ''")
        if "interpretation_source" not in mapping_columns:
            connection.execute("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN interpretation_source TEXT NOT NULL DEFAULT 'product-generated-v1'")
        if "interpretation_updated_at" not in mapping_columns:
            connection.execute("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN interpretation_updated_at TEXT")
        if "generic_action_title" not in guidance_columns:
            connection.execute("ALTER TABLE csf_subcategory_guidance ADD COLUMN generic_action_title TEXT NOT NULL DEFAULT ''")
        if "generic_action_details" not in guidance_columns:
            connection.execute("ALTER TABLE csf_subcategory_guidance ADD COLUMN generic_action_details TEXT NOT NULL DEFAULT ''")
        if "generic_action_rationale" not in guidance_columns:
            connection.execute("ALTER TABLE csf_subcategory_guidance ADD COLUMN generic_action_rationale TEXT NOT NULL DEFAULT ''")
        if "supporting_evidence_reference" not in profile_audit_columns:
            connection.execute("ALTER TABLE csf_profile_audit_events ADD COLUMN supporting_evidence_reference TEXT NOT NULL DEFAULT ''")
        if "profile_status" not in profile_outcome_columns:
            connection.execute("ALTER TABLE csf_profiles ADD COLUMN profile_status TEXT NOT NULL DEFAULT 'not_selected'")
        if "community_priority" not in profile_outcome_columns:
            connection.execute("ALTER TABLE csf_profiles ADD COLUMN community_priority TEXT NOT NULL DEFAULT ''")
        if "community_risk_rationale" not in profile_outcome_columns:
            connection.execute("ALTER TABLE csf_profiles ADD COLUMN community_risk_rationale TEXT NOT NULL DEFAULT ''")
        if "community_supporting_references" not in profile_outcome_columns:
            connection.execute("ALTER TABLE csf_profiles ADD COLUMN community_supporting_references TEXT NOT NULL DEFAULT ''")
        if "community_other_guidance" not in profile_outcome_columns:
            connection.execute("ALTER TABLE csf_profiles ADD COLUMN community_other_guidance TEXT NOT NULL DEFAULT ''")
        if "community_source_locator" not in profile_outcome_columns:
            connection.execute("ALTER TABLE csf_profiles ADD COLUMN community_source_locator TEXT NOT NULL DEFAULT ''")
        if "archived_at" not in profile_definition_columns:
            connection.execute("ALTER TABLE csf_profile_definitions ADD COLUMN archived_at TEXT")
        if "profile_id" not in profile_definition_columns:
            connection.execute("ALTER TABLE csf_profile_definitions ADD COLUMN profile_id TEXT")
        if "profile_kind" not in profile_definition_columns:
            connection.execute("ALTER TABLE csf_profile_definitions ADD COLUMN profile_kind TEXT NOT NULL DEFAULT 'organizational'")
        if "source_version" not in frozen_source_columns:
            connection.execute("ALTER TABLE csf_community_profile_frozen_sources ADD COLUMN source_version TEXT NOT NULL DEFAULT ''")
        if "source_published_at" not in frozen_source_columns:
            connection.execute("ALTER TABLE csf_community_profile_frozen_sources ADD COLUMN source_published_at TEXT")
        if "source_reviewed_at" not in frozen_source_columns:
            connection.execute("ALTER TABLE csf_community_profile_frozen_sources ADD COLUMN source_reviewed_at TEXT")
        if "next_source_review_at" not in frozen_source_columns:
            connection.execute("ALTER TABLE csf_community_profile_frozen_sources ADD COLUMN next_source_review_at TEXT")
        # Action progress entries are immutable while their parent action exists.
        # Removing a parent action must still be able to cascade its history.
        connection.execute("DROP TRIGGER IF EXISTS prevent_csf_reviewed_action_update_delete")
        catalog_now = utc_now()
        connection.execute(
            """INSERT INTO csf_control_catalogs(
                framework_id, display_name, version, source_label, source_path,
                is_enabled, registered_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(framework_id) DO UPDATE SET
                display_name=excluded.display_name, version=excluded.version,
                source_label=excluded.source_label, source_path=excluded.source_path,
                updated_at=excluded.updated_at""",
            (
                "nist-sp-800-53-r5.2.0", "NIST SP 800-53", "5.2.0",
                "NIST SP 800-53 Rev. 5.2.0 OSCAL catalog",
                "reference-data/NIST/NIST_SP-800-53_rev5_catalog.json",
                catalog_now, catalog_now,
            ),
        )
        community_catalog_checked_at = utc_now()
        connection.executemany(
            """INSERT INTO csf_community_profile_catalog(
                community_profile_id, profile_name, publisher, publication_status, focus,
                source_url, catalog_source_url, catalog_checked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(community_profile_id) DO UPDATE SET
                profile_name=excluded.profile_name, publisher=excluded.publisher,
                publication_status=excluded.publication_status, focus=excluded.focus,
                source_url=excluded.source_url, catalog_source_url=excluded.catalog_source_url,
                catalog_checked_at=excluded.catalog_checked_at""",
            [
                (*row, NIST_CSF_COMMUNITY_PROFILE_CATALOG_URL,
                 NIST_CSF_COMMUNITY_PROFILE_CATALOG_URL, community_catalog_checked_at)
                for row in NIST_CSF_COMMUNITY_PROFILES
            ],
        )
        profile_now = utc_now()
        connection.execute(
            """INSERT OR IGNORE INTO csf_profile_definitions(
                profile_id, profile_name, context_summary, community_profile_source, created_at, updated_at
            ) VALUES (?, ?, ?, '', ?, ?)""",
            (str(uuid.uuid4()), "Single-PC baseline", "A single user PC and its local cybersecurity context.", profile_now, profile_now),
        )
        profile_id_rows = connection.execute(
            "SELECT profile_name, profile_id FROM csf_profile_definitions"
        ).fetchall()
        for profile_id_row in profile_id_rows:
            if not str(profile_id_row["profile_id"] or "").strip():
                connection.execute(
                    "UPDATE csf_profile_definitions SET profile_id = ? WHERE profile_name = ?",
                    (str(uuid.uuid4()), profile_id_row["profile_name"]),
                )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_csf_profile_definitions_profile_id ON csf_profile_definitions(profile_id)"
        )
        connection.execute(
            """INSERT OR IGNORE INTO csf_active_profile(selection_id, profile_name, updated_at)
            VALUES (1, ?, ?)""",
            ("Single-PC baseline", profile_now),
        )
        base_profile_id = _seed_frozen_nist_base_profile(connection)
        _seed_csf_profile_outcome_rows(connection, "Single-PC baseline", profile_now)
        connection.execute(
            """INSERT OR IGNORE INTO csf_profile_source_lineage(profile_id, source_profile_id, source_role, copied_at)
            SELECT profile_id, ?, 'base', ? FROM csf_profile_definitions WHERE profile_name = 'Single-PC baseline'""",
            (base_profile_id, profile_now),
        )
        _seed_frozen_ransomware_community_profile(connection)
        _refresh_frozen_profile_category_statuses(connection, "NIST IR 8374 Rev. 1 Ransomware Community Profile")
        connection.execute(
            """UPDATE csf_community_profile_frozen_sources
            SET source_version = CASE community_profile_id
                WHEN 'nist-ransomware' THEN 'NIST IR 8374 Rev. 1'
                WHEN 'nist-cyber-ai-secure' THEN 'NIST IR 8596'
                WHEN 'nist-cyber-ai-defend' THEN 'NIST IR 8596'
                WHEN 'nist-cyber-ai-thwart' THEN 'NIST IR 8596'
                ELSE source_version END
            WHERE source_version = ''"""
        )
        connection.execute(
            """INSERT OR IGNORE INTO csf_profile_outcome_targets(
                profile_id, subcategory_id, target_assessment_level, updated_by, updated_at
            )
            SELECT definition.profile_id, outcome.outcome_id, 'fully_implemented', NULL, ?
            FROM csf_profiles outcome
            JOIN csf_profile_definitions definition ON definition.profile_name = outcome.profile_name
            WHERE outcome.outcome_type = 'subcategory'
              AND outcome.profile_status IN ('included', 'inherited')""",
            (profile_now,),
        )
        # Preserve working assessments created before profiles existed by
        # assigning them to the original single-PC baseline context.
        connection.execute(
            """INSERT OR IGNORE INTO csf_profile_current_assessments(
                profile_id, subcategory_id, assessment_level, updated_by, updated_at
            ) SELECT definition.profile_id, legacy.subcategory_id, legacy.assessment_level, legacy.updated_by, legacy.updated_at
            FROM csf_current_assessments legacy
            JOIN csf_profile_definitions definition ON definition.profile_name = 'Single-PC baseline'"""
        )
        baseline_profile_id = connection.execute(
            "SELECT profile_id FROM csf_profile_definitions WHERE profile_name = ?", ("Single-PC baseline",)
        ).fetchone()["profile_id"]
        if "profile_name" in basis_columns:
            connection.execute(
                """UPDATE csf_supporting_basis SET profile_id = (
                    SELECT profile_id FROM csf_profile_definitions definition
                    WHERE definition.profile_name = csf_supporting_basis.profile_name
                ) WHERE profile_id IS NULL"""
            )
        connection.execute("UPDATE csf_supporting_basis SET profile_id = ? WHERE profile_id IS NULL", (baseline_profile_id,))
        legacy_basis_rows = connection.execute(
            """SELECT basis_id, profile_id, subcategory_id, created_by, created_at
            FROM csf_supporting_basis
            WHERE profile_id IS NOT NULL AND trim(subcategory_id) <> ''"""
        ).fetchall()
        connection.executemany(
            """INSERT OR IGNORE INTO csf_evidence_outcome_links(
                evidence_outcome_link_id, basis_id, profile_id, subcategory_id,
                link_role, assertion_text, applicability_note, linked_by,
                linked_at, reviewed_at, review_note
            ) VALUES (?, ?, ?, ?, 'supports_outcome', '', '', ?, ?, NULL, '')""",
            [
                (str(uuid.uuid4()), row["basis_id"], row["profile_id"], row["subcategory_id"], row["created_by"], row["created_at"])
                for row in legacy_basis_rows
            ],
        )
        if "profile_name" in action_columns:
            connection.execute(
                """UPDATE csf_reviewed_actions SET profile_id = (
                    SELECT profile_id FROM csf_profile_definitions definition
                    WHERE definition.profile_name = csf_reviewed_actions.profile_name
                ) WHERE profile_id IS NULL"""
            )
        connection.execute("UPDATE csf_reviewed_actions SET profile_id = ? WHERE profile_id IS NULL", (baseline_profile_id,))
        # Existing profiles start with the workspace selection that was in
        # effect at migration time. Future edits are Profile-specific.
        connection.execute(
            """INSERT OR IGNORE INTO csf_profile_control_catalogs(
                profile_id, framework_id, is_enabled, configured_by, configured_at
            )
            SELECT profile.profile_id, catalog.framework_id, catalog.is_enabled, NULL, ?
            FROM csf_profile_definitions profile
            CROSS JOIN csf_control_catalogs catalog
            WHERE profile.profile_id IS NOT NULL""",
            (profile_now,),
        )
    connection.executemany(
        "INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES (?, ?, ?)",
        [
            (1, utc_now(), "Initial normalized indicator, state, baseline, and evidence schema."),
            (2, utc_now(), "Additive Phase 2 collector, report, finding, alert, and delivery schema foundation."),
            (3, utc_now(), "Add advisory-only local CSF Category and outcome storage."),
            (4, utc_now(), "Add product-authored plain-English guidance for official CSF Subcategories."),
            (5, utc_now(), "Add Single-PC CSF Profile assessment metadata for official CSF Subcategories."),
            (6, utc_now(), "Add append-only CSF outcome assessment audit events."),
            (7, utc_now(), "Remove product scope notes from CSF Subcategory guidance."),
            (8, utc_now(), "Add current CSF Subcategory assessment storage outside the audit ledger."),
            (9, utc_now(), "Add supporting-basis and reviewed-action records linked to CSF Subcategories."),
            (10, utc_now(), "Add action rationale and supporting-basis review dates."),
            (11, utc_now(), "Add append-only progress updates for reviewed actions."),
            (12, utc_now(), "Permit parent-action deletion to cascade its progress history."),
            (13, utc_now(), "Add NIST SP 800-53 reference controls and CSF informative-reference mappings."),
            (14, utc_now(), "Link one reviewed action to an optional mapped reference control."),
            (15, utc_now(), "Store official NIST SP 800-53 control statements for contextual action selection."),
            (16, utc_now(), "Add product-authored, per-mapping applicability and action-direction descriptions."),
            (17, utc_now(), "Add per-mapping action-field examples for the Tile 3 action form."),
            (18, utc_now(), "Store batch-generated action-detail examples and mapping review notes."),
            (19, utc_now(), "Add product-authored CSF outcome information-flow planning relationships."),
            (20, utc_now(), "Add product-authored CSF capability prerequisite relationships."),
            (21, utc_now(), "Add reviewed product-authored control-to-outcome relationship directions."),
            (22, utc_now(), "Store product-authored generic action titles for CSF Subcategories."),
            (23, utc_now(), "Store generic action details and rationale for CSF Subcategories."),
            (24, utc_now(), "Add selectable, framework-neutral control catalogs."),
            (25, utc_now(), "Add NIST CSF Organizational Profile rows for Categories and Subcategories."),
            (26, utc_now(), "Add defined CSF Profiles and persistent active-profile selection."),
            (27, utc_now(), "Add sourced NIST CSF Community Profile catalog and profile-source links."),
            (28, utc_now(), "Add append-only audit events for CSF Organizational Profile creation and tailoring."),
            (29, utc_now(), "Add explicit profile tailoring status for each Category and Subcategory."),
            (30, utc_now(), "Allow retired Organizational Profiles to be archived while retaining their audit history."),
            (31, utc_now(), "Scope Tile 3 assessments, actions, and evidence to the selected Organizational Profile."),
            (32, utc_now(), "Use globally unique Profile identifiers for Tile 3 records."),
            (33, utc_now(), "Store per-outcome Target assessments using the Organizational Profile UUID."),
            (34, utc_now(), "Add supporting-evidence references to immutable Organizational Profile audit events."),
            (35, utc_now(), "Add frozen UUID-backed Community Profile source artifacts."),
            (36, utc_now(), "Add frozen NIST base source and profile source-lineage records."),
            (37, utc_now(), "Correct a typographical error in the frozen Ransomware Community Profile guidance."),
            (38, utc_now(), "Store Community Profile priority, risk rationale, supporting references, and source locators separately from outcome notes."),
            (39, utc_now(), "Store distinct Community Profile focus-area guidance without flattening it into outcome notes."),
            (40, utc_now(), "Add profile-specific action example templates with generic CSF fallback."),
            (41, utc_now(), "Correct the ID.IM-02 Cyber AI Thwart source rationale and retain base CSF Tile 2 guidance."),
            (42, utc_now(), "Add reusable profile-scoped evidence artifacts and auditable outcome, action, and action-update uses."),
            (43, utc_now(), "Add append-only audit events for evidence-link changes."),
            (44, utc_now(), "Scope control-catalog selection to each CSF Profile."),
        ],
    )
    connection.execute(
        """UPDATE csf_profiles
        SET notes = REPLACE(notes, 'Communicationregarding', 'Communication regarding')
        WHERE profile_name = 'NIST IR 8374 Rev. 1 Ransomware Community Profile'
          AND notes LIKE '%Communicationregarding%'"""
    )
    connection.execute(
        """UPDATE csf_profiles
        SET notes = ?, rationale = '', updated_at = ?
        WHERE profile_name = 'Cyber AI - Thwart' AND outcome_id = 'ID.IM-02'""",
        (
            "Organizations may consider leveraging and implementing AI-assisted penetration-testing and "
            "red-teaming tools to maintain pace and scale of AI-enabled cyber-attacks when performing "
            "security tests.",
            utc_now(),
        ),
    )
    connection.execute(
        """UPDATE csf_community_profile_outcome_facets
        SET considerations = ?, updated_at = ?
        WHERE profile_id = ? AND outcome_id = 'ID.IM-02' AND facet_id = 'thwart'""",
        (
            "Standard cybersecurity practices apply. (Rationale) Organizations may consider leveraging and "
            "implementing AI-assisted penetration-testing and red-teaming tools to maintain pace and scale "
            "of AI-enabled cyber-attacks when performing security tests.",
            utc_now(),
            "c2dc3303-5dae-4789-bc88-85419ac445c6",
        ),
    )
    connection.executemany(
        """INSERT INTO csf_subcategory_guidance(subcategory_id, language_code, plain_english_text, examples_json, generic_action_title, generic_action_details, generic_action_rationale)
        VALUES (?, 'en-US', ?, ?, ?, ?, ?)
        ON CONFLICT(subcategory_id, language_code) DO UPDATE SET plain_english_text=excluded.plain_english_text,
            examples_json=excluded.examples_json, generic_action_title=excluded.generic_action_title,
            generic_action_details=excluded.generic_action_details, generic_action_rationale=excluded.generic_action_rationale""",
        [(identifier, text, json.dumps(PRODUCT_EXAMPLES_EN_US[identifier]), GENERIC_ACTION_TITLE_EN_US[identifier], GENERIC_ACTION_DETAILS_EN_US[identifier], GENERIC_ACTION_RATIONALE_EN_US[identifier]) for identifier, text in PLAIN_ENGLISH_GUIDANCE_EN_US.items()],
    )
    connection.executemany(
        """INSERT INTO csf_subcategory_profile_metadata(subcategory_id, language_code, assessment_method, research_guidance, supporting_note_required)
        VALUES (?, 'en-US', ?, ?, ?)
        ON CONFLICT(subcategory_id, language_code) DO UPDATE SET assessment_method=excluded.assessment_method, research_guidance=excluded.research_guidance, supporting_note_required=excluded.supporting_note_required""",
        [(identifier, value["assessment_method"], value["research_guidance"], int(value["supporting_note_required"])) for identifier, value in SUBCATEGORY_PROFILE_METADATA_EN_US.items()],
    )
    flow_updated_at = utc_now()
    connection.executemany(
        """INSERT INTO csf_information_items(information_id, title, description, source_label, updated_at)
        VALUES (?, ?, ?, 'product-authored-v1', ?)
        ON CONFLICT(information_id) DO UPDATE SET title=excluded.title, description=excluded.description,
            source_label=excluded.source_label, updated_at=excluded.updated_at""",
        [(item["information_id"], item["title"], item["description"], flow_updated_at) for item in INFORMATION_ITEMS],
    )
    connection.executemany(
        """INSERT INTO csf_subcategory_information_sources(information_id, source_subcategory_id, source_guidance)
        VALUES (?, ?, ?)
        ON CONFLICT(information_id, source_subcategory_id) DO UPDATE SET source_guidance=excluded.source_guidance""",
        [(item["information_id"], item["source_subcategory_id"], item["source_guidance"]) for item in INFORMATION_SOURCES],
    )
    connection.executemany(
        """INSERT INTO csf_subcategory_information_uses(information_id, consumer_subcategory_id, dependency_kind, use_reason)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(information_id, consumer_subcategory_id) DO UPDATE SET dependency_kind=excluded.dependency_kind,
            use_reason=excluded.use_reason""",
        [(item["information_id"], item["consumer_subcategory_id"], item["dependency_kind"], item["use_reason"]) for item in INFORMATION_USES],
    )
    capability_updated_at = utc_now()
    connection.executemany(
        """INSERT INTO csf_subcategory_capability_dependencies(
            prerequisite_subcategory_id, dependent_subcategory_id, dependency_strength, rationale, source_label, updated_at
        ) VALUES (?, ?, ?, ?, 'product-authored-v1', ?)
        ON CONFLICT(prerequisite_subcategory_id, dependent_subcategory_id) DO UPDATE SET
            dependency_strength=excluded.dependency_strength, rationale=excluded.rationale,
            source_label=excluded.source_label, updated_at=excluded.updated_at""",
        [
            (
                item["prerequisite_subcategory_id"], item["dependent_subcategory_id"],
                item["dependency_strength"], item["rationale"], capability_updated_at,
            )
            for item in CAPABILITY_DEPENDENCIES
        ],
    )
    connection.commit()


LOCAL_CSF_FUNCTION_IDS = {"GV", "ID", "PR", "DE", "RS", "RC"}
LOCAL_CSF_CATEGORY_ID_RE = re.compile(r"^LOCAL\.(GV|ID|PR|DE|RS|RC)\.(\d{2,})$")
LOCAL_CSF_OUTCOME_ID_RE = re.compile(r"^LOCAL\.(GV|ID|PR|DE|RS|RC)\.(\d{2,})\.(\d{2,})$")
CSF_AUDIT_EVENT_TYPES = {
    "evidence_linked",
    "evidence_unlinked",
    "note_recorded",
    "action_linked",
    "action_unlinked",
    "assessment_drafted",
    "assessment_recorded",
    "assessment_superseded",
}
CSF_ASSESSMENT_METHODS = {"evidence", "attestation", "review", "hybrid"}
CSF_ASSESSMENT_LEVELS = {
    "fully_implemented",
    "partly_implemented",
    "not_implemented",
    "not_applicable",
}
CSF_SUPPORTING_BASIS_TYPES = {
    "local_evidence",
    "document",
    "attestation",
    "decision_note",
    "other",
}
CSF_REVIEWED_ACTION_STATUSES = {
    "planned",
    "in_progress",
    "completed",
    "not_proceeding",
}


def _local_csf_text(value: Any, field_name: str, *, required: bool, maximum: int) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{field_name} is required.")
    if len(text) > maximum:
        raise ValueError(f"{field_name} must be {maximum} characters or fewer.")
    return text


def _optional_csf_audit_value(value: Any, field_name: str, allowed_values: set[str]) -> Optional[str]:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    if normalized not in allowed_values:
        allowed = ", ".join(sorted(allowed_values))
        raise ValueError(f"{field_name} must be one of: {allowed}.")
    return normalized


def _active_csf_profile_id(connection: sqlite3.Connection, profile_id: Any) -> str:
    """Validate a live Profile UUID before attaching Tile 3 work."""
    identifier = str(profile_id or "").strip()
    if not identifier:
        raise ValueError("profile_id is required.")
    row = connection.execute(
        """SELECT 1 FROM csf_profile_definitions
        WHERE profile_id = ? AND archived_at IS NULL""",
        (identifier,),
    ).fetchone()
    if row is None:
        raise ValueError("The selected Organizational Profile is not available.")
    return identifier


def record_csf_outcome_audit_event(
    connection: sqlite3.Connection,
    *,
    subcategory_id: Any,
    event_type: Any,
    assessment_method: Any = "",
    profile_id: Any = "",
    profile_version: Any = "",
    target_assessment_level: Any = "",
    current_assessment_level: Any = "",
    related_record_type: Any = "",
    related_record_id: Any = "",
    rationale_note: Any = "",
    payload: Any = None,
    recorded_by: Any = "",
    recorded_at: Optional[str] = None,
    supersedes_audit_event_id: Any = "",
    audit_event_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Append a durable, immutable event for one official CSF Subcategory outcome."""
    subcategory = str(subcategory_id or "").strip().upper()
    if not subcategory:
        raise ValueError("subcategory_id is required.")
    event = _optional_csf_audit_value(event_type, "event_type", CSF_AUDIT_EVENT_TYPES)
    if event is None:
        raise ValueError("event_type is required.")
    event_id = str(audit_event_id or uuid.uuid4()).strip()
    if not event_id:
        raise ValueError("audit_event_id must not be blank.")
    try:
        payload_json = json.dumps({} if payload is None else payload, ensure_ascii=True, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("payload must be JSON-serializable.") from exc

    values = {
        "audit_event_id": event_id,
        "subcategory_id": subcategory,
        "event_type": event,
        "assessment_method": _optional_csf_audit_value(assessment_method, "assessment_method", CSF_ASSESSMENT_METHODS),
        "profile_id": str(profile_id or "").strip() or None,
        "profile_version": str(profile_version or "").strip() or None,
        "target_assessment_level": _optional_csf_audit_value(target_assessment_level, "target_assessment_level", CSF_ASSESSMENT_LEVELS),
        "current_assessment_level": _optional_csf_audit_value(current_assessment_level, "current_assessment_level", CSF_ASSESSMENT_LEVELS),
        "related_record_type": str(related_record_type or "").strip() or None,
        "related_record_id": str(related_record_id or "").strip() or None,
        "rationale_note": str(rationale_note or "").strip() or None,
        "payload_json": payload_json,
        "recorded_by": str(recorded_by or "").strip() or None,
        "recorded_at": str(recorded_at or utc_now()).strip(),
        "supersedes_audit_event_id": str(supersedes_audit_event_id or "").strip() or None,
    }
    if not values["recorded_at"]:
        raise ValueError("recorded_at must not be blank.")
    with connection:
        connection.execute(
            """
            INSERT INTO csf_outcome_audit_events (
                audit_event_id, subcategory_id, event_type, assessment_method, profile_id,
                profile_version, target_assessment_level, current_assessment_level,
                related_record_type, related_record_id, rationale_note, payload_json,
                recorded_by, recorded_at, supersedes_audit_event_id
            ) VALUES (
                :audit_event_id, :subcategory_id, :event_type, :assessment_method, :profile_id,
                :profile_version, :target_assessment_level, :current_assessment_level,
                :related_record_type, :related_record_id, :rationale_note, :payload_json,
                :recorded_by, :recorded_at, :supersedes_audit_event_id
            )
            """,
            values,
        )
    row = connection.execute(
        "SELECT * FROM csf_outcome_audit_events WHERE audit_event_id = ?", (event_id,)
    ).fetchone()
    return dict(row) if row else {}


def list_csf_outcome_audit_events(
    connection: sqlite3.Connection, subcategory_id: Any, limit: int = 200
) -> List[Dict[str, Any]]:
    """Return a Subcategory's audit ledger in stable chronological order."""
    subcategory = str(subcategory_id or "").strip().upper()
    if not subcategory:
        raise ValueError("subcategory_id is required.")
    try:
        row_limit = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be a positive integer.") from exc
    if row_limit < 1:
        raise ValueError("limit must be a positive integer.")
    return [
        dict(row)
        for row in connection.execute(
            """
            SELECT * FROM csf_outcome_audit_events
            WHERE subcategory_id = ?
            ORDER BY recorded_at, audit_event_id
            LIMIT ?
            """,
            (subcategory, row_limit),
        ).fetchall()
    ]


def set_current_csf_assessment(
    connection: sqlite3.Connection,
    profile_id: Any,
    subcategory_id: Any,
    assessment_level: Any,
    updated_by: Any = "",
) -> Dict[str, Any]:
    """Store the current assessment and append an immutable change event."""
    profile = _active_csf_profile_id(connection, profile_id)
    subcategory = str(subcategory_id or "").strip().upper()
    if not subcategory:
        raise ValueError("subcategory_id is required.")
    level = _optional_csf_audit_value(
        assessment_level, "assessment_level", CSF_ASSESSMENT_LEVELS
    )
    if level is None:
        raise ValueError("assessment_level is required.")
    previous = connection.execute(
        """SELECT assessment_level, updated_at FROM csf_profile_current_assessments
        WHERE profile_id = ? AND subcategory_id = ?""",
        (profile, subcategory),
    ).fetchone()
    prior_level = str(previous["assessment_level"]) if previous is not None else None
    now = utc_now()
    if previous is not None and datetime.fromisoformat(now) <= datetime.fromisoformat(str(previous["updated_at"])):
        now = (datetime.fromisoformat(str(previous["updated_at"])) + timedelta(microseconds=1)).isoformat()
    with connection:
        connection.execute(
            """
            INSERT INTO csf_profile_current_assessments (
                profile_id, subcategory_id, assessment_level, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(profile_id, subcategory_id) DO UPDATE SET
                assessment_level=excluded.assessment_level,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (profile, subcategory, level, str(updated_by or "").strip() or None, now),
        )
        if prior_level != level:
            record_csf_outcome_audit_event(
                connection,
                subcategory_id=subcategory,
                event_type="assessment_recorded" if prior_level is None else "assessment_superseded",
                profile_id=profile,
                current_assessment_level=level,
                related_record_type="current_assessment",
                rationale_note="Current assessment changed.",
                payload={"previous_current_assessment_level": prior_level, "current_assessment_level": level},
                recorded_by=updated_by,
                recorded_at=now,
            )
    row = connection.execute(
        """SELECT * FROM csf_profile_current_assessments
        WHERE profile_id = ? AND subcategory_id = ?""", (profile, subcategory),
    ).fetchone()
    return dict(row) if row else {}


def list_current_csf_assessments(connection: sqlite3.Connection, profile_id: Any) -> Dict[str, Dict[str, Any]]:
    """Return one Profile's latest working assessment by official CSF Subcategory."""
    profile = _active_csf_profile_id(connection, profile_id)
    return {
        str(row["subcategory_id"]): dict(row)
        for row in connection.execute(
            """SELECT * FROM csf_profile_current_assessments
            WHERE profile_id = ? ORDER BY subcategory_id""",
            (profile,),
        ).fetchall()
    }


def list_csf_profile_definitions(connection: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Return the defined Organizational Profiles available to the CSF UI."""
    return [
        dict(row)
        for row in connection.execute(
            """SELECT * FROM csf_profile_definitions
            WHERE archived_at IS NULL ORDER BY
                CASE profile_kind WHEN 'frozen_base' THEN 0 WHEN 'frozen_community' THEN 1 ELSE 2 END,
                profile_name COLLATE NOCASE"""
        ).fetchall()
    ]


def list_csf_community_profiles(connection: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Return Community Profiles that have a locally imported, frozen artifact.

    The broader reference index is retained for provenance, but it must not
    appear as a selectable catalog until its actual profile content is present.
    """
    return [
        dict(row)
        for row in connection.execute(
            """SELECT catalog.*, frozen.profile_id AS frozen_profile_id,
                      frozen.source_version, frozen.source_published_at,
                      frozen.source_reviewed_at, frozen.next_source_review_at,
                      definition.profile_name AS imported_profile_name
            FROM csf_community_profile_catalog AS catalog
            JOIN csf_community_profile_frozen_sources AS frozen
                ON frozen.community_profile_id = catalog.community_profile_id
            JOIN csf_profile_definitions AS definition
                ON definition.profile_id = frozen.profile_id
               AND definition.profile_kind = 'frozen_community'
               AND definition.archived_at IS NULL
            ORDER BY catalog.publisher COLLATE NOCASE, catalog.profile_name COLLATE NOCASE"""
        ).fetchall()
    ]


def get_active_csf_profile(connection: sqlite3.Connection) -> Dict[str, Any]:
    """Return the one active profile and its profile-definition context."""
    row = connection.execute(
        """SELECT active.profile_name, active.updated_at, definition.profile_id, definition.profile_kind, definition.context_summary,
            definition.community_profile_source,
            COALESCE(selected_source.community_profile_id, frozen_source.community_profile_id) AS community_profile_id,
            catalog.profile_name AS community_profile_name,
            catalog.publisher AS community_profile_publisher,
            catalog.publication_status AS community_profile_publication_status,
            catalog.focus AS community_profile_focus,
            COALESCE(selected_frozen_source.source_version, frozen_source.source_version) AS community_profile_source_version,
            COALESCE(selected_frozen_source.source_published_at, frozen_source.source_published_at) AS community_profile_source_published_at,
            COALESCE(selected_frozen_source.source_reviewed_at, frozen_source.source_reviewed_at) AS community_profile_source_reviewed_at,
            COALESCE(selected_frozen_source.next_source_review_at, frozen_source.next_source_review_at) AS community_profile_next_source_review_at,
            lineage.source_profile_id,
            lineage.source_role,
            source_definition.profile_name AS source_profile_name,
            source_definition.profile_kind AS source_profile_kind
        FROM csf_active_profile active
        JOIN csf_profile_definitions definition ON definition.profile_name = active.profile_name
        LEFT JOIN csf_profile_community_profile_sources selected_source
            ON selected_source.profile_name = definition.profile_name
        LEFT JOIN csf_community_profile_frozen_sources frozen_source
            ON frozen_source.profile_id = definition.profile_id
        LEFT JOIN csf_community_profile_frozen_sources selected_frozen_source
            ON selected_frozen_source.community_profile_id = selected_source.community_profile_id
        LEFT JOIN csf_community_profile_catalog catalog
            ON catalog.community_profile_id = COALESCE(selected_source.community_profile_id, frozen_source.community_profile_id)
        LEFT JOIN csf_profile_source_lineage lineage
            ON lineage.profile_id = definition.profile_id
        LEFT JOIN csf_profile_definitions source_definition
            ON source_definition.profile_id = lineage.source_profile_id
        WHERE active.selection_id = 1 AND definition.archived_at IS NULL"""
    ).fetchone()
    return dict(row) if row is not None else {}


def set_active_csf_profile(connection: sqlite3.Connection, profile_name: Any) -> Dict[str, Any]:
    """Select a defined profile as the UI context without modifying profile rows."""
    name = str(profile_name or "").strip()
    if not name:
        raise ValueError("A defined profile must be selected.")
    exists = connection.execute(
        "SELECT 1 FROM csf_profile_definitions WHERE profile_name = ? AND archived_at IS NULL", (name,)
    ).fetchone()
    if exists is None:
        raise ValueError("The selected CSF Profile is not defined.")
    now = utc_now()
    with connection:
        connection.execute(
            """INSERT INTO csf_active_profile(selection_id, profile_name, updated_at)
            VALUES (1, ?, ?)
            ON CONFLICT(selection_id) DO UPDATE SET profile_name=excluded.profile_name,
                updated_at=excluded.updated_at""",
            (name, now),
        )
    return get_active_csf_profile(connection)


def archive_csf_profile_definition(connection: sqlite3.Connection, profile_name: Any, recorded_by: str = "") -> Dict[str, Any]:
    """Retire a Profile from use while retaining its append-only audit history."""
    name = str(profile_name or "").strip()
    if name == "Single-PC baseline":
        raise ValueError("The NIST CSF 2.0 base profile cannot be deleted.")
    row = connection.execute(
        "SELECT archived_at FROM csf_profile_definitions WHERE profile_name = ?", (name,)
    ).fetchone()
    if row is None or row["archived_at"] is not None:
        raise ValueError("The selected Profile is not available.")
    now = utc_now()
    with connection:
        record_csf_profile_audit_event(
            connection,
            profile_name=name,
            event_type="profile_archived",
            new_value={"archived_at": now},
            rationale="Profile removed from active use.",
            recorded_by=recorded_by,
        )
        connection.execute(
            """UPDATE csf_profile_definitions
            SET archived_at = ?, updated_at = ? WHERE profile_name = ?""",
            (now, now, name),
        )
        active = connection.execute(
            "SELECT profile_name FROM csf_active_profile WHERE selection_id = 1"
        ).fetchone()
        if active is not None and active["profile_name"] == name:
            connection.execute(
                """UPDATE csf_active_profile SET profile_name = ?, updated_at = ?
                WHERE selection_id = 1""",
                ("Single-PC baseline", now),
            )
    return get_active_csf_profile(connection)


def _seed_csf_profile_outcome_rows(
    connection: sqlite3.Connection, profile_name: str, timestamp: Optional[str] = None
) -> None:
    """Add the official NIST base outcomes as included rows for a new Profile.

    Each new organizational profile begins as an independent copy of the NIST
    CSF base.  Tailoring can later mark an outcome out of scope or otherwise
    change its status, but the base itself contains every official outcome.
    """
    now = timestamp or utc_now()
    rows: List[Tuple[str, str, str, str, int, str, str, str]] = []
    for function in csf_catalog.load_official_catalog().get("functions") or []:
        for category in function.get("categories") or []:
            rows.append((
                profile_name, str(category["id"]), "category", str(category.get("outcome") or ""),
                1, "included", now, now,
            ))
            for subcategory in category.get("subcategories") or []:
                rows.append((
                    profile_name, str(subcategory["id"]), "subcategory", str(subcategory.get("outcome") or ""),
                    1, "included", now, now,
                ))
    connection.executemany(
        """INSERT OR IGNORE INTO csf_profiles(
            profile_name, outcome_id, outcome_type, outcome_description,
            included_in_profile, profile_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )


def _seed_frozen_nist_base_profile(connection: sqlite3.Connection) -> str:
    """Ensure the official NIST base exists as a non-editable UUID-backed source."""
    name = "NIST CSF 2.0 Base Profile"
    row = connection.execute("SELECT profile_id FROM csf_profile_definitions WHERE profile_name = ?", (name,)).fetchone()
    if row is not None:
        return str(row["profile_id"])
    profile_id = str(uuid.uuid4())
    now = utc_now()
    connection.execute(
        """INSERT INTO csf_profile_definitions(
            profile_id, profile_name, profile_kind, context_summary, community_profile_source, created_at, updated_at
        ) VALUES (?, ?, 'frozen_base', ?, ?, ?, ?)""",
        (profile_id, name, "Frozen official NIST CSF 2.0 base.", "NIST Cybersecurity Framework 2.0 official catalog.", now, now),
    )
    _seed_csf_profile_outcome_rows(connection, name, now)
    return profile_id


def _find_xlsx_header(
    records: List[Dict[str, str]], required_headers: set[str], *, workbook_label: str,
) -> Tuple[int, Dict[str, str]]:
    """Find a row whose cell values contain every required worksheet header."""
    header_index, headers = next(
        (
            (index, {column: str(value or "").strip() for column, value in candidate.items()})
            for index, candidate in enumerate(records)
            if required_headers.issubset({str(value or "").strip() for value in candidate.values()})
        ),
        (-1, {}),
    )
    missing_headers = sorted(required_headers - set(headers.values()))
    if missing_headers:
        raise ValueError(f"{workbook_label} is missing required columns: {', '.join(missing_headers)}")
    return header_index, {name: column for column, name in headers.items()}


def _official_csf_subcategory_ids() -> set[str]:
    return {
        str(subcategory["id"])
        for function in csf_catalog.load_official_catalog().get("functions") or []
        for category in function.get("categories") or []
        for subcategory in category.get("subcategories") or []
    }


def _clean_community_profile_text(value: Any) -> str:
    """Normalize extraction artifacts without changing the source's meaning."""
    return str(value or "").replace("�", "—").strip()


def _import_frozen_cyber_ai_community_profile_from_workbook(
    connection: sqlite3.Connection, *, workbook: Path, sheet_name: str,
    community_profile_id: str, profile_name: str, publisher: str,
    publication_status: str, focus: str, source_url: str, focus_area: str = "",
) -> Dict[str, Any]:
    """Import a reviewed NIST IR 8596 workbook as an immutable source profile.

    NIST IR 8596 assigns independent guidance to Secure, Defend, and Thwart.
    A focus-area import creates one profile from one of those columns.
    """
    workbook = workbook.resolve()
    profile_key = str(community_profile_id or "").strip()
    source_name = str(profile_name or "").strip()
    requested_focus = str(focus_area or "").strip().lower()
    if requested_focus and requested_focus not in {"secure", "defend", "thwart"}:
        raise ValueError("Cyber AI Profile focus area must be Secure, Defend, or Thwart.")
    workbook_hash = _sha256_file(workbook)
    existing = connection.execute(
        "SELECT profile_id, source_sha256 FROM csf_community_profile_frozen_sources WHERE community_profile_id = ?",
        (profile_key,),
    ).fetchone()
    if existing is not None:
        if str(existing["source_sha256"]) != workbook_hash:
            raise ValueError(
                "This frozen Community Profile has a different source workbook. "
                "Create a separately versioned source artifact instead of overwriting it."
            )
        return {"community_profile_id": profile_key, "profile_id": str(existing["profile_id"]), "imported": False, "reason": "already_imported"}

    outcomes_sheet = _xlsx_sheet_rows(workbook, sheet_name)
    outcome_headers_required = {
        "CSF Identifier", "Outcome", "General Considerations", "General Example Informative References",
        "Secure Proposed Priority", "Defend Proposed Priority", "Thwart Proposed Priority", "PDF pages",
    }
    outcome_header_index, outcome_columns = _find_xlsx_header(
        outcomes_sheet, outcome_headers_required, workbook_label="Cyber AI Profile outcomes worksheet",
    )
    outcome_rows = [
        {name: _clean_community_profile_text(row.get(column)) for name, column in outcome_columns.items()}
        for row in outcomes_sheet[outcome_header_index + 1:]
        if _clean_community_profile_text(row.get(outcome_columns["CSF Identifier"]))
    ]
    outcome_ids = [row["CSF Identifier"].upper() for row in outcome_rows]
    official_ids = _official_csf_subcategory_ids()
    invalid_ids = [identifier for identifier in outcome_ids if not _NIST_CSF_SUBCATEGORY_PATTERN.match(identifier)]
    duplicate_ids = sorted({identifier for identifier in outcome_ids if outcome_ids.count(identifier) > 1})
    if invalid_ids or duplicate_ids or set(outcome_ids) != official_ids:
        raise ValueError("Cyber AI Profile outcomes must contain each official CSF Subcategory exactly once: " + json.dumps({
            "invalid": invalid_ids, "duplicate": duplicate_ids,
            "missing": sorted(official_ids - set(outcome_ids)), "unknown": sorted(set(outcome_ids) - official_ids),
        }))

    facet_sheet = _xlsx_sheet_rows(workbook, "Focus area details")
    facet_headers_required = {
        "CSF Identifier", "Outcome", "Focus area", "Proposed Priority", "Sample Opportunities",
        "Sample Focus Area Considerations", "Example Informative References", "PDF pages",
    }
    facet_header_index, facet_columns = _find_xlsx_header(
        facet_sheet, facet_headers_required, workbook_label="Cyber AI Profile focus-area worksheet",
    )
    facet_rows = [
        {name: _clean_community_profile_text(row.get(column)) for name, column in facet_columns.items()}
        for row in facet_sheet[facet_header_index + 1:]
        if _clean_community_profile_text(row.get(facet_columns["CSF Identifier"]))
    ]
    expected_facets = {"secure", "defend", "thwart"}
    facet_keys = [(row["CSF Identifier"].upper(), row["Focus area"].lower()) for row in facet_rows]
    duplicate_facet_keys = sorted({key for key in facet_keys if facet_keys.count(key) > 1})
    invalid_facet_rows = [
        {"outcome_id": row["CSF Identifier"], "focus_area": row["Focus area"], "priority": row["Proposed Priority"]}
        for row in facet_rows
        if row["CSF Identifier"].upper() not in official_ids
        or row["Focus area"].lower() not in expected_facets
        or row["Proposed Priority"] not in {"1", "2", "3"}
    ]
    expected_facet_keys = {(outcome_id, focus) for outcome_id in official_ids for focus in expected_facets}
    if duplicate_facet_keys or invalid_facet_rows or set(facet_keys) != expected_facet_keys:
        raise ValueError("Cyber AI Profile focus-area details must retain Secure, Defend, and Thwart for every official outcome: " + json.dumps({
            "duplicate": duplicate_facet_keys, "invalid": invalid_facet_rows,
            "missing": sorted(expected_facet_keys - set(facet_keys)), "unknown": sorted(set(facet_keys) - expected_facet_keys),
        }))
    selected_facets = {
        row["CSF Identifier"].upper(): row
        for row in facet_rows
        if not requested_focus or row["Focus area"].lower() == requested_focus
    }
    if requested_focus and set(selected_facets) != official_ids:
        raise ValueError(f"Cyber AI Profile {requested_focus.title()} focus area is incomplete.")

    name_conflict = connection.execute(
        "SELECT 1 FROM csf_profile_definitions WHERE profile_name = ?", (source_name,)
    ).fetchone()
    if name_conflict is not None:
        raise ValueError("A Profile with this name already exists.")
    now = utc_now()
    frozen_id = str(uuid.uuid4())
    source_relpath = str(workbook.relative_to(Path(__file__).resolve().parent))
    with connection:
        connection.execute(
            """INSERT INTO csf_community_profile_catalog(
                community_profile_id, profile_name, publisher, publication_status, focus,
                source_url, catalog_source_url, catalog_checked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(community_profile_id) DO UPDATE SET
                profile_name=excluded.profile_name, publisher=excluded.publisher,
                publication_status=excluded.publication_status, focus=excluded.focus,
                source_url=excluded.source_url, catalog_source_url=excluded.catalog_source_url,
                catalog_checked_at=excluded.catalog_checked_at""",
            (profile_key, source_name, publisher, publication_status, focus, source_url,
             NIST_CSF_COMMUNITY_PROFILE_CATALOG_URL, now),
        )
        connection.execute(
            """INSERT INTO csf_profile_definitions(
                profile_id, profile_name, profile_kind, context_summary, community_profile_source, created_at, updated_at
            ) VALUES (?, ?, 'frozen_community', ?, ?, ?, ?)""",
            (frozen_id, source_name, "Frozen NIST IR 8596 Community Profile source.", source_url, now, now),
        )
        _seed_csf_profile_outcome_rows(connection, source_name, now)
        for row in outcome_rows:
            outcome_id = row["CSF Identifier"].upper()
            selected = selected_facets.get(outcome_id)
            if selected is not None and requested_focus:
                consideration = selected["Sample Focus Area Considerations"]
                # This exact NIST phrase means that the focus area offers no
                # outcome-specific text, so leave the normal CSF guidance in place.
                use_base_guidance = bool(re.fullmatch(
                    r"standard cybersecurity practices apply\.?", consideration.strip(), flags=re.IGNORECASE,
                ))
                priorities = selected["Proposed Priority"]
                supporting_references = selected["Example Informative References"]
                other_guidance = selected["Sample Opportunities"]
                locator = f"NIST IR 8596 {selected['Focus area']} focus-area matrix, PDF page(s) {selected['PDF pages']}"
                notes = "" if use_base_guidance else consideration
                risk_rationale = row["General Considerations"]
            else:
                priorities = "; ".join(
                    f"{label}: {row[f'{label} Proposed Priority']}" for label in ("Secure", "Defend", "Thwart")
                )
                supporting_references = row["General Example Informative References"]
                other_guidance = ""
                locator = f"NIST IR 8596 CSF Profile matrix, PDF page(s) {row['PDF pages']}"
                notes = row["General Considerations"]
                risk_rationale = ""
            connection.execute(
                """UPDATE csf_profiles SET included_in_profile = 1, profile_status = 'included',
                    community_priority = ?, community_risk_rationale = ?,
                    community_supporting_references = ?, community_other_guidance = ?,
                    community_source_locator = ?, notes = ?, updated_at = ?
                WHERE profile_name = ? AND outcome_id = ?""",
                (priorities, risk_rationale, supporting_references, other_guidance,
                 locator, notes, now, source_name, outcome_id),
            )
        for row in facet_rows:
            outcome_id = row["CSF Identifier"].upper()
            facet_label = row["Focus area"]
            if requested_focus and facet_label.lower() != requested_focus:
                continue
            source_text = "\n".join((
                f"Proposed Priority: {row['Proposed Priority']}",
                f"Sample Opportunities: {row['Sample Opportunities']}",
                f"Sample Focus Area Considerations: {row['Sample Focus Area Considerations']}",
                f"Example Informative References: {row['Example Informative References']}",
            ))
            connection.execute(
                """INSERT INTO csf_community_profile_outcome_facets(
                    profile_id, outcome_id, facet_id, facet_label, proposed_priority,
                    considerations, opportunities, informative_references, source_text,
                    source_locator, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (frozen_id, outcome_id, facet_label.lower(), facet_label, row["Proposed Priority"],
                 row["Sample Focus Area Considerations"], row["Sample Opportunities"],
                 row["Example Informative References"], source_text,
                 f"NIST IR 8596 CSF Profile matrix, PDF page(s) {row['PDF pages']}", now, now),
            )
        _refresh_frozen_profile_category_statuses(connection, source_name)
        connection.execute(
            """INSERT INTO csf_community_profile_frozen_sources(
                community_profile_id, profile_id, source_workbook_path, source_sha256, imported_at
            ) VALUES (?, ?, ?, ?, ?)""",
            (profile_key, frozen_id, source_relpath, workbook_hash, now),
        )
        base = connection.execute(
            "SELECT profile_id FROM csf_profile_definitions WHERE profile_name = 'NIST CSF 2.0 Base Profile'"
        ).fetchone()
        if base is not None:
            connection.execute(
                """INSERT INTO csf_profile_source_lineage(profile_id, source_profile_id, source_role, copied_at)
                VALUES (?, ?, 'base', ?)""", (frozen_id, base["profile_id"], now)
            )
    return {
        "community_profile_id": profile_key, "profile_id": frozen_id, "imported": True,
        "source_outcome_count": len(outcome_rows),
        "focus_area_record_count": len(selected_facets) if requested_focus else len(facet_rows),
        "focus_area": requested_focus.title() if requested_focus else "",
        "source_workbook_path": source_relpath, "source_sha256": workbook_hash,
    }


def import_frozen_cyber_ai_focus_profiles_from_workbook(
    connection: sqlite3.Connection, *, workbook: Path, sheet_name: str, publisher: str,
    publication_status: str, source_url: str,
) -> Dict[str, Any]:
    """Create the three independent NIST IR 8596 Community Profile sources."""
    profiles = (
        ("secure", "nist-cyber-ai-secure", "Cyber AI - Secure", "Cybersecurity of AI systems"),
        ("defend", "nist-cyber-ai-defend", "Cyber AI - Defend", "Defending against AI-enabled cyber threats"),
        ("thwart", "nist-cyber-ai-thwart", "Cyber AI - Thwart", "Thwarting AI-enabled cyber threats"),
    )
    results = [
        _import_frozen_cyber_ai_community_profile_from_workbook(
            connection, workbook=workbook, sheet_name=sheet_name,
            community_profile_id=profile_id, profile_name=profile_name, publisher=publisher,
            publication_status=publication_status, focus=focus, source_url=source_url,
            focus_area=focus_area,
        )
        for focus_area, profile_id, profile_name, focus in profiles
    ]
    # The initial combined import was a provisional interpretation of the
    # source. Retain it and its provenance, but no longer offer it as a
    # selectable baseline now that the three source profiles exist.
    legacy = connection.execute(
        """SELECT frozen.profile_id FROM csf_community_profile_frozen_sources AS frozen
        JOIN csf_profile_definitions AS definition ON definition.profile_id = frozen.profile_id
        WHERE frozen.community_profile_id = 'nist-cyber-ai'
          AND definition.profile_name = 'NIST IR 8596 Cyber AI Profile'
          AND definition.archived_at IS NULL"""
    ).fetchone()
    if legacy is not None:
        archived_at = utc_now()
        with connection:
            connection.execute(
                "UPDATE csf_profile_definitions SET archived_at = ?, updated_at = ? WHERE profile_id = ?",
                (archived_at, archived_at, legacy["profile_id"]),
            )
    return {"profiles": results, "legacy_combined_profile_archived": legacy is not None}


def import_frozen_community_profile_from_workbook(
    connection: sqlite3.Connection, *, workbook: Path, sheet_name: str,
    community_profile_id: str, profile_name: str, publisher: str,
    publication_status: str, focus: str, source_url: str,
) -> Dict[str, Any]:
    """Import a reviewed Community Profile worksheet as an immutable source.

    The source worksheet retains its own priority, threat/risk, and supporting
    reference fields.  Only its concise Notes field is used as Tile 2's
    outcome-specific community guidance.
    """
    workbook = workbook.resolve()
    if not workbook.exists():
        raise ValueError(f"Community Profile workbook does not exist: {workbook}")
    profile_key = str(community_profile_id or "").strip()
    source_name = str(profile_name or "").strip()
    if not profile_key or not source_name:
        raise ValueError("Community Profile id and profile name are required.")
    # The reviewed Cyber AI intermediate workbook has a second, mandatory
    # worksheet of per-focus-area content. Route it to the importer that can
    # retain those separate source records.
    workbook_records = _xlsx_sheet_rows(workbook, sheet_name)
    workbook_values = {str(value or "").strip() for row in workbook_records for value in row.values()}
    if {"General Considerations", "Secure Proposed Priority", "Defend Proposed Priority", "Thwart Proposed Priority"}.issubset(workbook_values):
        return _import_frozen_cyber_ai_community_profile_from_workbook(
            connection, workbook=workbook, sheet_name=sheet_name,
            community_profile_id=profile_key, profile_name=source_name, publisher=publisher,
            publication_status=publication_status, focus=focus, source_url=source_url,
        )
    workbook_hash = _sha256_file(workbook)
    existing = connection.execute(
        "SELECT profile_id, source_sha256 FROM csf_community_profile_frozen_sources WHERE community_profile_id = ?",
        (profile_key,),
    ).fetchone()
    if existing is not None:
        if str(existing["source_sha256"]) != workbook_hash:
            raise ValueError(
                "This frozen Community Profile has a different source workbook. "
                "Create a separately versioned source artifact instead of overwriting it."
            )
        return {"community_profile_id": profile_key, "profile_id": str(existing["profile_id"]), "imported": False, "reason": "already_imported"}

    records = workbook_records
    if not records:
        raise ValueError("Community Profile worksheet is empty.")
    required_headers = {
        "CSF Identifier", "Outcome", "Priority", "O-RAN Threat Analysis TR Risk Score (Rationale)",
        "O-RAN ALLIANCE TS/TR that Support Outcome", "Other Guidance that may Support Outcome", "Notes",
    }
    header_index, header_columns = _find_xlsx_header(
        records, required_headers, workbook_label="Community Profile worksheet",
    )
    source_rows = [
        {name: str(row.get(column) or "").strip() for name, column in header_columns.items()}
        for row in records[header_index + 1:]
        if str(row.get(header_columns["CSF Identifier"]) or "").strip()
    ]
    outcome_ids = [str(row["CSF Identifier"]).upper() for row in source_rows]
    invalid_ids = [identifier for identifier in outcome_ids if not _NIST_CSF_SUBCATEGORY_PATTERN.match(identifier)]
    duplicate_ids = sorted({identifier for identifier in outcome_ids if outcome_ids.count(identifier) > 1})
    official_ids = _official_csf_subcategory_ids()
    unknown_ids = sorted(set(outcome_ids) - official_ids)
    if invalid_ids or duplicate_ids or unknown_ids:
        raise ValueError(
            "Community Profile identifiers are invalid: "
            + json.dumps({"invalid": invalid_ids, "duplicate": duplicate_ids, "unknown": unknown_ids})
        )
    name_conflict = connection.execute(
        "SELECT 1 FROM csf_profile_definitions WHERE profile_name = ?", (source_name,)
    ).fetchone()
    if name_conflict is not None:
        raise ValueError("A Profile with this name already exists.")

    now = utc_now()
    frozen_id = str(uuid.uuid4())
    source_relpath = str(workbook.relative_to(Path(__file__).resolve().parent))
    with connection:
        connection.execute(
            """INSERT INTO csf_community_profile_catalog(
                community_profile_id, profile_name, publisher, publication_status, focus,
                source_url, catalog_source_url, catalog_checked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(community_profile_id) DO UPDATE SET
                profile_name=excluded.profile_name, publisher=excluded.publisher,
                publication_status=excluded.publication_status, focus=excluded.focus,
                source_url=excluded.source_url, catalog_source_url=excluded.catalog_source_url,
                catalog_checked_at=excluded.catalog_checked_at""",
            (profile_key, source_name, publisher, publication_status, focus, source_url,
             NIST_CSF_COMMUNITY_PROFILE_CATALOG_URL, now),
        )
        connection.execute(
            """INSERT INTO csf_profile_definitions(
                profile_id, profile_name, profile_kind, context_summary, community_profile_source, created_at, updated_at
            ) VALUES (?, ?, 'frozen_community', ?, ?, ?, ?)""",
            (frozen_id, source_name, "Frozen Community Profile source.", source_url, now, now),
        )
        _seed_csf_profile_outcome_rows(connection, source_name, now)
        connection.execute(
            """UPDATE csf_profiles SET included_in_profile = 0, profile_status = 'not_selected', updated_at = ?
            WHERE profile_name = ?""", (now, source_name)
        )
        for row in source_rows:
            outcome_id = str(row["CSF Identifier"]).upper()
            page = str(row.get("PDF page") or "").strip()
            locator = f"Appendix A, PDF page {page}" if page else "Appendix A"
            connection.execute(
                """UPDATE csf_profiles SET included_in_profile = 1, profile_status = 'included',
                    community_priority = ?, community_risk_rationale = ?,
                    community_supporting_references = ?, community_other_guidance = ?,
                    community_source_locator = ?, notes = ?, updated_at = ?
                WHERE profile_name = ? AND outcome_id = ?""",
                (
                    row["Priority"], row["O-RAN Threat Analysis TR Risk Score (Rationale)"],
                    row["O-RAN ALLIANCE TS/TR that Support Outcome"],
                    row["Other Guidance that may Support Outcome"], locator, row["Notes"], now,
                    source_name, outcome_id,
                ),
            )
        _refresh_frozen_profile_category_statuses(connection, source_name)
        connection.execute(
            """INSERT INTO csf_community_profile_frozen_sources(
                community_profile_id, profile_id, source_workbook_path, source_sha256, imported_at
            ) VALUES (?, ?, ?, ?, ?)""",
            (profile_key, frozen_id, source_relpath, workbook_hash, now),
        )
        base = connection.execute(
            "SELECT profile_id FROM csf_profile_definitions WHERE profile_name = 'NIST CSF 2.0 Base Profile'"
        ).fetchone()
        if base is not None:
            connection.execute(
                """INSERT INTO csf_profile_source_lineage(profile_id, source_profile_id, source_role, copied_at)
                VALUES (?, ?, 'base', ?)""", (frozen_id, base["profile_id"], now)
            )
    return {
        "community_profile_id": profile_key, "profile_id": frozen_id, "imported": True,
        "source_outcome_count": len(source_rows), "source_workbook_path": source_relpath,
        "source_sha256": workbook_hash,
    }


def _seed_frozen_ransomware_community_profile(connection: sqlite3.Connection) -> None:
    """Import the supplied NIST ransomware selection as an immutable source Profile."""
    workbook = Path(__file__).resolve().parent / "output" / "nist-ir-8374r1-ransomware-community-profile.xlsx"
    if not workbook.exists():
        return
    frozen_name = "NIST IR 8374 Rev. 1 Ransomware Community Profile"
    existing = connection.execute(
        "SELECT profile_id FROM csf_community_profile_frozen_sources WHERE community_profile_id = 'nist-ransomware'"
    ).fetchone()
    if existing is None:
        frozen_id = str(uuid.uuid4())
        now = utc_now()
        connection.execute(
            """INSERT INTO csf_profile_definitions(
                profile_id, profile_name, profile_kind, context_summary, community_profile_source, created_at, updated_at
            ) VALUES (?, ?, 'frozen_community', ?, ?, ?, ?)""",
            (frozen_id, frozen_name, "Frozen NIST Community Profile source.",
             "NIST IR 8374 Rev. 1; Table 1; June 2026.", now, now),
        )
        _seed_csf_profile_outcome_rows(connection, frozen_name, now)
        rows = _xlsx_sheet_rows(workbook, "Ransomware Profile")
        selected = [row for row in rows if str(row.get("B") or "").strip().lower() == "yes"]
        connection.execute(
            """UPDATE csf_profiles SET included_in_profile = 0, profile_status = 'not_selected', updated_at = ?
            WHERE profile_name = ?""", (now, frozen_name)
        )
        for row in selected:
            outcome_id = str(row.get("A") or "").strip().upper()
            # Preserve the official source wording while correcting a known
            # transcription typo in the supplied profile workbook.
            application = str(row.get("C") or "").strip().replace(
                "Communicationregarding", "Communication regarding"
            )
            source_page = str(row.get("D") or "").strip()
            connection.execute(
                """UPDATE csf_profiles SET included_in_profile = 1, profile_status = 'included',
                    notes = ?, considerations = ?, updated_at = ? WHERE profile_name = ? AND outcome_id = ?""",
                (application, f"NIST IR 8374 Rev. 1, Table 1, page {source_page}.", now, frozen_name, outcome_id),
            )
        connection.execute(
            """UPDATE csf_profiles AS category SET included_in_profile = 1, profile_status = 'included', updated_at = ?
            WHERE category.profile_name = ? AND category.outcome_type = 'category' AND EXISTS (
                SELECT 1 FROM csf_profiles AS outcome
                WHERE outcome.profile_name = category.profile_name
                  AND outcome.outcome_type = 'subcategory'
                  AND outcome.profile_status = 'included'
                  AND outcome.outcome_id LIKE category.outcome_id || '-%'
            )""", (now, frozen_name)
        )
        connection.execute(
            """INSERT INTO csf_community_profile_frozen_sources(
                community_profile_id, profile_id, source_workbook_path, source_sha256, imported_at
            ) VALUES ('nist-ransomware', ?, ?, ?, ?)""",
            (frozen_id, str(workbook.relative_to(Path(__file__).resolve().parent)), _sha256_file(workbook), now),
        )
        base = connection.execute(
            "SELECT profile_id FROM csf_profile_definitions WHERE profile_name = 'NIST CSF 2.0 Base Profile'"
        ).fetchone()
        if base is not None:
            connection.execute(
                """INSERT OR IGNORE INTO csf_profile_source_lineage(profile_id, source_profile_id, source_role, copied_at)
                VALUES (?, ?, 'base', ?)""", (frozen_id, base["profile_id"], now)
            )


def _refresh_frozen_profile_category_statuses(connection: sqlite3.Connection, profile_name: str) -> None:
    """Derive frozen Profile Category selection from its selected Subcategories."""
    now = utc_now()
    connection.execute(
        """UPDATE csf_profiles SET included_in_profile = 0, profile_status = 'not_selected', updated_at = ?
        WHERE profile_name = ? AND outcome_type = 'category'""", (now, profile_name)
    )
    connection.execute(
        """UPDATE csf_profiles AS category SET included_in_profile = 1, profile_status = 'included', updated_at = ?
        WHERE category.profile_name = ? AND category.outcome_type = 'category' AND EXISTS (
            SELECT 1 FROM csf_profiles AS outcome
            WHERE outcome.profile_name = category.profile_name
              AND outcome.outcome_type = 'subcategory'
              AND outcome.profile_status = 'included'
              AND outcome.outcome_id LIKE category.outcome_id || '-%'
        )""", (now, profile_name)
    )


def record_csf_profile_audit_event(
    connection: sqlite3.Connection, *, profile_name: str, event_type: str,
    outcome_id: Optional[str] = None, field_name: Optional[str] = None,
    old_value: Any = None, new_value: Any = None, rationale: str = "", recorded_by: str = "",
    supporting_evidence_reference: str = "",
) -> Dict[str, Any]:
    """Record an immutable profile lifecycle or tailoring event."""
    event = {
        "profile_audit_event_id": str(uuid.uuid4()), "profile_name": profile_name,
        "event_type": event_type, "outcome_id": outcome_id, "field_name": field_name,
        "old_value_json": json.dumps(old_value) if old_value is not None else None,
        "new_value_json": json.dumps(new_value if new_value is not None else {}),
        "rationale": rationale, "recorded_by": recorded_by or None,
        "supporting_evidence_reference": str(supporting_evidence_reference or "").strip(),
        "recorded_at": utc_now(),
    }
    connection.execute("""INSERT INTO csf_profile_audit_events (
        profile_audit_event_id, profile_name, event_type, outcome_id, field_name,
        old_value_json, new_value_json, rationale, recorded_by, supporting_evidence_reference, recorded_at
    ) VALUES (
        :profile_audit_event_id,:profile_name,:event_type,:outcome_id,:field_name,
        :old_value_json,:new_value_json,:rationale,:recorded_by,:supporting_evidence_reference,:recorded_at)""", event)
    return event


def list_csf_profile_audit_events(connection: sqlite3.Connection, profile_name: str) -> List[Dict[str, Any]]:
    return [dict(row) for row in connection.execute(
        "SELECT * FROM csf_profile_audit_events WHERE profile_name = ? ORDER BY recorded_at, rowid",
        (profile_name,),
    ).fetchall()]


def list_csf_profile_outcomes(connection: sqlite3.Connection, profile_name: str) -> List[Dict[str, Any]]:
    rows = [dict(row) for row in connection.execute(
        """SELECT outcome.*, target.target_assessment_level
        FROM csf_profiles outcome
        JOIN csf_profile_definitions definition ON definition.profile_name = outcome.profile_name
        LEFT JOIN csf_profile_outcome_targets target
            ON target.profile_id = definition.profile_id AND target.subcategory_id = outcome.outcome_id
        WHERE outcome.profile_name = ?""", (profile_name,)
    ).fetchall()]
    order: Dict[str, int] = {}
    position = 0
    for function in csf_catalog.load_official_catalog().get("functions") or []:
        for category in function.get("categories") or []:
            order[str(category["id"])] = position
            position += 1
            for subcategory in category.get("subcategories") or []:
                order[str(subcategory["id"])] = position
                position += 1
    return sorted(rows, key=lambda row: order.get(str(row.get("outcome_id") or ""), position))


def set_csf_profile_outcome_status(connection: sqlite3.Connection, profile_name: str, outcome_id: str, profile_status: str, recorded_by: str = "") -> None:
    allowed = {"not_selected", "included", "inherited", "out_of_scope"}
    if profile_status not in allowed:
        raise ValueError("Invalid profile status.")
    row = connection.execute("SELECT profile_status, outcome_type FROM csf_profiles WHERE profile_name = ? AND outcome_id = ?", (profile_name, outcome_id)).fetchone()
    if row is None:
        raise ValueError("Profile outcome not found.")
    old = str(row["profile_status"] or "not_selected")
    if old == profile_status:
        return
    profile_row = connection.execute(
        "SELECT profile_id FROM csf_profile_definitions WHERE profile_name = ? AND archived_at IS NULL",
        (profile_name,),
    ).fetchone()
    if profile_row is None:
        raise ValueError("Profile is not available.")
    profile_id = str(profile_row["profile_id"])
    target_row = connection.execute(
        """SELECT target_assessment_level FROM csf_profile_outcome_targets
        WHERE profile_id = ? AND subcategory_id = ?""", (profile_id, outcome_id)
    ).fetchone()
    old_target = str(target_row["target_assessment_level"]) if target_row is not None else ""
    with connection:
        connection.execute("UPDATE csf_profiles SET profile_status=?, included_in_profile=?, updated_at=? WHERE profile_name=? AND outcome_id=?", (profile_status, int(profile_status in {"included", "inherited"}), utc_now(), profile_name, outcome_id))
        record_csf_profile_audit_event(connection, profile_name=profile_name, event_type="outcome_status_changed", outcome_id=outcome_id, field_name="profile_status", old_value=old, new_value=profile_status, rationale="Profile tailoring", recorded_by=recorded_by)
        if str(row["outcome_type"]) == "subcategory":
            if profile_status in {"out_of_scope", "not_selected"}:
                connection.execute("DELETE FROM csf_profile_outcome_targets WHERE profile_id = ? AND subcategory_id = ?", (profile_id, outcome_id))
                if old_target:
                    record_csf_profile_audit_event(connection, profile_name=profile_name, event_type="outcome_target_cleared", outcome_id=outcome_id, field_name="target_assessment_level", old_value=old_target, new_value=None, rationale="Outcome is not a selected Profile target.", recorded_by=recorded_by)
            elif not old_target:
                connection.execute("""INSERT INTO csf_profile_outcome_targets(profile_id, subcategory_id, target_assessment_level, updated_by, updated_at)
                VALUES (?, ?, 'fully_implemented', ?, ?)""", (profile_id, outcome_id, recorded_by or None, utc_now()))
                record_csf_profile_audit_event(connection, profile_name=profile_name, event_type="outcome_target_initialized", outcome_id=outcome_id, field_name="target_assessment_level", old_value=None, new_value="fully_implemented", rationale="Included Profile outcomes start with a fully implemented target.", recorded_by=recorded_by)


def set_csf_profile_outcome_target(
    connection: sqlite3.Connection, profile_name: str, subcategory_id: str,
    target_assessment_level: str, rationale: str, recorded_by: str = "", supporting_evidence_reference: str = ""
) -> None:
    """Set a Profile's desired assessment for one included Subcategory."""
    level = _optional_csf_audit_value(target_assessment_level, "target_assessment_level", CSF_ASSESSMENT_LEVELS)
    if level is None:
        raise ValueError("target_assessment_level is required.")
    reason = _csf_record_text(rationale, "Target rationale", required=True, maximum=2000)
    profile = connection.execute(
        "SELECT profile_id FROM csf_profile_definitions WHERE profile_name = ? AND archived_at IS NULL", (profile_name,)
    ).fetchone()
    outcome = connection.execute(
        "SELECT profile_status, outcome_type FROM csf_profiles WHERE profile_name = ? AND outcome_id = ?", (profile_name, subcategory_id)
    ).fetchone()
    if profile is None or outcome is None or outcome["outcome_type"] != "subcategory":
        raise ValueError("Profile Subcategory was not found.")
    if str(outcome["profile_status"]) not in {"included", "inherited"}:
        raise ValueError("Include the outcome before setting its Target assessment.")
    profile_id = str(profile["profile_id"])
    previous = connection.execute(
        "SELECT target_assessment_level FROM csf_profile_outcome_targets WHERE profile_id = ? AND subcategory_id = ?", (profile_id, subcategory_id)
    ).fetchone()
    old = str(previous["target_assessment_level"]) if previous is not None else None
    if old == level:
        with connection:
            connection.execute(
                "UPDATE csf_profiles SET rationale = ?, updated_at = ? WHERE profile_name = ? AND outcome_id = ?",
                (reason, utc_now(), profile_name, subcategory_id),
            )
            record_csf_profile_audit_event(
                connection, profile_name=profile_name,
                event_type="outcome_target_rationale_recorded", outcome_id=subcategory_id,
                field_name="target_assessment_level", old_value=level, new_value=level,
                rationale=reason, recorded_by=recorded_by,
                supporting_evidence_reference=supporting_evidence_reference,
            )
        return
    with connection:
        connection.execute(
            "UPDATE csf_profiles SET rationale = ?, updated_at = ? WHERE profile_name = ? AND outcome_id = ?",
            (reason, utc_now(), profile_name, subcategory_id),
        )
        connection.execute(
            """INSERT INTO csf_profile_outcome_targets(profile_id, subcategory_id, target_assessment_level, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(profile_id, subcategory_id) DO UPDATE SET target_assessment_level=excluded.target_assessment_level,
                updated_by=excluded.updated_by, updated_at=excluded.updated_at""",
            (profile_id, subcategory_id, level, recorded_by or None, utc_now()),
        )
        record_csf_profile_audit_event(connection, profile_name=profile_name, event_type="outcome_target_changed", outcome_id=subcategory_id, field_name="target_assessment_level", old_value=old, new_value=level, rationale=reason, recorded_by=recorded_by, supporting_evidence_reference=supporting_evidence_reference)


def list_csf_profile_outcome_targets(connection: sqlite3.Connection, profile_id: str) -> Dict[str, Dict[str, Any]]:
    identifier = _active_csf_profile_id(connection, profile_id)
    return {
        str(row["selected_subcategory_id"]): dict(row)
        for row in connection.execute(
            """SELECT target.*, outcome.outcome_id AS selected_subcategory_id,
                outcome.rationale AS profile_outcome_reason,
                outcome.community_priority AS community_priority,
                (
                    SELECT audit.rationale
                    FROM csf_profile_audit_events audit
                    JOIN csf_profile_definitions definition
                        ON definition.profile_name = audit.profile_name
                    WHERE definition.profile_id = target.profile_id
                      AND audit.outcome_id = target.subcategory_id
                      AND audit.event_type IN ('outcome_target_changed', 'outcome_target_rationale_recorded')
                    ORDER BY audit.recorded_at DESC, audit.rowid DESC
                    LIMIT 1
                ) AS target_reason
            FROM csf_profile_definitions definition
            JOIN csf_profiles outcome
                ON outcome.profile_name = definition.profile_name
               AND outcome.outcome_type = 'subcategory'
            LEFT JOIN csf_profile_outcome_targets target
                ON target.profile_id = definition.profile_id
               AND target.subcategory_id = outcome.outcome_id
            WHERE definition.profile_id = ?""",
            (identifier,),
        ).fetchall()
    }


def upsert_csf_profile_action_guidance(
    connection: sqlite3.Connection, *, profile_id: str, subcategory_id: str,
    action_title_example: str, action_details_example: str, action_rationale_example: str,
    source_kind: str = "", prompt_version: str = "",
) -> None:
    """Store profile-specific, non-binding examples for the Add Action form."""
    profile = _active_csf_profile_id(connection, profile_id)
    outcome_id = str(subcategory_id or "").strip().upper()
    if outcome_id not in _official_csf_subcategory_ids():
        raise ValueError("subcategory_id must identify an official CSF Subcategory.")
    title = _local_csf_text(action_title_example, "action_title_example", required=False, maximum=240)
    details = _local_csf_text(action_details_example, "action_details_example", required=False, maximum=4000)
    rationale = _local_csf_text(action_rationale_example, "action_rationale_example", required=False, maximum=4000)
    source = _local_csf_text(source_kind, "source_kind", required=False, maximum=120)
    prompt = _local_csf_text(prompt_version, "prompt_version", required=False, maximum=120)
    now = utc_now()
    connection.execute(
        """INSERT INTO csf_profile_action_guidance(
            profile_id, subcategory_id, action_title_example, action_details_example,
            action_rationale_example, source_kind, prompt_version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(profile_id, subcategory_id) DO UPDATE SET
            action_title_example=excluded.action_title_example,
            action_details_example=excluded.action_details_example,
            action_rationale_example=excluded.action_rationale_example,
            source_kind=excluded.source_kind, prompt_version=excluded.prompt_version,
            updated_at=excluded.updated_at""",
        (profile, outcome_id, title, details, rationale, source, prompt, now, now),
    )


def list_csf_profile_action_guidance(connection: sqlite3.Connection, profile_id: str) -> Dict[str, Dict[str, str]]:
    """Return non-empty profile-specific templates keyed by official outcome."""
    profile = _active_csf_profile_id(connection, profile_id)
    return {
        str(row["subcategory_id"]): {
            "title": str(row["action_title_example"] or ""),
            "details": str(row["action_details_example"] or ""),
            "rationale": str(row["action_rationale_example"] or ""),
            "source_kind": str(row["source_kind"] or ""),
            "prompt_version": str(row["prompt_version"] or ""),
        }
        for row in connection.execute(
            """SELECT subcategory_id, action_title_example, action_details_example,
                      action_rationale_example, source_kind, prompt_version
            FROM csf_profile_action_guidance WHERE profile_id = ?""", (profile,)
        ).fetchall()
    }


def import_csf_profile_action_guidance_outputs(
    connection: sqlite3.Connection,
    output_paths: List[Path],
    profile_id: str,
    source_kind: str = "nist_ir_8596_cyber_ai_batch",
) -> Dict[str, Any]:
    """Import completed Responses Batch action templates for one frozen profile.

    Files are processed in the supplied order so a later retry artifact replaces
    an earlier response for the same profile outcome.  Incomplete batch results
    are retained in their source artifact but never become UI guidance.
    """
    profile = _active_csf_profile_id(connection, profile_id)
    fields = (
        ("action_title_example", 72),
        ("action_details_example", 220),
        ("action_rationale_example", 220),
    )
    selected: Dict[str, Tuple[Dict[str, str], str]] = {}
    completed_rows = skipped_incomplete = skipped_other_profile = 0

    for path in output_paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            envelope = json.loads(line)
            body = envelope.get("response", {}).get("body", {})
            if body.get("status") != "completed":
                skipped_incomplete += 1
                continue
            output_text = next(
                (
                    content.get("text")
                    for output in body.get("output", [])
                    if output.get("type") == "message"
                    for content in output.get("content", [])
                    if content.get("type") == "output_text"
                ),
                None,
            )
            if not output_text:
                skipped_incomplete += 1
                continue
            parts = str(envelope.get("custom_id", "")).split("|", 2)
            if len(parts) != 3:
                raise ValueError(f"{path}:{line_number} has an invalid action-guidance custom_id.")
            response_profile_id, outcome_id, prompt_version = parts
            if response_profile_id != profile:
                skipped_other_profile += 1
                continue
            template = json.loads(output_text)
            if not isinstance(template, dict):
                raise ValueError(f"{path}:{line_number} must return a JSON object.")
            cleaned: Dict[str, str] = {}
            for field_name, maximum in fields:
                value = template.get(field_name)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"{path}:{line_number} is missing {field_name}.")
                value = value.strip()
                if len(value) > maximum:
                    raise ValueError(f"{path}:{line_number} {field_name} exceeds {maximum} characters.")
                cleaned[field_name] = value
            selected[outcome_id] = (cleaned, prompt_version)
            completed_rows += 1

    with connection:
        for outcome_id, (template, prompt_version) in selected.items():
            upsert_csf_profile_action_guidance(
                connection,
                profile_id=profile,
                subcategory_id=outcome_id,
                action_title_example=template["action_title_example"],
                action_details_example=template["action_details_example"],
                action_rationale_example=template["action_rationale_example"],
                source_kind=source_kind,
                prompt_version=prompt_version,
            )

    return {
        "profile_id": profile,
        "outputs_read": len(output_paths),
        "completed_rows": completed_rows,
        "unique_outcomes_imported": len(selected),
        "skipped_incomplete": skipped_incomplete,
        "skipped_other_profile": skipped_other_profile,
        "source_kind": source_kind,
    }


def create_csf_profile_definition(
    connection: sqlite3.Connection,
    profile_name: Any,
    context_summary: Any,
    community_profile_source: Any = "",
    community_profile_id: Any = "",
    source_profile_id: Any = "",
    control_framework_ids: Optional[Iterable[Any]] = None,
    recorded_by: str = "",
) -> Dict[str, Any]:
    """Create and select a defined Profile with its complete official outcome rows."""
    name = str(profile_name or "").strip()
    context = str(context_summary or "").strip()
    source = str(community_profile_source or "").strip()
    catalog_profile_id = str(community_profile_id or "").strip()
    requested_source_profile_id = str(source_profile_id or "").strip()
    requested_framework_ids = None if control_framework_ids is None else {
        str(value or "").strip() for value in control_framework_ids if str(value or "").strip()
    }
    if not name:
        raise ValueError("Profile name is required.")
    if not context:
        raise ValueError("Profile context is required.")
    catalog_profile = None
    if catalog_profile_id:
        catalog_profile = connection.execute(
            """SELECT profile_name, publisher, source_url
            FROM csf_community_profile_catalog WHERE community_profile_id = ?""",
            (catalog_profile_id,),
        ).fetchone()
        if catalog_profile is None:
            raise ValueError("The selected Community Profile is not in the catalog.")
        source = f"{catalog_profile['profile_name']} ({catalog_profile['publisher']}) — {catalog_profile['source_url']}"
    now = utc_now()
    try:
        with connection:
            connection.execute(
                """INSERT INTO csf_profile_definitions(
                    profile_id, profile_name, context_summary, community_profile_source, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (str(uuid.uuid4()), name, context, source, now, now),
            )
            _seed_csf_profile_outcome_rows(connection, name, now)
            frozen_profile_id = ""
            if catalog_profile is not None:
                connection.execute(
                    """INSERT INTO csf_profile_community_profile_sources(
                        profile_name, community_profile_id, selected_at
                    ) VALUES (?, ?, ?)""",
                    (name, catalog_profile_id, now),
                )
                frozen = connection.execute(
                    "SELECT profile_id FROM csf_community_profile_frozen_sources WHERE community_profile_id = ?",
                    (catalog_profile_id,),
                ).fetchone()
                if frozen is not None:
                    frozen_profile_id = str(frozen["profile_id"])
                    connection.execute(
                        """UPDATE csf_profiles SET included_in_profile = 0, profile_status = 'not_selected',
                            rationale = '', notes = '', considerations = '', updated_at = ?
                        WHERE profile_name = ?""", (now, name)
                    )
                    connection.execute(
                        """UPDATE csf_profiles AS destination
                        SET included_in_profile = 1, profile_status = 'inherited',
                            notes = source.notes, considerations = source.considerations, updated_at = ?
                        FROM csf_profiles AS source
                        JOIN csf_profile_definitions frozen_definition ON frozen_definition.profile_name = source.profile_name
                        WHERE destination.profile_name = ?
                          AND frozen_definition.profile_id = ?
                          AND source.profile_status = 'included'
                          AND destination.outcome_id = source.outcome_id""",
                        (now, name, frozen_profile_id),
                    )
            if requested_source_profile_id:
                source_definition = connection.execute(
                    """SELECT profile_id, profile_kind FROM csf_profile_definitions
                    WHERE profile_id = ? AND archived_at IS NULL""", (requested_source_profile_id,)
                ).fetchone()
                if source_definition is None or str(source_definition["profile_kind"]) != "organizational":
                    raise ValueError("The selected source Organizational Profile is not available.")
                connection.execute(
                    """UPDATE csf_profiles AS destination
                    SET included_in_profile = source.included_in_profile, profile_status = source.profile_status,
                        rationale = source.rationale, notes = source.notes, considerations = source.considerations,
                        updated_at = ?
                    FROM csf_profiles AS source
                    JOIN csf_profile_definitions source_definition ON source_definition.profile_name = source.profile_name
                    WHERE destination.profile_name = ? AND source_definition.profile_id = ?
                      AND destination.outcome_id = source.outcome_id""",
                    (now, name, requested_source_profile_id),
                )
                frozen_profile_id = requested_source_profile_id
            elif not frozen_profile_id:
                base = connection.execute(
                    "SELECT profile_id FROM csf_profile_definitions WHERE profile_name = 'NIST CSF 2.0 Base Profile'"
                ).fetchone()
                frozen_profile_id = str(base["profile_id"]) if base is not None else ""
            created_profile_id = connection.execute(
                "SELECT profile_id FROM csf_profile_definitions WHERE profile_name = ?", (name,)
            ).fetchone()["profile_id"]
            if requested_source_profile_id:
                connection.execute(
                    """INSERT OR IGNORE INTO csf_profile_control_catalogs(
                        profile_id, framework_id, is_enabled, configured_by, configured_at
                    )
                    SELECT ?, framework_id, is_enabled, ?, ?
                    FROM csf_profile_control_catalogs
                    WHERE profile_id = ?""",
                    (created_profile_id, recorded_by or None, now, requested_source_profile_id),
                )
            else:
                connection.execute(
                    """INSERT OR IGNORE INTO csf_profile_control_catalogs(
                        profile_id, framework_id, is_enabled, configured_by, configured_at
                    )
                    SELECT ?, framework_id, is_enabled, ?, ? FROM csf_control_catalogs""",
                    (created_profile_id, recorded_by or None, now),
                )
            if requested_framework_ids is not None:
                registered_framework_ids = {
                    str(row[0]) for row in connection.execute("SELECT framework_id FROM csf_control_catalogs")
                }
                unknown_framework_ids = requested_framework_ids - registered_framework_ids
                if unknown_framework_ids:
                    raise ValueError("The selected control catalog is not registered.")
                for framework_id in registered_framework_ids:
                    connection.execute(
                        """UPDATE csf_profile_control_catalogs
                        SET is_enabled = ?, configured_by = ?, configured_at = ?
                        WHERE profile_id = ? AND framework_id = ?""",
                        (1 if framework_id in requested_framework_ids else 0, recorded_by or None, now,
                         created_profile_id, framework_id),
                    )
            if frozen_profile_id:
                connection.execute(
                    """INSERT OR IGNORE INTO csf_profile_source_lineage(profile_id, source_profile_id, source_role, copied_at)
                    VALUES (?, ?, ?, ?)""",
                    (created_profile_id, frozen_profile_id, "organizational_copy" if requested_source_profile_id else "base_or_community", now),
                )
            record_csf_profile_audit_event(
                connection, profile_name=name, event_type="profile_created",
                new_value={"base": "NIST CSF 2.0", "community_profile_id": catalog_profile_id or None,
                           "frozen_source_profile_id": frozen_profile_id or None,
                           "context_summary": context,
                           "control_framework_ids": sorted(requested_framework_ids) if requested_framework_ids is not None else None},
                rationale="Profile creation", recorded_by=recorded_by
            )
            connection.execute(
                """INSERT INTO csf_active_profile(selection_id, profile_name, updated_at)
                VALUES (1, ?, ?)
                ON CONFLICT(selection_id) DO UPDATE SET profile_name=excluded.profile_name,
                    updated_at=excluded.updated_at""",
                (name, now),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError("A profile with that name already exists.") from exc
    return get_active_csf_profile(connection)


def _csf_record_text(value: Any, field_name: str, *, required: bool, maximum: int) -> str:
    return _local_csf_text(value, field_name, required=required, maximum=maximum)


def _record_csf_evidence_link_audit_event(
    connection: sqlite3.Connection,
    *,
    profile_id: str,
    basis_id: str,
    target_type: str,
    target_id: str,
    event_type: str,
    link_role: str = "",
    assertion_text: str = "",
    applicability_note: str = "",
    recorded_by: Optional[str] = None,
    recorded_at: Optional[str] = None,
) -> None:
    """Append one immutable record of a change to an evidence-use link."""
    connection.execute(
        """INSERT INTO csf_evidence_link_audit_events(
            evidence_link_audit_event_id, profile_id, basis_id, target_type,
            target_id, event_type, link_role, assertion_text,
            applicability_note, recorded_by, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            str(uuid.uuid4()), profile_id, basis_id, target_type, target_id,
            event_type, link_role, assertion_text, applicability_note,
            recorded_by, recorded_at or utc_now(),
        ),
    )


def list_csf_evidence_link_audit_events(
    connection: sqlite3.Connection,
    profile_id: Any,
    *,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Return append-only evidence-link changes, newest first."""
    profile = _active_csf_profile_id(connection, profile_id)
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer.")
    clauses = ["event.profile_id = ?"]
    values: List[Any] = [profile]
    if target_type is not None:
        clauses.append("event.target_type = ?")
        values.append(str(target_type))
    if target_id is not None:
        clauses.append("event.target_id = ?")
        values.append(str(target_id))
    values.append(limit)
    rows = connection.execute(
        """SELECT event.*, evidence.title AS evidence_title
        FROM csf_evidence_link_audit_events event
        JOIN csf_supporting_basis evidence ON evidence.basis_id = event.basis_id
        WHERE """ + " AND ".join(clauses) + " ORDER BY event.recorded_at DESC, event.evidence_link_audit_event_id DESC LIMIT ?",
        tuple(values),
    ).fetchall()
    return [dict(row) for row in rows]


def list_csf_profile_activity_log(
    connection: sqlite3.Connection, profile_id: Any, limit: int = 500
) -> List[Dict[str, Any]]:
    """Return one chronological, profile-scoped view across core CSF audit ledgers."""
    profile = _active_csf_profile_id(connection, profile_id)
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer.")
    definition = connection.execute(
        "SELECT profile_name FROM csf_profile_definitions WHERE profile_id = ?", (profile,)
    ).fetchone()
    profile_name = str(definition["profile_name"]) if definition is not None else ""
    rows = connection.execute(
        """SELECT * FROM (
            SELECT recorded_at, 'profile' AS log_kind, event_type,
                COALESCE(outcome_id, profile_name) AS subject,
                TRIM(COALESCE(field_name, '') || CASE WHEN rationale <> '' THEN ': ' || rationale ELSE '' END) AS summary,
                recorded_by
            FROM csf_profile_audit_events
            WHERE profile_name = ?
            UNION ALL
            SELECT recorded_at,
                CASE WHEN related_record_type = 'evidence' THEN 'evidence' ELSE 'assessment' END AS log_kind,
                event_type,
                subcategory_id AS subject,
                CASE WHEN related_record_type = 'evidence'
                    THEN rationale_note
                    ELSE 'Current assessment: ' || REPLACE(COALESCE(current_assessment_level, ''), '_', ' ') ||
                        CASE WHEN rationale_note <> '' THEN ' — ' || rationale_note ELSE '' END
                END AS summary,
                recorded_by
            FROM csf_outcome_audit_events
            WHERE profile_id = ? AND related_record_type IN ('current_assessment', 'evidence')
            UNION ALL
            SELECT event.recorded_at, 'evidence' AS log_kind, event.event_type,
                event.target_type || ': ' || event.target_id AS subject,
                evidence.title || CASE WHEN event.link_role <> '' THEN ' — ' || REPLACE(event.link_role, '_', ' ') ELSE '' END AS summary,
                event.recorded_by
            FROM csf_evidence_link_audit_events event
            JOIN csf_supporting_basis evidence ON evidence.basis_id = event.basis_id
            WHERE event.profile_id = ?
            UNION ALL
            SELECT update_record.recorded_at, 'action' AS log_kind, 'action_updated' AS event_type,
                action.subcategory_id || ': ' || action.title AS subject,
                REPLACE(update_record.action_status, '_', ' ') ||
                    CASE WHEN COALESCE(update_record.progress_note, '') <> '' THEN ' — ' || update_record.progress_note ELSE '' END AS summary,
                update_record.recorded_by
            FROM csf_reviewed_action_updates update_record
            JOIN csf_reviewed_actions action ON action.action_id = update_record.action_id
            WHERE action.profile_id = ?
        ) activity
        ORDER BY recorded_at DESC, log_kind, event_type
        LIMIT ?""",
        (profile_name, profile, profile, profile, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def create_csf_supporting_basis(
    connection: sqlite3.Connection,
    *,
    profile_id: Any,
    subcategory_id: Any,
    basis_type: Any,
    title: Any,
    details: Any = "",
    reference_location: Any = "",
    recorded_on: Any = "",
    review_on: Any = "",
    created_by: Any = "",
    outcome_link_role: Any = "supports_outcome",
    assertion_text: Any = "",
    applicability_note: Any = "",
    basis_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a Profile-scoped evidence artifact and its first outcome-use link."""
    profile = _active_csf_profile_id(connection, profile_id)
    subcategory = str(subcategory_id or "").strip().upper()
    if not subcategory:
        raise ValueError("subcategory_id is required.")
    normalized_type = _optional_csf_audit_value(
        basis_type, "basis_type", CSF_SUPPORTING_BASIS_TYPES
    )
    if normalized_type is None:
        raise ValueError("basis_type is required.")
    link_role = _optional_csf_audit_value(
        outcome_link_role,
        "outcome_link_role",
        {"supports_outcome", "supports_current_assessment", "supports_target_rationale"},
    )
    if link_role is None:
        raise ValueError("outcome_link_role is required.")
    record_id = str(basis_id or uuid.uuid4()).strip()
    if not record_id:
        raise ValueError("basis_id must not be blank.")
    now = utc_now()
    with connection:
        connection.execute(
            """
            INSERT INTO csf_supporting_basis (
                basis_id, profile_id, subcategory_id, basis_type, title, details, reference_location, recorded_on, review_on,
                created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                profile,
                subcategory,
                normalized_type,
                _csf_record_text(title, "Title", required=True, maximum=240),
                _csf_record_text(details, "Details", required=False, maximum=8000) or None,
                _csf_record_text(reference_location, "Reference location", required=False, maximum=2000) or None,
                _csf_record_text(recorded_on, "Recorded on", required=False, maximum=64) or None,
                _csf_record_text(review_on, "Review on", required=False, maximum=64) or None,
                _csf_record_text(created_by, "Created by", required=False, maximum=240) or None,
                now,
                now,
            ),
        )
        connection.execute(
            """INSERT INTO csf_evidence_outcome_links(
                evidence_outcome_link_id, basis_id, profile_id, subcategory_id,
                link_role, assertion_text, applicability_note, linked_by,
                linked_at, reviewed_at, review_note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '')""",
            (
                str(uuid.uuid4()), record_id, profile, subcategory,
                link_role,
                _csf_record_text(assertion_text, "Assertion", required=False, maximum=4000),
                _csf_record_text(applicability_note, "Applicability note", required=False, maximum=4000),
                _csf_record_text(created_by, "Created by", required=False, maximum=240) or None,
                now,
            ),
        )
        record_csf_outcome_audit_event(
            connection,
            subcategory_id=subcategory,
            event_type="evidence_linked",
            profile_id=profile,
            related_record_type="evidence",
            related_record_id=record_id,
            rationale_note="Evidence created and linked to this outcome.",
            payload={
                "title": _csf_record_text(title, "Title", required=True, maximum=240),
                "basis_type": normalized_type,
                "outcome_link_role": link_role,
            },
            recorded_by=created_by,
            recorded_at=now,
        )
    row = connection.execute("SELECT * FROM csf_supporting_basis WHERE basis_id = ?", (record_id,)).fetchone()
    return dict(row) if row else {}


def list_csf_supporting_basis(
    connection: sqlite3.Connection, profile_id: Any, subcategory_id: Any, limit: int = 200
) -> List[Dict[str, Any]]:
    profile = _active_csf_profile_id(connection, profile_id)
    subcategory = str(subcategory_id or "").strip().upper()
    if not subcategory:
        raise ValueError("subcategory_id is required.")
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer.")
    return [
        dict(row)
        for row in connection.execute(
            """
            SELECT DISTINCT evidence.*
            FROM csf_supporting_basis evidence
            WHERE evidence.profile_id = ? AND evidence.basis_id IN (
                SELECT link.basis_id
                FROM csf_evidence_outcome_links link
                WHERE link.profile_id = ? AND link.subcategory_id = ?
                UNION
                SELECT action_link.basis_id
                FROM csf_reviewed_action_basis_links action_link
                JOIN csf_reviewed_actions action ON action.action_id = action_link.action_id
                WHERE action.profile_id = ? AND action.subcategory_id = ?
            )
            ORDER BY evidence.updated_at DESC, evidence.basis_id
            LIMIT ?
            """,
            (profile, profile, subcategory, profile, subcategory, limit),
        ).fetchall()
    ]


def link_csf_evidence_to_outcome(
    connection: sqlite3.Connection,
    *,
    basis_id: Any,
    profile_id: Any,
    subcategory_id: Any,
    link_role: Any = "supports_outcome",
    assertion_text: Any = "",
    applicability_note: Any = "",
    linked_by: Any = "",
    reviewed_at: Any = "",
    review_note: Any = "",
) -> Dict[str, Any]:
    """Link a Profile-scoped evidence artifact to an outcome with a distinct assertion."""
    record_id = str(basis_id or "").strip()
    profile = _active_csf_profile_id(connection, profile_id)
    subcategory = str(subcategory_id or "").strip().upper()
    if not record_id or not subcategory:
        raise ValueError("basis_id and subcategory_id are required.")
    role = _optional_csf_audit_value(
        link_role, "link_role", {"supports_outcome", "supports_current_assessment", "supports_target_rationale"}
    )
    if role is None:
        raise ValueError("link_role is required.")
    evidence = connection.execute(
        "SELECT profile_id FROM csf_supporting_basis WHERE basis_id = ?", (record_id,)
    ).fetchone()
    if evidence is None or evidence["profile_id"] != profile:
        raise ValueError("Evidence can be linked only within the same Profile.")
    now = utc_now()
    with connection:
        connection.execute(
            """INSERT INTO csf_evidence_outcome_links(
                evidence_outcome_link_id, basis_id, profile_id, subcategory_id,
                link_role, assertion_text, applicability_note, linked_by,
                linked_at, reviewed_at, review_note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(basis_id, subcategory_id, link_role) DO UPDATE SET
                assertion_text=excluded.assertion_text,
                applicability_note=excluded.applicability_note,
                linked_by=excluded.linked_by,
                linked_at=excluded.linked_at,
                reviewed_at=excluded.reviewed_at,
                review_note=excluded.review_note""",
            (
                str(uuid.uuid4()), record_id, profile, subcategory, role,
                _csf_record_text(assertion_text, "Assertion", required=False, maximum=4000),
                _csf_record_text(applicability_note, "Applicability note", required=False, maximum=4000),
                _csf_record_text(linked_by, "Linked by", required=False, maximum=240) or None,
                now,
                _csf_record_text(reviewed_at, "Reviewed at", required=False, maximum=64) or None,
                _csf_record_text(review_note, "Review note", required=False, maximum=4000),
            ),
        )
    row = connection.execute(
        """SELECT * FROM csf_evidence_outcome_links
        WHERE basis_id = ? AND subcategory_id = ? AND link_role = ?""",
        (record_id, subcategory, role),
    ).fetchone()
    return dict(row) if row else {}


def list_csf_evidence_library(
    connection: sqlite3.Connection, profile_id: Any, limit: int = 500
) -> List[Dict[str, Any]]:
    """Return each evidence artifact once, with counts of its current uses."""
    profile = _active_csf_profile_id(connection, profile_id)
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer.")
    rows = connection.execute(
        """SELECT evidence.*,
            COUNT(DISTINCT outcome_link.evidence_outcome_link_id) AS outcome_link_count,
            COUNT(DISTINCT action_link.action_id) AS action_link_count,
            COUNT(DISTINCT update_link.action_update_id) AS action_update_link_count
        FROM csf_supporting_basis evidence
        LEFT JOIN csf_evidence_outcome_links outcome_link ON outcome_link.basis_id = evidence.basis_id
        LEFT JOIN csf_reviewed_action_basis_links action_link ON action_link.basis_id = evidence.basis_id
        LEFT JOIN csf_reviewed_action_update_basis_links update_link ON update_link.basis_id = evidence.basis_id
        WHERE evidence.profile_id = ?
        GROUP BY evidence.basis_id
        ORDER BY evidence.updated_at DESC, evidence.basis_id
        LIMIT ?""",
        (profile, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def get_csf_evidence_detail(
    connection: sqlite3.Connection, profile_id: Any, basis_id: Any
) -> Dict[str, Any]:
    """Return one Profile evidence artifact and every current, auditable use of it."""
    profile = _active_csf_profile_id(connection, profile_id)
    record_id = str(basis_id or "").strip()
    if not record_id:
        raise ValueError("basis_id is required.")
    evidence_row = connection.execute(
        "SELECT * FROM csf_supporting_basis WHERE basis_id = ? AND profile_id = ?",
        (record_id, profile),
    ).fetchone()
    if evidence_row is None:
        raise ValueError("Evidence was not found in the selected Profile.")
    outcome_uses = connection.execute(
        """SELECT subcategory_id, link_role, assertion_text, applicability_note,
            linked_by, linked_at, reviewed_at, review_note
        FROM csf_evidence_outcome_links
        WHERE basis_id = ? AND profile_id = ?
        ORDER BY subcategory_id, link_role""",
        (record_id, profile),
    ).fetchall()
    action_uses = connection.execute(
        """SELECT action.action_id, action.subcategory_id, action.title,
            action.action_status, link.link_role, link.assertion_text,
            link.applicability_note, link.linked_by, link.linked_at,
            link.reviewed_at, link.review_note
        FROM csf_reviewed_action_basis_links link
        JOIN csf_reviewed_actions action ON action.action_id = link.action_id
        WHERE link.basis_id = ? AND action.profile_id = ?
        ORDER BY action.updated_at DESC, action.action_id""",
        (record_id, profile),
    ).fetchall()
    update_uses = connection.execute(
        """SELECT update_record.action_update_id, action.action_id,
            action.subcategory_id, action.title, update_record.action_status,
            update_record.progress_note, update_record.recorded_by,
            update_record.recorded_at, link.assertion_text,
            link.applicability_note, link.linked_by, link.linked_at,
            link.reviewed_at, link.review_note
        FROM csf_reviewed_action_update_basis_links link
        JOIN csf_reviewed_action_updates update_record ON update_record.action_update_id = link.action_update_id
        JOIN csf_reviewed_actions action ON action.action_id = update_record.action_id
        WHERE link.basis_id = ? AND action.profile_id = ?
        ORDER BY update_record.recorded_at DESC, update_record.action_update_id DESC""",
        (record_id, profile),
    ).fetchall()
    return {
        "evidence": dict(evidence_row),
        "outcome_uses": [dict(row) for row in outcome_uses],
        "action_uses": [dict(row) for row in action_uses],
        "action_update_uses": [dict(row) for row in update_uses],
    }


def link_csf_evidence_to_action_update(
    connection: sqlite3.Connection,
    *,
    action_update_id: Any,
    basis_id: Any,
    assertion_text: Any = "",
    applicability_note: Any = "",
    linked_by: Any = "",
    reviewed_at: Any = "",
    review_note: Any = "",
) -> Dict[str, Any]:
    """Link evidence to one immutable action-update assertion within its Profile."""
    update_id = str(action_update_id or "").strip()
    record_id = str(basis_id or "").strip()
    if not update_id or not record_id:
        raise ValueError("action_update_id and basis_id are required.")
    row = connection.execute(
        """SELECT action.profile_id AS action_profile_id, evidence.profile_id AS evidence_profile_id
        FROM csf_reviewed_action_updates update_record
        JOIN csf_reviewed_actions action ON action.action_id = update_record.action_id
        JOIN csf_supporting_basis evidence ON evidence.basis_id = ?
        WHERE update_record.action_update_id = ?""",
        (record_id, update_id),
    ).fetchone()
    if row is None or row["action_profile_id"] != row["evidence_profile_id"]:
        raise ValueError("Evidence and action update must belong to the same Profile.")
    now = utc_now()
    with connection:
        connection.execute(
            """INSERT INTO csf_reviewed_action_update_basis_links(
                action_update_id, basis_id, assertion_text, applicability_note,
                linked_by, linked_at, reviewed_at, review_note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(action_update_id, basis_id) DO UPDATE SET
                assertion_text=excluded.assertion_text,
                applicability_note=excluded.applicability_note,
                linked_by=excluded.linked_by,
                linked_at=excluded.linked_at,
                reviewed_at=excluded.reviewed_at,
                review_note=excluded.review_note""",
            (
                update_id, record_id,
                _csf_record_text(assertion_text, "Assertion", required=False, maximum=4000),
                _csf_record_text(applicability_note, "Applicability note", required=False, maximum=4000),
                _csf_record_text(linked_by, "Linked by", required=False, maximum=240) or None,
                now,
                _csf_record_text(reviewed_at, "Reviewed at", required=False, maximum=64) or None,
                _csf_record_text(review_note, "Review note", required=False, maximum=4000),
            ),
        )
    linked = connection.execute(
        """SELECT * FROM csf_reviewed_action_update_basis_links
        WHERE action_update_id = ? AND basis_id = ?""",
        (update_id, record_id),
    ).fetchone()
    return dict(linked) if linked else {}


def create_csf_reviewed_action(
    connection: sqlite3.Connection,
    *,
    profile_id: Any,
    subcategory_id: Any,
    title: Any,
    action_status: Any,
    details: Any = "",
    rationale: Any = "",
    progress_note: Any = "",
    completed_at: Any = "",
    created_by: Any = "",
    basis_ids: Iterable[Any] = (),
    control_id: Any = "",
    framework_id: str = "nist-sp-800-53-r5.2.0",
    action_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a reviewed action and optional Profile-scoped evidence links."""
    profile = _active_csf_profile_id(connection, profile_id)
    subcategory = str(subcategory_id or "").strip().upper()
    if not subcategory:
        raise ValueError("subcategory_id is required.")
    status = _optional_csf_audit_value(
        action_status, "action_status", CSF_REVIEWED_ACTION_STATUSES
    )
    if status is None:
        raise ValueError("action_status is required.")
    linked_basis_ids = sorted({str(value or "").strip() for value in basis_ids if str(value or "").strip()})
    selected_control_id = str(control_id or "").strip().upper()
    if linked_basis_ids:
        placeholders = ", ".join("?" for _ in linked_basis_ids)
        basis_rows = connection.execute(
            f"SELECT basis_id, profile_id FROM csf_supporting_basis WHERE basis_id IN ({placeholders})",
            linked_basis_ids,
        ).fetchall()
        if len(basis_rows) != len(linked_basis_ids) or any(row["profile_id"] != profile for row in basis_rows):
            raise ValueError("Reviewed actions can link only evidence from the same Profile.")
    if selected_control_id:
        mapping = connection.execute(
            """SELECT 1 FROM csf_subcategory_control_mappings
            WHERE framework_id = ? AND control_id = ? AND subcategory_id = ?""",
            (framework_id, selected_control_id, subcategory),
        ).fetchone()
        if mapping is None:
            raise ValueError("Choose a control mapped to the selected CSF Subcategory.")
        existing_link = connection.execute(
            """SELECT link.action_id FROM csf_reviewed_action_control_links link
            JOIN csf_reviewed_actions action ON action.action_id = link.action_id
            WHERE link.framework_id = ? AND link.control_id = ? AND link.subcategory_id = ?
              AND action.profile_id = ?""",
            (framework_id, selected_control_id, subcategory, profile),
        ).fetchone()
        if existing_link is not None:
            raise ValueError("This mapped control already has an action for the selected CSF Subcategory.")
    record_id = str(action_id or uuid.uuid4()).strip()
    if not record_id:
        raise ValueError("action_id must not be blank.")
    now = utc_now()
    recorded_completed_at = _csf_record_text(completed_at, "Completed at", required=False, maximum=64) or None
    if status == "completed" and recorded_completed_at is None:
        recorded_completed_at = now
    with connection:
        connection.execute(
            """
            INSERT INTO csf_reviewed_actions (
                action_id, profile_id, subcategory_id, title, details, rationale, action_status, completed_at,
                created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                profile,
                subcategory,
                _csf_record_text(title, "Title", required=True, maximum=240),
                _csf_record_text(details, "Details", required=False, maximum=8000) or None,
                _csf_record_text(rationale, "Rationale", required=False, maximum=4000) or None,
                status,
                recorded_completed_at,
                _csf_record_text(created_by, "Created by", required=False, maximum=240) or None,
                now,
                now,
            ),
        )
        connection.executemany(
            """INSERT INTO csf_reviewed_action_basis_links(
                action_id, basis_id, link_role, assertion_text, applicability_note,
                linked_by, linked_at, reviewed_at, review_note
            ) VALUES (?, ?, 'supports_action', '', '', ?, ?, NULL, '')""",
            [
                (
                    record_id, basis_id,
                    _csf_record_text(created_by, "Created by", required=False, maximum=240) or None,
                    now,
                )
                for basis_id in linked_basis_ids
            ],
        )
        for linked_basis_id in linked_basis_ids:
            _record_csf_evidence_link_audit_event(
                connection, profile_id=profile, basis_id=linked_basis_id,
                target_type="action", target_id=record_id, event_type="linked",
                link_role="supports_action",
                recorded_by=_csf_record_text(created_by, "Created by", required=False, maximum=240) or None,
                recorded_at=now,
            )
        if selected_control_id:
            connection.execute(
                """INSERT INTO csf_reviewed_action_control_links(
                    action_id, framework_id, control_id, subcategory_id, linked_at
                ) VALUES (?, ?, ?, ?, ?)""",
                (record_id, framework_id, selected_control_id, subcategory, now),
            )
        connection.execute(
            """
            INSERT INTO csf_reviewed_action_updates(
                action_update_id, action_id, action_status, progress_note, recorded_by, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                status,
                _csf_record_text(progress_note, "Progress note", required=False, maximum=8000) or None,
                _csf_record_text(created_by, "Created by", required=False, maximum=240) or None,
                now,
            ),
        )
    connection.commit()
    row = connection.execute("SELECT * FROM csf_reviewed_actions WHERE action_id = ?", (record_id,)).fetchone()
    return dict(row) if row else {}


def list_csf_reviewed_action_updates(
    connection: sqlite3.Connection, action_id: Any, limit: int = 200
) -> List[Dict[str, Any]]:
    """Return an action's immutable progress history, newest first."""
    record_id = str(action_id or "").strip()
    if not record_id:
        raise ValueError("action_id is required.")
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer.")
    return [
        {
            **dict(row),
            "basis_titles": str(row["basis_titles"] or "").split(",") if row["basis_titles"] else [],
        }
        for row in connection.execute(
            """
            SELECT update_record.*, GROUP_CONCAT(DISTINCT evidence.title) AS basis_titles
            FROM csf_reviewed_action_updates update_record
            LEFT JOIN csf_reviewed_action_update_basis_links link
                ON link.action_update_id = update_record.action_update_id
            LEFT JOIN csf_supporting_basis evidence ON evidence.basis_id = link.basis_id
            WHERE update_record.action_id = ?
            GROUP BY update_record.action_update_id
            ORDER BY update_record.recorded_at DESC, update_record.action_update_id DESC
            LIMIT ?
            """,
            (record_id, limit),
        ).fetchall()
    ]


def update_csf_reviewed_action(
    connection: sqlite3.Connection,
    *,
    action_id: Any,
    title: Any,
    action_status: Any,
    details: Any = "",
    rationale: Any = "",
    progress_note: Any = "",
    updated_by: Any = "",
    basis_ids: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    """Update an action and reconcile its current Profile evidence links."""
    record_id = str(action_id or "").strip()
    if not record_id:
        raise ValueError("action_id is required.")
    status = _optional_csf_audit_value(
        action_status, "action_status", CSF_REVIEWED_ACTION_STATUSES
    )
    if status is None:
        raise ValueError("action_status is required.")
    current = connection.execute(
        "SELECT profile_id, completed_at, updated_at FROM csf_reviewed_actions WHERE action_id = ?", (record_id,)
    ).fetchone()
    if current is None:
        raise ValueError("Reviewed action was not found.")
    linked_basis_ids = None if basis_ids is None else sorted(
        {str(value or "").strip() for value in basis_ids if str(value or "").strip()}
    )
    if linked_basis_ids:
        placeholders = ", ".join("?" for _ in linked_basis_ids)
        basis_rows = connection.execute(
            f"SELECT basis_id, profile_id FROM csf_supporting_basis WHERE basis_id IN ({placeholders})",
            linked_basis_ids,
        ).fetchall()
        if len(basis_rows) != len(linked_basis_ids) or any(row["profile_id"] != current["profile_id"] for row in basis_rows):
            raise ValueError("Action updates can link only evidence from the same Profile.")
    existing_basis_ids = {
        str(row["basis_id"])
        for row in connection.execute(
            "SELECT basis_id FROM csf_reviewed_action_basis_links WHERE action_id = ?",
            (record_id,),
        ).fetchall()
    }
    now = utc_now()
    previous_updated_at = datetime.fromisoformat(str(current["updated_at"]))
    if datetime.fromisoformat(now) <= previous_updated_at:
        now = (previous_updated_at + timedelta(microseconds=1)).isoformat()
    completed_at = current["completed_at"] or (now if status == "completed" else None)
    update_id = str(uuid.uuid4())
    with connection:
        connection.execute(
            """
            UPDATE csf_reviewed_actions
            SET title = ?, details = ?, rationale = ?, action_status = ?, completed_at = ?, updated_at = ?
            WHERE action_id = ?
            """,
            (
                _csf_record_text(title, "Title", required=True, maximum=240),
                _csf_record_text(details, "Details", required=False, maximum=8000) or None,
                _csf_record_text(rationale, "Rationale", required=False, maximum=4000) or None,
                status,
                completed_at,
                now,
                record_id,
            ),
        )
        if linked_basis_ids is not None:
            requested_basis_ids = set(linked_basis_ids)
            removed_basis_ids = sorted(existing_basis_ids - requested_basis_ids)
            added_basis_ids = sorted(requested_basis_ids - existing_basis_ids)
            connection.executemany(
                "DELETE FROM csf_reviewed_action_basis_links WHERE action_id = ? AND basis_id = ?",
                [(record_id, basis_id) for basis_id in removed_basis_ids],
            )
            connection.executemany(
                """INSERT INTO csf_reviewed_action_basis_links(
                    action_id, basis_id, link_role, assertion_text, applicability_note,
                    linked_by, linked_at, reviewed_at, review_note
                ) VALUES (?, ?, 'supports_action', '', '', ?, ?, NULL, '')""",
                [
                    (
                        record_id, basis_id,
                        _csf_record_text(updated_by, "Updated by", required=False, maximum=240) or None,
                        now,
                    )
                    for basis_id in added_basis_ids
                ],
            )
            for removed_basis_id in removed_basis_ids:
                _record_csf_evidence_link_audit_event(
                    connection, profile_id=str(current["profile_id"]), basis_id=removed_basis_id,
                    target_type="action", target_id=record_id, event_type="unlinked",
                    link_role="supports_action",
                    recorded_by=_csf_record_text(updated_by, "Updated by", required=False, maximum=240) or None,
                    recorded_at=now,
                )
            for added_basis_id in added_basis_ids:
                _record_csf_evidence_link_audit_event(
                    connection, profile_id=str(current["profile_id"]), basis_id=added_basis_id,
                    target_type="action", target_id=record_id, event_type="linked",
                    link_role="supports_action",
                    recorded_by=_csf_record_text(updated_by, "Updated by", required=False, maximum=240) or None,
                    recorded_at=now,
                )
        connection.execute(
            """
            INSERT INTO csf_reviewed_action_updates(
                action_update_id, action_id, action_status, progress_note, recorded_by, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                update_id,
                record_id,
                status,
                _csf_record_text(progress_note, "Progress note", required=False, maximum=8000) or None,
                _csf_record_text(updated_by, "Updated by", required=False, maximum=240) or None,
                now,
            ),
        )
    row = connection.execute("SELECT * FROM csf_reviewed_actions WHERE action_id = ?", (record_id,)).fetchone()
    return dict(row) if row else {}


def delete_csf_reviewed_action(
    connection: sqlite3.Connection, action_id: Any
) -> Dict[str, Any]:
    """Delete one action and its dependent progress history and basis links."""
    record_id = str(action_id or "").strip()
    if not record_id:
        raise ValueError("action_id is required.")
    row = connection.execute(
        "SELECT * FROM csf_reviewed_actions WHERE action_id = ?", (record_id,)
    ).fetchone()
    if row is None:
        raise ValueError("Reviewed action was not found.")
    deleted = dict(row)
    with connection:
        connection.execute(
            "DELETE FROM csf_reviewed_action_basis_links WHERE action_id = ?", (record_id,)
        )
        connection.execute(
            "DELETE FROM csf_reviewed_action_updates WHERE action_id = ?", (record_id,)
        )
        connection.execute("DELETE FROM csf_reviewed_actions WHERE action_id = ?", (record_id,))
    return deleted


def list_csf_reviewed_actions(
    connection: sqlite3.Connection, profile_id: Any, subcategory_id: Any, limit: int = 200
) -> List[Dict[str, Any]]:
    profile = _active_csf_profile_id(connection, profile_id)
    subcategory = str(subcategory_id or "").strip().upper()
    if not subcategory:
        raise ValueError("subcategory_id is required.")
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer.")
    rows = connection.execute(
        """
        SELECT a.*, GROUP_CONCAT(link.basis_id) AS basis_ids,
            GROUP_CONCAT(DISTINCT evidence.title) AS basis_titles,
            control_link.framework_id AS control_framework_id,
            control_link.control_id AS control_id,
            control.title AS control_title,
            catalog.display_name AS control_catalog_name
        FROM csf_reviewed_actions a
        LEFT JOIN csf_reviewed_action_basis_links link ON link.action_id = a.action_id
        LEFT JOIN csf_supporting_basis evidence ON evidence.basis_id = link.basis_id
        LEFT JOIN csf_reviewed_action_control_links control_link ON control_link.action_id = a.action_id
        LEFT JOIN csf_reference_controls control
            ON control.framework_id = control_link.framework_id AND control.control_id = control_link.control_id
        LEFT JOIN csf_control_catalogs catalog ON catalog.framework_id = control_link.framework_id
        WHERE a.profile_id = ? AND a.subcategory_id = ?
        GROUP BY a.action_id
        ORDER BY a.updated_at DESC, a.action_id
        LIMIT ?
        """,
        (profile, subcategory, limit),
    ).fetchall()
    return [
        {
            **dict(row),
            "basis_ids": str(row["basis_ids"] or "").split(",") if row["basis_ids"] else [],
            "basis_titles": str(row["basis_titles"] or "").split(",") if row["basis_titles"] else [],
        }
        for row in rows
    ]


def list_csf_control_catalogs(connection: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Return registered control catalogs with their imported control and mapping counts."""
    rows = connection.execute(
        """SELECT catalog.*,
            COUNT(DISTINCT control.control_id) AS control_count,
            COUNT(DISTINCT mapping.control_id || '|' || mapping.subcategory_id) AS mapping_count
        FROM csf_control_catalogs catalog
        LEFT JOIN csf_reference_controls control ON control.framework_id = catalog.framework_id
        LEFT JOIN csf_subcategory_control_mappings mapping ON mapping.framework_id = catalog.framework_id
        GROUP BY catalog.framework_id
        ORDER BY catalog.display_name, catalog.framework_id"""
    ).fetchall()
    return [dict(row) for row in rows]


def list_csf_profile_control_catalogs(
    connection: sqlite3.Connection, profile_id: Any
) -> List[Dict[str, Any]]:
    """Return catalog availability for one Profile, with imported-data counts."""
    profile = _active_csf_profile_id(connection, profile_id)
    rows = connection.execute(
        """SELECT catalog.*, selection.is_enabled AS profile_is_enabled,
            selection.configured_by, selection.configured_at,
            COUNT(DISTINCT control.control_id) AS control_count,
            COUNT(DISTINCT mapping.control_id || '|' || mapping.subcategory_id) AS mapping_count
        FROM csf_control_catalogs catalog
        JOIN csf_profile_control_catalogs selection
            ON selection.framework_id = catalog.framework_id AND selection.profile_id = ?
        LEFT JOIN csf_reference_controls control ON control.framework_id = catalog.framework_id
        LEFT JOIN csf_subcategory_control_mappings mapping ON mapping.framework_id = catalog.framework_id
        GROUP BY catalog.framework_id
        ORDER BY catalog.display_name, catalog.framework_id""",
        (profile,),
    ).fetchall()
    return [dict(row) for row in rows]


def set_csf_profile_control_catalog_enabled(
    connection: sqlite3.Connection,
    profile_id: Any,
    framework_id: Any,
    is_enabled: Any,
    configured_by: Any = "",
) -> Dict[str, Any]:
    """Enable or disable one catalog for one editable Organizational Profile."""
    profile = _active_csf_profile_id(connection, profile_id)
    framework = str(framework_id or "").strip()
    if not framework:
        raise ValueError("framework_id is required.")
    definition = connection.execute(
        "SELECT profile_kind FROM csf_profile_definitions WHERE profile_id = ?", (profile,)
    ).fetchone()
    if definition is None or str(definition["profile_kind"]) != "organizational":
        raise ValueError("Control catalogs can be changed only for an Organizational Profile.")
    catalog = connection.execute(
        "SELECT 1 FROM csf_control_catalogs WHERE framework_id = ?", (framework,)
    ).fetchone()
    if catalog is None:
        raise ValueError("The selected control catalog is not registered.")
    enabled = 1 if bool(is_enabled) else 0
    now = utc_now()
    with connection:
        connection.execute(
            """INSERT INTO csf_profile_control_catalogs(
                profile_id, framework_id, is_enabled, configured_by, configured_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(profile_id, framework_id) DO UPDATE SET
                is_enabled=excluded.is_enabled,
                configured_by=excluded.configured_by,
                configured_at=excluded.configured_at""",
            (
                profile, framework, enabled,
                _csf_record_text(configured_by, "Configured by", required=False, maximum=240) or None,
                now,
            ),
        )
    row = connection.execute(
        "SELECT * FROM csf_profile_control_catalogs WHERE profile_id = ? AND framework_id = ?",
        (profile, framework),
    ).fetchone()
    return dict(row) if row else {}


def set_csf_control_catalog_enabled(
    connection: sqlite3.Connection, framework_id: Any, is_enabled: Any
) -> Dict[str, Any]:
    """Enable or disable a catalog without modifying its source data or linked actions."""
    identifier = str(framework_id or "").strip()
    if not identifier:
        raise ValueError("framework_id is required.")
    enabled = 1 if str(is_enabled).strip().lower() in {"1", "true", "yes", "on"} else 0
    now = utc_now()
    with connection:
        result = connection.execute(
            "UPDATE csf_control_catalogs SET is_enabled = ?, updated_at = ? WHERE framework_id = ?",
            (enabled, now, identifier),
        )
    if result.rowcount != 1:
        raise ValueError("The selected control catalog is not registered.")
    row = connection.execute(
        "SELECT * FROM csf_control_catalogs WHERE framework_id = ?", (identifier,)
    ).fetchone()
    return dict(row) if row is not None else {}


def list_csf_mapped_controls_for_subcategory(
    connection: sqlite3.Connection, profile_id: Any, subcategory_id: Any, framework_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Return controls from enabled catalogs mapped to a subcategory and any linked action."""
    profile = _active_csf_profile_id(connection, profile_id)
    subcategory = str(subcategory_id or "").strip().upper()
    if not subcategory:
        raise ValueError("subcategory_id is required.")
    return [
        dict(row)
        for row in connection.execute(
            """SELECT mapping.framework_id, catalog.display_name AS catalog_name,
                mapping.control_id, control.title, control.statement_text,
                mapping.interpretation_text, mapping.suggested_action_text, mapping.action_title_example,
                mapping.action_details_example, mapping.action_rationale_example, mapping.confidence_note,
                mapping.interpretation_source,
                action.action_id, action.title AS action_title,
                action.action_status
            FROM csf_subcategory_control_mappings mapping
            JOIN csf_reference_controls control
                ON control.framework_id = mapping.framework_id AND control.control_id = mapping.control_id
            JOIN csf_control_catalogs catalog
                ON catalog.framework_id = mapping.framework_id
            JOIN csf_profile_control_catalogs selection
                ON selection.framework_id = mapping.framework_id
                AND selection.profile_id = ? AND selection.is_enabled = 1
            LEFT JOIN csf_reviewed_action_control_links action_link
                ON action_link.framework_id = mapping.framework_id
                AND action_link.control_id = mapping.control_id
                AND action_link.subcategory_id = mapping.subcategory_id
                AND action_link.action_id IN (
                    SELECT action_id FROM csf_reviewed_actions WHERE profile_id = ?
                )
            LEFT JOIN csf_reviewed_actions action
                ON action.action_id = action_link.action_id
            WHERE mapping.subcategory_id = ?
                AND (? IS NULL OR mapping.framework_id = ?)
            ORDER BY catalog.display_name, mapping.control_id""",
            (profile, profile, subcategory, framework_id, framework_id),
        ).fetchall()
    ]


def _next_local_csf_suffix(connection: sqlite3.Connection, function_id: str) -> int:
    rows = connection.execute(
        "SELECT local_category_id FROM local_csf_categories WHERE function_id = ?",
        (function_id,),
    ).fetchall()
    suffixes = []
    for row in rows:
        match = LOCAL_CSF_CATEGORY_ID_RE.fullmatch(str(row["local_category_id"]))
        if match:
            suffixes.append(int(match.group(2)))
    return (max(suffixes) if suffixes else 0) + 1


def create_local_csf_category(
    connection: sqlite3.Connection,
    function_id: str,
    title: Any,
    objective: Any,
    advisory_evidence_text: Any = "",
    advisory_action_text: Any = "",
) -> Dict[str, Any]:
    """Create advisory-only local CSF content; no executable field exists in this contract."""
    function = str(function_id or "").strip().upper()
    if function not in LOCAL_CSF_FUNCTION_IDS:
        raise ValueError("Local Category must belong to one official CSF Function.")
    now = utc_now()
    with connection:
        local_category_id = f"LOCAL.{function}.{_next_local_csf_suffix(connection, function):02d}"
        connection.execute(
            """
            INSERT INTO local_csf_categories (
                local_category_id, function_id, title, objective, advisory_evidence_text,
                advisory_action_text, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                local_category_id,
                function,
                _local_csf_text(title, "Title", required=True, maximum=160),
                _local_csf_text(objective, "Objective", required=True, maximum=2000),
                _local_csf_text(advisory_evidence_text, "Advisory evidence description", required=False, maximum=2000),
                _local_csf_text(advisory_action_text, "Advisory action description", required=False, maximum=2000),
                now,
                now,
            ),
        )
    return get_local_csf_category(connection, local_category_id)


def get_local_csf_category(connection: sqlite3.Connection, local_category_id: str) -> Dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM local_csf_categories WHERE local_category_id = ?",
        (str(local_category_id or "").strip().upper(),),
    ).fetchone()
    return dict(row) if row else {}


def list_local_csf_categories(connection: sqlite3.Connection, function_id: str) -> List[Dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM local_csf_categories WHERE function_id = ? ORDER BY local_category_id",
            (str(function_id or "").strip().upper(),),
        ).fetchall()
    ]


def create_local_csf_outcome(
    connection: sqlite3.Connection,
    local_category_id: str,
    title: Any,
    objective: Any,
    advisory_evidence_text: Any = "",
    advisory_action_text: Any = "",
) -> Dict[str, Any]:
    category = get_local_csf_category(connection, local_category_id)
    if not category:
        raise ValueError("Local outcome must belong to an existing local Category.")
    match = LOCAL_CSF_CATEGORY_ID_RE.fullmatch(category["local_category_id"])
    if not match:
        raise ValueError("Local Category identifier is invalid.")
    rows = connection.execute(
        "SELECT local_outcome_id FROM local_csf_outcomes WHERE local_category_id = ?",
        (category["local_category_id"],),
    ).fetchall()
    suffixes = [
        int(item.group(3))
        for row in rows
        if (item := LOCAL_CSF_OUTCOME_ID_RE.fullmatch(str(row["local_outcome_id"])))
    ]
    local_outcome_id = f"{category['local_category_id']}.{(max(suffixes) if suffixes else 0) + 1:02d}"
    now = utc_now()
    with connection:
        connection.execute(
            """
            INSERT INTO local_csf_outcomes (
                local_outcome_id, local_category_id, title, objective, advisory_evidence_text,
                advisory_action_text, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                local_outcome_id,
                category["local_category_id"],
                _local_csf_text(title, "Title", required=True, maximum=160),
                _local_csf_text(objective, "Objective", required=True, maximum=2000),
                _local_csf_text(advisory_evidence_text, "Advisory evidence description", required=False, maximum=2000),
                _local_csf_text(advisory_action_text, "Advisory action description", required=False, maximum=2000),
                now,
                now,
            ),
        )
    row = connection.execute("SELECT * FROM local_csf_outcomes WHERE local_outcome_id = ?", (local_outcome_id,)).fetchone()
    return dict(row) if row else {}


def list_local_csf_outcomes(connection: sqlite3.Connection, local_category_id: str) -> List[Dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM local_csf_outcomes WHERE local_category_id = ? ORDER BY local_outcome_id",
            (str(local_category_id or "").strip().upper(),),
        ).fetchall()
    ]


def parse_tripwire_timestamp(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return utc_now()

    candidates = [text]
    if text.endswith("Z"):
        candidates.append(text[:-1] + "+00:00")
    for candidate in candidates:
        try:
            return datetime.fromisoformat(candidate).astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
    for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S %p"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return text


def derive_baseline_id(document: Dict[str, Any], source_json_path: Path) -> str:
    metadata = document.get("Metadata") or {}
    explicit = str(metadata.get("BaselineId") or "").strip()
    if explicit:
        return explicit
    return source_json_path.stem


def index_tripwire_baseline(
    connection: sqlite3.Connection,
    source_json_path: Path,
    source_markdown_path: Optional[Path] = None,
) -> Dict[str, Any]:
    document = load_json(source_json_path)
    if not isinstance(document, dict):
        raise ValueError(f"Tripwire baseline must be a JSON object: {source_json_path}")

    metadata = document.get("Metadata") or {}
    watched_files = list(document.get("WatchedFiles") or [])
    baseline_id = derive_baseline_id(document, source_json_path)
    created_at = parse_tripwire_timestamp(metadata.get("CollectionTimeUtc"))
    host = str(metadata.get("ComputerName") or "")
    execution_context = metadata.get("ExecutionContext") or {}
    scope = str((execution_context.get("Scope") if isinstance(execution_context, dict) else "") or "")
    watched_file_count = len(watched_files)
    hashed_file_count = sum(1 for item in watched_files if str(item.get("SHA256") or "").strip())

    connection.execute(
        """
        INSERT INTO baseline_runs (
            baseline_id, created_at, host, scope, watched_file_count, hashed_file_count,
            source_json_path, source_markdown_path
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(baseline_id) DO UPDATE SET
            created_at = excluded.created_at,
            host = excluded.host,
            scope = excluded.scope,
            watched_file_count = excluded.watched_file_count,
            hashed_file_count = excluded.hashed_file_count,
            source_json_path = excluded.source_json_path,
            source_markdown_path = excluded.source_markdown_path
        """,
        (
            baseline_id,
            created_at,
            host,
            scope,
            watched_file_count,
            hashed_file_count,
            str(source_json_path),
            str(source_markdown_path) if source_markdown_path else "",
        ),
    )

    indexed_rows = 0
    for entry in watched_files:
        path = str(entry.get("Path") or "").strip()
        if not path:
            continue
        sha256 = str(entry.get("SHA256") or "").strip().lower() or None
        connection.execute(
            """
            INSERT INTO baseline_file_hashes (
                baseline_id, path, sha256, size_bytes, last_write_time_utc, exists_at_baseline, source_json_path
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(baseline_id, path) DO UPDATE SET
                sha256 = excluded.sha256,
                size_bytes = excluded.size_bytes,
                last_write_time_utc = excluded.last_write_time_utc,
                exists_at_baseline = excluded.exists_at_baseline,
                source_json_path = excluded.source_json_path
            """,
            (
                baseline_id,
                path,
                sha256,
                entry.get("Length"),
                str(entry.get("LastWriteTimeUtc") or "").strip() or None,
                1 if bool(entry.get("Exists")) else 0,
                str(source_json_path),
            ),
        )
        indexed_rows += 1

    connection.commit()
    return {
        "baseline_id": baseline_id,
        "created_at": created_at,
        "host": host,
        "scope": scope,
        "watched_file_count": watched_file_count,
        "hashed_file_count": hashed_file_count,
        "indexed_file_rows": indexed_rows,
        "source_json_path": str(source_json_path),
        "source_markdown_path": str(source_markdown_path) if source_markdown_path else "",
    }


def backfill_tripwire_baselines(connection: sqlite3.Connection, root: Path) -> Dict[str, Any]:
    indexed = []
    for path in sorted(root.glob("HOST_TRIPWIRE_BASELINE_*.json")):
        md_path = path.with_suffix(".md")
        indexed.append(index_tripwire_baseline(connection, path.resolve(), md_path.resolve() if md_path.exists() else None))
    return {
        "root": str(root),
        "baseline_count": len(indexed),
        "baselines": indexed,
    }


def get_latest_baseline_hash_status(connection: sqlite3.Connection) -> Dict[str, Any]:
    row = connection.execute(
        """
        SELECT baseline_id, created_at, host, scope, watched_file_count, hashed_file_count, source_json_path, source_markdown_path
        FROM baseline_runs
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        return {
            "available": False,
            "status": "empty",
            "latest_baseline_id": None,
            "baseline_timestamp": None,
            "baseline_hash_count": 0,
            "watched_file_count": 0,
            "source_json_path": None,
            "source_markdown_path": None,
        }

    hash_count = connection.execute(
        """
        SELECT COUNT(*) FROM baseline_file_hashes
        WHERE baseline_id = ? AND sha256 IS NOT NULL AND trim(sha256) <> ''
        """,
        (row["baseline_id"],),
    ).fetchone()[0]
    return {
        "available": True,
        "status": "available",
        "latest_baseline_id": row["baseline_id"],
        "baseline_timestamp": row["created_at"],
        "baseline_hash_count": int(hash_count),
        "watched_file_count": int(row["watched_file_count"] or 0),
        "source_json_path": row["source_json_path"],
        "source_markdown_path": row["source_markdown_path"],
        "host": row["host"],
        "scope": row["scope"],
    }


def match_sha256_indicators_against_baseline_hashes(
    connection: sqlite3.Connection,
    latest_only: bool = True,
) -> Dict[str, Any]:
    baseline_status = get_latest_baseline_hash_status(connection)
    if not baseline_status["available"]:
        return {
            "baseline_hash_index_status": "empty",
            "baseline_id": None,
            "baseline_timestamp": None,
            "baseline_hashes_checked": 0,
            "matches": [],
        }

    params: List[Any] = []
    baseline_filter = ""
    if latest_only and baseline_status["latest_baseline_id"]:
        baseline_filter = " AND b.baseline_id = ?"
        params.append(baseline_status["latest_baseline_id"])

    rows = connection.execute(
        f"""
        SELECT
            b.baseline_id,
            br.created_at AS baseline_timestamp,
            b.path,
            b.sha256,
            b.size_bytes,
            b.last_write_time_utc,
            i.value AS indicator_value,
            i.source,
            i.confidence,
            i.severity,
            i.valid_until
        FROM baseline_file_hashes b
        JOIN baseline_runs br
          ON br.baseline_id = b.baseline_id
        JOIN indicators i
          ON i.value = b.sha256
        WHERE i.type = 'sha256'
          AND b.sha256 IS NOT NULL
          AND trim(b.sha256) <> ''
          {baseline_filter}
        ORDER BY br.created_at DESC, b.path
        """,
        params,
    ).fetchall()

    if latest_only and baseline_status["latest_baseline_id"]:
        baseline_hashes_checked = connection.execute(
            """
            SELECT COUNT(*) FROM baseline_file_hashes
            WHERE baseline_id = ? AND sha256 IS NOT NULL AND trim(sha256) <> ''
            """,
            (baseline_status["latest_baseline_id"],),
        ).fetchone()[0]
    else:
        baseline_hashes_checked = connection.execute(
            "SELECT COUNT(*) FROM baseline_file_hashes WHERE sha256 IS NOT NULL AND trim(sha256) <> ''"
        ).fetchone()[0]

    reference_time = datetime.now(timezone.utc)
    matches = [
        {
            "baseline_id": row["baseline_id"],
            "baseline_timestamp": row["baseline_timestamp"],
            "path": row["path"],
            "sha256": row["sha256"],
            "size_bytes": row["size_bytes"],
            "last_write_time_utc": row["last_write_time_utc"],
            "indicator_value": row["indicator_value"],
            "source": row["source"],
            "confidence": row["confidence"],
            "severity": row["severity"],
        }
        for row in rows
        if indicator_is_active({"valid_until": row["valid_until"]}, reference_time)
    ]
    return {
        "baseline_hash_index_status": "available",
        "baseline_id": baseline_status["latest_baseline_id"] if latest_only else None,
        "baseline_timestamp": baseline_status["baseline_timestamp"] if latest_only else None,
        "baseline_hashes_checked": int(baseline_hashes_checked),
        "matches": matches,
    }


URL_PATTERN = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


def parse_snapshot_timestamp(value: Any, fallback: Optional[str] = None) -> str:
    text = str(value or "").strip()
    if not text:
        return fallback or utc_now()
    return parse_tripwire_timestamp(text)


def normalize_sha256(value: Any) -> str:
    return str(value or "").strip().lower()


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def normalize_optional_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def extract_command_path(command_line: str) -> str:
    text = normalize_text(command_line)
    if not text:
        return ""
    quoted = re.match(r'^"([^"]+)"', text)
    if quoted:
        return quoted.group(1)
    token = text.split()[0]
    if re.search(r"\.(exe|dll|ps1|bat|cmd|vbs|js)$", token, re.IGNORECASE):
        return token
    return ""


def extract_urls_from_text(text: str) -> List[str]:
    values = []
    for match in URL_PATTERN.findall(text or ""):
        values.append(match.rstrip(".,;)]").lower())
    return sorted(set(values))


def upsert_evidence_snapshot(
    connection: sqlite3.Connection,
    snapshot_id: str,
    snapshot_type: str,
    created_at: str,
    host: str,
    source_json_path: str,
    source_markdown_path: str,
    collector_version: str,
    trust_label: str,
) -> None:
    connection.execute(
        """
        INSERT INTO evidence_snapshots (
            snapshot_id, snapshot_type, created_at, host, source_json_path, source_markdown_path, collector_version, trust_label
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(snapshot_id) DO UPDATE SET
            snapshot_type = excluded.snapshot_type,
            created_at = excluded.created_at,
            host = excluded.host,
            source_json_path = excluded.source_json_path,
            source_markdown_path = excluded.source_markdown_path,
            collector_version = excluded.collector_version,
            trust_label = excluded.trust_label
        """,
        (
            snapshot_id,
            snapshot_type,
            created_at,
            host,
            source_json_path,
            source_markdown_path,
            collector_version,
            trust_label,
        ),
    )


def clear_snapshot_observations(connection: sqlite3.Connection, snapshot_id: str) -> None:
    for table_name in [
        "network_connection_observations",
        "dns_cache_observations",
        "powershell_event_observations",
        "windows_event_observations",
        "registry_observations",
        "service_observations",
        "scheduled_task_observations",
        "autorun_observations",
        "process_observations",
        "file_observations",
    ]:
        connection.execute(f"DELETE FROM {table_name} WHERE snapshot_id = ?", (snapshot_id,))


def index_evidence_snapshot(
    connection: sqlite3.Connection,
    input_path: Path,
    snapshot_id: str,
    snapshot_type: str,
    source_json_path: str,
    source_markdown_path: str,
    collector_version: str,
    trust_label: str,
) -> Dict[str, Any]:
    document = load_json(input_path)
    if not isinstance(document, dict):
        raise ValueError(f"Evidence snapshot input must be a JSON object: {input_path}")

    metadata = document.get("Metadata") or {}
    created_at = parse_snapshot_timestamp(metadata.get("CollectionTimeUtc"))
    host = normalize_text(metadata.get("ComputerName"))
    records = list(document.get("NormalizedIOCRecords") or [])

    upsert_evidence_snapshot(
        connection=connection,
        snapshot_id=snapshot_id,
        snapshot_type=snapshot_type,
        created_at=created_at,
        host=host,
        source_json_path=source_json_path,
        source_markdown_path=source_markdown_path,
        collector_version=collector_version,
        trust_label=trust_label,
    )
    clear_snapshot_observations(connection, snapshot_id)

    counts = {
        "process_observations": 0,
        "service_observations": 0,
        "scheduled_task_observations": 0,
        "autorun_observations": 0,
        "network_connection_observations": 0,
        "dns_cache_observations": 0,
        "powershell_event_observations": 0,
        "windows_event_observations": 0,
        "registry_observations": 0,
        "file_observations": 0,
    }

    for record in records:
        if not isinstance(record, dict):
            continue
        category = normalize_text(record.get("Category"))
        observed_at = parse_snapshot_timestamp(record.get("Timestamp"), created_at)
        path = normalize_text(record.get("Path"))
        command_line = normalize_text(record.get("CommandLine"))
        name = normalize_text(record.get("Name"))
        value = normalize_text(record.get("Value"))
        registry_path = normalize_text(record.get("RegistryPath"))
        sha256 = normalize_sha256(record.get("Hash")) if normalize_text(record.get("HashAlgorithm")).lower() == "sha256" else ""

        if category == "Process":
            connection.execute(
                """
                INSERT INTO process_observations (
                    snapshot_id, observed_at, name, path, sha256, command_line, owner, process_id, parent_process_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    observed_at,
                    name,
                    path,
                    sha256 or None,
                    command_line or None,
                    normalize_text(record.get("Owner")) or None,
                    normalize_optional_int(record.get("PID")),
                    normalize_optional_int(record.get("ParentPID")),
                ),
            )
            counts["process_observations"] += 1
            if path:
                connection.execute(
                    """
                    INSERT INTO file_observations (
                        snapshot_id, observed_at, observation_type, path, filename, sha256, size_bytes, last_write_time_utc, source_note
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        observed_at,
                        "ProcessExecutable",
                        path,
                        Path(path).name,
                        sha256 or None,
                        None,
                        observed_at,
                        "Process executable observed in current collector output.",
                    ),
                )
                counts["file_observations"] += 1
            continue

        if category == "Service":
            connection.execute(
                """
                INSERT INTO service_observations (
                    snapshot_id, observed_at, service_name, display_name, image_path, start_name, state, start_mode, registry_path, process_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    observed_at,
                    name or None,
                    value or None,
                    path or None,
                    normalize_text(record.get("Owner")) or None,
                    normalize_text(record.get("Notes")) or None,
                    None,
                    registry_path or None,
                    normalize_optional_int(record.get("PID")),
                ),
            )
            counts["service_observations"] += 1
            if registry_path:
                connection.execute(
                    """
                    INSERT INTO registry_observations (
                        snapshot_id, observed_at, key_path, value_name, value_data, source_type
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        observed_at,
                        registry_path,
                        "ImagePath",
                        path or None,
                        "Service",
                    ),
                )
                counts["registry_observations"] += 1
            continue

        if category == "ScheduledTask":
            task_path = ""
            task_name = name
            if path:
                task_path = path
                task_name = Path(path).name if path not in ("\\", "/") else name
            connection.execute(
                """
                INSERT INTO scheduled_task_observations (
                    snapshot_id, observed_at, task_name, task_path, author, state, last_run_time, next_run_time, last_task_result, action
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    observed_at,
                    task_name or None,
                    path or None,
                    normalize_text(record.get("Owner")) or None,
                    None,
                    observed_at,
                    None,
                    normalize_text(record.get("Notes")) or None,
                    command_line or None,
                ),
            )
            counts["scheduled_task_observations"] += 1
            continue

        if category == "Autorun":
            autorun_path = extract_command_path(command_line)
            connection.execute(
                """
                INSERT INTO autorun_observations (
                    snapshot_id, observed_at, name, path, command_line, registry_path
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    observed_at,
                    name or None,
                    autorun_path or None,
                    command_line or None,
                    registry_path or None,
                ),
            )
            counts["autorun_observations"] += 1
            if registry_path:
                connection.execute(
                    """
                    INSERT INTO registry_observations (
                        snapshot_id, observed_at, key_path, value_name, value_data, source_type
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        observed_at,
                        registry_path,
                        name or None,
                        command_line or None,
                        "Autorun",
                    ),
                )
                counts["registry_observations"] += 1
            continue

        if category == "NetworkConnection":
            remote_address = value or name
            local_address = local_port = remote_port = state = None
            match = re.match(r"([^:]+):(\d+)->([^:]+):(\d+)\s+\[([^\]]+)\]", command_line)
            if match:
                local_address = match.group(1)
                local_port = normalize_optional_int(match.group(2))
                remote_address = match.group(3)
                remote_port = normalize_optional_int(match.group(4))
                state = match.group(5)
            connection.execute(
                """
                INSERT INTO network_connection_observations (
                    snapshot_id, observed_at, local_address, local_port, remote_address, remote_port, state, owning_process, command_line
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    observed_at,
                    local_address,
                    local_port,
                    remote_address or None,
                    remote_port,
                    state,
                    normalize_optional_int(record.get("PID")),
                    command_line or None,
                ),
            )
            counts["network_connection_observations"] += 1
            continue

        if category == "DnsCache":
            record_type = data = ttl = ""
            match = re.match(r"Type=([^;]+);\s*Data=([^;]+);\s*TTL=(.+)$", command_line)
            if match:
                record_type = match.group(1).strip()
                data = match.group(2).strip()
                ttl = match.group(3).strip()
            connection.execute(
                """
                INSERT INTO dns_cache_observations (
                    snapshot_id, observed_at, entry, name, data, record_type, time_to_live
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    observed_at,
                    name or None,
                    value or None,
                    data or None,
                    record_type or None,
                    ttl or None,
                ),
            )
            counts["dns_cache_observations"] += 1
            continue

        if category == "PowerShellLog":
            event_id = normalize_optional_int(name)
            connection.execute(
                """
                INSERT INTO powershell_event_observations (
                    snapshot_id, observed_at, event_id, command_line, script_block_text, provider_name, message
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    observed_at,
                    event_id,
                    command_line or None,
                    command_line if event_id == 4104 else None,
                    ",".join(record.get("Source") or []) or None,
                    command_line or None,
                ),
            )
            counts["powershell_event_observations"] += 1
            continue

        if category == "EventLog":
            connection.execute(
                """
                INSERT INTO windows_event_observations (
                    snapshot_id, observed_at, event_id, provider_name, channel, message
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    observed_at,
                    normalize_optional_int(name),
                    None,
                    ",".join(record.get("Source") or []) or None,
                    command_line or None,
                ),
            )
            counts["windows_event_observations"] += 1
            continue

        if category in {"Hash", "RecentFile", "LNK", "Prefetch"}:
            size_bytes = None
            notes = normalize_text(record.get("Notes"))
            size_match = re.search(r"Length=(\d+)", notes)
            if size_match:
                size_bytes = normalize_optional_int(size_match.group(1))
            file_path = path
            if file_path:
                connection.execute(
                    """
                    INSERT INTO file_observations (
                        snapshot_id, observed_at, observation_type, path, filename, sha256, size_bytes, last_write_time_utc, source_note
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        observed_at,
                        category,
                        file_path,
                        Path(file_path).name,
                        sha256 or None,
                        size_bytes,
                        observed_at,
                        ",".join(record.get("Source") or []) or None,
                    ),
                )
                counts["file_observations"] += 1
            continue

    connection.commit()
    return {
        "snapshot_id": snapshot_id,
        "snapshot_type": snapshot_type,
        "created_at": created_at,
        "host": host,
        "source_json_path": source_json_path,
        "source_markdown_path": source_markdown_path,
        "collector_version": collector_version,
        "trust_label": trust_label,
        "observation_counts": counts,
        "normalized_record_count": len(records),
    }


def list_evidence_snapshot_rows(connection: sqlite3.Connection, current_snapshot_id: Optional[str]) -> List[sqlite3.Row]:
    params: List[Any] = []
    clause = ""
    if current_snapshot_id:
        clause = "WHERE snapshot_id = ? OR snapshot_id <> ?"
        params.extend([current_snapshot_id, current_snapshot_id])
    return connection.execute(
        f"""
        SELECT snapshot_id, snapshot_type, created_at, host, source_json_path, source_markdown_path, collector_version, trust_label
        FROM evidence_snapshots
        {clause}
        ORDER BY created_at DESC, snapshot_id DESC
        """,
        params,
    ).fetchall()


def get_snapshot_status(connection: sqlite3.Connection, snapshot_id: str) -> Dict[str, Any]:
    row = connection.execute(
        """
        SELECT snapshot_id, snapshot_type, created_at, host, source_json_path, source_markdown_path, collector_version, trust_label
        FROM evidence_snapshots
        WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ).fetchone()
    if row is None:
        return {"available": False, "snapshot_id": snapshot_id}

    counts = {}
    for table_name in [
        "network_connection_observations",
        "dns_cache_observations",
        "powershell_event_observations",
        "windows_event_observations",
        "registry_observations",
        "service_observations",
        "scheduled_task_observations",
        "autorun_observations",
        "process_observations",
        "file_observations",
    ]:
        counts[table_name] = connection.execute(
            f"SELECT COUNT(*) FROM {table_name} WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()[0]

    payload = dict(row)
    payload["available"] = True
    payload["observation_counts"] = counts
    return payload


def make_scope_note(snapshot_type: str, is_current_snapshot: bool) -> str:
    if snapshot_type == "baseline":
        return "Matched in a baseline/reference indexed local evidence snapshot."
    if is_current_snapshot:
        return "Matched in the current indexed local evidence snapshot."
    return "Matched in a historical indexed local evidence snapshot. Evidence may no longer be current."


def make_interpretation(indicator_type: str, snapshot_type: str, is_current_snapshot: bool, matched_field: str) -> str:
    scope = "current" if is_current_snapshot else ("baseline/reference" if snapshot_type == "baseline" else "historical")
    return (
        f"This {indicator_type} indicator matched the {matched_field} field in a {scope} indexed local evidence snapshot. "
        f"Validate whether the evidence is still relevant before drawing conclusions beyond the collected snapshot."
    )


def make_false_positive_risk(indicator_type: str, matched_field: str) -> str:
    if indicator_type == "sha256":
        return "low"
    if indicator_type in {"service_name", "scheduled_task", "ipv4", "ipv6"}:
        return "medium"
    if matched_field in {"command_line", "script_block_text", "message", "value_data"}:
        return "medium"
    return "medium"


def build_match_record(
    snapshot_row: sqlite3.Row,
    indicator: sqlite3.Row,
    table_name: str,
    matched_field: str,
    matched_value: str,
    evidence_strength: str,
    extra: Dict[str, Any],
    current_snapshot_id: Optional[str],
) -> Dict[str, Any]:
    snapshot_id = snapshot_row["snapshot_id"]
    snapshot_type = snapshot_row["snapshot_type"] or "unknown"
    is_current_snapshot = bool(current_snapshot_id) and snapshot_id == current_snapshot_id
    return {
        "snapshot_id": snapshot_id,
        "snapshot_type": snapshot_type,
        "snapshot_time": snapshot_row["created_at"],
        "match_source": table_name,
        "match_method": "sqlite_evidence_join",
        "matched_field": matched_field,
        "matched_value": matched_value,
        "evidence_strength": evidence_strength,
        "false_positive_risk": make_false_positive_risk(str(indicator["type"]), matched_field),
        "indicator_type": indicator["type"],
        "indicator_value": indicator["value"],
        "indicator_source": indicator["source"],
        "confidence": indicator["confidence"],
        "severity": indicator["severity"],
        "interpretation": make_interpretation(str(indicator["type"]), snapshot_type, is_current_snapshot, matched_field),
        "scope_note": make_scope_note(snapshot_type, is_current_snapshot),
        **extra,
    }


def match_indicators_against_evidence_snapshots(
    connection: sqlite3.Connection,
    current_snapshot_id: str,
) -> Dict[str, Any]:
    snapshot_rows = {
        row["snapshot_id"]: row
        for row in connection.execute(
            """
            SELECT snapshot_id, snapshot_type, created_at, host, source_json_path, source_markdown_path, collector_version, trust_label
            FROM evidence_snapshots
            ORDER BY created_at DESC, snapshot_id DESC
            """
        ).fetchall()
    }
    current_snapshot = snapshot_rows.get(current_snapshot_id)
    if current_snapshot is None:
        return {
            "snapshot_available": False,
            "current_snapshot_id": current_snapshot_id,
            "matches": [],
            "coverage": {},
        }

    supported_types = ('sha256', 'ipv4', 'ipv6', 'domain', 'url', 'registry_key', 'registry_value', 'service_name', 'scheduled_task', 'command_line_pattern')
    indicator_rows = query_active_indicators(
        connection,
        indicator_types=supported_types,
    )["Indicators"]

    indicators_by_type: Dict[str, Dict[str, List[sqlite3.Row]]] = {
        "sha256": {},
        "ipv4": {},
        "ipv6": {},
        "domain": {},
        "url": {},
        "service_name": {},
        "scheduled_task": {},
    }
    registry_key_indicators: List[sqlite3.Row] = []
    registry_value_indicators: List[sqlite3.Row] = []
    command_line_patterns: List[Tuple[sqlite3.Row, re.Pattern[str]]] = []

    for indicator in indicator_rows:
        indicator_type = str(indicator["type"])
        indicator_value = normalize_text(indicator["value"]).lower()
        if indicator_type in indicators_by_type:
            indicators_by_type[indicator_type].setdefault(indicator_value, []).append(indicator)
        elif indicator_type == "registry_key":
            registry_key_indicators.append(indicator)
        elif indicator_type == "registry_value":
            registry_value_indicators.append(indicator)
        elif indicator_type == "command_line_pattern":
            try:
                command_line_patterns.append((indicator, re.compile(str(indicator["value"]), re.IGNORECASE)))
            except re.error:
                continue

    current_matches: List[Dict[str, Any]] = []
    historical_matches: List[Dict[str, Any]] = []
    coverage = {
        "current_snapshot_id": current_snapshot_id,
        "current_snapshot_type": current_snapshot["snapshot_type"],
        "current_snapshot_time": current_snapshot["created_at"],
    }

    def append_match(snapshot_id: str, indicator: sqlite3.Row, table_name: str, matched_field: str, matched_value: str, evidence_strength: str, extra: Dict[str, Any]) -> None:
        target = current_matches if snapshot_id == current_snapshot_id else historical_matches
        target.append(
            build_match_record(
                snapshot_row=snapshot_rows[snapshot_id],
                indicator=indicator,
                table_name=table_name,
                matched_field=matched_field,
                matched_value=matched_value,
                evidence_strength=evidence_strength,
                extra=extra,
                current_snapshot_id=current_snapshot_id,
            )
        )

    file_rows = connection.execute(
        """
        SELECT e.snapshot_id, e.snapshot_type, e.created_at, f.path, f.filename, f.sha256
        FROM file_observations f
        JOIN evidence_snapshots e ON e.snapshot_id = f.snapshot_id
        """
    ).fetchall()
    for row in file_rows:
        sha256 = normalize_sha256(row["sha256"])
        if sha256 and sha256 in indicators_by_type["sha256"]:
            for indicator in indicators_by_type["sha256"][sha256]:
                append_match(
                    row["snapshot_id"],
                    indicator,
                    "file_observations",
                    "sha256",
                    row["sha256"],
                    "strong",
                    {
                        "matched_observation_type": "FileObservation",
                        "matched_path": row["path"],
                        "matched_name": row["filename"],
                        "matched_sha256": row["sha256"],
                    },
                )

    network_rows = connection.execute(
        """
        SELECT e.snapshot_id, e.snapshot_type, e.created_at, n.remote_address, n.local_address, n.local_port, n.remote_port, n.state
        FROM network_connection_observations n
        JOIN evidence_snapshots e ON e.snapshot_id = n.snapshot_id
        """
    ).fetchall()
    for row in network_rows:
        remote_address = normalize_text(row["remote_address"]).lower()
        for indicator_type in ("ipv4", "ipv6"):
            for indicator in indicators_by_type[indicator_type].get(remote_address, []):
                append_match(
                    row["snapshot_id"],
                    indicator,
                    "network_connection_observations",
                    "remote_address",
                    row["remote_address"],
                    "strong",
                    {
                        "matched_observation_type": "NetworkConnection",
                        "matched_remote_address": row["remote_address"],
                        "matched_local_address": row["local_address"],
                        "matched_local_port": row["local_port"],
                        "matched_remote_port": row["remote_port"],
                        "matched_state": row["state"],
                    },
                )

    dns_rows = connection.execute(
        """
        SELECT e.snapshot_id, e.snapshot_type, e.created_at, d.name, d.data
        FROM dns_cache_observations d
        JOIN evidence_snapshots e ON e.snapshot_id = d.snapshot_id
        """
    ).fetchall()
    for row in dns_rows:
        for field_name in ("name", "data"):
            value = normalize_text(row[field_name]).lower()
            if not value:
                continue
            for indicator in indicators_by_type["domain"].get(value, []):
                append_match(
                    row["snapshot_id"],
                    indicator,
                    "dns_cache_observations",
                    field_name,
                    row[field_name],
                    "medium",
                    {
                        "matched_observation_type": "DnsCacheEntry",
                        "matched_name": row["name"],
                        "matched_data": row["data"],
                    },
                )

    service_rows = connection.execute(
        """
        SELECT e.snapshot_id, e.snapshot_type, e.created_at, s.service_name, s.display_name, s.image_path
        FROM service_observations s
        JOIN evidence_snapshots e ON e.snapshot_id = s.snapshot_id
        """
    ).fetchall()
    for row in service_rows:
        service_name = normalize_text(row["service_name"]).lower()
        for indicator in indicators_by_type["service_name"].get(service_name, []):
            append_match(
                row["snapshot_id"],
                indicator,
                "service_observations",
                "service_name",
                row["service_name"],
                "strong",
                {
                    "matched_observation_type": "ServiceObservation",
                    "matched_name": row["service_name"],
                    "matched_display_name": row["display_name"],
                    "matched_path": row["image_path"],
                },
            )

    task_rows = connection.execute(
        """
        SELECT e.snapshot_id, e.snapshot_type, e.created_at, t.task_name, t.task_path, t.action
        FROM scheduled_task_observations t
        JOIN evidence_snapshots e ON e.snapshot_id = t.snapshot_id
        """
    ).fetchall()
    for row in task_rows:
        for field_name in ("task_name", "task_path"):
            value = normalize_text(row[field_name]).lower()
            if not value:
                continue
            for indicator in indicators_by_type["scheduled_task"].get(value, []):
                append_match(
                    row["snapshot_id"],
                    indicator,
                    "scheduled_task_observations",
                    field_name,
                    row[field_name],
                    "strong",
                    {
                        "matched_observation_type": "ScheduledTaskObservation",
                        "matched_name": row["task_name"],
                        "matched_path": row["task_path"],
                        "matched_action": row["action"],
                    },
                )

    registry_rows = connection.execute(
        """
        SELECT e.snapshot_id, e.snapshot_type, e.created_at, r.key_path, r.value_name, r.value_data
        FROM registry_observations r
        JOIN evidence_snapshots e ON e.snapshot_id = r.snapshot_id
        """
    ).fetchall()
    for row in registry_rows:
        key_path_lc = normalize_text(row["key_path"]).lower()
        value_name_lc = normalize_text(row["value_name"]).lower()
        value_data_lc = normalize_text(row["value_data"]).lower()
        for indicator in registry_key_indicators:
            needle = normalize_text(indicator["value"]).lower()
            if needle and needle in key_path_lc:
                append_match(
                    row["snapshot_id"],
                    indicator,
                    "registry_observations",
                    "key_path",
                    row["key_path"],
                    "medium",
                    {
                        "matched_observation_type": "RegistryObservation",
                        "matched_registry_key": row["key_path"],
                        "matched_value_name": row["value_name"],
                        "matched_value_data": row["value_data"],
                    },
                )
        for indicator in registry_value_indicators:
            needle = normalize_text(indicator["value"]).lower()
            if not needle:
                continue
            if needle in value_name_lc:
                matched_field = "value_name"
                matched_value = row["value_name"]
            elif needle in value_data_lc:
                matched_field = "value_data"
                matched_value = row["value_data"]
            else:
                continue
            append_match(
                row["snapshot_id"],
                indicator,
                "registry_observations",
                matched_field,
                matched_value,
                "medium",
                {
                    "matched_observation_type": "RegistryObservation",
                    "matched_registry_key": row["key_path"],
                    "matched_value_name": row["value_name"],
                    "matched_value_data": row["value_data"],
                },
            )

    text_rows = connection.execute(
        """
        SELECT e.snapshot_id, e.snapshot_type, e.created_at, 'process_observations' AS table_name, p.command_line AS text_value, p.name AS object_name, p.path AS object_path
        FROM process_observations p
        JOIN evidence_snapshots e ON e.snapshot_id = p.snapshot_id
        UNION ALL
        SELECT e.snapshot_id, e.snapshot_type, e.created_at, 'powershell_event_observations' AS table_name, coalesce(pe.script_block_text, pe.command_line) AS text_value, CAST(pe.event_id AS TEXT) AS object_name, NULL AS object_path
        FROM powershell_event_observations pe
        JOIN evidence_snapshots e ON e.snapshot_id = pe.snapshot_id
        UNION ALL
        SELECT e.snapshot_id, e.snapshot_type, e.created_at, 'windows_event_observations' AS table_name, we.message AS text_value, CAST(we.event_id AS TEXT) AS object_name, NULL AS object_path
        FROM windows_event_observations we
        JOIN evidence_snapshots e ON e.snapshot_id = we.snapshot_id
        """
    ).fetchall()
    for row in text_rows:
        text_value = normalize_text(row["text_value"])
        if not text_value:
            continue
        for url in extract_urls_from_text(text_value):
            for indicator in indicators_by_type["url"].get(url, []):
                append_match(
                    row["snapshot_id"],
                    indicator,
                    row["table_name"],
                    "command_line_or_event_text",
                    indicator["value"],
                    "medium",
                    {
                        "matched_observation_type": "TextObservation",
                        "matched_name": row["object_name"],
                        "matched_path": row["object_path"],
                    },
                )
        for indicator, pattern in command_line_patterns:
            if pattern.search(text_value):
                append_match(
                    row["snapshot_id"],
                    indicator,
                    row["table_name"],
                    "command_line",
                    text_value,
                    "medium",
                    {
                        "matched_observation_type": "TextObservation",
                        "matched_name": row["object_name"],
                        "matched_path": row["object_path"],
                        "matched_command_line": text_value,
                    },
                )

    return {
        "snapshot_available": True,
        "current_snapshot_id": current_snapshot_id,
        "current_snapshot_type": current_snapshot["snapshot_type"],
        "current_snapshot_time": current_snapshot["created_at"],
        "current_matches": current_matches,
        "historical_matches": historical_matches,
        "match_count": len(current_matches) + len(historical_matches),
    }


def normalize_indicators(document: Any) -> Tuple[List[Dict[str, Any]], str]:
    if isinstance(document, dict) and "Indicators" in document:
        indicators = list(document.get("Indicators") or [])
        source_name = str(document.get("Metadata", {}).get("Format", "normalized-indicator-set"))
        return indicators, source_name

    if isinstance(document, list):
        return list(document), "normalized-indicator-array"

    raise ValueError(
        "Unsupported indicator input. Provide a normalized indicator JSON object with an Indicators array or a raw array."
    )


def begin_ingest_run(
    connection: sqlite3.Connection,
    source_name: str,
    input_path: Path,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO ingest_runs (started_at, source_name, input_path, status)
        VALUES (?, ?, ?, ?)
        """,
        (utc_now(), source_name, str(input_path), "running"),
    )
    connection.commit()
    return int(cursor.lastrowid)


def finish_ingest_run(
    connection: sqlite3.Connection,
    run_id: int,
    status: str,
    indicator_count: int,
    notes: str = "",
) -> None:
    connection.execute(
        """
        UPDATE ingest_runs
        SET completed_at = ?, status = ?, indicator_count = ?, notes = ?
        WHERE id = ?
        """,
        (utc_now(), status, indicator_count, notes, run_id),
    )
    connection.commit()


def upsert_indicators(
    connection: sqlite3.Connection,
    run_id: int,
    indicators: Iterable[Dict[str, Any]],
) -> int:
    count = 0
    for indicator in indicators:
        row = {
            "indicator_key": indicator_key(
                str(indicator.get("type", "")),
                str(indicator.get("value", "")),
                str(indicator.get("source", "")),
            ),
            "indicator_id": indicator.get("indicator_id"),
            "type": indicator.get("type"),
            "value": indicator.get("value"),
            "source": indicator.get("source", "internal"),
            "confidence": int(indicator.get("confidence", 50)),
            "severity": indicator.get("severity", "medium"),
            "first_seen": indicator.get("first_seen"),
            "last_seen": indicator.get("last_seen"),
            "valid_from": indicator.get("valid_from"),
            "valid_until": indicator.get("valid_until"),
            "tlp": indicator.get("tlp", "clear"),
            "malware_family": indicator.get("malware_family"),
            "campaign": indicator.get("campaign"),
            "threat_actor": indicator.get("threat_actor"),
            "attack_technique": indicator.get("attack_technique"),
            "reference_url": indicator.get("reference_url"),
            "raw_source_record_json": json.dumps(indicator.get("raw_source_record"), ensure_ascii=True),
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "last_ingest_run_id": run_id,
        }

        connection.execute(
            """
            INSERT INTO indicators (
                indicator_key, indicator_id, type, value, source, confidence, severity,
                first_seen, last_seen, valid_from, valid_until, tlp, malware_family,
                campaign, threat_actor, attack_technique, reference_url,
                raw_source_record_json, created_at, updated_at, last_ingest_run_id
            )
            VALUES (
                :indicator_key, :indicator_id, :type, :value, :source, :confidence, :severity,
                :first_seen, :last_seen, :valid_from, :valid_until, :tlp, :malware_family,
                :campaign, :threat_actor, :attack_technique, :reference_url,
                :raw_source_record_json, :created_at, :updated_at, :last_ingest_run_id
            )
            ON CONFLICT(indicator_key) DO UPDATE SET
                indicator_id = excluded.indicator_id,
                confidence = excluded.confidence,
                severity = excluded.severity,
                first_seen = COALESCE(excluded.first_seen, indicators.first_seen),
                last_seen = COALESCE(excluded.last_seen, indicators.last_seen),
                valid_from = COALESCE(excluded.valid_from, indicators.valid_from),
                valid_until = COALESCE(excluded.valid_until, indicators.valid_until),
                tlp = COALESCE(excluded.tlp, indicators.tlp),
                malware_family = COALESCE(excluded.malware_family, indicators.malware_family),
                campaign = COALESCE(excluded.campaign, indicators.campaign),
                threat_actor = COALESCE(excluded.threat_actor, indicators.threat_actor),
                attack_technique = COALESCE(excluded.attack_technique, indicators.attack_technique),
                reference_url = COALESCE(excluded.reference_url, indicators.reference_url),
                raw_source_record_json = excluded.raw_source_record_json,
                updated_at = excluded.updated_at,
                last_ingest_run_id = excluded.last_ingest_run_id
            """,
            row,
        )
        count += 1

    connection.commit()
    return count


def export_indicators(connection: sqlite3.Connection) -> Dict[str, Any]:
    rows = connection.execute(
        """
        SELECT
            indicator_id,
            type,
            value,
            source,
            confidence,
            severity,
            first_seen,
            last_seen,
            valid_from,
            valid_until,
            tlp,
            malware_family,
            campaign,
            threat_actor,
            attack_technique,
            reference_url,
            raw_source_record_json
        FROM indicators
        ORDER BY type, value
        """
    ).fetchall()

    indicators = [indicator_row_to_dict(row) for row in rows]

    return {
        "Metadata": {
            "Format": "normalized-indicator-set",
            "CollectionTimeUtc": utc_now(),
            "IndicatorCount": len(indicators),
            "Source": "sqlite-ioc-store",
        },
        "Indicators": indicators,
    }


def indicator_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    raw_source_record = None
    if row["raw_source_record_json"]:
        try:
            raw_source_record = json.loads(row["raw_source_record_json"])
        except json.JSONDecodeError:
            raw_source_record = row["raw_source_record_json"]
    return {
        "indicator_id": row["indicator_id"], "type": row["type"], "value": row["value"], "source": row["source"],
        "confidence": row["confidence"], "severity": row["severity"], "first_seen": row["first_seen"] or "",
        "last_seen": row["last_seen"] or "", "valid_from": row["valid_from"] or "", "valid_until": row["valid_until"] or "",
        "tlp": row["tlp"] or "clear", "malware_family": row["malware_family"] or "", "campaign": row["campaign"] or "",
        "threat_actor": row["threat_actor"] or "", "attack_technique": row["attack_technique"] or "",
        "reference_url": row["reference_url"] or "", "raw_source_record": raw_source_record,
    }


def indicator_is_active(indicator: Dict[str, Any], now: datetime) -> bool:
    valid_until = str(indicator.get("valid_until") or "").strip()
    if not valid_until:
        return True
    try:
        expires_at = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    except ValueError:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at > now


def query_active_indicators(connection: sqlite3.Connection, indicator_types: Optional[Iterable[str]] = None, include_expired: bool = False, now: Optional[datetime] = None) -> Dict[str, Any]:
    normalized_types = sorted({str(value).strip().lower() for value in (indicator_types or []) if str(value).strip()})
    params: List[Any] = []
    where = ""
    if normalized_types:
        where = "WHERE lower(type) IN ({0})".format(", ".join("?" for _ in normalized_types))
        params.extend(normalized_types)
    rows = connection.execute(
        f"SELECT indicator_id, type, value, source, confidence, severity, first_seen, last_seen, valid_from, valid_until, tlp, malware_family, campaign, threat_actor, attack_technique, reference_url, raw_source_record_json FROM indicators {where} ORDER BY type, value, source",
        params,
    ).fetchall()
    reference_time = now or datetime.now(timezone.utc)
    indicators = [indicator_row_to_dict(row) for row in rows]
    if not include_expired:
        indicators = [indicator for indicator in indicators if indicator_is_active(indicator, reference_time)]
    return {"Metadata": {"Format": "sqlite-active-indicator-set", "CollectionTimeUtc": reference_time.isoformat(), "IndicatorCount": len(indicators), "Source": "sqlite-ioc-store", "IncludeExpired": include_expired, "Types": normalized_types}, "Indicators": indicators}


def stats(connection: sqlite3.Connection) -> Dict[str, Any]:
    indicator_count = connection.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    run_count = connection.execute("SELECT COUNT(*) FROM ingest_runs").fetchone()[0]
    app_state_count = connection.execute("SELECT COUNT(*) FROM app_state").fetchone()[0]
    baseline_run_count = connection.execute("SELECT COUNT(*) FROM baseline_runs").fetchone()[0]
    baseline_hash_count = connection.execute("SELECT COUNT(*) FROM baseline_file_hashes").fetchone()[0]
    evidence_snapshot_count = connection.execute("SELECT COUNT(*) FROM evidence_snapshots").fetchone()[0]
    by_type = [
        {"type": row["type"], "count": row["count"]}
        for row in connection.execute(
            "SELECT type, COUNT(*) AS count FROM indicators GROUP BY type ORDER BY count DESC"
        ).fetchall()
    ]
    by_source = [
        {"source": row["source"], "count": row["count"]}
        for row in connection.execute(
            "SELECT source, COUNT(*) AS count FROM indicators GROUP BY source ORDER BY count DESC"
        ).fetchall()
    ]

    return {
        "indicator_count": indicator_count,
        "ingest_run_count": run_count,
        "app_state_count": app_state_count,
        "baseline_run_count": baseline_run_count,
        "baseline_hash_count": baseline_hash_count,
        "evidence_snapshot_count": evidence_snapshot_count,
        "baseline_hash_status": get_latest_baseline_hash_status(connection),
        "by_type": by_type,
        "by_source": by_source,
    }


def _required_text(document: Dict[str, Any], field_name: str) -> str:
    value = str(document.get(field_name) or "").strip()
    if not value:
        raise ValueError(f"{field_name} is required.")
    return value


def _json_payload(value: Any) -> str:
    return json.dumps({} if value is None else value, ensure_ascii=True, sort_keys=True)


def persist_collector_run_report_findings(
    connection: sqlite3.Connection,
    collector_run: Dict[str, Any],
    report: Dict[str, Any],
    findings: Iterable[Dict[str, Any]],
    alerts: Iterable[Dict[str, Any]] = (),
) -> Dict[str, Any]:
    """Persist one immutable collector run, report, findings, and alerts atomically."""
    collector_run_id = _required_text(collector_run, "collector_run_id")
    report_id = _required_text(report, "report_id")
    if str(report.get("collector_run_id") or collector_run_id).strip() != collector_run_id:
        raise ValueError("report.collector_run_id must match collector_run.collector_run_id.")

    now = utc_now()
    finding_rows = list(findings)
    alert_rows = list(alerts)
    with connection:
        connection.execute(
            """
            INSERT INTO collector_runs (
                collector_run_id, collector_name, collector_version, started_at,
                completed_at, outcome, summary_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                collector_run_id,
                _required_text(collector_run, "collector_name"),
                str(collector_run.get("collector_version") or "").strip() or None,
                _required_text(collector_run, "started_at"),
                str(collector_run.get("completed_at") or "").strip() or None,
                _required_text(collector_run, "outcome"),
                _json_payload(collector_run.get("summary")),
                str(collector_run.get("created_at") or now),
            ),
        )
        connection.execute(
            """
            INSERT INTO reports (
                report_id, collector_run_id, report_type, collection_time_utc,
                overall_status, severity, summary_json, export_json_path,
                export_markdown_path, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                collector_run_id,
                _required_text(report, "report_type"),
                _required_text(report, "collection_time_utc"),
                str(report.get("overall_status") or "").strip() or None,
                str(report.get("severity") or "").strip() or None,
                _json_payload(report.get("summary")),
                str(report.get("export_json_path") or "").strip() or None,
                str(report.get("export_markdown_path") or "").strip() or None,
                str(report.get("created_at") or now),
            ),
        )
        for index, finding in enumerate(finding_rows):
            sequence = finding.get("finding_sequence", index)
            if not isinstance(sequence, int) or sequence < 0:
                raise ValueError("finding_sequence must be a non-negative integer.")
            connection.execute(
                """
                INSERT INTO findings (
                    finding_id, report_id, finding_sequence, category, severity,
                    classification, title, summary, evidence_json, csf_mapping,
                    guardrail_state, response_state, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _required_text(finding, "finding_id"),
                    report_id,
                    sequence,
                    str(finding.get("category") or "").strip() or None,
                    str(finding.get("severity") or "").strip() or None,
                    str(finding.get("classification") or "").strip() or None,
                    str(finding.get("title") or "").strip() or None,
                    str(finding.get("summary") or "").strip() or None,
                    _json_payload(finding.get("evidence")),
                    str(finding.get("csf_mapping") or "").strip() or None,
                    str(finding.get("guardrail_state") or "").strip() or None,
                    str(finding.get("response_state") or "open").strip() or "open",
                    str(finding.get("created_at") or now),
                ),
            )
        finding_ids = {_required_text(finding, "finding_id") for finding in finding_rows}
        for alert in alert_rows:
            alert_id = _required_text(alert, "alert_id")
            finding_id = str(alert.get("finding_id") or "").strip() or None
            if finding_id is not None and finding_id not in finding_ids:
                raise ValueError("alert.finding_id must identify a finding persisted with the same report.")
            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, report_id, finding_id, severity, summary, lifecycle_state,
                    created_at, acknowledged_at, closed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    report_id,
                    finding_id,
                    _required_text(alert, "severity"),
                    _required_text(alert, "summary"),
                    str(alert.get("lifecycle_state") or "pending").strip() or "pending",
                    str(alert.get("created_at") or now),
                    str(alert.get("acknowledged_at") or "").strip() or None,
                    str(alert.get("closed_at") or "").strip() or None,
                ),
            )
            delivery_channel = str(alert.get("delivery_channel") or "interactive_popup").strip()
            recipient = str(alert.get("recipient") or "interactive-user").strip()
            connection.execute(
                """
                INSERT INTO alert_deliveries (
                    alert_delivery_id, alert_id, delivery_channel, recipient,
                    delivery_state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
                """,
                (f"{alert_id}:{delivery_channel}:{recipient}", alert_id, delivery_channel, recipient, now, now),
            )

    result = {
        "collector_run_id": collector_run_id,
        "report_id": report_id,
        "finding_count": len(finding_rows),
    }
    if alert_rows:
        result["alert_count"] = len(alert_rows)
    return result


def claim_alert_deliveries(
    connection: sqlite3.Connection, delivery_channel: str, recipient: str, limit: int = 20, claim_lease_seconds: int = 300
) -> List[Dict[str, Any]]:
    """Atomically claim retryable deliveries for one notifier channel and recipient."""
    if not isinstance(limit, int) or limit < 1 or limit > 100:
        raise ValueError("limit must be an integer between 1 and 100.")
    if not isinstance(claim_lease_seconds, int) or claim_lease_seconds < 1 or claim_lease_seconds > 3600:
        raise ValueError("claim_lease_seconds must be an integer between 1 and 3600.")
    channel = _required_text({"delivery_channel": delivery_channel}, "delivery_channel")
    target = _required_text({"recipient": recipient}, "recipient")
    claimed_at = utc_now()
    lease_cutoff = (datetime.now(timezone.utc) - timedelta(seconds=claim_lease_seconds)).isoformat()
    with connection:
        rows = connection.execute(
            """
            SELECT d.alert_delivery_id, d.alert_id, d.delivery_channel, d.recipient,
                   d.attempt_count, a.report_id, a.finding_id, a.severity, a.summary,
                   r.export_json_path, r.export_markdown_path
            FROM alert_deliveries d
            JOIN alerts a ON a.alert_id = d.alert_id
            LEFT JOIN reports r ON r.report_id = a.report_id
            WHERE d.delivery_channel = ? AND d.recipient = ?
              AND (d.delivery_state IN ('pending', 'failed')
                   OR (d.delivery_state = 'claimed' AND d.claimed_at <= ?))
              AND a.lifecycle_state = 'pending'
            ORDER BY a.created_at ASC, d.created_at ASC
            LIMIT ?
            """,
            (channel, target, lease_cutoff, limit),
        ).fetchall()
        claimed_rows = [dict(row) for row in rows]
        for claimed_row in claimed_rows:
            claimed_row["attempt_count"] = int(claimed_row["attempt_count"]) + 1
        ids = [row["alert_delivery_id"] for row in rows]
        for delivery_id in ids:
            connection.execute(
                """UPDATE alert_deliveries
                   SET delivery_state = 'claimed', claimed_at = ?, attempt_count = attempt_count + 1,
                       updated_at = ?, last_error = NULL
                   WHERE alert_delivery_id = ?
                     AND (delivery_state IN ('pending', 'failed')
                          OR (delivery_state = 'claimed' AND claimed_at <= ?))""",
                (claimed_at, claimed_at, delivery_id, lease_cutoff),
            )
    return claimed_rows


def complete_alert_delivery(
    connection: sqlite3.Connection, delivery_id: str, outcome: str, error: str = ""
) -> Dict[str, Any]:
    """Mark a claimed delivery delivered or failed; failed rows remain retryable."""
    delivery_id = _required_text({"delivery_id": delivery_id}, "delivery_id")
    if outcome not in {"delivered", "failed"}:
        raise ValueError("outcome must be delivered or failed.")
    now = utc_now()
    with connection:
        row = connection.execute(
            "SELECT alert_id, delivery_state FROM alert_deliveries WHERE alert_delivery_id = ?", (delivery_id,)
        ).fetchone()
        if row is None:
            raise ValueError("alert delivery was not found.")
        if row["delivery_state"] != "claimed":
            raise ValueError("alert delivery is not currently claimed.")
        if outcome == "delivered":
            connection.execute(
                "UPDATE alert_deliveries SET delivery_state='delivered', delivered_at=?, updated_at=?, last_error=NULL WHERE alert_delivery_id=?",
                (now, now, delivery_id),
            )
            connection.execute(
                "UPDATE alerts SET lifecycle_state='acknowledged', acknowledged_at=? WHERE alert_id=? AND lifecycle_state='pending'",
                (now, row["alert_id"]),
            )
        else:
            connection.execute(
                "UPDATE alert_deliveries SET delivery_state='failed', updated_at=?, last_error=? WHERE alert_delivery_id=?",
                (now, str(error or "delivery failed"), delivery_id),
            )
    return {"alert_delivery_id": delivery_id, "outcome": outcome}


def _read_json_payload(value: Any) -> Any:
    try:
        return json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}


def list_persisted_reports(connection: sqlite3.Connection, limit: int = 15) -> List[Dict[str, Any]]:
    if not isinstance(limit, int) or limit < 1 or limit > 100:
        raise ValueError("limit must be an integer between 1 and 100.")
    rows = connection.execute(
        """
        SELECT report_id, report_type, collection_time_utc, overall_status, severity,
               summary_json, export_json_path, export_markdown_path
        FROM reports
        ORDER BY collection_time_utc DESC, report_id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [
        {
            "report_id": row["report_id"],
            "name": row["report_id"],
            "report_type": row["report_type"],
            "collection_time": row["collection_time_utc"],
            "overall_status": row["overall_status"] or "",
            "severity": row["severity"] or "",
            "summary": _read_json_payload(row["summary_json"]),
            "export_json_path": row["export_json_path"] or "",
            "export_markdown_path": row["export_markdown_path"] or "",
        }
        for row in rows
    ]


def get_persisted_report(connection: sqlite3.Connection, report_id: str) -> Dict[str, Any]:
    row = connection.execute(
        """
        SELECT r.report_id, r.collector_run_id, r.report_type, r.collection_time_utc,
               r.overall_status, r.severity, r.summary_json, r.export_json_path,
               r.export_markdown_path, cr.collector_name, cr.collector_version,
               cr.started_at, cr.completed_at, cr.outcome, cr.summary_json AS run_summary_json
        FROM reports r
        JOIN collector_runs cr ON cr.collector_run_id = r.collector_run_id
        WHERE r.report_id = ?
        """,
        (str(report_id or "").strip(),),
    ).fetchone()
    if row is None:
        return {"found": False, "report": None, "findings": []}

    finding_rows = connection.execute(
        """
        SELECT finding_id, finding_sequence, category, severity, classification,
               title, summary, evidence_json, csf_mapping, guardrail_state,
               response_state, created_at
        FROM findings
        WHERE report_id = ?
        ORDER BY finding_sequence ASC, finding_id ASC
        """,
        (row["report_id"],),
    ).fetchall()
    return {
        "found": True,
        "report": {
            "report_id": row["report_id"],
            "collector_run_id": row["collector_run_id"],
            "report_type": row["report_type"],
            "collection_time": row["collection_time_utc"],
            "overall_status": row["overall_status"] or "",
            "severity": row["severity"] or "",
            "summary": _read_json_payload(row["summary_json"]),
            "export_json_path": row["export_json_path"] or "",
            "export_markdown_path": row["export_markdown_path"] or "",
            "collector": {
                "name": row["collector_name"],
                "version": row["collector_version"] or "",
                "started_at": row["started_at"],
                "completed_at": row["completed_at"] or "",
                "outcome": row["outcome"],
                "summary": _read_json_payload(row["run_summary_json"]),
            },
        },
        "findings": [
            {
                "finding_id": finding["finding_id"],
                "finding_sequence": finding["finding_sequence"],
                "category": finding["category"] or "",
                "severity": finding["severity"] or "",
                "classification": finding["classification"] or "",
                "title": finding["title"] or "",
                "summary": finding["summary"] or "",
                "evidence": _read_json_payload(finding["evidence_json"]),
                "csf_mapping": finding["csf_mapping"] or "",
                "guardrail_state": finding["guardrail_state"] or "",
                "response_state": finding["response_state"],
                "created_at": finding["created_at"],
            }
            for finding in finding_rows
        ],
    }


def get_persisted_alert(connection: sqlite3.Connection, alert_id: str) -> Dict[str, Any]:
    row = connection.execute(
        """SELECT a.alert_id, a.report_id, a.finding_id, a.severity, a.summary,
                  a.lifecycle_state, a.created_at, a.acknowledged_at, a.closed_at,
                  r.export_json_path, r.export_markdown_path
           FROM alerts a LEFT JOIN reports r ON r.report_id=a.report_id
           WHERE a.alert_id=?""",
        (str(alert_id or "").strip(),),
    ).fetchone()
    return {"found": bool(row), "alert": dict(row) if row else None}


def list_persisted_alerts(connection: sqlite3.Connection, limit: int = 50) -> List[Dict[str, Any]]:
    rows = connection.execute(
        """SELECT alert_id, report_id, finding_id, severity, summary, lifecycle_state,
                  created_at, acknowledged_at, closed_at
           FROM alerts
           ORDER BY CASE lifecycle_state WHEN 'pending' THEN 0 ELSE 1 END,
                    created_at DESC, alert_id ASC
           LIMIT ?""",
        (max(1, int(limit)),),
    ).fetchall()
    return [dict(row) for row in rows]


_NIST_CSF_SUBCATEGORY_PATTERN = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d{2}$")
_NIST_SP800_53_REFERENCE_PATTERN = re.compile(
    r"^SP 800-53 Rev 5\.2\.0:\s*(.+)$", re.MULTILINE
)
_NIST_SP800_53_CONTROL_PATTERN = re.compile(r"^[a-z]{2,3}-\d{1,2}(?:\.\d{1,2})?$")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _xlsx_sheet_rows(workbook_path: Path, sheet_name: str) -> List[Dict[str, str]]:
    """Read a simple worksheet without adding an Excel-library dependency."""
    namespace = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    rel_namespace = {"rel": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    package_rel_namespace = {"rel": "http://schemas.openxmlformats.org/package/2006/relationships"}
    with zipfile.ZipFile(workbook_path) as archive:
        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            shared_root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
            shared_strings = ["".join(item.itertext()) for item in shared_root.findall("main:si", namespace)]
        workbook_root = ElementTree.fromstring(archive.read("xl/workbook.xml"))
        sheet = next(
            (item for item in workbook_root.findall("main:sheets/main:sheet", namespace) if item.attrib.get("name") == sheet_name),
            None,
        )
        if sheet is None:
            raise ValueError(f"Workbook does not contain a worksheet named {sheet_name!r}.")
        relationship_id = sheet.attrib.get("{%s}id" % rel_namespace["rel"])
        rel_root = ElementTree.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        relationship = next(
            (item for item in rel_root.findall("rel:Relationship", package_rel_namespace) if item.attrib.get("Id") == relationship_id),
            None,
        )
        if relationship is None:
            raise ValueError(f"Workbook relationship for worksheet {sheet_name!r} is missing.")
        # Relationship targets may be package-root paths (``/xl/...``),
        # workbook-relative paths (``worksheets/...``), or explicit
        # ``xl/...`` paths. Normalize all three forms.
        target = relationship.attrib["Target"].lstrip("/")
        sheet_path = target if target.startswith("xl/") else "xl/" + target
        sheet_root = ElementTree.fromstring(archive.read(sheet_path))

    rows: List[Dict[str, str]] = []
    for row in sheet_root.findall("main:sheetData/main:row", namespace):
        values: Dict[str, str] = {}
        for cell in row.findall("main:c", namespace):
            reference = cell.attrib.get("r", "")
            column = re.match(r"[A-Z]+", reference)
            if not column:
                continue
            cell_type = cell.attrib.get("t")
            if cell_type == "s":
                index = cell.findtext("main:v", default="", namespaces=namespace)
                values[column.group(0)] = shared_strings[int(index)] if index else ""
            elif cell_type == "inlineStr":
                values[column.group(0)] = "".join(cell.find("main:is", namespace).itertext()) if cell.find("main:is", namespace) is not None else ""
            else:
                values[column.group(0)] = cell.findtext("main:v", default="", namespaces=namespace)
        rows.append(values)
    return rows


def _nist_control_display_id(catalog_control_id: str) -> str:
    family, number = catalog_control_id.upper().split("-", 1)
    base, separator, enhancement = number.partition(".")
    display = f"{family}-{int(base):02d}"
    return f"{display}({int(enhancement):02d})" if separator else display


def _load_nist_sp800_53_catalog(catalog_path: Path) -> Tuple[Dict[str, Dict[str, str]], Dict[str, Any]]:
    catalog = load_json(catalog_path)
    metadata = catalog.get("catalog", {}).get("metadata", {})
    if metadata.get("version") != "5.2.0":
        raise ValueError(f"Expected NIST SP 800-53 catalog version 5.2.0; found {metadata.get('version')!r}.")
    controls: Dict[str, Dict[str, str]] = {}

    def statement_text(control: Dict[str, Any]) -> str:
        parameter_labels = {
            str(parameter.get("id") or ""): str(parameter.get("label") or "organization-defined value")
            for parameter in control.get("params", [])
        }
        prose: List[str] = []

        def visit_part(part: Dict[str, Any], inside_statement: bool = False) -> None:
            in_statement = inside_statement or part.get("name") == "statement"
            text = str(part.get("prose") or "").strip()
            if in_statement and text:
                prose.append(text)
            for child in part.get("parts", []):
                visit_part(child, in_statement)

        for part in control.get("parts", []):
            visit_part(part)
        text = " ".join(prose)
        return re.sub(
            r"\{\{\s*insert:\s*param,\s*([^}\s]+)\s*\}\}",
            lambda match: "[organization-defined " + parameter_labels.get(match.group(1), "value") + "]",
            text,
        )

    def visit_groups(groups: Iterable[Dict[str, Any]]) -> None:
        for group in groups:
            visit_controls(group.get("controls", []))
            visit_groups(group.get("groups", []))

    def visit_controls(items: Iterable[Dict[str, Any]]) -> None:
        for control in items:
            control_id = str(control.get("id", "")).lower()
            title = str(control.get("title", "")).strip()
            if _NIST_SP800_53_CONTROL_PATTERN.fullmatch(control_id) and title:
                controls[_nist_control_display_id(control_id)] = {
                    "catalog_control_id": control_id,
                    "title": title,
                    "statement_text": statement_text(control),
                }
            visit_controls(control.get("controls", []))

    visit_groups(catalog.get("catalog", {}).get("groups", []))
    if not controls:
        raise ValueError("No SP 800-53 controls were found in the supplied OSCAL catalog.")
    return controls, metadata


def _generated_mapping_interpretation(
    subcategory_id: str, outcome: str, control_id: str, control_title: str, control_statement: str
) -> Tuple[str, str, str, str]:
    """Create a clearly product-authored draft interpretation for an official mapping."""
    key = (subcategory_id, control_id)
    curated_seed = {
        ("GV.OC-01", "PM-11"): (
            "PM-11 applies here because defining and periodically reviewing the organization's mission and business processes makes the mission clear, shared, and current for the people responsible for cybersecurity decisions.",
            "Document the current mission statement, share it with the person responsible for cybersecurity decisions, and review it when the mission or business activities change.",
            "Document and share the current mission statement",
            "Keeping the mission statement current and available helps cybersecurity decisions remain grounded in what the organization is trying to accomplish.",
        ),
    }.get(key)
    if curated_seed:
        return curated_seed
    normalized_outcome = outcome.rstrip(".")
    requirement = re.split(r"(?<=[.;])\s+", control_statement.strip(), maxsplit=1)[0].strip()
    if not requirement:
        requirement = f"Apply the {control_title or control_id} requirement"
    return (
        f"{requirement} For {subcategory_id}, apply that requirement only to this outcome: {normalized_outcome}.",
        f"{requirement} Keep the action focused on this outcome: {normalized_outcome}.",
        f"{control_title or control_id} for {subcategory_id}",
        f"This action connects {control_id} to the selected outcome: {normalized_outcome}.",
    )


def import_nist_sp800_53_csf_2_mappings(
    connection: sqlite3.Connection, workbook_path: Path, catalog_path: Path
) -> Dict[str, Any]:
    """Import the final SP 800-53 Rev. 5.2.0 CSF 2.0 Informative Reference mapping.

    The workbook is the mapping source; the OSCAL JSON catalog is the authoritative
    source for the available controls and their titles.  Other workbook references
    and superseded SP 800-53 versions are intentionally not imported.
    """
    workbook_path = workbook_path.resolve()
    catalog_path = catalog_path.resolve()
    if not workbook_path.is_file() or not catalog_path.is_file():
        raise FileNotFoundError("Both the CSF Informative References workbook and SP 800-53 catalog must exist.")
    controls, catalog_metadata = _load_nist_sp800_53_catalog(catalog_path)
    mappings: set[Tuple[str, str]] = set()
    mapping_outcomes: Dict[Tuple[str, str], str] = {}
    skipped_references: set[str] = set()
    for row in _xlsx_sheet_rows(workbook_path, "CSF 2.0"):
        subcategory_match = re.match(r"^([A-Z]{2}\.[A-Z]{2}-\d{2}):", row.get("C", "").strip())
        if not subcategory_match:
            continue
        subcategory_id = subcategory_match.group(1)
        outcome = row.get("C", "").strip().split(":", 1)[1].strip()
        for match in _NIST_SP800_53_REFERENCE_PATTERN.finditer(row.get("E", "")):
            for candidate in re.split(r"[,;]", match.group(1)):
                value = candidate.strip()
                if not value:
                    continue
                if not re.fullmatch(r"[A-Z]{2,3}-\d{2}(?:\(\d{2}\))?", value):
                    skipped_references.add(value)
                    continue
                if value not in controls:
                    raise ValueError(f"CSF mapping references {value}, which is absent from the supplied SP 800-53 5.2.0 catalog.")
                mappings.add((subcategory_id, value))
                mapping_outcomes[(subcategory_id, value)] = outcome
    if not mappings:
        raise ValueError("No SP 800-53 Rev. 5.2.0 CSF mappings were found in the workbook.")

    framework_id = "nist-sp-800-53-r5.2.0"
    now = utc_now()
    with connection:
        connection.execute(
            """INSERT INTO csf_reference_frameworks(
                framework_id, framework_name, publisher, version, mapping_name,
                mapping_reference_id, mapping_status, mapping_source_path, mapping_source_sha256,
                catalog_source_path, catalog_source_sha256, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(framework_id) DO UPDATE SET
                framework_name=excluded.framework_name, publisher=excluded.publisher, version=excluded.version,
                mapping_name=excluded.mapping_name, mapping_reference_id=excluded.mapping_reference_id,
                mapping_status=excluded.mapping_status, mapping_source_path=excluded.mapping_source_path,
                mapping_source_sha256=excluded.mapping_source_sha256, catalog_source_path=excluded.catalog_source_path,
                catalog_source_sha256=excluded.catalog_source_sha256, imported_at=excluded.imported_at""",
            (framework_id, "NIST SP 800-53", "National Institute of Standards and Technology", "5.2.0",
             "NIST CSF 2.0 to SP 800-53 Rev. 5.2.0", "186", "final", str(workbook_path),
             _sha256_file(workbook_path), str(catalog_path), _sha256_file(catalog_path), now),
        )
        connection.executemany(
            """INSERT INTO csf_reference_controls(
                framework_id, control_id, title, statement_text, catalog_control_id, source_catalog_uuid
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(framework_id, control_id) DO UPDATE SET title=excluded.title,
                statement_text=excluded.statement_text, catalog_control_id=excluded.catalog_control_id,
                source_catalog_uuid=excluded.source_catalog_uuid""",
            [(framework_id, control_id, control["title"], control["statement_text"], control["catalog_control_id"], catalog_metadata.get("uuid"))
             for control_id, control in controls.items()],
        )
        connection.executemany(
            """INSERT INTO csf_subcategory_control_mappings(
                framework_id, control_id, subcategory_id, interpretation_text, suggested_action_text,
                action_title_example, action_rationale_example,
                interpretation_source, interpretation_updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'product-generated-v1', ?)
            ON CONFLICT(framework_id, control_id, subcategory_id) DO UPDATE SET
                interpretation_text = CASE WHEN csf_subcategory_control_mappings.interpretation_source = 'product-generated-v1'
                    OR csf_subcategory_control_mappings.interpretation_text = '' THEN excluded.interpretation_text
                    ELSE csf_subcategory_control_mappings.interpretation_text END,
                suggested_action_text = CASE WHEN csf_subcategory_control_mappings.interpretation_source = 'product-generated-v1'
                    OR csf_subcategory_control_mappings.suggested_action_text = '' THEN excluded.suggested_action_text
                    ELSE csf_subcategory_control_mappings.suggested_action_text END,
                action_title_example = CASE WHEN csf_subcategory_control_mappings.interpretation_source = 'product-generated-v1'
                    OR csf_subcategory_control_mappings.action_title_example = '' THEN excluded.action_title_example
                    ELSE csf_subcategory_control_mappings.action_title_example END,
                action_rationale_example = CASE WHEN csf_subcategory_control_mappings.interpretation_source = 'product-generated-v1'
                    OR csf_subcategory_control_mappings.action_rationale_example = '' THEN excluded.action_rationale_example
                    ELSE csf_subcategory_control_mappings.action_rationale_example END,
                interpretation_source = CASE WHEN csf_subcategory_control_mappings.interpretation_source = 'product-generated-v1'
                    OR csf_subcategory_control_mappings.interpretation_text = '' THEN excluded.interpretation_source
                    ELSE csf_subcategory_control_mappings.interpretation_source END,
                interpretation_updated_at = CASE WHEN csf_subcategory_control_mappings.interpretation_source = 'product-generated-v1'
                    OR csf_subcategory_control_mappings.interpretation_text = '' THEN excluded.interpretation_updated_at
                    ELSE csf_subcategory_control_mappings.interpretation_updated_at END""",
            [
                (
                    framework_id,
                    control_id,
                    subcategory_id,
                    *_generated_mapping_interpretation(
                        subcategory_id,
                        mapping_outcomes[(subcategory_id, control_id)],
                        control_id,
                        controls[control_id]["title"],
                        controls[control_id]["statement_text"],
                    ),
                    now,
                )
                for subcategory_id, control_id in sorted(mappings)
            ],
        )
        # The composite relationship key includes role and information ID, so
        # remove only superseded maintained seed rows before inserting them.
        for item in CONTROL_MAPPING_RELATIONSHIPS:
            if item["framework_id"] == framework_id:
                connection.execute(
                    "DELETE FROM csf_control_mapping_relationships WHERE framework_id=? AND control_id=? AND subcategory_id=? AND source_label='product-authored-v1'",
                    (item["framework_id"], item["control_id"], item["subcategory_id"]),
                )
        connection.executemany(
            """INSERT INTO csf_control_mapping_relationships(
                framework_id, control_id, subcategory_id, relationship_role, information_id,
                relationship_scope, rationale, review_status, source_label, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reviewed', 'product-authored-v1', ?)
            ON CONFLICT(framework_id, control_id, subcategory_id, relationship_role, information_id)
            DO UPDATE SET relationship_scope=excluded.relationship_scope,
                rationale=excluded.rationale, review_status=excluded.review_status,
                source_label=excluded.source_label, updated_at=excluded.updated_at""",
            [
                (
                    item["framework_id"], item["control_id"], item["subcategory_id"],
                    item["relationship_role"], item["information_id"], item["relationship_scope"],
                    item["rationale"], now,
                )
                for item in CONTROL_MAPPING_RELATIONSHIPS
                if item["framework_id"] == framework_id
            ],
        )
    return {
        "framework_id": framework_id,
        "catalog_version": catalog_metadata["version"],
        "control_count": len(controls),
        "mapped_control_count": len({control_id for _, control_id in mappings}),
        "mapping_count": len(mappings),
        "skipped_reference_values": sorted(skipped_references),
        "workbook_path": str(workbook_path),
        "catalog_path": str(catalog_path),
    }


CONTROL_MAPPING_V7_REVIEW_DECISIONS: Dict[Tuple[str, str, str], Dict[str, str]] = {
    ("CA-07", "DE.AE-02", "nist-sp-800-53-r5.2.0"): {"relationship_role": "produces_outcome_information", "information_id": "monitoring_findings", "relationship_scope": "partial", "rationale": "CA-07 produces monitoring and assessment information that DE.AE-02 can analyze, but it does not require the outcome's full adverse-event and associated-activity analysis."},
    ("SC-07", "DE.CM-01", "nist-sp-800-53-r5.2.0"): {"relationship_role": "enables_outcome_capability", "information_id": "", "relationship_scope": "partial", "rationale": "SC-07 requires monitoring communications at managed network boundaries, but it does not require adverse-event detection across all networks and network services."},
    ("CM-10", "DE.CM-03", "nist-sp-800-53-r5.2.0"): {"relationship_role": "context_only", "information_id": "", "relationship_scope": "indirect", "rationale": "CM-10 tracks licensing and peer-to-peer use for copyright and contract compliance, not for identifying cybersecurity-relevant potentially adverse events."},
    ("CM-11", "DE.CM-03", "nist-sp-800-53-r5.2.0"): {"relationship_role": "context_only", "information_id": "", "relationship_scope": "indirect", "rationale": "CM-11 monitors compliance with user software-installation policy, a configuration-management activity rather than monitoring to identify potentially adverse events."},
    ("AU-12", "DE.CM-09", "nist-sp-800-53-r5.2.0"): {"relationship_role": "produces_outcome_information", "information_id": "log_records", "relationship_scope": "partial", "rationale": "AU-12 directly generates audit records that continuous monitoring can use, but it does not itself identify potentially adverse events."},
    ("CM-06", "DE.CM-09", "nist-sp-800-53-r5.2.0"): {"relationship_role": "enables_outcome_capability", "information_id": "", "relationship_scope": "partial", "rationale": "CM-06 establishes secure settings, identifies deviations, and monitors configuration changes, directly covering part of DE.CM-09's configuration-deviation monitoring example."},
    ("PL-02", "ID.AM-08", "nist-sp-800-53-r5.2.0"): {"relationship_role": "produces_outcome_information", "information_id": "asset_inventory", "relationship_scope": "partial", "rationale": "PL-02 requires documented system components and information types, producing partial asset-inventory information."},
    ("PM-11", "RC.RP-04", "nist-sp-800-53-r5.2.0"): {"relationship_role": "produces_outcome_information", "information_id": "organizational_mission", "relationship_scope": "indirect", "rationale": "PM-11 directly produces mission and business-process information, but using it to identify critical functions and establish post-incident operational norms requires product interpretation."},
    ("IR-05", "RS.MA-04", "nist-sp-800-53-r5.2.0"): {"relationship_role": "enables_outcome_capability", "information_id": "", "relationship_scope": "partial", "rationale": "IR-05 requires tracking incidents, directly covering part of the RS.MA-04 example, but does not validate status, decide on escalation, or coordinate escalation."},
}


def import_control_mapping_relationship_outputs(connection: sqlite3.Connection, output_paths: List[Path], prompt_version: str) -> Dict[str, Any]:
    """Import valid Responses Batch results without changing official NIST mappings."""
    rows: Dict[Tuple[str, str, str], Tuple[Dict[str, Any], Path]] = {}
    skipped_incomplete = 0
    for path in output_paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            envelope = json.loads(line)
            body = envelope.get("response", {}).get("body", {})
            if body.get("status") != "completed":
                skipped_incomplete += 1
                continue
            output_text = next((item.get("text") for item in body.get("output", [])[-1].get("content", []) if item.get("type") == "output_text"), None)
            if not output_text:
                skipped_incomplete += 1
                continue
            classification = json.loads(output_text)
            framework_id, control_id, subcategory_id, _ = envelope["custom_id"].split("|", 3)
            key = (framework_id, control_id, subcategory_id)
            rows[key] = ({"envelope": envelope, "classification": classification}, path)
    now = utc_now()
    imported_drafts = imported_reviewed = preserved_reviewed = 0
    with connection:
        for (framework_id, control_id, subcategory_id), (item, path) in rows.items():
            decision = CONTROL_MAPPING_V7_REVIEW_DECISIONS.get((control_id, subcategory_id, framework_id))
            classification = decision or item["classification"]
            status = "reviewed" if decision else "draft"
            source_kind = "human_reviewed_decision" if decision else "ai_assisted_draft"
            existing_reviewed = connection.execute("SELECT 1 FROM csf_control_mapping_relationships WHERE framework_id=? AND control_id=? AND subcategory_id=? AND review_status='reviewed'", (framework_id, control_id, subcategory_id)).fetchone()
            if existing_reviewed:
                preserved_reviewed += 1
                continue
            connection.execute("""INSERT INTO csf_control_mapping_relationships(framework_id, control_id, subcategory_id, relationship_role, information_id, relationship_scope, rationale, review_status, source_label, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(framework_id, control_id, subcategory_id, relationship_role, information_id) DO UPDATE SET relationship_scope=excluded.relationship_scope, rationale=excluded.rationale, review_status=excluded.review_status, source_label=excluded.source_label, updated_at=excluded.updated_at""", (framework_id, control_id, subcategory_id, classification["relationship_role"], classification["information_id"], classification["relationship_scope"], classification["rationale"], status, f"gpt-6-sol:{prompt_version}", now))
            connection.execute("""INSERT INTO csf_control_mapping_relationship_sources(framework_id, control_id, subcategory_id, source_artifact, request_custom_id, model_name, prompt_version, source_kind, response_json, imported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(framework_id, control_id, subcategory_id, source_artifact) DO UPDATE SET request_custom_id=excluded.request_custom_id, model_name=excluded.model_name, prompt_version=excluded.prompt_version, source_kind=excluded.source_kind, response_json=excluded.response_json, imported_at=excluded.imported_at""", (framework_id, control_id, subcategory_id, str(path), item["envelope"]["custom_id"], item["envelope"]["response"]["body"].get("model", "unknown"), prompt_version, source_kind, json.dumps(item["envelope"], ensure_ascii=True), now))
            if decision: imported_reviewed += 1
            else: imported_drafts += 1
    return {"outputs_read": len(output_paths), "unique_mappings": len(rows), "imported_drafts": imported_drafts, "imported_reviewed": imported_reviewed, "preserved_reviewed": preserved_reviewed, "skipped_incomplete": skipped_incomplete}


def get_app_state(connection: sqlite3.Connection, namespace: str, state_key: str) -> Dict[str, Any]:
    row = connection.execute(
        """
        SELECT namespace, state_key, value_json, updated_at
        FROM app_state
        WHERE namespace = ? AND state_key = ?
        """,
        (namespace, state_key),
    ).fetchone()

    if row is None:
        return {
            "found": False,
            "namespace": namespace,
            "key": state_key,
            "updated_at": None,
            "value": None,
        }

    value: Any
    try:
        value = json.loads(row["value_json"])
    except json.JSONDecodeError:
        value = row["value_json"]

    return {
        "found": True,
        "namespace": row["namespace"],
        "key": row["state_key"],
        "updated_at": row["updated_at"],
        "value": value,
    }


def get_app_state_meta(connection: sqlite3.Connection, namespace: str, state_key: str) -> Dict[str, Any]:
    row = connection.execute(
        """
        SELECT namespace, state_key, value_json, updated_at
        FROM app_state
        WHERE namespace = ? AND state_key = ?
        """,
        (namespace, state_key),
    ).fetchone()

    if row is None:
        return {
            "found": False,
            "namespace": namespace,
            "key": state_key,
            "updated_at": None,
            "metadata": None,
        }

    metadata = None
    try:
        value = json.loads(row["value_json"])
        if isinstance(value, dict):
            metadata = value.get("Metadata")
            if metadata is None and "LastRunUtc" in value:
                metadata = {"LastRunUtc": value.get("LastRunUtc")}
    except json.JSONDecodeError:
        metadata = None

    return {
        "found": True,
        "namespace": row["namespace"],
        "key": row["state_key"],
        "updated_at": row["updated_at"],
        "metadata": metadata,
    }


def put_app_state(connection: sqlite3.Connection, namespace: str, state_key: str, value: Any) -> None:
    connection.execute(
        """
        INSERT INTO app_state (namespace, state_key, value_json, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(namespace, state_key) DO UPDATE SET
            value_json = excluded.value_json,
            updated_at = excluded.updated_at
        """,
        (namespace, state_key, json.dumps(value, ensure_ascii=True), utc_now()),
    )
    connection.commit()


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _is_active_accepted_posture_drift_row(row: sqlite3.Row) -> bool:
    if int(row['enabled'] or 0) != 1:
        return False
    expires_utc = _parse_iso_datetime(row['expires_utc'])
    if expires_utc is None:
        return True
    return expires_utc > datetime.now(timezone.utc)


def _row_to_accepted_posture_drift_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        'AcceptanceId': row['acceptance_id'],
        'Enabled': bool(row['enabled']),
        'Scope': row['scope'],
        'Section': row['section'],
        'ItemName': row['item_name'],
        'ItemType': row['item_type'],
        'Field': row['field'],
        'AcceptedCurrentValue': row['accepted_current_value'],
        'BaselineValue': row['baseline_value'],
        'MatchedRuleId': row['matched_rule_id'],
        'MatchedRuleDescription': row['matched_rule_description'],
        'Reason': row['reason'],
        'AcceptedBy': row['accepted_by'],
        'AcceptedUtc': row['accepted_utc'],
        'ExpiresUtc': row['expires_utc'],
        'SourceReportId': row['source_report_id'],
        'SourceReportPath': row['source_report_path'],
        'CsfMapping': row['csf_mapping'],
        'CreatedByAppVersion': row['created_by_app_version'],
        'CreatedUtc': row['created_utc'],
        'UpdatedUtc': row['updated_utc'],
    }


def list_active_accepted_posture_drift(connection: sqlite3.Connection) -> Dict[str, Any]:
    rows = connection.execute(
        """
        SELECT acceptance_id, enabled, scope, section, item_name, item_type, field,
               accepted_current_value, baseline_value, matched_rule_id, matched_rule_description,
               reason, accepted_by, accepted_utc, expires_utc, source_report_id,
               source_report_path, csf_mapping, created_by_app_version, created_utc, updated_utc
        FROM accepted_posture_drift
        ORDER BY accepted_utc DESC, acceptance_id ASC
        """
    ).fetchall()
    active_rows = [row for row in rows if _is_active_accepted_posture_drift_row(row)]
    return {
        'registry_status': 'sqlite',
        'registry_path': None,
        'loaded_count': len(active_rows),
        'entries': [_row_to_accepted_posture_drift_dict(row) for row in active_rows],
    }


def upsert_accepted_posture_drift_entries(connection: sqlite3.Connection, entries: Iterable[Dict[str, Any]], created_by_app_version: str = 'unknown') -> int:
    now = utc_now()
    count = 0
    for entry in entries:
        acceptance_id = str(entry.get('AcceptanceId') or entry.get('acceptance_id') or '').strip()
        if not acceptance_id:
            continue
        enabled = 1 if bool(entry.get('Enabled', True)) else 0
        scope = str(entry.get('Scope') or entry.get('scope') or 'exact')
        section = str(entry.get('Section') or entry.get('section') or '').strip()
        item_name = str(entry.get('ItemName') or entry.get('item_name') or '').strip()
        item_type = entry.get('ItemType') or entry.get('item_type')
        field = entry.get('Field') or entry.get('field')
        accepted_current_value = entry.get('AcceptedCurrentValue') or entry.get('accepted_current_value')
        baseline_value = entry.get('BaselineValue') or entry.get('baseline_value')
        matched_rule_id = entry.get('MatchedRuleId') or entry.get('matched_rule_id')
        matched_rule_description = entry.get('MatchedRuleDescription') or entry.get('matched_rule_description')
        reason = str(entry.get('Reason') or entry.get('reason') or '').strip()
        accepted_by = entry.get('AcceptedBy') or entry.get('accepted_by')
        accepted_utc = str(entry.get('AcceptedUtc') or entry.get('accepted_utc') or now)
        expires_utc = entry.get('ExpiresUtc') or entry.get('expires_utc')
        source_report_id = entry.get('SourceReportId') or entry.get('source_report_id')
        source_report_path = entry.get('SourceReportPath') or entry.get('source_report_path')
        csf_mapping = entry.get('CsfMapping') or entry.get('csf_mapping')
        created_by = str(entry.get('CreatedByAppVersion') or entry.get('created_by_app_version') or created_by_app_version or 'unknown')
        created_utc = str(entry.get('CreatedUtc') or entry.get('created_utc') or now)
        updated_utc = str(entry.get('UpdatedUtc') or entry.get('updated_utc') or now)
        connection.execute(
            """
            INSERT INTO accepted_posture_drift (
                acceptance_id, enabled, scope, section, item_name, item_type, field,
                accepted_current_value, baseline_value, matched_rule_id, matched_rule_description,
                reason, accepted_by, accepted_utc, expires_utc, source_report_id,
                source_report_path, csf_mapping, created_by_app_version, created_utc, updated_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(acceptance_id) DO UPDATE SET
                enabled = excluded.enabled,
                scope = excluded.scope,
                section = excluded.section,
                item_name = excluded.item_name,
                item_type = excluded.item_type,
                field = excluded.field,
                accepted_current_value = excluded.accepted_current_value,
                baseline_value = excluded.baseline_value,
                matched_rule_id = excluded.matched_rule_id,
                matched_rule_description = excluded.matched_rule_description,
                reason = excluded.reason,
                accepted_by = excluded.accepted_by,
                accepted_utc = excluded.accepted_utc,
                expires_utc = excluded.expires_utc,
                source_report_id = excluded.source_report_id,
                source_report_path = excluded.source_report_path,
                csf_mapping = excluded.csf_mapping,
                created_by_app_version = excluded.created_by_app_version,
                updated_utc = excluded.updated_utc
            """,
            (
                acceptance_id, enabled, scope, section, item_name, item_type, field,
                accepted_current_value, baseline_value, matched_rule_id, matched_rule_description,
                reason, accepted_by, accepted_utc, expires_utc, source_report_id,
                source_report_path, csf_mapping, created_by, created_utc, updated_utc,
            ),
        )
        count += 1
    connection.commit()
    return count


def load_accepted_posture_drift_json(path: Path) -> Dict[str, Any]:
    payload = load_json(path)
    entries = payload.get('entries') if isinstance(payload, dict) else payload
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list):
        entries = []
    return {'schema_version': payload.get('schema_version', 1) if isinstance(payload, dict) else 1, 'entries': entries}


def import_accepted_posture_drift_json(connection: sqlite3.Connection, input_path: Path, created_by_app_version: str = 'unknown') -> Dict[str, Any]:
    payload = load_accepted_posture_drift_json(input_path)
    imported_count = upsert_accepted_posture_drift_entries(connection, payload.get('entries', []), created_by_app_version=created_by_app_version)
    return {
        'registry_status': 'sqlite_imported_json',
        'registry_path': str(input_path),
        'imported_count': imported_count,
        'loaded_count': imported_count,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local SQLite IOC store manager.")
    parser.add_argument(
        "--db",
        default=str(Path("state") / "codex-monitor.db"),
        help="Path to the SQLite database file.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Initialize the IOC store schema.")

    nist_mapping_parser = subparsers.add_parser(
        "import-nist-sp800-53-csf-mappings",
        help="Import NIST SP 800-53 Rev. 5.2.0 controls and final CSF 2.0 informative-reference mappings.",
    )
    nist_mapping_parser.add_argument("--workbook", required=True, help="Path to csf-2.0-informative-references.xlsx.")
    nist_mapping_parser.add_argument("--catalog", required=True, help="Path to the NIST SP 800-53 Rev. 5 OSCAL JSON catalog.")

    relationship_import_parser = subparsers.add_parser("import-control-mapping-relationship-outputs", help="Import AI-assisted relationship classifications from Responses Batch JSONL outputs.")
    relationship_import_parser.add_argument("--output", action="append", required=True, help="Batch output JSONL path; repeat for each artifact.")
    relationship_import_parser.add_argument("--prompt-version", required=True, help="Prompt version retained with each imported source record.")

    action_guidance_import_parser = subparsers.add_parser(
        "import-profile-action-guidance-outputs",
        help="Import completed Responses Batch Add Action templates for one CSF profile.",
    )
    action_guidance_import_parser.add_argument("--output", action="append", required=True, help="Batch output JSONL path; repeat in original-to-retry order.")
    action_guidance_import_parser.add_argument("--profile-id", required=True, help="Frozen or organizational profile UUID expected in every batch custom_id.")
    action_guidance_import_parser.add_argument("--source-kind", default="nist_ir_8596_cyber_ai_batch", help="Provenance label retained with imported templates.")

    community_profile_import_parser = subparsers.add_parser(
        "import-community-profile-workbook",
        help="Import a reviewed Community Profile worksheet as a frozen, read-only source artifact.",
    )
    community_profile_import_parser.add_argument("--workbook", required=True, help="Path to the reviewed Community Profile workbook.")
    community_profile_import_parser.add_argument("--sheet", required=True, help="Worksheet containing the Community Profile outcomes.")
    community_profile_import_parser.add_argument("--community-profile-id", required=True, help="Stable catalog identifier for the source profile.")
    community_profile_import_parser.add_argument("--profile-name", required=True, help="Display name for the frozen source profile.")
    community_profile_import_parser.add_argument("--publisher", required=True, help="Source publisher.")
    community_profile_import_parser.add_argument("--publication-status", required=True, help="Source publication status.")
    community_profile_import_parser.add_argument("--focus", required=True, help="Short source-profile focus description.")
    community_profile_import_parser.add_argument("--source-url", required=True, help="Official source URL for the profile.")

    cyber_ai_profile_import_parser = subparsers.add_parser(
        "import-cyber-ai-focus-profiles",
        help="Import the reviewed NIST IR 8596 Secure, Defend, and Thwart profiles as separate frozen source artifacts.",
    )
    cyber_ai_profile_import_parser.add_argument("--workbook", required=True, help="Path to the reviewed Cyber AI Profile workbook.")
    cyber_ai_profile_import_parser.add_argument("--sheet", default="Profile outcomes", help="Worksheet containing the Cyber AI Profile outcomes.")
    cyber_ai_profile_import_parser.add_argument("--publisher", default="NIST", help="Source publisher.")
    cyber_ai_profile_import_parser.add_argument("--publication-status", default="Initial Preliminary Draft", help="Source publication status.")
    cyber_ai_profile_import_parser.add_argument("--source-url", default="https://csrc.nist.gov/pubs/ir/8596/iprd", help="Official source URL for the profile.")

    import_parser = subparsers.add_parser("import-json", help="Import normalized indicators from a JSON file.")
    import_parser.add_argument("--input", required=True, help="Path to a normalized indicator JSON file.")

    export_parser = subparsers.add_parser("export-json", help="Export normalized indicators from SQLite to JSON.")
    export_parser.add_argument("--output", required=True, help="Destination JSON file.")
    export_indicators_parser = subparsers.add_parser("export-indicators", help="Explicitly export normalized indicators from SQLite to JSON.")
    export_indicators_parser.add_argument("--output", required=True, help="Destination JSON file.")

    active_indicator_parser = subparsers.add_parser("query-active-indicators", help="Read active normalized indicators from SQLite.")
    active_indicator_parser.add_argument("--type", action="append", default=[], help="Optional indicator type filter; repeat for multiple types.")
    active_indicator_parser.add_argument("--include-expired", action="store_true", help="Include expired indicators for diagnostics or tests.")

    persist_report_parser = subparsers.add_parser("persist-collector-report", help="Atomically persist a collector run, report, and findings from a JSON envelope.")
    persist_report_parser.add_argument("--input", required=True, help="JSON object with collector_run, report, findings, and optional alerts fields.")

    claim_delivery_parser = subparsers.add_parser("claim-alert-deliveries", help="Atomically claim pending or failed alert deliveries for one notifier.")
    claim_delivery_parser.add_argument("--channel", required=True, help="Delivery channel, such as interactive_popup.")
    claim_delivery_parser.add_argument("--recipient", required=True, help="Stable recipient identity for the notifier.")
    claim_delivery_parser.add_argument("--limit", type=int, default=20, help="Maximum deliveries to claim (1-100).")
    claim_delivery_parser.add_argument("--claim-lease-seconds", type=int, default=300, help="Reclaim an interrupted claim only after this lease (1-3600 seconds).")

    complete_delivery_parser = subparsers.add_parser("complete-alert-delivery", help="Complete a claimed delivery or return it to retryable failed state.")
    complete_delivery_parser.add_argument("--delivery-id", required=True, help="Immutable claimed alert-delivery identifier.")
    complete_delivery_parser.add_argument("--outcome", required=True, choices=["delivered", "failed"], help="Final delivery outcome.")
    complete_delivery_parser.add_argument("--error", default="", help="Failure detail retained for retry diagnostics.")

    persisted_report_parser = subparsers.add_parser("get-persisted-report", help="Read one persisted report and its ordered findings by immutable report ID.")
    persisted_report_parser.add_argument("--report-id", required=True, help="Immutable report identifier to read.")

    export_report_parser = subparsers.add_parser("export-report", help="Explicitly export one persisted report and findings to JSON.")
    export_report_parser.add_argument("--report-id", required=True)
    export_report_parser.add_argument("--output", required=True)
    export_alert_parser = subparsers.add_parser("export-alert", help="Explicitly export one persisted alert to JSON.")
    export_alert_parser.add_argument("--alert-id", required=True)
    export_alert_parser.add_argument("--output", required=True)

    state_get_parser = subparsers.add_parser("state-get", help="Read a JSON state document from SQLite.")
    state_get_parser.add_argument("--namespace", required=True, help="Logical namespace for the state record.")
    state_get_parser.add_argument("--key", required=True, help="State key inside the namespace.")

    state_meta_parser = subparsers.add_parser("state-meta", help="Read lightweight metadata for a JSON state document from SQLite.")
    state_meta_parser.add_argument("--namespace", required=True, help="Logical namespace for the state record.")
    state_meta_parser.add_argument("--key", required=True, help="State key inside the namespace.")

    state_put_parser = subparsers.add_parser("state-put", help="Write a JSON state document into SQLite.")
    state_put_parser.add_argument("--namespace", required=True, help="Logical namespace for the state record.")
    state_put_parser.add_argument("--key", required=True, help="State key inside the namespace.")
    state_put_parser.add_argument("--input", required=True, help="Path to a JSON file containing the state value.")

    baseline_index_parser = subparsers.add_parser("index-tripwire-baseline", help="Index a tripwire baseline JSON into SQLite baseline tables.")
    baseline_index_parser.add_argument("--input", required=True, help="Path to a HOST_TRIPWIRE_BASELINE_*.json file.")
    baseline_index_parser.add_argument("--markdown", help="Optional matching markdown path.")

    baseline_backfill_parser = subparsers.add_parser("backfill-tripwire-baselines", help="Backfill existing tripwire baseline JSON reports into SQLite.")
    baseline_backfill_parser.add_argument("--root", required=True, help="Root directory to search for HOST_TRIPWIRE_BASELINE_*.json files.")

    accepted_get_parser = subparsers.add_parser("accepted-drift-get", help="Read active accepted-drift entries from SQLite.")
    accepted_get_parser.add_argument("--json-fallback", default="", help="Optional JSON registry path to import if SQLite is empty or unavailable.")

    accepted_import_parser = subparsers.add_parser("accepted-drift-import-json", help="Import accepted-drift entries from JSON into SQLite.")
    accepted_import_parser.add_argument("--input", required=True, help="Path to the JSON accepted-drift registry.")

    snapshot_import_parser = subparsers.add_parser("import-evidence-snapshot", help="Import a baseline/current-scan evidence snapshot JSON into normalized SQLite observation tables.")
    snapshot_import_parser.add_argument("--input", required=True, help="Path to the collector JSON document to import.")
    snapshot_import_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier to store.")
    snapshot_import_parser.add_argument("--snapshot-type", required=True, choices=["baseline", "current_scan", "scheduled_check"], help="Snapshot type label.")
    snapshot_import_parser.add_argument("--source-json-path", required=True, help="Path to the report JSON artifact represented by this snapshot.")
    snapshot_import_parser.add_argument("--source-markdown-path", default="", help="Optional path to the matching Markdown artifact.")
    snapshot_import_parser.add_argument("--collector-version", default="invoke-host-ioc.ps1", help="Collector version label.")
    snapshot_import_parser.add_argument("--trust-label", default="unknown", choices=["known_good", "unknown", "untrusted"], help="Trust label for the snapshot.")

    snapshot_status_parser = subparsers.add_parser("evidence-snapshot-status", help="Show snapshot metadata and observation counts for a stored evidence snapshot.")
    snapshot_status_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier to inspect.")

    snapshot_match_parser = subparsers.add_parser("evidence-snapshot-match", help="Match indicators against normalized SQLite evidence snapshots for a current snapshot context.")
    snapshot_match_parser.add_argument("--snapshot-id", required=True, help="Current snapshot identifier to match against.")

    subparsers.add_parser("baseline-hash-status", help="Show latest indexed tripwire baseline hash status.")
    baseline_match_parser = subparsers.add_parser("baseline-hash-match", help="Join SHA-256 indicators against indexed tripwire baseline hashes.")
    baseline_match_parser.add_argument("--all-baselines", action="store_true", help="Match against all indexed baselines instead of only the latest one.")

    subparsers.add_parser("stats", help="Show basic IOC store statistics.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    db_path = Path(args.db).resolve()
    db_existed = db_path.exists()
    connection = connect_db(db_path)
    init_db(connection)

    if args.command == "init":
        print(
            "Initialized application state store and seeded CSF profile content "
            f"(existing operational records retained): {db_path}"
        )
        return 0

    if args.command == "import-nist-sp800-53-csf-mappings":
        payload = import_nist_sp800_53_csf_2_mappings(
            connection,
            Path(args.workbook),
            Path(args.catalog),
        )
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "import-control-mapping-relationship-outputs":
        payload = import_control_mapping_relationship_outputs(connection, [Path(path).resolve() for path in args.output], args.prompt_version)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "import-profile-action-guidance-outputs":
        payload = import_csf_profile_action_guidance_outputs(
            connection,
            [Path(path).resolve() for path in args.output],
            args.profile_id,
            args.source_kind,
        )
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "import-community-profile-workbook":
        payload = import_frozen_community_profile_from_workbook(
            connection,
            workbook=Path(args.workbook), sheet_name=args.sheet,
            community_profile_id=args.community_profile_id, profile_name=args.profile_name,
            publisher=args.publisher, publication_status=args.publication_status,
            focus=args.focus, source_url=args.source_url,
        )
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "import-cyber-ai-focus-profiles":
        payload = import_frozen_cyber_ai_focus_profiles_from_workbook(
            connection, workbook=Path(args.workbook), sheet_name=args.sheet,
            publisher=args.publisher, publication_status=args.publication_status,
            source_url=args.source_url,
        )
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "import-json":
        input_path = Path(args.input).resolve()
        document = load_json(input_path)
        indicators, source_name = normalize_indicators(document)
        run_id = begin_ingest_run(connection, source_name, input_path)
        try:
            imported_count = upsert_indicators(connection, run_id, indicators)
            finish_ingest_run(connection, run_id, "success", imported_count)
            print(f"Imported indicators: {imported_count}")
            print(f"IOC store: {db_path}")
            return 0
        except Exception as exc:  # pragma: no cover
            finish_ingest_run(connection, run_id, "error", 0, str(exc))
            raise

    if args.command in {"export-json", "export-indicators"}:
        output_path = Path(args.output).resolve()
        payload = export_indicators(connection)
        write_json(output_path, payload)
        print(f"Exported indicators: {payload['Metadata']['IndicatorCount']}")
        print(f"Output: {output_path}")
        return 0

    if args.command == "query-active-indicators":
        payload = query_active_indicators(connection, indicator_types=args.type, include_expired=args.include_expired)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "persist-collector-report":
        envelope = load_json(Path(args.input).resolve())
        if not isinstance(envelope, dict):
            raise ValueError("Collector report envelope must be a JSON object.")
        collector_run = envelope.get("collector_run")
        report = envelope.get("report")
        findings = envelope.get("findings", [])
        alerts = envelope.get("alerts", [])
        if not isinstance(collector_run, dict) or not isinstance(report, dict) or not isinstance(findings, list) or not isinstance(alerts, list):
            raise ValueError("Collector report envelope requires object collector_run/report fields and array findings/alerts fields.")
        payload = persist_collector_run_report_findings(connection, collector_run, report, findings, alerts)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "claim-alert-deliveries":
        print(json.dumps(claim_alert_deliveries(connection, args.channel, args.recipient, args.limit, args.claim_lease_seconds), indent=2))
        return 0

    if args.command == "complete-alert-delivery":
        print(json.dumps(complete_alert_delivery(connection, args.delivery_id, args.outcome, args.error), indent=2))
        return 0

    if args.command == "get-persisted-report":
        print(json.dumps(get_persisted_report(connection, args.report_id), indent=2))
        return 0

    if args.command == "export-report":
        payload = get_persisted_report(connection, args.report_id)
        if not payload["found"]:
            raise ValueError("persisted report was not found.")
        write_json(Path(args.output).resolve(), payload)
        print(f"Exported report: {args.report_id}")
        return 0

    if args.command == "export-alert":
        payload = get_persisted_alert(connection, args.alert_id)
        if not payload["found"]:
            raise ValueError("persisted alert was not found.")
        write_json(Path(args.output).resolve(), payload)
        print(f"Exported alert: {args.alert_id}")
        return 0

    if args.command == "state-get":
        payload = get_app_state(connection, args.namespace, args.key)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "state-meta":
        payload = get_app_state_meta(connection, args.namespace, args.key)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "state-put":
        input_path = Path(args.input).resolve()
        payload = load_json(input_path)
        put_app_state(connection, args.namespace, args.key, payload)
        print(f"Stored state: {args.namespace}/{args.key}")
        print(f"IOC store: {db_path}")
        return 0

    if args.command == "index-tripwire-baseline":
        input_path = Path(args.input).resolve()
        markdown_path = Path(args.markdown).resolve() if getattr(args, "markdown", None) else None
        payload = index_tripwire_baseline(connection, input_path, markdown_path)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "backfill-tripwire-baselines":
        root = Path(args.root).resolve()
        payload = backfill_tripwire_baselines(connection, root)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "accepted-drift-get":
        try:
            payload = list_active_accepted_posture_drift(connection)
            payload["registry_path"] = str(db_path)
            payload["registry_status"] = "sqlite_missing_created" if not db_existed else "sqlite"
            if payload["loaded_count"] == 0 and args.json_fallback:
                fallback_path = Path(args.json_fallback).resolve()
                if fallback_path.exists():
                    fallback_payload = load_accepted_posture_drift_json(fallback_path)
                    if fallback_payload.get("entries"):
                        imported = upsert_accepted_posture_drift_entries(connection, fallback_payload.get("entries", []))
                        payload = list_active_accepted_posture_drift(connection)
                        payload["registry_status"] = "sqlite_imported_json"
                        payload["registry_path"] = str(db_path)
                        payload["imported_count"] = imported
            print(json.dumps(payload, indent=2))
            return 0
        except Exception as exc:  # pragma: no cover
            print(json.dumps({"registry_status": "sqlite_error", "registry_path": str(db_path), "loaded_count": 0, "entries": [], "warning": str(exc)}, indent=2))
            return 0

    if args.command == "accepted-drift-import-json":
        input_path = Path(args.input).resolve()
        payload = import_accepted_posture_drift_json(connection, input_path)
        payload["registry_path"] = str(db_path)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "import-evidence-snapshot":
        payload = index_evidence_snapshot(
            connection=connection,
            input_path=Path(args.input).resolve(),
            snapshot_id=args.snapshot_id,
            snapshot_type=args.snapshot_type,
            source_json_path=args.source_json_path,
            source_markdown_path=args.source_markdown_path,
            collector_version=args.collector_version,
            trust_label=args.trust_label,
        )
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "evidence-snapshot-status":
        payload = get_snapshot_status(connection, args.snapshot_id)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "evidence-snapshot-match":
        payload = match_indicators_against_evidence_snapshots(connection, args.snapshot_id)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "baseline-hash-status":
        print(json.dumps(get_latest_baseline_hash_status(connection), indent=2))
        return 0

    if args.command == "baseline-hash-match":
        payload = match_sha256_indicators_against_baseline_hashes(connection, latest_only=not args.all_baselines)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "stats":
        print(json.dumps(stats(connection), indent=2))
        return 0

    parser.error("Unknown command")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

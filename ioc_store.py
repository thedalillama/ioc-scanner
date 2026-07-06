import argparse
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


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
        """
    )
    connection.commit()


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
            i.severity
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

    indicator_rows = connection.execute(
        """
        SELECT type, value, source, confidence, severity
        FROM indicators
        WHERE type IN ('sha256', 'ipv4', 'ipv6', 'domain', 'url', 'registry_key', 'registry_value', 'service_name', 'scheduled_task', 'command_line_pattern')
        """
    ).fetchall()

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

    indicators = []
    for row in rows:
        raw_source_record = None
        if row["raw_source_record_json"]:
            try:
                raw_source_record = json.loads(row["raw_source_record_json"])
            except json.JSONDecodeError:
                raw_source_record = row["raw_source_record_json"]

        indicators.append(
            {
                "indicator_id": row["indicator_id"],
                "type": row["type"],
                "value": row["value"],
                "source": row["source"],
                "confidence": row["confidence"],
                "severity": row["severity"],
                "first_seen": row["first_seen"] or "",
                "last_seen": row["last_seen"] or "",
                "valid_from": row["valid_from"] or "",
                "valid_until": row["valid_until"] or "",
                "tlp": row["tlp"] or "clear",
                "malware_family": row["malware_family"] or "",
                "campaign": row["campaign"] or "",
                "threat_actor": row["threat_actor"] or "",
                "attack_technique": row["attack_technique"] or "",
                "reference_url": row["reference_url"] or "",
                "raw_source_record": raw_source_record,
            }
        )

    return {
        "Metadata": {
            "Format": "normalized-indicator-set",
            "CollectionTimeUtc": utc_now(),
            "IndicatorCount": len(indicators),
            "Source": "sqlite-ioc-store",
        },
        "Indicators": indicators,
    }


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
        default=str(Path("state") / "ioc-store.db"),
        help="Path to the SQLite database file.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Initialize the IOC store schema.")

    import_parser = subparsers.add_parser("import-json", help="Import normalized indicators from a JSON file.")
    import_parser.add_argument("--input", required=True, help="Path to a normalized indicator JSON file.")

    export_parser = subparsers.add_parser("export-json", help="Export normalized indicators from SQLite to JSON.")
    export_parser.add_argument("--output", required=True, help="Destination JSON file.")

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
        print(f"Initialized IOC store: {db_path}")
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

    if args.command == "export-json":
        output_path = Path(args.output).resolve()
        payload = export_indicators(connection)
        write_json(output_path, payload)
        print(f"Exported indicators: {payload['Metadata']['IndicatorCount']}")
        print(f"Output: {output_path}")
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

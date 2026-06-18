import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


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
        """
    )
    connection.commit()


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

    subparsers.add_parser("stats", help="Show basic IOC store statistics.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    db_path = Path(args.db).resolve()
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

    if args.command == "stats":
        print(json.dumps(stats(connection), indent=2))
        return 0

    parser.error("Unknown command")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Copy a legacy combined Codex database into independent app databases.

The legacy source remains unchanged.  CSF/Profile records go only to the
analyst database; collector, scan, finding, and alert records go only to the
monitoring database.
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Iterable

import codex_monitor_store as store


ANALYST_PREFIXES = ("csf_", "local_csf_")
SHARED_SCHEMA_TABLES = {"schema_migrations"}


def source_tables(connection: sqlite3.Connection) -> list[str]:
    return [
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]


def copy_tables(
    source: sqlite3.Connection,
    target: sqlite3.Connection,
    tables: Iterable[str],
) -> int:
    copied = 0
    target.execute("PRAGMA foreign_keys = OFF")
    try:
        for table in tables:
            columns = [str(row[1]) for row in source.execute(f'PRAGMA table_info("{table}")')]
            if not columns:
                continue
            column_sql = ", ".join(f'"{column}"' for column in columns)
            placeholders = ", ".join("?" for _ in columns)
            rows = source.execute(f'SELECT {column_sql} FROM "{table}"').fetchall()
            if rows:
                target.executemany(
                    f'INSERT OR REPLACE INTO "{table}" ({column_sql}) VALUES ({placeholders})', rows
                )
            copied += len(rows)
        target.commit()
    finally:
        target.execute("PRAGMA foreign_keys = ON")
    return copied


def prepare_destination(path: Path) -> sqlite3.Connection:
    if path.exists():
        raise ValueError(f"Destination already exists: {path}. Refusing to overwrite it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = store.connect_db(path)
    store.init_db(connection)
    return connection


def split(source_path: Path, analyst_path: Path, monitor_path: Path) -> dict[str, int]:
    source_path = source_path.resolve()
    analyst_path = analyst_path.resolve()
    monitor_path = monitor_path.resolve()
    if not source_path.is_file():
        raise ValueError(f"Legacy source database was not found: {source_path}")
    if len({source_path, analyst_path, monitor_path}) != 3:
        raise ValueError("Source, analyst destination, and monitoring destination must be different files.")

    source = sqlite3.connect(source_path)
    analyst = None
    monitor = None
    try:
        tables = source_tables(source)
        analyst_tables = [table for table in tables if table.startswith(ANALYST_PREFIXES) or table in SHARED_SCHEMA_TABLES]
        monitor_tables = [table for table in tables if table not in analyst_tables]
        analyst = prepare_destination(analyst_path)
        monitor = prepare_destination(monitor_path)
        analyst_rows = copy_tables(source, analyst, analyst_tables)
        monitor_rows = copy_tables(source, monitor, monitor_tables)
        return {
            "analyst_tables": len(analyst_tables),
            "analyst_rows": analyst_rows,
            "monitor_tables": len(monitor_tables),
            "monitor_rows": monitor_rows,
        }
    except Exception:
        if analyst is not None:
            analyst.close()
        if monitor is not None:
            monitor.close()
        # Both destinations are created only for this run and contain copied data
        # that can be regenerated from the untouched legacy source.
        for path in (analyst_path, monitor_path):
            if path.exists():
                path.unlink()
        raise
    finally:
        source.close()
        if analyst is not None:
            analyst.close()
        if monitor is not None:
            monitor.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Split a combined Codex SQLite state database by application.")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--analyst-db", required=True, type=Path)
    parser.add_argument("--monitor-db", required=True, type=Path)
    args = parser.parse_args()
    result = split(args.source, args.analyst_db, args.monitor_db)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

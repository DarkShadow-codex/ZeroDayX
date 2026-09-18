"""Persistent Database Engine for ZeroDay v2.0."""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path

    from zeroday.storage.models import AuditLogRecord, ScanRecord


logger = logging.getLogger(__name__)


class Database:
    """Thread-safe SQLite persistent store with multi-tenant/project keying."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = str(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    metadata JSON
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    safety_mode TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    completed_at REAL,
                    summary JSON
                );

                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    hostname TEXT,
                    ip TEXT,
                    port INTEGER,
                    service TEXT,
                    criticality TEXT,
                    exposure TEXT,
                    metadata JSON,
                    last_seen REAL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    cvss REAL NOT NULL,
                    cwe JSON,
                    owasp JSON,
                    attack JSON,
                    endpoint TEXT,
                    status TEXT NOT NULL,
                    data JSON NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    log_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    details JSON,
                    timestamp REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS regression_tests (
                    test_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    data JSON NOT NULL
                );
                """
            )
            conn.commit()

    def insert_scan(self, scan: ScanRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans
                (
                    scan_id, project_id, target, status, scan_mode,
                    safety_mode, created_at, completed_at, summary
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.scan_id,
                    scan.project_id,
                    scan.target,
                    scan.status,
                    scan.scan_mode,
                    scan.safety_mode,
                    scan.created_at,
                    scan.completed_at,
                    json.dumps(scan.summary),
                ),
            )
            conn.commit()

    def insert_audit_log(self, log: AuditLogRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO audit_logs
                (
                    log_id, project_id, scan_id, agent_id, action,
                    target, outcome, details, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log.log_id,
                    log.project_id,
                    log.scan_id,
                    log.agent_id,
                    log.action,
                    log.target,
                    log.outcome,
                    json.dumps(log.details),
                    log.timestamp,
                ),
            )
            conn.commit()

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if row:
                d = dict(row)
                d["summary"] = json.loads(d["summary"]) if d["summary"] else {}
                return d
            return None

    def list_audit_logs(self, scan_id: str | None = None) -> list[dict[str, Any]]:
        with self._get_connection() as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT * FROM audit_logs WHERE scan_id = ? ORDER BY timestamp ASC",
                    (scan_id,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp ASC").fetchall()
            return [dict(r) for r in rows]

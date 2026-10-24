"""Persistent audit; source code is intentionally excluded from stored records."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class RunConflict(ValueError):
    pass


class AuditStore:
    def __init__(self, url: str):
        self.url = url
        self.is_sqlite = url.startswith("sqlite:///")
        self.placeholder = "?" if self.is_sqlite else "%s"
        if not self.is_sqlite and not url.startswith(("postgresql://", "postgres://")):
            raise ValueError("DATABASE_URL must use SQLite or PostgreSQL")
        if self.is_sqlite:
            self.path = url[len("sqlite:///"):]
            if self.path == ":memory:":
                raise ValueError("Use a file-backed SQLite audit database")
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, "
                         "fingerprint TEXT NOT NULL, status TEXT NOT NULL, record TEXT NOT NULL)")

    @contextmanager
    def _connection(self):
        if self.is_sqlite:
            conn = sqlite3.connect(self.path, timeout=10)
        else:
            import psycopg
            conn = psycopg.connect(self.url, connect_timeout=5)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get(self, run_id: str) -> dict | None:
        with self._connection() as conn:
            row = conn.execute(f"SELECT fingerprint, status, record FROM runs WHERE run_id={self.placeholder}",
                               (run_id,)).fetchone()
        if row is None:
            return None
        return {"fingerprint": row[0], "status": row[1], "record": json.loads(row[2])}

    def list_records(self, limit: int = 1000) -> dict:
        """Read a bounded audit window without exposing keys or fingerprints.

        Historical tables have no insertion timestamp column, so the query
        selects deterministically by run_id. Consumers can order this window
        by the timestamps stored in each record and disclose any truncation.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Audit list limit must be an integer in [1, 1000]")
        with self._connection() as conn:
            if self.is_sqlite:
                conn.execute("BEGIN")
            total = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            rows = conn.execute(f"SELECT run_id, record FROM runs ORDER BY run_id DESC "
                                f"LIMIT {self.placeholder}", (limit,)).fetchall()
        records = []
        for run_id, payload in rows:
            try:
                record = json.loads(payload)
            except (TypeError, ValueError):
                record = None
            records.append({"run_id": run_id, "record": record})
        return {"records": records, "total_records": total, "limit": limit,
                "truncated": total > len(records), "selection": "run_id_desc"}

    def reserve(self, run_id: str, fingerprint: str, record: dict) -> dict | None:
        # ON CONFLICT handles concurrent duplicate submissions atomically.
        with self._connection() as conn:
            cursor = conn.execute(
                f"INSERT INTO runs (run_id, fingerprint, status, record) VALUES "
                f"({self.placeholder}, {self.placeholder}, {self.placeholder}, {self.placeholder}) "
                "ON CONFLICT(run_id) DO NOTHING", (run_id, fingerprint, "processing", json.dumps(record)),
            )
            inserted = cursor.rowcount == 1
        existing = self.get(run_id)
        if existing and existing["fingerprint"] != fingerprint:
            raise RunConflict("run_id already belongs to a different immutable submission")
        return None if inserted else existing

    def finish(self, run_id: str, status: str, record: dict):
        with self._connection() as conn:
            conn.execute(f"UPDATE runs SET status={self.placeholder}, record={self.placeholder} "
                         f"WHERE run_id={self.placeholder}", (status, json.dumps(record), run_id))

    def update(self, run_id: str, transform) -> dict:
        """Atomically join independently arriving branches without losing either."""
        with self._connection() as conn:
            if self.is_sqlite:
                conn.execute("BEGIN IMMEDIATE")
            lock = "" if self.is_sqlite else " FOR UPDATE"
            row = conn.execute(f"SELECT record FROM runs WHERE run_id={self.placeholder}{lock}",
                               (run_id,)).fetchone()
            if row is None:
                raise KeyError(run_id)
            record = transform(json.loads(row[0]))
            status = "decided" if record.get("decision") else "pending"
            conn.execute(f"UPDATE runs SET status={self.placeholder}, record={self.placeholder} "
                         f"WHERE run_id={self.placeholder}", (status, json.dumps(record), run_id))
        return record

    def ready(self):
        with self._connection() as conn:
            conn.execute("SELECT 1").fetchone()

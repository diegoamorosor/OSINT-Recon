from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


class ReconCache:
    """SQLite-backed cache for OSINT query results."""

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            db_path = Path.home() / ".osint-recon" / "cache.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                query_type  TEXT NOT NULL,
                query_value TEXT NOT NULL,
                data        TEXT NOT NULL,
                created_at  REAL NOT NULL,
                PRIMARY KEY (query_type, query_value)
            )
            """
        )
        self._conn.commit()

    def get(self, query_type: str, query_value: str, ttl_hours: int = 24) -> dict | None:
        row = self._conn.execute(
            "SELECT data, created_at FROM cache WHERE query_type = ? AND query_value = ?",
            (query_type, query_value),
        ).fetchone()
        if row is None:
            return None
        data, created_at = row
        if (time.time() - created_at) > ttl_hours * 3600:
            self._conn.execute(
                "DELETE FROM cache WHERE query_type = ? AND query_value = ?",
                (query_type, query_value),
            )
            self._conn.commit()
            return None
        return json.loads(data)

    def set(self, query_type: str, query_value: str, data: dict) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO cache (query_type, query_value, data, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (query_type, query_value, json.dumps(data), time.time()),
        )
        self._conn.commit()

    def clear(self, older_than_hours: int | None = None) -> int:
        if older_than_hours is None:
            cursor = self._conn.execute("DELETE FROM cache")
        else:
            cutoff = time.time() - older_than_hours * 3600
            cursor = self._conn.execute("DELETE FROM cache WHERE created_at < ?", (cutoff,))
        self._conn.commit()
        return cursor.rowcount

    def close(self) -> None:
        self._conn.close()

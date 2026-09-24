"""
Named, saved requests — distinct from history_store.py's log of what
actually ran. A collection entry is a request you're keeping on purpose
(a "check auth", a "list users"), edited in place by re-saving under the
same id; history is an automatic, capped trail of everything sent.
"""
import json
import os
import sqlite3
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class CollectionStore:
    def __init__(self, db_path="webservice_collection.db"):
        self.db_path = os.path.join(SCRIPT_DIR, db_path)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS collection (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    headers TEXT,
                    body TEXT,
                    target_host TEXT,
                    target_port INTEGER,
                    config_file TEXT,
                    worker_count INTEGER,
                    with_encryption INTEGER,
                    recipient_pubkey_path TEXT,
                    with_timing_defense INTEGER
                )
                """
            )
            conn.commit()

    def add(self, entry: dict) -> int:
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO collection (
                    name, created_at, method, url, headers, body,
                    target_host, target_port, config_file, worker_count,
                    with_encryption, recipient_pubkey_path, with_timing_defense
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.get("name") or "Untitled request",
                    time.time(),
                    entry.get("method"),
                    entry.get("url"),
                    json.dumps(entry.get("headers") or {}),
                    entry.get("body"),
                    entry.get("target_host"),
                    entry.get("target_port"),
                    entry.get("config_file"),
                    entry.get("worker_count"),
                    1 if entry.get("with_encryption") else 0,
                    entry.get("recipient_pubkey_path"),
                    1 if entry.get("with_timing_defense") else 0,
                ),
            )
            conn.commit()
            return cur.lastrowid

    def list(self):
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM collection ORDER BY id DESC").fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete(self, entry_id: int):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM collection WHERE id = ?", (entry_id,))
            conn.commit()

    @staticmethod
    def _row_to_dict(row):
        d = dict(row)
        try:
            d["headers"] = json.loads(d["headers"]) if d.get("headers") else {}
        except (TypeError, json.JSONDecodeError):
            d["headers"] = {}
        d["with_encryption"] = bool(d.get("with_encryption"))
        d["with_timing_defense"] = bool(d.get("with_timing_defense"))
        return d

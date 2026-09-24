"""
Request/response history for the webservice app, in a small sqlite db next
to this file — same shape as ztrClient.py's TunnelCache, just for a
different table. Capped at MAX_ROWS so a long session of firing requests
doesn't grow this file forever.
"""
import json
import os
import sqlite3
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_ROWS = 200

# list() feeds the sidebar, which only ever reads method/url/status/timing
# for the row itself, plus request_headers/request_body for "load into
# composer" — response_headers/response_body are display-only and can be
# arbitrarily large (a real OSINT response body can run into the hundreds
# of KB), so shipping them on every list refresh made the sidebar resend
# everything that had ever come back, on every single request. get() still
# returns the full row, for the day something wants to show a past response.
LIST_COLUMNS = (
    "id, created_at, method, url, target_host, target_port, config_file, "
    "request_headers, request_body, ok, status_code, error, elapsed_ms"
)


class HistoryStore:
    def __init__(self, db_path="webservice_history.db"):
        self.db_path = os.path.join(SCRIPT_DIR, db_path)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    target_host TEXT,
                    target_port INTEGER,
                    config_file TEXT,
                    request_headers TEXT,
                    request_body TEXT,
                    ok INTEGER,
                    status_code INTEGER,
                    response_headers TEXT,
                    response_body TEXT,
                    error TEXT,
                    elapsed_ms REAL
                )
                """
            )
            conn.commit()

    def add(self, entry: dict) -> int:
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO history (
                    created_at, method, url, target_host, target_port, config_file,
                    request_headers, request_body, ok, status_code,
                    response_headers, response_body, error, elapsed_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    entry.get("method"),
                    entry.get("url"),
                    entry.get("target_host"),
                    entry.get("target_port"),
                    entry.get("config_file"),
                    json.dumps(entry.get("request_headers") or {}),
                    entry.get("request_body"),
                    1 if entry.get("ok") else 0,
                    entry.get("status_code"),
                    json.dumps(entry.get("response_headers") or {}),
                    entry.get("response_body"),
                    entry.get("error"),
                    entry.get("elapsed_ms"),
                ),
            )
            row_id = cur.lastrowid
            # Trim to MAX_ROWS oldest-first, in the same transaction.
            conn.execute(
                """
                DELETE FROM history WHERE id NOT IN (
                    SELECT id FROM history ORDER BY id DESC LIMIT ?
                )
                """,
                (MAX_ROWS,),
            )
            conn.commit()
            return row_id

    def list(self, limit: int = 50):
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"SELECT {LIST_COLUMNS} FROM history ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get(self, entry_id: int):
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM history WHERE id = ?", (entry_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def clear(self):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM history")
            conn.commit()

    def delete(self, entry_id: int):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM history WHERE id = ?", (entry_id,))
            conn.commit()

    @staticmethod
    def _row_to_dict(row):
        d = dict(row)
        for key in ("request_headers", "response_headers"):
            try:
                d[key] = json.loads(d[key]) if d.get(key) else {}
            except (TypeError, json.JSONDecodeError):
                d[key] = {}
        d["ok"] = bool(d.get("ok"))
        return d

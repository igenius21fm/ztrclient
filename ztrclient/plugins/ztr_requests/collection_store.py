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
            self._migrate(conn)
            conn.commit()

    # New columns added after the table already existed on deployed
    # instances — CREATE TABLE IF NOT EXISTS above is a no-op against an
    # existing table, so a real ALTER TABLE is the only way an already
    # -running install picks these up, hence the guarded, idempotent add.
    def _migrate(self, conn):
        existing = {row[1] for row in conn.execute("PRAGMA table_info(collection)")}
        for col, decl in (("timeout", "REAL"), ("verify", "INTEGER"), ("client_cert", "TEXT")):
            if col not in existing:
                conn.execute(f"ALTER TABLE collection ADD COLUMN {col} {decl}")

    def add(self, entry: dict) -> int:
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO collection (
                    name, created_at, method, url, headers, body,
                    target_host, target_port, config_file, worker_count,
                    with_encryption, recipient_pubkey_path, with_timing_defense,
                    timeout, verify, client_cert
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    entry.get("timeout"),
                    # verify defaults True (matches ztr_https.Session's own
                    # default), so a missing/None value has to be stored as
                    # 1, not "whatever falsy 1-if-x-else-0 would give None".
                    1 if entry.get("verify", True) else 0,
                    entry.get("client_cert"),
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
        # NULL here means "saved before this column existed", not "verify
        # was turned off" — bool(None) would silently flip every
        # pre-existing saved request to unverified the moment it's
        # reloaded, which is the opposite of what nobody asked for.
        d["verify"] = True if d.get("verify") is None else bool(d.get("verify"))
        return d

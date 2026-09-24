"""
Named environments ({{key}} -> value substitution profiles), persisted
next to this file — same sqlite-next-to-the-script shape as
history_store.py. Multiple environments (dev/staging/prod-style) rather
than one flat namespace, so switching targets means picking a different
environment instead of retyping (or overwriting) the same variable names
with different values every time.
"""
import os
import sqlite3

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ENV_NAME = "Default"


class EnvironmentStore:
    def __init__(self, db_path="webservice_env.db"):
        self.db_path = os.path.join(SCRIPT_DIR, db_path)
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _extract_legacy_vars(self, conn):
        """The pre-environments shape was a single flat env_vars(key,
        value) table. If that's what's on disk, pull its rows out and
        drop the table before the real schema goes in, so upgrading
        doesn't silently lose whatever was already saved there — it
        becomes this store's first ("Default") environment instead."""
        cols = {row[1] for row in conn.execute("PRAGMA table_info(env_vars)")}
        if not cols or "env_id" in cols:
            return []  # fresh db, or already migrated
        rows = conn.execute("SELECT key, value FROM env_vars").fetchall()
        conn.execute("DROP TABLE env_vars")
        conn.commit()
        return rows

    def _ensure_secret_column(self, conn):
        """Upgrades an env_vars table created before the secret flag
        existed — CREATE TABLE IF NOT EXISTS doesn't retroactively add a
        column to a table that's already there, so this covers that path
        explicitly. A no-op on a fresh table (already has the column) or
        a table that hasn't been created yet."""
        cols = {row[1] for row in conn.execute("PRAGMA table_info(env_vars)")}
        if cols and "secret" not in cols:
            conn.execute("ALTER TABLE env_vars ADD COLUMN secret INTEGER NOT NULL DEFAULT 0")
            conn.commit()

    def _init_db(self):
        with self._get_connection() as conn:
            legacy_vars = self._extract_legacy_vars(conn)

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS environments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    sort_order INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS env_vars (
                    env_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    secret INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (env_id, key)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS env_active (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    env_id INTEGER REFERENCES environments(id) ON DELETE SET NULL
                )
                """
            )
            conn.commit()
            self._ensure_secret_column(conn)

            if not conn.execute("SELECT 1 FROM environments LIMIT 1").fetchone():
                env_id = self._insert_environment(conn, DEFAULT_ENV_NAME)
                for key, value in legacy_vars:
                    conn.execute("INSERT INTO env_vars (env_id, key, value) VALUES (?, ?, ?)", (env_id, key, value))
                conn.execute("INSERT OR REPLACE INTO env_active (id, env_id) VALUES (1, ?)", (env_id,))
                conn.commit()

    def _insert_environment(self, conn, name: str) -> int:
        next_order = conn.execute("SELECT COALESCE(MAX(sort_order), -1) + 1 FROM environments").fetchone()[0]
        cur = conn.execute("INSERT INTO environments (name, sort_order) VALUES (?, ?)", (name, next_order))
        return cur.lastrowid

    def _active_id(self, conn):
        """The active environment id, falling back to the first one by
        sort order if none was ever set, or the one that was is since
        gone (e.g. just deleted) — mirrors how the composer always has
        *some* route selected rather than none."""
        row = conn.execute("SELECT env_id FROM env_active WHERE id = 1").fetchone()
        if row and row[0] is not None:
            if conn.execute("SELECT 1 FROM environments WHERE id = ?", (row[0],)).fetchone():
                return row[0]
        first = conn.execute("SELECT id FROM environments ORDER BY sort_order, id LIMIT 1").fetchone()
        return first[0] if first else None

    # ── environments ─────────────────────────────────────────────────
    def list_environments(self) -> list:
        with self._get_connection() as conn:
            active_id = self._active_id(conn)
            rows = conn.execute("SELECT id, name FROM environments ORDER BY sort_order, id").fetchall()
        return [{"id": row_id, "name": name, "active": row_id == active_id} for row_id, name in rows]

    def create_environment(self, name: str) -> dict:
        name = (name or "").strip()
        if not name:
            raise ValueError("environment name is required")
        with self._get_connection() as conn:
            try:
                env_id = self._insert_environment(conn, name)
            except sqlite3.IntegrityError:
                raise ValueError(f'an environment named "{name}" already exists')
            conn.commit()
        return {"id": env_id, "name": name}

    def rename_environment(self, env_id: int, name: str):
        name = (name or "").strip()
        if not name:
            raise ValueError("environment name is required")
        with self._get_connection() as conn:
            try:
                cur = conn.execute("UPDATE environments SET name = ? WHERE id = ?", (name, env_id))
            except sqlite3.IntegrityError:
                raise ValueError(f'an environment named "{name}" already exists')
            if cur.rowcount == 0:
                raise ValueError("no such environment")
            conn.commit()

    def delete_environment(self, env_id: int):
        """Refuses to delete the last remaining environment — there has
        to always be one for {{var}} substitution to resolve against."""
        with self._get_connection() as conn:
            if not conn.execute("SELECT 1 FROM environments WHERE id = ?", (env_id,)).fetchone():
                raise ValueError("no such environment")
            count = conn.execute("SELECT COUNT(*) FROM environments").fetchone()[0]
            if count <= 1:
                raise ValueError("can't delete the last remaining environment")
            was_active = self._active_id(conn) == env_id
            cur = conn.execute("DELETE FROM environments WHERE id = ?", (env_id,))
            if cur.rowcount == 0:
                raise ValueError("no such environment")
            if was_active:
                new_active = self._active_id(conn)
                conn.execute("INSERT OR REPLACE INTO env_active (id, env_id) VALUES (1, ?)", (new_active,))
            conn.commit()

    def set_active_environment(self, env_id: int):
        with self._get_connection() as conn:
            if not conn.execute("SELECT 1 FROM environments WHERE id = ?", (env_id,)).fetchone():
                raise ValueError("no such environment")
            conn.execute("INSERT OR REPLACE INTO env_active (id, env_id) VALUES (1, ?)", (env_id,))
            conn.commit()

    # ── variables (within an environment — active one if none given) ──
    def list(self, env_id: int = None) -> dict:
        """{key: value} — everything {{var}} substitution needs and
        nothing else. See list_full() for the secret flag too."""
        with self._get_connection() as conn:
            if env_id is None:
                env_id = self._active_id(conn)
            if env_id is None:
                return {}
            rows = conn.execute(
                "SELECT key, value FROM env_vars WHERE env_id = ? ORDER BY key", (env_id,)
            ).fetchall()
        return {k: v for k, v in rows}

    def list_full(self, env_id: int = None) -> list:
        """[{key, value, secret}], ordered by key — same rows as list(),
        plus the secret flag list() leaves out since substitution itself
        doesn't care whether a var is marked secret."""
        with self._get_connection() as conn:
            if env_id is None:
                env_id = self._active_id(conn)
            if env_id is None:
                return []
            rows = conn.execute(
                "SELECT key, value, secret FROM env_vars WHERE env_id = ? ORDER BY key", (env_id,)
            ).fetchall()
        return [{"key": k, "value": v, "secret": bool(s)} for k, v, s in rows]

    def set(self, key: str, value: str, env_id: int = None, secret: bool = False):
        with self._get_connection() as conn:
            if env_id is None:
                env_id = self._active_id(conn)
            if env_id is None:
                raise ValueError("no environment to save into")
            conn.execute(
                "INSERT INTO env_vars (env_id, key, value, secret) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(env_id, key) DO UPDATE SET value = excluded.value, secret = excluded.secret",
                (env_id, key, value, int(bool(secret))),
            )
            conn.commit()

    def delete(self, key: str, env_id: int = None):
        with self._get_connection() as conn:
            if env_id is None:
                env_id = self._active_id(conn)
            if env_id is None:
                return
            conn.execute("DELETE FROM env_vars WHERE env_id = ? AND key = ?", (env_id, key))
            conn.commit()

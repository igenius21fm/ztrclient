"""
Full per-line results for a $$QF$$ batch run, persisted next to this file
— same sqlite-next-to-the-script shape as history_store.py. Deliberately
separate from HistoryStore: history's own row shape only ever kept enough
to repopulate the composer (request method/url/headers/body) plus a thin
ok/status_code/error/elapsed_ms summary — never the full response
(headers, cookies, TLS info, relay path, metadata) a batch line needs, so
by the time a run finished, only the *last* line's full detail was still
visible anywhere; every earlier line's was already gone. This store keeps
everything /api/send itself returns, for every line, so any line in a run
can be re-inspected in full afterward — not just the most recent one.
"""
import json
import os
import sqlite3
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_RUNS = 20  # oldest whole runs are pruned once more than this many exist


class BatchStore:
    def __init__(self, db_path="webservice_batch.db"):
        self.db_path = os.path.join(SCRIPT_DIR, db_path)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS batch_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    line_index INTEGER NOT NULL,
                    line_value TEXT,
                    method TEXT,
                    url TEXT,
                    url_template TEXT,
                    request_headers TEXT,
                    request_body TEXT,
                    ok INTEGER,
                    status_code INTEGER,
                    response_headers TEXT,
                    response_body TEXT,
                    body_base64 TEXT,
                    content_type TEXT,
                    is_image INTEGER,
                    is_video INTEGER,
                    metadata TEXT,
                    set_cookies TEXT,
                    set_cookie_headers TEXT,
                    tls_info TEXT,
                    route_info TEXT,
                    error TEXT,
                    elapsed_ms REAL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_batch_run ON batch_requests (run_id, line_index)"
            )
            conn.commit()

    def add(self, run_id, line_index, line_value, method, url, url_template, request_headers, request_body, result):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO batch_requests (
                    run_id, line_index, line_value, method, url, url_template,
                    request_headers, request_body, ok, status_code,
                    response_headers, response_body, body_base64, content_type,
                    is_image, is_video, metadata, set_cookies, set_cookie_headers,
                    tls_info, route_info, error, elapsed_ms, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id,
                    line_index,
                    line_value,
                    method,
                    url,
                    url_template,
                    json.dumps(request_headers or {}),
                    request_body,
                    1 if result.get("ok") else 0,
                    result.get("status_code"),
                    json.dumps(result.get("headers") or {}),
                    result.get("body"),
                    result.get("body_base64"),
                    result.get("content_type"),
                    1 if result.get("is_image") else 0,
                    1 if result.get("is_video") else 0,
                    json.dumps(result.get("metadata")) if result.get("metadata") is not None else None,
                    json.dumps(result.get("set_cookies") or {}),
                    json.dumps(result.get("set_cookie_headers") or []),
                    json.dumps(result.get("tls_info")) if result.get("tls_info") is not None else None,
                    json.dumps(result.get("route_info")) if result.get("route_info") is not None else None,
                    result.get("error"),
                    result.get("elapsed_ms"),
                    time.time(),
                ),
            )
            conn.commit()
            self._prune(conn)

    def _prune(self, conn):
        rows = conn.execute(
            "SELECT run_id, MIN(created_at) AS started FROM batch_requests GROUP BY run_id ORDER BY started DESC"
        ).fetchall()
        if len(rows) > MAX_RUNS:
            stale_run_ids = [r[0] for r in rows[MAX_RUNS:]]
            conn.executemany(
                "DELETE FROM batch_requests WHERE run_id = ?", [(rid,) for rid in stale_run_ids]
            )
            conn.commit()

    def list_runs(self, limit=20):
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT
                    run_id,
                    MIN(created_at) AS started_at,
                    COUNT(*) AS total,
                    SUM(CASE WHEN ok THEN 1 ELSE 0 END) AS ok_count,
                    (SELECT method FROM batch_requests b2 WHERE b2.run_id = b1.run_id ORDER BY line_index LIMIT 1) AS method,
                    (SELECT url_template FROM batch_requests b2 WHERE b2.run_id = b1.run_id ORDER BY line_index LIMIT 1) AS url_template
                FROM batch_requests b1
                GROUP BY run_id
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def list_requests(self, run_id):
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT line_index, line_value, method, url, ok, status_code, error, elapsed_ms
                FROM batch_requests WHERE run_id = ? ORDER BY line_index
                """,
                (run_id,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["ok"] = bool(d.get("ok"))
            out.append(d)
        return out

    def get_request(self, run_id, line_index):
        """The full row, shaped the same way /api/send's own result dict
        is — so the exact same renderResponse() the live response panel
        already uses can render a past batch line too, unmodified."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM batch_requests WHERE run_id = ? AND line_index = ?",
                (run_id, line_index),
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["ok"] = bool(d.get("ok"))
        d["is_image"] = bool(d.get("is_image"))
        d["is_video"] = bool(d.get("is_video"))
        for key in ("request_headers", "response_headers", "set_cookies"):
            try:
                d[key] = json.loads(d[key]) if d.get(key) else {}
            except (TypeError, json.JSONDecodeError):
                d[key] = {}
        try:
            d["set_cookie_headers"] = json.loads(d["set_cookie_headers"]) if d.get("set_cookie_headers") else []
        except (TypeError, json.JSONDecodeError):
            d["set_cookie_headers"] = []
        for key in ("metadata", "tls_info", "route_info"):
            try:
                d[key] = json.loads(d[key]) if d.get(key) else None
            except (TypeError, json.JSONDecodeError):
                d[key] = None
        # Rename to exactly match /api/send's own result shape.
        d["headers"] = d.pop("response_headers")
        d["body"] = d.pop("response_body")
        return d

    def delete_run(self, run_id):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM batch_requests WHERE run_id = ?", (run_id,))
            conn.commit()

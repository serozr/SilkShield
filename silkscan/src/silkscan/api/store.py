"""Verdict persistence. Raw features and file bytes never enter this store."""
from __future__ import annotations

import json
import fcntl
import os
import sqlite3
import threading
from pathlib import Path
from typing import Protocol


class VerdictStore(Protocol):
    def put(self, record: dict, event: dict) -> dict: ...
    def get_by_sha(self, sha256: str, namespace: str, cache_key: str | None = None) -> dict | None: ...
    def get_job(self, job_id: str) -> dict | None: ...
    def list_events_since(self, event_id: int, limit: int = 10000) -> list[dict]: ...
    def create_job(self, job_id: str): ...
    def update_job(self, job_id: str, status: str, error: str | None = None): ...
    def latest_events(self, limit: int) -> list[dict]: ...
    def close(self): ...


class SQLiteVerdictStore:
    def __init__(self, url: str):
        path = url.removeprefix("sqlite:///")
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.owner_lock = None
        if path != ":memory:":
            self.owner_lock = os.open(path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(self.owner_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(self.owner_lock)
                self.owner_lock = None
                raise RuntimeError("This SQLite store already has a coordinator; run one ASGI process") from None
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY, status TEXT NOT NULL, verdict TEXT, error TEXT);
            CREATE TABLE IF NOT EXISTS verdicts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL,
                namespace TEXT NOT NULL, cache_key TEXT NOT NULL, record TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS verdict_lookup ON verdicts(namespace, sha256, seq DESC);
            CREATE INDEX IF NOT EXISTS cache_lookup ON verdicts(namespace, cache_key, seq DESC);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
        """)
        # Bytes are intentionally not durable. Interrupted jobs cannot be resumed safely.
        with self.db:
            self.db.execute("UPDATE jobs SET status='failed', error='Service restarted before completion' "
                            "WHERE status IN ('queued', 'running')")

    def create_job(self, job_id):
        with self.lock, self.db:
            self.db.execute("INSERT INTO jobs(job_id,status) VALUES (?, 'queued')", (job_id,))

    def update_job(self, job_id, status, error=None):
        with self.lock, self.db:
            self.db.execute("UPDATE jobs SET status=?, error=? WHERE job_id=?", (status, error, job_id))

    def put(self, record, event):
        with self.lock, self.db:
            self.db.execute("INSERT INTO verdicts(sha256,namespace,cache_key,record) VALUES (?,?,?,?)",
                            (record["sha256"], record["namespace"], record["cache_key"], json.dumps(record)))
            self.db.execute("UPDATE jobs SET status='done', verdict=?, error=NULL WHERE job_id=?",
                            (json.dumps(record["verdict"]), record["job_id"]))
            cur = self.db.execute("INSERT INTO events(payload) VALUES (?)", (json.dumps(event),))
            return {"event_id": cur.lastrowid, "data": event}

    def get_by_sha(self, sha256, namespace, cache_key=None):
        with self.lock:
            if cache_key is None:
                row = self.db.execute("SELECT record FROM verdicts WHERE namespace=? AND sha256=? "
                                      "ORDER BY seq DESC LIMIT 1", (namespace, sha256)).fetchone()
            else:
                row = self.db.execute("SELECT record FROM verdicts WHERE namespace=? AND sha256=? AND cache_key=? "
                                      "ORDER BY seq DESC LIMIT 1", (namespace, sha256, cache_key)).fetchone()
            return json.loads(row[0]) if row else None

    def get_job(self, job_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None:
                return None
            result = {"job_id": row["job_id"], "status": row["status"]}
            if row["verdict"]:
                result["verdict"] = json.loads(row["verdict"])
            if row["error"]:
                result["error"] = row["error"]
            return result

    def list_events_since(self, event_id, limit=10000):
        with self.lock:
            rows = self.db.execute("SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?", (event_id, limit))
            return [{"event_id": r["id"], "data": json.loads(r["payload"])} for r in rows]

    def latest_events(self, limit):
        with self.lock:
            rows = list(self.db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)))
            return [{"event_id": r["id"], "data": json.loads(r["payload"])} for r in reversed(rows)]

    def close(self):
        with self.lock:
            self.db.close()
            if self.owner_lock is not None:
                os.close(self.owner_lock)
                self.owner_lock = None

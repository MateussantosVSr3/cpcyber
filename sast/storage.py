"""Small DB-API repository. SQLite for local demo, PostgreSQL in Compose."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

@contextmanager
def connection():
    url = os.getenv("DATABASE_URL", "sqlite:///sast.db")
    if url.startswith("sqlite:///"):
        conn = sqlite3.connect(url.removeprefix("sqlite:///"), timeout=20)
    else:
        import psycopg
        conn = psycopg.connect(url)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def run(conn, sql, args=()):
    if not isinstance(conn, sqlite3.Connection):
        sql = sql.replace("?", "%s")
    return conn.execute(sql, args)


def init():
    with connection() as conn:
        run(conn, "CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, project TEXT NOT NULL, created TEXT NOT NULL, status TEXT NOT NULL, files TEXT NOT NULL, result TEXT NOT NULL)")


def create(project, files):
    scan_id = str(uuid4())
    created = datetime.now(timezone.utc).isoformat()
    with connection() as conn:
        run(conn, "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)", (scan_id, project, created, "QUEUED", json.dumps(files), "{}"))
    return scan_id


def get(scan_id, include_source=False):
    with connection() as conn:
        row = run(conn, "SELECT id, project, created, status, files, result FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    result = dict(zip(["id", "project", "created", "status", "files", "result"], row))
    result["result"] = json.loads(result["result"])
    if include_source:
        result["files"] = json.loads(result["files"])
    else:
        result.pop("files")
    return result


def recent():
    with connection() as conn:
        rows = run(conn, "SELECT id, project, created, status, result FROM scans ORDER BY created DESC LIMIT 100").fetchall()
    return [dict(id=r[0], project=r[1], created=r[2], status=r[3], result=json.loads(r[4])) for r in rows]


def status(scan_id, value):
    with connection() as conn:
        run(conn, "UPDATE scans SET status = ? WHERE id = ?", (value, scan_id))


def finish(scan_id, result, state="COMPLETED"):
    with connection() as conn:
        run(conn, "UPDATE scans SET status = ?, result = ?, files = ? WHERE id = ?", (state, json.dumps(result), "{}", scan_id))


def save_result(scan_id, result):
    with connection() as conn:
        run(conn, "UPDATE scans SET result = ? WHERE id = ?", (json.dumps(result), scan_id))

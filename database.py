# database.py - all SQLite work lives here
import sqlite3
import time

DB_NAME = "smartgrid.db"


def get_conn():
    """Open a connection to the SQLite file; rows behave like dictionaries."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables and insert 4 sample meters (only the first time)."""
    conn = get_conn()
    conn.executescript("""
        -- Pre-registered meters with their pre-shared secret keys
        CREATE TABLE IF NOT EXISTS meters (
            meter_id   TEXT PRIMARY KEY,
            location   TEXT,
            secret_key TEXT NOT NULL
        );
        -- Server nonces (challenges). 'used' stops a nonce being reused (replay)
        CREATE TABLE IF NOT EXISTS nonces (
            nonce    TEXT PRIMARY KEY,
            meter_id TEXT,
            created  REAL,
            used     INTEGER DEFAULT 0
        );
        -- One-time passwords. Valid 60 s and only once
        CREATE TABLE IF NOT EXISTS otps (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id TEXT,
            otp      TEXT,
            created  REAL,
            used     INTEGER DEFAULT 0
        );
        -- Accepted meter readings
        CREATE TABLE IF NOT EXISTS readings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id    TEXT,
            kwh         REAL,
            voltage     REAL,
            received_at TEXT
        );
        -- Authentication log: success / failed / replay / tampered
        CREATE TABLE IF NOT EXISTS auth_log (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id TEXT,
            log_time TEXT,
            status   TEXT,
            detail   TEXT
        );
    """)
    # Seed sample meters only if the table is empty
    if conn.execute("SELECT COUNT(*) FROM meters").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO meters (meter_id, location, secret_key) VALUES (?, ?, ?)",
            [
                ("SM001", "Anna Nagar", "k3y-SM001-9f2a7c"),
                ("SM002", "T Nagar", "k3y-SM002-b81d44"),
                ("SM003", "Adyar", "k3y-SM003-5e0c93"),
                ("SM004", "Velachery", "k3y-SM004-27aa18"),
            ],
        )
    conn.commit()
    conn.close()


def log_event(meter_id, status, detail=""):
    """Write one row to the authentication log."""
    conn = get_conn()
    conn.execute(
        "INSERT INTO auth_log (meter_id, log_time, status, detail) VALUES (?, ?, ?, ?)",
        (meter_id, time.strftime("%Y-%m-%d %H:%M:%S"), status, detail),
    )
    conn.commit()
    conn.close()
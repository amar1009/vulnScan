"""
SQLite-backed scan store.

Strategy:
- Active scans live in memory (scan_store dict) for fast polling.
- Every state change is persisted to SQLite via save_scan().
- On startup, load_all_from_db() rehydrates the in-memory dict from SQLite
  so history survives server restarts.
- delete_scan() removes from both memory and SQLite.
"""

import sqlite3
import os
from typing import Dict

from models import ScanStatus

DB_PATH = os.getenv("DB_PATH", "vulnscan.db")

scan_store: Dict[str, ScanStatus] = {}


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                data    TEXT NOT NULL
            )
        """)
        conn.commit()


def save_scan(scan: ScanStatus) -> None:
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (scan_id, data) VALUES (?, ?) "
            "ON CONFLICT(scan_id) DO UPDATE SET data = excluded.data",
            (scan.scan_id, scan.model_dump_json()),
        )
        conn.commit()


def delete_scan_from_db(scan_id: str) -> None:
    with _get_conn() as conn:
        conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()


def load_all_from_db() -> None:
    with _get_conn() as conn:
        rows = conn.execute("SELECT data FROM scans").fetchall()
    for row in rows:
        try:
            scan = ScanStatus.model_validate_json(row["data"])
            scan_store[scan.scan_id] = scan
        except Exception as e:
            print(f"[store] Skipping corrupted row: {e}")

"""
Simple in-memory store for active and completed scans.
Replace with a database (e.g. SQLite/PostgreSQL) for production use.
"""

from typing import Dict
from models import ScanStatus

scan_store: Dict[str, ScanStatus] = {}

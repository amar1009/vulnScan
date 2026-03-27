"""
Data models for scan results and status tracking.
"""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

class PortInfo(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    cve_hints: List[str] = []


class NmapResult(BaseModel):
    host: str
    hostname: str = ""
    state: str
    os_guess: str = ""
    ports: List[PortInfo] = []
    scan_duration: float = 0.0


class VTResult(BaseModel):
    target: str
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    community_score: int = 0
    categories: List[str] = []
    last_analysis_date: Optional[str] = None
    permalink: str = ""


class RiskScore(BaseModel):
    score: float
    severity: str
    cvss_estimate: float
    open_ports_count: int
    dangerous_ports: List[int] = []
    threat_flags: List[str] = []
    summary: str


class ScanStatus(BaseModel):
    scan_id: str
    target: str
    status: str
    current_step: Optional[str] = None
    created_at: str = datetime.utcnow().isoformat()
    completed_at: Optional[str] = None
    nmap_results: Optional[NmapResult] = None
    vt_results: Optional[VTResult] = None
    risk: Optional[RiskScore] = None
    error: Optional[str] = None
    alert_sent_to: Optional[str] = None    # populated if auto-alert was sent
    alert_error: Optional[str] = None      # populated if auto-alert failed


class ScanResult(BaseModel):
    scan_id: str
    status: str

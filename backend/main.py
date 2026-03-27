"""
Vulnerability Assessment Platform - FastAPI Backend
Integrates Nmap for port/service scanning and VirusTotal for threat intelligence.
Automatically sends email alerts when HIGH or CRITICAL risk is detected.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import asyncio
import uuid
import os

from scanner import run_nmap_scan
from virustotal import check_virustotal
from risk import compute_risk_score
from models import ScanResult, ScanStatus
from store import scan_store
from emailer import send_alert_email
from dotenv import load_dotenv
load_dotenv()
app = FastAPI(title="Vulnerability Assessment Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "basic"
    alert_email: Optional[str] = None   # if set, send alert email when HIGH/CRITICAL


class AlertEmailRequest(BaseModel):
    scan_id: str
    recipient: str


@app.post("/api/scan", response_model=dict)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """Initiate a new vulnerability scan. Returns a scan_id to poll for results."""
    scan_id = str(uuid.uuid4())
    scan_store[scan_id] = ScanStatus(scan_id=scan_id, status="queued", target=req.target)
    background_tasks.add_task(run_full_scan, scan_id, req.target, req.scan_type, req.alert_email)
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Poll the status and results of a running or completed scan."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_store[scan_id].dict()


@app.get("/api/scans")
async def list_scans():
    """Return all scans (history)."""
    return [s.dict() for s in scan_store.values()]


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Remove a scan record."""
    if scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    del scan_store[scan_id]
    return {"deleted": scan_id}


@app.post("/api/alert/send")
async def send_manual_alert(req: AlertEmailRequest):
    """Manually trigger an alert email for a completed scan."""
    if req.scan_id not in scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scan_store[req.scan_id]
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan is not completed yet")
    try:
        send_alert_email(scan, req.recipient)
        return {"sent": True, "recipient": req.recipient}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/config/sender")
async def get_sender_email():
    """Return the configured sender email (from .env) so the frontend can display it."""
    email = os.getenv("ALERT_EMAIL", "")
    return {"configured": bool(email), "email": email}


async def run_full_scan(scan_id: str, target: str, scan_type: str, alert_email: Optional[str]):
    """
    Orchestrates the full scan pipeline:
    1. Nmap port/service scan
    2. VirusTotal reputation check
    3. Risk scoring
    4. Auto-send alert email if risk is HIGH or CRITICAL and alert_email is provided
    """
    try:
        scan_store[scan_id].status = "scanning"

        # Step 1: Nmap scan
        scan_store[scan_id].current_step = "nmap"
        nmap_results = await asyncio.to_thread(run_nmap_scan, target, scan_type)
        scan_store[scan_id].nmap_results = nmap_results

        # Step 2: VirusTotal threat check
        scan_store[scan_id].current_step = "virustotal"
        vt_results = await check_virustotal(target)
        scan_store[scan_id].vt_results = vt_results

        # Step 3: Risk scoring
        scan_store[scan_id].current_step = "scoring"
        risk = compute_risk_score(nmap_results, vt_results)
        scan_store[scan_id].risk = risk

        scan_store[scan_id].status = "completed"
        scan_store[scan_id].current_step = None

        # Step 4: Auto-alert if recipient configured and risk is HIGH or CRITICAL
        if alert_email and risk.severity in ("HIGH", "CRITICAL"):
            try:
                send_alert_email(scan_store[scan_id], alert_email)
                scan_store[scan_id].alert_sent_to = alert_email
            except Exception as mail_err:
                # Don't fail the scan if email errors; just log it
                scan_store[scan_id].alert_error = str(mail_err)

    except Exception as e:
        scan_store[scan_id].status = "error"
        scan_store[scan_id].error = str(e)

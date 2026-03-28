# VulnScan — Vulnerability Assessment Platform

A full-stack cybersecurity tool built as a virtual internship project. Combines **Nmap** port scanning with **VirusTotal** threat intelligence to produce CVSS-inspired risk scores, persist scan history in SQLite, and automatically send email alerts with PDF reports when high-risk targets are detected.

**Tech Stack:** React (Frontend) · FastAPI/Python (Backend) · SQLite (Database) · Nmap · VirusTotal v3 API

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Folder Structure](#folder-structure)
4. [Modules](#modules)
5. [Backend File Explanations](#backend-file-explanations)
6. [Frontend File Explanations](#frontend-file-explanations)
7. [Data Flow](#data-flow)
8. [Database Design](#database-design)
9. [Risk Scoring System](#risk-scoring-system)
10. [Email Alerting](#email-alerting)
11. [API Reference](#api-reference)
12. [Scan Profiles](#scan-profiles)
13. [Prerequisites](#prerequisites)
14. [Setup & Running](#setup--running)
15. [Environment Variables](#environment-variables)
16. [Legal Notice](#legal-notice)

---

## Project Overview

VulnScan automates the process of assessing the security posture of an IP address or domain. A single scan does the following:

1. Runs an **Nmap** scan to discover open ports, running services, version info, and OS
2. Queries **VirusTotal** to check how many threat intelligence engines have flagged the target as malicious
3. Combines both results in a **risk scoring engine** to produce a 0–100 score with a severity label (LOW / MEDIUM / HIGH / CRITICAL)
4. Persists the result in **SQLite** so history survives server restarts
5. Automatically sends a **styled HTML email with a PDF report** attached if the risk level is HIGH or CRITICAL

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        React Frontend                           │
│                                                                 │
│   Sidebar          Dashboard       Analytics      History       │
│  (nav + alerts)   (stats/charts)  (7 charts)    (all scans)    │
│                                                                 │
│              ScanPage (form → progress → results)               │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP (axios, proxied)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      FastAPI Backend                            │
│                                                                 │
│   POST /api/scan ──► BackgroundTask ──► run_full_scan()         │
│   GET  /api/scan/{id}   (polling)            │                  │
│   GET  /api/scans                            ▼                  │
│   DELETE /api/scan/{id}              ┌───────────────┐          │
│   POST /api/alert/send               │  scanner.py   │ Nmap     │
│   GET  /api/config/sender            │  virustotal.py│ VT API   │
│                                      │  risk.py      │ Scoring  │
│                                      │  emailer.py   │ SMTP     │
│                                      └───────┬───────┘          │
│                                              │                  │
│                                      ┌───────▼───────┐          │
│                                      │   store.py    │          │
│                                      │  (SQLite DB)  │          │
│                                      └───────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
                     vulnscan.db (SQLite file)
```

---

## Folder Structure

```
vuln-scanner/
│
├── backend/
│   ├── main.py            # FastAPI app, all API routes, scan pipeline orchestration
│   ├── scanner.py         # Nmap wrapper — port/service/OS scanning
│   ├── virustotal.py      # VirusTotal v3 API client — IP/domain reputation
│   ├── risk.py            # Risk scoring engine — CVSS-inspired 0-100 formula
│   ├── models.py          # Pydantic data models for all scan data
│   ├── store.py           # SQLite persistence layer + in-memory scan dict
│   ├── emailer.py         # PDF report generation + HTML email sending
│   ├── requirements.txt   # Python dependencies
│   ├── .env.example       # Template for environment variables
│   └── vulnscan.db        # SQLite database (auto-created on first run)
│
├── frontend/
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── App.jsx        # Root layout — sidebar + page routing
│   │   ├── App.css        # Global styles — dark industrial theme
│   │   ├── index.js       # React entry point
│   │   │
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx      # Summary stats + risk score bar chart
│   │   │   ├── ScanPage.jsx       # New scan form, live progress, results
│   │   │   ├── AnalyticsPage.jsx  # 7 Recharts visualizations
│   │   │   └── HistoryPage.jsx    # All scans, expandable rows, delete
│   │   │
│   │   ├── components/
│   │   │   ├── RiskGauge.jsx      # SVG arc gauge showing 0-100 score
│   │   │   ├── PortTable.jsx      # Nmap port inventory table
│   │   │   ├── VTPanel.jsx        # VirusTotal radar chart + engine bars
│   │   │   └── ScanProgress.jsx   # 3-step animated pipeline indicator
│   │   │
│   │   ├── hooks/
│   │   │   └── useScan.js         # Polls GET /api/scan/{id} every 2 seconds
│   │   │
│   │   └── utils/
│   │       └── api.js             # All axios API call functions
│   │
│   └── package.json
│
├── .gitignore
└── README.md
```

---

## Modules

These are the four modules specified in the project requirements and how each is implemented:

| Module | File | What It Does |
|--------|------|--------------|
| Vulnerability Scanning Engine | `scanner.py` | Wraps python-nmap to automate port, service, version, and OS detection with 3 configurable scan profiles |
| Threat Intelligence Integration Layer | `virustotal.py` | Queries VirusTotal v3 API for IP/domain reputation — aggregates malicious, suspicious, harmless engine counts and community score |
| Risk Scoring & Analytics Core | `risk.py` | Combines Nmap and VT data into a 0–100 CVSS-inspired score, assigns severity tier, generates heatmap-ready data for the analytics charts |
| Dashboard & Reporting Hub | `Dashboard.jsx`, `AnalyticsPage.jsx`, `emailer.py` | React dashboards with Recharts visualizations + PDF export via fpdf2 + email delivery |

---

## Backend File Explanations

### `main.py` — API Routes & Scan Orchestration

The entry point for the backend. Responsibilities:
- Defines all HTTP endpoints using FastAPI route decorators
- Uses `lifespan` context manager to initialize SQLite and load saved scans before the server accepts any requests
- Accepts scan requests and hands them to `BackgroundTasks` so the HTTP response returns instantly without waiting for the scan to complete
- Calls `save_scan()` after every pipeline step so progress is durable

Key design decision — why `BackgroundTasks` and not blocking:
```
Client sends POST /api/scan
        │
        ▼
FastAPI returns {"scan_id": "...", "status": "queued"} immediately
        │
        ▼ (in background thread)
run_full_scan() runs for 30-60 seconds
        │
        ▼
Client polls GET /api/scan/{id} every 2 seconds until status = "completed"
```

### `scanner.py` — Nmap Integration

Wraps the `python-nmap` library to run Nmap as a subprocess and parse its results into structured Pydantic models.

Three scan profiles:

| Profile | Nmap Arguments | Use Case |
|---------|---------------|----------|
| basic | `-sV --open -T4` | Fast scan, version detection, common ports only |
| full | `-sV -O --open -T4 -p-` | All 65535 ports + OS fingerprinting, slow |
| stealth | `-sS -sV --open -T2` | SYN half-open scan, quieter, requires root |

After scanning, each open port is checked against two sets of known-dangerous port numbers. Matching ports get a `cve_hints` label explaining why they are risky (e.g. port 445 → "SMB - EternalBlue target").

Why `asyncio.to_thread()` is used:
Nmap is a blocking subprocess call — it freezes the thread until the scan finishes. Calling it directly inside an async function would block FastAPI's event loop and freeze the entire server. `asyncio.to_thread()` runs it in a separate thread from the thread pool so the event loop stays free.

### `virustotal.py` — Threat Intelligence

Async HTTP client using `httpx` that queries the VirusTotal v3 API.

IP vs Domain detection:
```python
def _is_ip(target: str) -> bool:
    parts = target.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
```
Splits by `.` and checks if all 4 parts are digits. If true → hits `/ip_addresses/` endpoint. If false → hits `/domains/` endpoint. VirusTotal has separate endpoints for each that return different data structures.

### `risk.py` — Scoring Engine

Produces a composite 0–100 risk score from four weighted layers:

```
Score = Layer1 + Layer2 + Layer3 + Layer4  (max 100)

Layer 1 — Open port count         → up to 20 pts  (each port × 2, capped)
Layer 2 — Dangerous port types    → up to 25 pts  (high-risk × 5, medium × 2)
Layer 3 — VT malicious engines    → up to 35 pts  (each engine × 5, capped)
Layer 4 — VT suspicious + community → up to 20 pts
```

Severity mapping:

| Score | Severity |
|-------|----------|
| 75–100 | CRITICAL |
| 50–74 | HIGH |
| 25–49 | MEDIUM |
| 0–24 | LOW |

CVSS estimate = score ÷ 10 (produces a familiar 0–10 number).

### `store.py` — SQLite Persistence

Two-layer storage strategy:
- **In-memory dict** (`scan_store`) — fast lookup during active scans and for API responses
- **SQLite file** (`vulnscan.db`) — durable storage that survives restarts

Four functions:

| Function | When Called | What It Does |
|----------|------------|--------------|
| `init_db()` | Server startup | Creates `scans` table if not exists |
| `save_scan(scan)` | After every state change | Upserts full scan JSON to SQLite |
| `delete_scan_from_db(id)` | DELETE endpoint | Hard deletes row from SQLite |
| `load_all_from_db()` | Server startup | Reads all rows back into memory |

Schema — intentionally simple:
```sql
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    data    TEXT NOT NULL      -- full ScanStatus object as JSON string
)
```
Storing as JSON means no schema migrations are ever needed when the data model changes.

### `emailer.py` — Alert Email + PDF

Two responsibilities:

**PDF generation** using `fpdf2`:
- Multi-page PDF with dark header, KPI summary table, open port inventory, threat flags, and footer
- Saved to `backend/reports/` folder
- Filename includes target IP and timestamp

**Email sending** via Gmail SMTP SSL (port 465):
- Styled HTML email with inline CSS (required because Gmail strips external CSS)
- PDF attached as MIME application/pdf
- Sender credentials read exclusively from `.env` — never hardcoded
- Uses Gmail App Password, not account password

### `models.py` — Data Models

All Pydantic v2 schemas. `ScanStatus` is the central model that flows through the entire pipeline:

```
ScanStatus
  ├── scan_id, target, status, created_at
  ├── nmap_results: NmapResult
  │     └── ports: List[PortInfo]
  ├── vt_results: VTResult
  ├── risk: RiskScore
  ├── alert_sent_to (populated if auto-alert fired)
  └── alert_error (populated if auto-alert failed)
```

---

## Frontend File Explanations

### `App.jsx` — Root Layout

Contains the sidebar and page routing. The sidebar is here (not a separate component) because it owns shared state that all pages need — `alertRecipient` (passed as prop to every page) and `senderEmail` (fetched from backend on load).

### `pages/Dashboard.jsx`

Shows aggregate statistics across all completed scans: total scans, CRITICAL/HIGH/MEDIUM/LOW counts, and a bar chart of risk scores per host with color-coded bars.

### `pages/ScanPage.jsx`

The main workflow page:
1. Form to enter target IP/domain and choose scan profile
2. Live step-by-step progress indicator while scan runs
3. Full results view — risk gauge, threat flags, port table, VT panel
4. Auto-alert status banner (green if sent, red if failed)
5. Manual alert send button with recipient override

### `pages/AnalyticsPage.jsx`

Seven Recharts visualizations built from completed scan history:

| Chart | Type | What It Shows |
|-------|------|---------------|
| Risk score per host | Bar | Which host is most dangerous |
| Severity distribution | Pie | Overall security posture |
| Open vs dangerous ports | Grouped bar | Quality of exposure, not just quantity |
| VirusTotal engine hits | Grouped bar | Confirmed vs uncertain threats |
| Risk score trend | Line | Is environment improving over time |
| Average threat profile | Radar | What type of risk dominates |
| Most frequent open ports | Horizontal bar | Systemic network-wide patterns |

### `pages/HistoryPage.jsx`

Table of all scans (newest first) with expandable rows. Clicking a row reveals the full risk gauge, threat flags, port table, and VirusTotal panel inline. Each row has a Delete button that calls `DELETE /api/scan/{id}` which removes from both memory and SQLite.

### `components/RiskGauge.jsx`

Custom SVG arc gauge. Draws two concentric arcs — a grey background arc and a colored filled arc proportional to the score. Color changes based on severity. Uses a `drop-shadow` SVG filter to add a glow effect matching the severity color.

### `hooks/useScan.js`

Polling hook that calls `GET /api/scan/{id}` every 2 seconds using `setInterval`. Clears the interval automatically when status reaches `completed` or `error`. Also cleans up on component unmount via the `useEffect` return function to prevent memory leaks.

---

## Data Flow

Complete flow from button click to completed scan:

```
1. User types "192.168.1.1" and clicks Launch Scan
        │
2. ScanPage calls startScan() in api.js
        │
3. POST /api/scan → { target, scan_type, alert_email }
        │
4. main.py creates ScanStatus, saves to SQLite, queues BackgroundTask
        │
5. Returns { scan_id: "abc-123", status: "queued" } immediately
        │
6. useScan hook starts polling GET /api/scan/abc-123 every 2s
        │
7. BackgroundTask runs run_full_scan():
        │
        ├── status = "scanning"        → save_scan() → SQLite
        ├── current_step = "nmap"      → save_scan() → SQLite
        ├── asyncio.to_thread(run_nmap_scan) → Nmap subprocess runs
        ├── nmap_results saved         → save_scan() → SQLite
        ├── current_step = "virustotal"→ save_scan() → SQLite
        ├── await check_virustotal()   → VirusTotal API HTTP call
        ├── vt_results saved           → save_scan() → SQLite
        ├── current_step = "scoring"   → save_scan() → SQLite
        ├── compute_risk_score()       → pure calculation
        ├── status = "completed"       → save_scan() → SQLite
        └── if HIGH/CRITICAL + email:
              send_alert_email()       → Gmail SMTP + PDF
              save_scan()              → SQLite
        │
8. Polling detects status = "completed", stops interval
        │
9. ScanPage renders full results — gauge, ports, VT panel
```

---

## Database Design

SQLite database file: `backend/vulnscan.db` (auto-created on first run)

```sql
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    data    TEXT NOT NULL
);
```

Each row stores the complete `ScanStatus` Pydantic object serialized as a JSON string. Example of what `data` looks like:

```json
{
  "scan_id": "a1b2c3d4-...",
  "target": "192.168.1.1",
  "status": "completed",
  "created_at": "2024-01-15T10:30:00",
  "nmap_results": {
    "host": "192.168.1.1",
    "ports": [
      { "port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9" },
      { "port": 3389, "protocol": "tcp", "state": "open", "service": "ms-wbt-server", "cve_hints": ["RDP - brute-force / BlueKeep target"] }
    ]
  },
  "vt_results": {
    "malicious_count": 3,
    "suspicious_count": 1,
    "community_score": -8
  },
  "risk": {
    "score": 72.5,
    "severity": "HIGH",
    "cvss_estimate": 7.3,
    "threat_flags": ["High-risk port open: 3389/ms-wbt-server", "Flagged malicious by 3 VirusTotal engines"]
  }
}
```

To inspect the database directly:
```bash
sqlite3 backend/vulnscan.db
SELECT scan_id, json_extract(data, '$.target'), json_extract(data, '$.status') FROM scans;
.quit
```

---

## Risk Scoring System

### Scoring Formula

```
Total Score (0–100) = Layer1 + Layer2 + Layer3 + Layer4

Layer 1: min(open_port_count × 2, 20)
Layer 2: sum of port risk weights, combined cap of 45 with Layer 1
         High-risk port (23,135,139,445,3389,4444,5900,6379,27017) → +5 each
         Medium-risk port (21,22,25,110,143,1433,1521,3306,5432,8080) → +2 each
Layer 3: min(malicious_count × 5, 35)
Layer 4: min(suspicious_count × 2, 10) + min(max(-community_score, 0), 10)
```

### Severity Tiers

```
0 ─────────────── 25 ─────────────── 50 ─────────────── 75 ──────── 100
│       LOW        │     MEDIUM       │      HIGH        │  CRITICAL  │
│   Green (#00e676)│  Yellow(#ffd600) │  Orange(#ff8c00) │ Red(#ff3b5c│
```

### High-Risk Ports and Why

| Port | Service | Risk Reason |
|------|---------|-------------|
| 23 | Telnet | Transmits credentials in plain text |
| 135 | MS-RPC | Lateral movement vector in Windows networks |
| 139 | NetBIOS | SMB vulnerability surface |
| 445 | SMB | EternalBlue exploit, primary ransomware vector |
| 3389 | RDP | BlueKeep CVE, brute force target |
| 4444 | Metasploit | Default reverse shell listener port |
| 5900 | VNC | Remote access, often no authentication |
| 6379 | Redis | Commonly deployed with no authentication |
| 27017 | MongoDB | Commonly deployed with no authentication |

---

## Email Alerting

### How It Works

```
Scan completes with HIGH or CRITICAL severity
        │
        ▼
send_alert_email(scan, recipient)
        │
        ├── generate_pdf_report() → fpdf2 builds PDF → saved to reports/
        │
        ├── _build_html_body() → styled inline-CSS HTML email
        │
        └── smtplib.SMTP_SSL("smtp.gmail.com", 465)
              server.login(ALERT_EMAIL, ALERT_PASSWORD)
              server.sendmail(sender, recipient, message)
```

### Gmail App Password Setup

1. Go to `myaccount.google.com`
2. Security → 2-Step Verification → App passwords
3. Generate a password for "Mail"
4. Copy the 16-character password (no spaces) into `.env`

An App Password is safer than your account password because it can be revoked independently and only grants access to sending email, not the full Google account.

### Trigger Conditions

| Trigger | When |
|---------|------|
| Auto-alert | Scan completes + severity is HIGH or CRITICAL + alert recipient set in sidebar |
| Manual send | Click "Send Alert + PDF" button on any completed scan results page |

---

## API Reference

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/scan` | `{target, scan_type, alert_email?}` | Start a new scan |
| GET | `/api/scan/{id}` | — | Poll scan status and results |
| GET | `/api/scans` | — | List all scans, newest first |
| DELETE | `/api/scan/{id}` | — | Delete from memory and SQLite |
| POST | `/api/alert/send` | `{scan_id, recipient}` | Manually send alert email |
| GET | `/api/config/sender` | — | Get configured sender email |

### POST /api/scan — Request Body

```json
{
  "target": "192.168.1.1",
  "scan_type": "basic",
  "alert_email": "recipient@example.com"
}
```

### GET /api/scan/{id} — Response

```json
{
  "scan_id": "uuid",
  "target": "192.168.1.1",
  "status": "completed",
  "current_step": null,
  "nmap_results": { ... },
  "vt_results": { ... },
  "risk": {
    "score": 67.5,
    "severity": "HIGH",
    "cvss_estimate": 6.8,
    "open_ports_count": 4,
    "dangerous_ports": [3389, 445],
    "threat_flags": ["High-risk port open: 3389/ms-wbt-server"],
    "summary": "Risk level is HIGH. 4 open port(s) detected..."
  },
  "alert_sent_to": "recipient@example.com",
  "alert_error": null
}
```

---

## Scan Profiles

| Profile | Nmap Args | Speed | Root Required | Best For |
|---------|-----------|-------|---------------|----------|
| basic | `-sV --open -T4` | Fast (~10s) | No | Quick assessment of common ports |
| full | `-sV -O --open -T4 -p-` | Slow (~5min) | Yes (OS detection) | Thorough audit of all 65535 ports |
| stealth | `-sS -sV --open -T2` | Medium | Yes | Low-noise scan, less likely to trigger IDS |

---

## Prerequisites

- **Python 3.10+**
- **Node.js 18+**
- **Nmap** installed on the system:
  ```bash
  # Linux
  sudo apt install nmap

  # macOS
  brew install nmap

  # Windows
  # Download installer from https://nmap.org/download.html
  ```
- **VirusTotal API key** — free at [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- **Gmail App Password** — for email alerting (optional but recommended)

---

## Setup & Running

### Step 1 — Clone and configure environment

```bash
cd backend
cp .env.example .env
```

Edit `.env` and fill in your values:
```
VT_API_KEY=your_virustotal_api_key
ALERT_EMAIL=yourgmail@gmail.com
ALERT_PASSWORD=xxxxxxxxxxxx
DB_PATH=vulnscan.db
```

### Step 2 — Install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

### Step 3 — Start the backend

```bash
cd backend
uvicorn main:app --reload --port 8000
```

On first run, `vulnscan.db` is automatically created in the `backend/` folder.

### Step 4 — Install and start the frontend

```bash
cd frontend
npm install
npm start
```

Opens at **http://localhost:3000**

The React app proxies all `/api/*` requests to `http://localhost:8000` via the `proxy` field in `package.json` — no CORS issues during development.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VT_API_KEY` | Yes | VirusTotal API key — get free at virustotal.com |
| `ALERT_EMAIL` | For email | Gmail address to send alerts from |
| `ALERT_PASSWORD` | For email | Gmail App Password (16 chars) — not your account password |
| `DB_PATH` | No | Path to SQLite file. Default: `vulnscan.db` in backend folder |

---
Author
Amarnath Vasanth
## Legal Notice

Only scan systems you own or have explicit written authorization to test. Unauthorized port scanning may violate computer fraud and abuse laws in your jurisdiction. This tool is built for educational purposes as part of a virtual internship project.

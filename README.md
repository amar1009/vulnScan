# VulnScan — Vulnerability Assessment Platform

Internship project: full-stack cybersecurity tool that combines Nmap port scanning with VirusTotal threat intelligence to produce CVSS-based risk scores.

## Architecture

```
vuln-scanner/
├── backend/          # FastAPI (Python)
│   ├── main.py       # API routes + scan orchestration
│   ├── scanner.py    # Nmap integration
│   ├── virustotal.py # VirusTotal v3 API integration
│   ├── risk.py       # Risk scoring engine
│   ├── models.py     # Pydantic data models
│   ├── store.py      # In-memory scan store
│   └── requirements.txt
└── frontend/         # React
    └── src/
        ├── pages/
        │   ├── Dashboard.jsx   # Stats + charts overview
        │   ├── ScanPage.jsx    # New scan form + live results
        │   └── HistoryPage.jsx # Scan history + expand/delete
        ├── components/
        │   ├── RiskGauge.jsx   # SVG arc risk score gauge
        │   ├── PortTable.jsx   # Nmap port results table
        │   ├── VTPanel.jsx     # VirusTotal radar + stats
        │   └── ScanProgress.jsx# Live scan pipeline steps
        ├── hooks/
        │   └── useScan.js      # Polling hook for scan status
        └── utils/
            └── api.js          # Axios API calls
```

## Modules Implemented

| Module | Implementation |
|--------|---------------|
| Vulnerability Scanning Engine | `scanner.py` — python-nmap wrapping Nmap with 3 scan profiles |
| Threat Intelligence Layer | `virustotal.py` — VirusTotal v3 IP/domain reputation API |
| Risk Scoring & Analytics Core | `risk.py` — CVSS-inspired 0–100 score with severity tiers |
| Dashboard & Reporting Hub | React dashboard with Recharts bar chart + history |

## Prerequisites

- Python 3.10+
- Node.js 18+
- Nmap installed on the system: `sudo apt install nmap` (Linux) or `brew install nmap` (macOS)
- A [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) (free tier works)

## Setup

### Backend

```bash
cd backend

# Copy and fill in your API key
cp .env.example .env
# Edit .env and set VT_API_KEY=your_key_here

pip install -r requirements.txt

# Nmap SYN scans require root; basic -sV scans work without root
python -m uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm start        # Runs on http://localhost:3000
```

The React app proxies `/api/*` requests to `http://localhost:8000` via `package.json`.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Start a new scan |
| GET | `/api/scan/{id}` | Poll scan status/results |
| GET | `/api/scans` | List all scans |
| DELETE | `/api/scan/{id}` | Delete a scan record |

### POST /api/scan body

```json
{
  "target": "192.168.1.1",
  "scan_type": "basic"   // basic | full | stealth
}
```

## Scan Profiles

| Profile | Nmap Args | Notes |
|---------|-----------|-------|
| basic | `-sV --open -T4` | Fast, version detection |
| full | `-sV -O --open -T4 -p-` | OS detection + all 65535 ports; slow |
| stealth | `-sS -sV --open -T2` | SYN scan; requires root/sudo |

## Risk Scoring

Scores are 0–100 and map to:

| Range | Severity |
|-------|----------|
| 75–100 | CRITICAL |
| 50–74 | HIGH |
| 25–49 | MEDIUM |
| 0–24 | LOW |

Score components:
- Open port count: up to 20 pts
- Dangerous ports (RDP, SMB, Telnet, etc.): up to 25 pts
- VirusTotal malicious flags: up to 35 pts
- VirusTotal suspicious flags: up to 10 pts
- Negative community score: up to 10 pts

## Legal Notice

Only scan systems you own or have explicit written authorization to test.
Unauthorized scanning may be illegal in your jurisdiction.

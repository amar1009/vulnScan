"""
Risk Scoring Engine.
Combines Nmap and VirusTotal results into a CVSS-inspired risk score (0-100).
"""

from models import NmapResult, VTResult, RiskScore
from dotenv import load_dotenv
load_dotenv()
# Ports that significantly raise risk score
HIGH_RISK_PORTS = {23, 135, 139, 445, 3389, 4444, 5900, 6379, 27017}
MEDIUM_RISK_PORTS = {21, 22, 25, 110, 143, 1433, 1521, 3306, 5432, 8080}


def compute_risk_score(nmap: NmapResult, vt: VTResult) -> RiskScore:
    """
    Compute a composite risk score (0-100) from Nmap port data and VirusTotal intel.

    Scoring breakdown:
    - Open port count:          up to 20 pts
    - High-risk ports present:  up to 25 pts
    - VirusTotal malicious hits: up to 35 pts
    - VirusTotal suspicious hits: up to 10 pts
    - Negative community score:  up to 10 pts
    """
    score = 0.0
    threat_flags: list[str] = []
    dangerous_ports_found: list[int] = []

    open_ports = [p for p in nmap.ports if p.state == "open"]
    open_count = len(open_ports)

    # --- Port count contribution ---
    port_score = min(open_count * 2, 20)
    score += port_score

    # --- Dangerous port contribution ---
    for p in open_ports:
        if p.port in HIGH_RISK_PORTS:
            score += 5
            dangerous_ports_found.append(p.port)
            threat_flags.append(f"High-risk port open: {p.port}/{p.service}")
        elif p.port in MEDIUM_RISK_PORTS:
            score += 2
            dangerous_ports_found.append(p.port)

    score = min(score, 45)  # Cap port contribution at 45

    # --- VirusTotal contribution ---
    malicious_pts = min(vt.malicious_count * 5, 35)
    suspicious_pts = min(vt.suspicious_count * 2, 10)
    community_pts = min(max(-vt.community_score, 0), 10)

    score += malicious_pts + suspicious_pts + community_pts

    if vt.malicious_count > 0:
        threat_flags.append(f"Flagged malicious by {vt.malicious_count} VirusTotal engines")
    if vt.suspicious_count > 0:
        threat_flags.append(f"Flagged suspicious by {vt.suspicious_count} VirusTotal engines")
    if vt.community_score < -5:
        threat_flags.append(f"Negative VirusTotal community score: {vt.community_score}")

    score = min(score, 100)

    # --- Severity mapping ---
    if score >= 75:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # --- Rough CVSS-like estimate (0-10 scale) ---
    cvss_estimate = round(score / 10, 1)

    # --- Human-readable summary ---
    summary = _build_summary(severity, open_count, dangerous_ports_found, vt)

    return RiskScore(
        score=round(score, 1),
        severity=severity,
        cvss_estimate=cvss_estimate,
        open_ports_count=open_count,
        dangerous_ports=dangerous_ports_found,
        threat_flags=threat_flags,
        summary=summary,
    )


def _build_summary(severity: str, open_count: int, dangerous: list, vt: VTResult) -> str:
    parts = [f"Risk level is {severity}."]
    parts.append(f"{open_count} open port(s) detected.")
    if dangerous:
        parts.append(f"{len(dangerous)} high/medium risk port(s) identified.")
    if vt.malicious_count > 0:
        parts.append(f"Target flagged by {vt.malicious_count} malicious intelligence source(s).")
    else:
        parts.append("No malicious flags from VirusTotal.")
    return " ".join(parts)

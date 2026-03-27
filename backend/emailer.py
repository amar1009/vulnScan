"""
Email alerting module.
Sends styled HTML alert email with PDF attachment when HIGH or CRITICAL risk is detected.
Sender credentials come from environment variables; recipient is passed per-scan.
"""

import smtplib
import os
from email.mime.text        import MIMEText
from email.mime.multipart   import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
from models import ScanStatus

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

SEV_COLOURS = {
    "CRITICAL": "#7f1d1d",
    "HIGH":     "#dc2626",
    "MEDIUM":   "#ea580c",
    "LOW":      "#16a34a",
}


def generate_pdf_report(scan: ScanStatus, output_path: str) -> str:
    """
    Build a PDF scan report using fpdf2.
    Includes: header, KPI summary, port findings table, VirusTotal summary, footer.
    Returns the path to the created PDF.
    """
    from fpdf import FPDF

    risk  = scan.risk
    nmap  = scan.nmap_results
    vt    = scan.vt_results
    now   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Header ────────────────────────────────────────────────────────────────
    pdf.set_fill_color(15, 17, 23)
    pdf.rect(0, 0, 210, 35, "F")
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(255, 255, 255)
    pdf.set_y(10)
    pdf.cell(0, 10, "VulnScan - Vulnerability Assessment Report", align="C", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, f"Generated: {now}  |  Target: {scan.target}", align="C", ln=True)
    pdf.ln(12)

    # ── Executive KPI Summary ─────────────────────────────────────────────────
    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)

    open_ports  = [p for p in (nmap.ports if nmap else []) if p.state == "open"]
    dangerous   = risk.dangerous_ports if risk else []

    kpis = [
        ("Target",               scan.target),
        ("Scan Status",          scan.status),
        ("Risk Severity",        risk.severity if risk else "-"),
        ("Risk Score",           f"{risk.score:.1f} / 100" if risk else "-"),
        ("CVSS Estimate",        f"{risk.cvss_estimate:.1f} / 10" if risk else "-"),
        ("Open Ports",           str(len(open_ports))),
        ("Dangerous Ports",      str(len(dangerous))),
        ("VT Malicious Engines", str(vt.malicious_count) if vt else "-"),
        ("VT Suspicious Engines",str(vt.suspicious_count) if vt else "-"),
        ("VT Community Score",   str(vt.community_score) if vt else "-"),
    ]
    for label, val in kpis:
        pdf.cell(80, 7, label, border=1)
        pdf.cell(60, 7, val,   border=1, ln=True)
    pdf.ln(6)

    # ── Threat Flags ──────────────────────────────────────────────────────────
    if risk and risk.threat_flags:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Threat Flags", ln=True)
        pdf.set_font("Helvetica", "", 9)
        for flag in risk.threat_flags:
            pdf.set_text_color(180, 20, 20)
            pdf.cell(0, 6, f"  * {flag}", ln=True)
        pdf.set_text_color(30, 30, 30)
        pdf.ln(4)

    # ── Port Table ────────────────────────────────────────────────────────────
    if open_ports:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Open Port Inventory", ln=True)
        pdf.set_font("Helvetica", "B", 8)
        headers = ["Port", "Proto", "State", "Service", "Version", "Notes"]
        widths  = [18, 14, 16, 26, 40, 76]
        for h, w in zip(headers, widths):
            pdf.set_fill_color(30, 58, 138)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(w, 7, h, border=1, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 7)
        for idx, p in enumerate(open_ports):
            bg = (249, 250, 251) if idx % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*bg)
            pdf.set_text_color(30, 30, 30)
            vals = [
                str(p.port),
                p.protocol,
                p.state,
                p.service[:20],
                p.version[:35],
                (p.cve_hints[0][:60] if p.cve_hints else ""),
            ]
            for val, w in zip(vals, widths):
                pdf.cell(w, 6, val, border=1, fill=True)
            pdf.ln()

    # ── Footer ────────────────────────────────────────────────────────────────
    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, "VulnScan  |  Confidential  |  For authorised recipients only", align="C", ln=True)

    pdf.output(output_path)
    return output_path


def _build_html_body(scan: ScanStatus) -> str:
    """Build the styled HTML email body from scan results."""
    risk = scan.risk
    vt   = scan.vt_results
    nmap = scan.nmap_results
    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    severity    = risk.severity if risk else "UNKNOWN"
    score       = f"{risk.score:.1f}" if risk else "-"
    cvss        = f"{risk.cvss_estimate:.1f}" if risk else "-"
    open_count  = risk.open_ports_count if risk else 0
    mal_count   = vt.malicious_count if vt else 0
    sev_colour  = SEV_COLOURS.get(severity, "#374151")

    flags_html = "".join(
        f'<li style="margin-bottom:4px;color:#dc2626;">{f}</li>'
        for f in (risk.threat_flags if risk else [])
    ) or '<li style="color:#16a34a;">No threat flags detected.</li>'

    ports = [p for p in (nmap.ports if nmap else []) if p.state == "open"]
    port_rows = ""
    for idx, p in enumerate(ports[:20]):  # cap at 20 rows in email
        bg = "#f9fafb" if idx % 2 == 0 else "#ffffff"
        note = p.cve_hints[0] if p.cve_hints else ""
        port_rows += (
            f'<tr style="background:{bg};">'
            f'<td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;font-family:monospace;">{p.port}/{p.protocol}</td>'
            f'<td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;">{p.service}</td>'
            f'<td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;color:#6b7280;font-size:11px;">{p.version}</td>'
            f'<td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;font-size:11px;color:#dc2626;">{note}</td>'
            f'</tr>'
        )

    return f"""
    <html><body style="font-family:Arial,sans-serif;background:#f3f4f6;margin:0;padding:20px;">
    <div style="max-width:820px;margin:0 auto;background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.12);">

      <div style="background:#0f172a;padding:22px 30px;">
        <h1 style="color:white;margin:0;font-size:20px;">VulnScan — Security Alert</h1>
        <p style="color:#94a3b8;margin:5px 0 0;font-size:13px;">Scan completed: {now}</p>
      </div>

      <div style="padding:24px 30px;">

        <!-- KPI row -->
        <div style="display:flex;gap:14px;margin-bottom:22px;">
          <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:14px 20px;flex:1;text-align:center;">
            <div style="font-size:26px;font-weight:bold;color:{sev_colour};">{severity}</div>
            <div style="font-size:12px;color:#991b1b;">Severity</div>
          </div>
          <div style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:6px;padding:14px 20px;flex:1;text-align:center;">
            <div style="font-size:26px;font-weight:bold;color:#0369a1;">{score}</div>
            <div style="font-size:12px;color:#0369a1;">Risk Score / 100</div>
          </div>
          <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;padding:14px 20px;flex:1;text-align:center;">
            <div style="font-size:26px;font-weight:bold;color:#c2410c;">{open_count}</div>
            <div style="font-size:12px;color:#c2410c;">Open Ports</div>
          </div>
          <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:14px 20px;flex:1;text-align:center;">
            <div style="font-size:26px;font-weight:bold;color:#7f1d1d;">{mal_count}</div>
            <div style="font-size:12px;color:#991b1b;">VT Malicious</div>
          </div>
        </div>

        <p style="color:#374151;font-size:13px;margin:0 0 16px;">
          Target <strong style="font-family:monospace;">{scan.target}</strong> has been assessed with
          a risk score of <strong>{score}/100</strong> (CVSS estimate: <strong>{cvss}/10</strong>).
          See the attached PDF for the full report.
        </p>

        <!-- Threat flags -->
        <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:14px 18px;margin-bottom:20px;">
          <strong style="color:#7f1d1d;font-size:13px;">Threat Flags</strong>
          <ul style="margin:8px 0 0;padding-left:18px;font-size:12px;">{flags_html}</ul>
        </div>

        <!-- Port table -->
        <strong style="color:#1e293b;font-size:13px;">Open Port Inventory</strong>
        <table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:8px;margin-bottom:20px;">
          <thead>
            <tr style="background:#1e3a5f;color:white;">
              <th style="padding:8px 10px;text-align:left;">Port</th>
              <th style="padding:8px 10px;text-align:left;">Service</th>
              <th style="padding:8px 10px;text-align:left;">Version</th>
              <th style="padding:8px 10px;text-align:left;">Risk Note</th>
            </tr>
          </thead>
          <tbody>{port_rows or "<tr><td colspan='4' style='padding:10px;color:#9ca3af;'>No open ports detected.</td></tr>"}</tbody>
        </table>

        <p style="font-size:11px;color:#9ca3af;margin:0;">
          This is an automated alert from VulnScan. Full report is attached.
          Take action within 1 hour for CRITICAL findings.
        </p>
      </div>
    </div>
    </body></html>
    """


def send_alert_email(scan: ScanStatus, recipient: str) -> bool:
    """
    Send a styled HTML alert email with PDF attachment.

    Sender credentials are read from environment variables:
        ALERT_EMAIL    - Gmail address to send from
        ALERT_PASSWORD - Gmail App Password (16 chars, no spaces)
                         Generate at: myaccount.google.com → Security → App passwords

    Args:
        scan:      Completed ScanStatus object
        recipient: Email address to receive the alert

    Returns: True on success, False on any error.
    """
    sender   = os.getenv("ALERT_EMAIL", "")
    password = os.getenv("ALERT_PASSWORD", "")

    if not sender or not password:
        raise RuntimeError("ALERT_EMAIL and ALERT_PASSWORD must be set in .env")

    risk     = scan.risk
    severity = risk.severity if risk else "UNKNOWN"
    now_str  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = f"[VulnScan] {severity} Risk Alert — {scan.target} — Score {risk.score:.0f}/100 — {now_str}"
        msg["From"]    = sender
        msg["To"]      = recipient

        msg.attach(MIMEText(_build_html_body(scan), "html"))

        # Generate and attach PDF
        ts       = now_str.replace(" ", "_").replace(":", "-")
        pdf_path = os.path.join(REPORTS_DIR, f"scan_{scan.target.replace('.','_')}_{ts}.pdf")
        generate_pdf_report(scan, pdf_path)

        with open(pdf_path, "rb") as f:
            part = MIMEApplication(f.read(), _subtype="pdf")
            part.add_header("Content-Disposition", "attachment", filename=os.path.basename(pdf_path))
            msg.attach(part)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())

        return True

    except Exception as e:
        print(f"Email error: {e}")
        raise RuntimeError(str(e))

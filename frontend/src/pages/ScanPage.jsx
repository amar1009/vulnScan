// New Scan page: form to submit a scan, live progress, and final results
import React, { useState } from "react";
import { startScan, sendAlert } from "../utils/api";
import { useScan } from "../hooks/useScan";
import ScanProgress from "../components/ScanProgress";
import RiskGauge from "../components/RiskGauge";
import PortTable from "../components/PortTable";
import VTPanel from "../components/VTPanel";

export default function ScanPage({ alertRecipient = "" }) {
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("basic");
  const [scanId, setScanId] = useState(null);
  const [submitError, setSubmitError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Manual alert state
  const [manualRecipient, setManualRecipient] = useState("");
  const [alertSending, setAlertSending] = useState(false);
  const [alertStatus, setAlertStatus] = useState(null); // { ok, msg }

  const { scan, error: pollError } = useScan(scanId);

  const handleSubmit = async () => {
    if (!target.trim()) return;
    setSubmitError("");
    setAlertStatus(null);
    setSubmitting(true);
    try {
      const res = await startScan(target.trim(), scanType, alertRecipient);
      setScanId(res.scan_id);
    } catch (e) {
      setSubmitError(e.response?.data?.detail || e.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleReset = () => {
    setScanId(null);
    setTarget("");
    setSubmitError("");
    setAlertStatus(null);
  };

  const handleManualAlert = async () => {
    const recipient = manualRecipient.trim() || alertRecipient;
    if (!recipient || !scanId) return;
    setAlertSending(true);
    setAlertStatus(null);
    try {
      await sendAlert(scanId, recipient);
      setAlertStatus({ ok: true, msg: `Alert sent to ${recipient}` });
    } catch (e) {
      setAlertStatus({ ok: false, msg: e.response?.data?.detail || e.message });
    } finally {
      setAlertSending(false);
    }
  };

  const isRunning = scan && (scan.status === "queued" || scan.status === "scanning");
  const isDone    = scan?.status === "completed";
  const isFailed  = scan?.status === "error";

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">New Scan</h1>
        <p className="page-subtitle">
          Run an Nmap + VirusTotal vulnerability assessment against an IP or hostname.
        </p>
      </div>

      {/* Scan form */}
      {!scanId && (
        <div className="card" style={{ maxWidth: 520 }}>
          <div className="card-title">Target Configuration</div>

          {submitError && <div className="alert alert-error">{submitError}</div>}

          <div className="form-group">
            <label className="form-label">Target IP / Hostname</label>
            <input
              className="form-input"
              placeholder="e.g. 192.168.1.1 or example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Scan Profile</label>
            <select className="form-select" value={scanType}
              onChange={(e) => setScanType(e.target.value)}>
              <option value="basic">Basic — Version detection, open ports</option>
              <option value="full">Full — OS detection + all ports (slow)</option>
              <option value="stealth">Stealth — SYN scan, low noise</option>
            </select>
          </div>

          {/* Show configured alert recipient */}
          {alertRecipient && (
            <div style={{
              fontSize: 11, padding: "8px 12px", marginBottom: 14,
              background: "var(--green-dim)", border: "1px solid var(--green)",
              borderRadius: "var(--radius)", color: "var(--green)",
            }}>
              Auto-alert enabled → {alertRecipient} (HIGH / CRITICAL only)
            </div>
          )}

          <div className="alert alert-info" style={{ marginBottom: 16, fontSize: 11 }}>
            Only scan systems you own or have explicit authorization to test.
          </div>

          <button className="btn btn-primary" onClick={handleSubmit}
            disabled={submitting || !target.trim()}>
            {submitting ? "Starting..." : "Launch Scan"}
          </button>
        </div>
      )}

      {/* Live progress */}
      {scanId && (isRunning || isFailed) && (
        <div className="card" style={{ maxWidth: 520 }}>
          <div className="flex-between" style={{ marginBottom: 8 }}>
            <div className="card-title" style={{ marginBottom: 0 }}>
              Scanning: <span style={{ color: "var(--accent)" }}>{scan?.target}</span>
            </div>
            {isFailed && (
              <button className="btn btn-ghost" onClick={handleReset} style={{ fontSize: 11 }}>
                Reset
              </button>
            )}
          </div>
          {pollError && <div className="alert alert-error">{pollError}</div>}
          {isFailed  && <div className="alert alert-error">Scan failed: {scan.error}</div>}
          <ScanProgress status={scan?.status} currentStep={scan?.current_step} />
        </div>
      )}

      {/* Results */}
      {isDone && scan && (
        <div>
          <div className="flex-between" style={{ marginBottom: 20 }}>
            <div>
              <div style={{ color: "var(--text-muted)", fontSize: 11, marginBottom: 4 }}>Target</div>
              <div style={{ fontSize: 18, fontFamily: "Syne, sans-serif", fontWeight: 700 }}>
                {scan.target}
              </div>
              {scan.nmap_results?.hostname && (
                <div className="text-muted" style={{ fontSize: 11 }}>{scan.nmap_results.hostname}</div>
              )}
            </div>
            <button className="btn btn-ghost" onClick={handleReset}>New Scan</button>
          </div>

          {/* Auto-alert status banner */}
          {scan.alert_sent_to && (
            <div className="alert" style={{
              background: "var(--green-dim)", border: "1px solid var(--green)",
              color: "var(--green)", marginBottom: 16,
            }}>
              Alert automatically sent to <strong>{scan.alert_sent_to}</strong>
            </div>
          )}
          {scan.alert_error && (
            <div className="alert alert-error" style={{ marginBottom: 16 }}>
              Auto-alert failed: {scan.alert_error}
            </div>
          )}

          {/* Risk overview */}
          <div className="grid-2" style={{ marginBottom: 20, alignItems: "start" }}>
            <div className="card" style={{ display: "flex", gap: 28, alignItems: "center" }}>
              <RiskGauge score={scan.risk?.score ?? 0} severity={scan.risk?.severity ?? "LOW"} />
              <div>
                <div className="card-title">Risk Summary</div>
                <p style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.7 }}>
                  {scan.risk?.summary}
                </p>
                <div style={{ marginTop: 12, fontSize: 11 }}>
                  <span className="text-muted">CVSS Estimate: </span>
                  <strong style={{ color: "var(--accent)" }}>{scan.risk?.cvss_estimate}</strong>
                  <span className="text-muted" style={{ marginLeft: 16 }}>Open Ports: </span>
                  <strong style={{ color: "var(--accent)" }}>{scan.risk?.open_ports_count}</strong>
                </div>
              </div>
            </div>

            <div className="card">
              <div className="card-title">Threat Flags</div>
              {scan.risk?.threat_flags?.length ? (
                <ul style={{ listStyle: "none", display: "flex", flexDirection: "column", gap: 8 }}>
                  {scan.risk.threat_flags.map((f, i) => (
                    <li key={i} style={{
                      fontSize: 12, padding: "8px 12px",
                      background: "var(--red-dim)", border: "1px solid var(--red)",
                      borderRadius: "var(--radius)", color: "var(--red)",
                    }}>{f}</li>
                  ))}
                </ul>
              ) : (
                <p style={{ fontSize: 12, color: "var(--green)" }}>No threat flags detected.</p>
              )}
              {scan.nmap_results?.os_guess && (
                <div style={{ marginTop: 12, fontSize: 11 }}>
                  <span className="text-muted">OS Guess: </span>
                  <span style={{ color: "var(--text-secondary)" }}>{scan.nmap_results.os_guess}</span>
                </div>
              )}
            </div>
          </div>

          {/* Port table */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">
              Port & Service Inventory
              <span style={{ marginLeft: 10, fontSize: 10, fontWeight: 400, color: "var(--text-muted)" }}>
                {scan.nmap_results?.ports?.length ?? 0} ports
              </span>
            </div>
            <PortTable ports={scan.nmap_results?.ports ?? []} />
          </div>

          {/* VT */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">VirusTotal Threat Intelligence</div>
            <VTPanel vt={scan.vt_results} />
          </div>

          {/* Manual alert sender */}
          <div className="card">
            <div className="card-title">Send Alert Email</div>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
              <div style={{ flex: 1 }}>
                <label className="form-label">Recipient Email</label>
                <input
                  className="form-input"
                  type="email"
                  placeholder={alertRecipient || "recipient@example.com"}
                  value={manualRecipient}
                  onChange={(e) => setManualRecipient(e.target.value)}
                />
              </div>
              <button className="btn btn-primary" onClick={handleManualAlert}
                disabled={alertSending || (!manualRecipient.trim() && !alertRecipient)}>
                {alertSending ? "Sending..." : "Send Alert + PDF"}
              </button>
            </div>
            {alertStatus && (
              <div className={`alert ${alertStatus.ok ? "" : "alert-error"}`} style={{
                marginTop: 10,
                ...(alertStatus.ok
                  ? { background: "var(--green-dim)", border: "1px solid var(--green)", color: "var(--green)" }
                  : {}),
              }}>
                {alertStatus.msg}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

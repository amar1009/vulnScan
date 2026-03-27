// Scan History page: view and manage all past scans
import React, { useEffect, useState } from "react";
import { listScans, deleteScan } from "../utils/api";
import RiskGauge from "../components/RiskGauge";
import PortTable from "../components/PortTable";
import VTPanel from "../components/VTPanel";

export default function HistoryPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);

  const load = () => {
    listScans()
      .then((data) => setScans([...data].reverse()))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleDelete = async (scanId, e) => {
    e.stopPropagation();
    await deleteScan(scanId);
    setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
    if (expanded === scanId) setExpanded(null);
  };

  const toggle = (scanId) =>
    setExpanded((prev) => (prev === scanId ? null : scanId));

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Scan History</h1>
        <p className="page-subtitle">All completed and failed assessment records</p>
      </div>

      {loading && <p className="text-muted">Loading...</p>}

      {!loading && scans.length === 0 && (
        <div className="card">
          <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
            No scan history. Run a scan from the New Scan page.
          </p>
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {scans.map((s) => (
          <div key={s.scan_id} className="card" style={{ padding: 0, overflow: "hidden" }}>
            {/* Row header */}
            <div
              onClick={() => toggle(s.scan_id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 16,
                padding: "14px 20px",
                cursor: "pointer",
                transition: "background 0.1s",
              }}
              onMouseEnter={(e) => e.currentTarget.style.background = "var(--bg-elevated)"}
              onMouseLeave={(e) => e.currentTarget.style.background = ""}
            >
              {/* Target */}
              <div style={{ flex: 2, fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--accent)" }}>
                {s.target}
              </div>

              {/* Status */}
              <div style={{ flex: 1 }}>
                <span style={{
                  fontSize: 10, padding: "2px 8px", borderRadius: 3,
                  background: s.status === "completed" ? "var(--green-dim)"
                    : s.status === "error" ? "var(--red-dim)" : "var(--accent-dim)",
                  color: s.status === "completed" ? "var(--green)"
                    : s.status === "error" ? "var(--red)" : "var(--accent)",
                  border: `1px solid ${s.status === "completed" ? "var(--green)"
                    : s.status === "error" ? "var(--red)" : "var(--accent)"}`,
                }}>
                  {s.status}
                </span>
              </div>

              {/* Risk badge */}
              <div style={{ flex: 1 }}>
                {s.risk
                  ? <span className={`risk-badge risk-${s.risk.severity}`}>{s.risk.severity}</span>
                  : <span className="text-muted">-</span>
                }
              </div>

              {/* Score */}
              <div style={{ flex: 1, color: "var(--text-secondary)", fontSize: 12 }}>
                {s.risk ? `${s.risk.score}/100` : "-"}
              </div>

              {/* Ports */}
              <div style={{ flex: 1, color: "var(--text-secondary)", fontSize: 12 }}>
                {s.risk ? `${s.risk.open_ports_count} ports` : "-"}
              </div>

              {/* Date */}
              <div style={{ flex: 2, fontSize: 11, color: "var(--text-muted)" }}>
                {new Date(s.created_at).toLocaleString()}
              </div>

              {/* Actions */}
              <button
                className="btn btn-ghost"
                onClick={(e) => handleDelete(s.scan_id, e)}
                style={{ fontSize: 11, padding: "5px 12px" }}
              >
                Delete
              </button>

              <span style={{ color: "var(--text-muted)", fontSize: 12, marginLeft: 4 }}>
                {expanded === s.scan_id ? "▲" : "▼"}
              </span>
            </div>

            {/* Expanded detail panel */}
            {expanded === s.scan_id && s.status === "completed" && (
              <div style={{ borderTop: "1px solid var(--border)", padding: "20px" }}>
                <div className="grid-2" style={{ marginBottom: 20, alignItems: "start" }}>
                  {/* Risk gauge */}
                  <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
                    <RiskGauge score={s.risk?.score ?? 0} severity={s.risk?.severity ?? "LOW"} />
                    <div>
                      <div style={{ marginBottom: 10, fontSize: 12, color: "var(--text-secondary)" }}>
                        {s.risk?.summary}
                      </div>
                      <div style={{ fontSize: 11 }}>
                        <span className="text-muted">CVSS Estimate: </span>
                        <strong style={{ color: "var(--accent)" }}>{s.risk?.cvss_estimate}</strong>
                      </div>
                      {s.nmap_results?.os_guess && (
                        <div style={{ fontSize: 11, marginTop: 6 }}>
                          <span className="text-muted">OS: </span>
                          <span style={{ color: "var(--text-secondary)" }}>{s.nmap_results.os_guess}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Threat flags */}
                  <div>
                    <div className="card-title">Threat Flags</div>
                    {s.risk?.threat_flags?.length ? (
                      s.risk.threat_flags.map((f, i) => (
                        <div key={i} style={{
                          fontSize: 11, padding: "7px 12px", marginBottom: 6,
                          background: "var(--red-dim)", border: "1px solid var(--red)",
                          borderRadius: "var(--radius)", color: "var(--red)",
                        }}>{f}</div>
                      ))
                    ) : (
                      <p style={{ fontSize: 12, color: "var(--green)" }}>No threat flags.</p>
                    )}
                  </div>
                </div>

                {/* Port table */}
                <div style={{ marginBottom: 20 }}>
                  <div className="card-title">Ports</div>
                  <PortTable ports={s.nmap_results?.ports ?? []} />
                </div>

                {/* VT */}
                <div>
                  <div className="card-title">VirusTotal</div>
                  <VTPanel vt={s.vt_results} />
                </div>
              </div>
            )}

            {expanded === s.scan_id && s.status === "error" && (
              <div style={{ borderTop: "1px solid var(--border)", padding: 16 }}>
                <div className="alert alert-error">Error: {s.error}</div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

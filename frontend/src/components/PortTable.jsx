// Table displaying Nmap port scan results
import React from "react";

const HIGH_RISK = new Set([23, 135, 139, 445, 3389, 4444, 5900, 6379, 27017]);

export default function PortTable({ ports = [] }) {
  if (!ports.length) {
    return <p className="text-muted" style={{ padding: "12px 0" }}>No open ports detected.</p>;
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Service</th>
            <th>Version</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((p, i) => (
            <tr key={i}>
              <td>
                <span className={`port-tag ${HIGH_RISK.has(p.port) ? "danger" : ""}`}>
                  {p.port}
                </span>
              </td>
              <td className="text-muted">{p.protocol}</td>
              <td style={{ color: p.state === "open" ? "var(--green)" : "var(--text-muted)" }}>
                {p.state}
              </td>
              <td>{p.service || "-"}</td>
              <td className="text-muted">{p.version || "-"}</td>
              <td className="text-muted" style={{ fontSize: 11 }}>
                {p.cve_hints?.[0] || ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

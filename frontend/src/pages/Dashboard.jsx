// Dashboard: summary statistics and recent scan history
import React, { useEffect, useState } from "react";
import { listScans } from "../utils/api";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";

const SEVERITY_COLOR = {
  CRITICAL: "#ff3b5c",
  HIGH: "#ff8c00",
  MEDIUM: "#ffd600",
  LOW: "#00e676",
};

const CustomTooltip = ({ active, payload }) => {
  if (active && payload?.length) {
    return (
      <div style={{
        background: "var(--bg-elevated)", border: "1px solid var(--border)",
        borderRadius: 6, padding: "8px 12px", fontSize: 11,
      }}>
        <div style={{ color: "var(--text-secondary)" }}>{payload[0].payload.target}</div>
        <div style={{ color: payload[0].payload.color, fontWeight: 700 }}>
          Score: {payload[0].value}
        </div>
      </div>
    );
  }
  return null;
};

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listScans()
      .then(setScans)
      .finally(() => setLoading(false));
  }, []);

  const completed = scans.filter((s) => s.status === "completed");

  // Aggregate severity counts
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  completed.forEach((s) => {
    const sev = s.risk?.severity;
    if (sev && counts[sev] !== undefined) counts[sev]++;
  });

  // Chart data — last 10 completed scans
  const chartData = completed.slice(-10).map((s) => ({
    target: s.target,
    score: s.risk?.score ?? 0,
    color: SEVERITY_COLOR[s.risk?.severity] ?? "#8891a8",
  }));

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <p className="page-subtitle">Vulnerability assessment overview</p>
      </div>

      {/* Stat cards */}
      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Total Scans</div>
          <div className="stat-value accent">{scans.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Critical</div>
          <div className="stat-value critical">{counts.CRITICAL}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">High</div>
          <div className="stat-value high">{counts.HIGH}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Medium / Low</div>
          <div className="stat-value medium">{counts.MEDIUM + counts.LOW}</div>
        </div>
      </div>

      {/* Risk score chart */}
      {chartData.length > 0 && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-title">Risk Score Trend (last 10 scans)</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chartData} margin={{ top: 4, right: 0, bottom: 0, left: -20 }}>
              <XAxis
                dataKey="target"
                tick={{ fill: "#4a5068", fontSize: 10, fontFamily: "JetBrains Mono" }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                domain={[0, 100]}
                tick={{ fill: "#4a5068", fontSize: 10, fontFamily: "JetBrains Mono" }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="score" radius={[3, 3, 0, 0]}>
                {chartData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent scans table */}
      <div className="card">
        <div className="card-title">Recent Scans</div>
        {loading ? (
          <p className="text-muted">Loading...</p>
        ) : scans.length === 0 ? (
          <p className="text-muted" style={{ fontSize: 12 }}>
            No scans yet. Go to "New Scan" to get started.
          </p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Score</th>
                <th>Open Ports</th>
                <th>VT Malicious</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {[...scans].reverse().map((s) => (
                <tr key={s.scan_id}>
                  <td style={{ color: "var(--accent)", fontFamily: "var(--font-mono)" }}>
                    {s.target}
                  </td>
                  <td>
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
                  </td>
                  <td>
                    {s.risk ? (
                      <span className={`risk-badge risk-${s.risk.severity}`}>
                        {s.risk.severity}
                      </span>
                    ) : "-"}
                  </td>
                  <td style={{ color: "var(--text-secondary)" }}>
                    {s.risk?.score ?? "-"}
                  </td>
                  <td style={{ color: "var(--text-secondary)" }}>
                    {s.risk?.open_ports_count ?? "-"}
                  </td>
                  <td style={{ color: s.vt_results?.malicious_count > 0 ? "var(--red)" : "var(--text-muted)" }}>
                    {s.vt_results?.malicious_count ?? "-"}
                  </td>
                  <td className="text-muted" style={{ fontSize: 11 }}>
                    {new Date(s.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

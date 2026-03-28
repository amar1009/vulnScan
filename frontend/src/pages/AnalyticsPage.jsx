// Analytics page: visual charts derived from all completed scan history
import React, { useEffect, useState } from "react";
import { listScans } from "../utils/api";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  LineChart, Line, CartesianGrid,
  Legend,
} from "recharts";

const SEV_COLOR = {
  CRITICAL: "#ff3b5c",
  HIGH:     "#ff8c00",
  MEDIUM:   "#ffd600",
  LOW:      "#00e676",
};

const TOOLTIP_STYLE = {
  background: "var(--bg-elevated)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  padding: "8px 12px",
  fontSize: 11,
  color: "var(--primary-color)",
};

function ChartCard({ title, children, style = {} }) {
  return (
    <div className="card" style={style}>
      <div className="card-title">{title}</div>
      {children}
    </div>
  );
}

export default function AnalyticsPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listScans()
      .then((data) => setScans(data.filter((s) => s.status === "completed")))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="page-header"><p className="text-muted">Loading analytics...</p></div>;

  if (!scans.length) {
    return (
      <div>
        <div className="page-header">
          <h1 className="page-title">Analytics</h1>
        </div>
        <div className="card">
          <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
            No completed scans yet. Run a scan to see analytics.
          </p>
        </div>
      </div>
    );
  }
  const servicesData = Object.entries(
  scans.reduce((acc, s) => {
    (s.nmap_results?.ports ?? []).forEach((p) => {
      if (p.state === "open" && p.service) {
        acc[p.service] = (acc[p.service] || 0) + 1;
      }
    });
    return acc;
  }, {})
)
  .sort((a, b) => b[1] - a[1])   // highest count first
  .slice(0, 8)                    // top 8 services
  .map(([service, count]) => ({ service, count }));
  // ── 1. Risk score per host (bar) ──────────────────────────────────────────
  const riskPerHost = scans.map((s) => ({
    target: s.target,
    score:  s.risk?.score ?? 0,
    color:  SEV_COLOR[s.risk?.severity] ?? "#8891a8",
  }));

  // ── 2. Severity distribution (pie) ───────────────────────────────────────
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  scans.forEach((s) => { if (s.risk?.severity) sevCounts[s.risk.severity]++; });
  const sevPie = Object.entries(sevCounts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value, fill: SEV_COLOR[name] }));

  // ── 3. Open ports per host (bar) ─────────────────────────────────────────
  const portsPerHost = scans.map((s) => ({
    target:       s.target,
    open:         s.risk?.open_ports_count ?? 0,
    dangerous:    s.risk?.dangerous_ports?.length ?? 0,
  }));

  // ── 4. VirusTotal hits per host ───────────────────────────────────────────
  const vtPerHost = scans
    .filter((s) => s.vt_results)
    .map((s) => ({
      target:     s.target,
      malicious:  s.vt_results.malicious_count,
      suspicious: s.vt_results.suspicious_count,
      harmless:   s.vt_results.harmless_count,
    }));

  // ── 5. Risk score trend over time (line) ─────────────────────────────────
  const trend = [...scans]
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
    .map((s) => ({
      label: s.target,
      score: s.risk?.score ?? 0,
      time:  new Date(s.created_at).toLocaleDateString(),
    }));

  // ── 6. Radar: average threat profile ─────────────────────────────────────
  const avg = (fn) => scans.reduce((acc, s) => acc + (fn(s) || 0), 0) / scans.length;
  const radarData = [
    { subject: "Risk Score",   value: avg((s) => s.risk?.score) },
    { subject: "Open Ports",   value: avg((s) => (s.risk?.open_ports_count ?? 0) * 5) },
    { subject: "Danger Ports", value: avg((s) => (s.risk?.dangerous_ports?.length ?? 0) * 10) },
    { subject: "VT Malicious", value: avg((s) => (s.vt_results?.malicious_count ?? 0) * 8) },
    { subject: "VT Suspicious",value: avg((s) => (s.vt_results?.suspicious_count ?? 0) * 4) },
  ];

  // ── 7. Top dangerous ports across all scans ───────────────────────────────
  const portFreq = {};
  scans.forEach((s) => {
    (s.nmap_results?.ports ?? []).forEach((p) => {
      if (p.state === "open") {
        const key = `${p.port}/${p.service || p.protocol}`;
        portFreq[key] = (portFreq[key] || 0) + 1;
      }
    });
  });
  const topPorts = Object.entries(portFreq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([port, count]) => ({ port, count }));

  // ── 8. Alert email stats ──────────────────────────────────────────────────
  const alertSent  = scans.filter((s) => s.alert_sent_to).length;
  const alertFailed= scans.filter((s) => s.alert_error).length;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Analytics</h1>
        <p className="page-subtitle">Visual breakdown of all {scans.length} completed scan(s)</p>
      </div>

      {/* Summary stat row */}
      <div className="stat-grid" style={{ marginBottom: 20 }}>
        <div className="stat-card">
          <div className="stat-label">Avg Risk Score</div>
          <div className="stat-value accent">
            {(scans.reduce((a, s) => a + (s.risk?.score ?? 0), 0) / scans.length).toFixed(1)}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Unique Hosts</div>
          <div className="stat-value accent">{new Set(scans.map((s) => s.target)).size}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Alerts Sent</div>
          <div className="stat-value" style={{ color: alertSent ? "var(--green)" : "var(--text-muted)" }}>
            {alertSent}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">VT Flagged Hosts</div>
          <div className="stat-value critical">
            {scans.filter((s) => s.vt_results?.malicious_count > 0).length}
          </div>
        </div>
      </div>

      {/* Row 1 */}
      <div className="grid-2" style={{ marginBottom: 16 }}>
        <ChartCard title="Risk Score per Host">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={riskPerHost} margin={{ left: -20 }}>
              <XAxis dataKey="target" tick={{ fill: "#4a5068", fontSize: 9, fontFamily: "JetBrains Mono" }}
                axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fill: "#4a5068", fontSize: 9 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="score" radius={[3, 3, 0, 0]}>
                {riskPerHost.map((e, i) => <Cell key={i} fill={e.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Top Services Detected">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={servicesData} margin={{ left: -20 }}>
              <XAxis dataKey="service"
                tick={{ fill: "#4a5068", fontSize: 9, fontFamily: "JetBrains Mono" }}
                axisLine={false} tickLine={false} />
              <YAxis
                tick={{ fill: "#4a5068", fontSize: 9 }}
                axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="count" name="Hosts" fill="var(--accent)"
                radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Row 2 */}
      <div className="grid-2" style={{ marginBottom: 16 }}>
        <ChartCard title="Open vs Dangerous Ports per Host">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={portsPerHost} margin={{ left: -20 }}>
              <XAxis dataKey="target" tick={{ fill: "#4a5068", fontSize: 9, fontFamily: "JetBrains Mono" }}
                axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#4a5068", fontSize: 9 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 10, color: "#8891a8" }} />
              <Bar dataKey="open"      name="Open Ports"      fill="#00e5ff" radius={[2, 2, 0, 0]} />
              <Bar dataKey="dangerous" name="Dangerous Ports" fill="#ff3b5c" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="VirusTotal Engine Hits per Host">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={vtPerHost} margin={{ left: -20 }}>
              <XAxis dataKey="target" tick={{ fill: "#4a5068", fontSize: 9, fontFamily: "JetBrains Mono" }}
                axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#4a5068", fontSize: 9 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 10, color: "#8891a8" }} />
              <Bar dataKey="malicious"  name="Malicious"  fill="#ff3b5c" radius={[2, 2, 0, 0]} />
              <Bar dataKey="suspicious" name="Suspicious" fill="#ff8c00" radius={[2, 2, 0, 0]} />
              <Bar dataKey="harmless"   name="Harmless"   fill="#00e676" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Row 3 */}
      <div className="grid-2" style={{ marginBottom: 16 }}>
        <ChartCard title="Risk Score Trend (chronological)">
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trend} margin={{ left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#252a35" />
              <XAxis dataKey="label" tick={{ fill: "#4a5068", fontSize: 9, fontFamily: "JetBrains Mono" }}
                axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fill: "#4a5068", fontSize: 9 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Line type="monotone" dataKey="score" stroke="#00e5ff" strokeWidth={2}
                dot={{ fill: "#00e5ff", r: 4 }} activeDot={{ r: 6 }} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Average Threat Profile (Radar)">
          <ResponsiveContainer width="100%" height={200}>
            <RadarChart data={radarData} margin={{ top: 10, right: 20, bottom: 10, left: 20 }}>
              <PolarGrid stroke="#252a35" />
              <PolarAngleAxis dataKey="subject"
                tick={{ fill: "#8891a8", fontSize: 9, fontFamily: "JetBrains Mono" }} />
              <Radar name="Avg" dataKey="value" stroke="#00e5ff" fill="#00e5ff" fillOpacity={0.18} />
            </RadarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Top ports table */}
      {topPorts.length > 0 && (
        <ChartCard title="Most Frequently Open Ports Across All Scans">
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {topPorts.map(({ port, count }) => (
              <div key={port} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span style={{ width: 110, fontFamily: "var(--font-mono)", fontSize: 12,
                  color: "var(--accent)" }}>{port}</span>
                <div style={{ flex: 1, height: 8, background: "var(--bg-elevated)",
                  borderRadius: 4, overflow: "hidden" }}>
                  <div style={{
                    width: `${(count / scans.length) * 100}%`,
                    height: "100%",
                    background: "var(--accent)",
                    borderRadius: 4,
                  }} />
                </div>
                <span style={{ width: 40, textAlign: "right", fontSize: 11,
                  color: "var(--text-secondary)" }}>{count}x</span>
              </div>
            ))}
          </div>
        </ChartCard>
      )}
    </div>
  );
}

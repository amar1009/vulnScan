// VirusTotal intelligence panel
import React from "react";
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer } from "recharts";

export default function VTPanel({ vt }) {
  if (!vt) return null;

  const radarData = [
    { subject: "Malicious", value: vt.malicious_count },
    { subject: "Suspicious", value: vt.suspicious_count },
    { subject: "Harmless", value: vt.harmless_count },
    { subject: "Undetected", value: vt.undetected_count },
  ];

  const total = vt.malicious_count + vt.suspicious_count + vt.harmless_count + vt.undetected_count;

  return (
    <div>
      <div className="grid-2" style={{ gap: 24, alignItems: "start" }}>
        {/* Stats */}
        <div>
          {[
            { label: "Malicious", value: vt.malicious_count, color: "var(--red)" },
            { label: "Suspicious", value: vt.suspicious_count, color: "var(--orange)" },
            { label: "Harmless", value: vt.harmless_count, color: "var(--green)" },
            { label: "Undetected", value: vt.undetected_count, color: "var(--text-muted)" },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
              <div style={{ width: 80, fontSize: 10, letterSpacing: "0.08em", color: "var(--text-muted)", textTransform: "uppercase" }}>
                {label}
              </div>
              <div style={{ flex: 1, height: 6, background: "var(--bg-elevated)", borderRadius: 3, overflow: "hidden" }}>
                <div style={{
                  width: total ? `${(value / total) * 100}%` : "0%",
                  height: "100%",
                  background: color,
                  borderRadius: 3,
                }} />
              </div>
              <div style={{ width: 28, textAlign: "right", color, fontWeight: 700 }}>{value}</div>
            </div>
          ))}

          <div style={{ marginTop: 16, fontSize: 11 }}>
            <div style={{ color: "var(--text-muted)", marginBottom: 4 }}>Community Score</div>
            <div style={{
              fontSize: 20,
              fontWeight: 700,
              color: vt.community_score < 0 ? "var(--red)" : "var(--green)",
              fontFamily: "Syne, sans-serif"
            }}>
              {vt.community_score >= 0 ? "+" : ""}{vt.community_score}
            </div>
          </div>

          {vt.categories?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div style={{ color: "var(--text-muted)", fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 6 }}>
                Categories
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {vt.categories.map((c, i) => (
                  <span key={i} style={{
                    padding: "2px 8px", borderRadius: 3, fontSize: 10,
                    background: "var(--bg-elevated)", border: "1px solid var(--border)",
                    color: "var(--text-secondary)"
                  }}>{c}</span>
                ))}
              </div>
            </div>
          )}

          {vt.permalink && (
            <div style={{ marginTop: 16 }}>
              <a href={vt.permalink} target="_blank" rel="noreferrer"
                style={{ color: "var(--accent)", fontSize: 11, textDecoration: "none" }}>
                View full report on VirusTotal →
              </a>
            </div>
          )}
        </div>

        {/* Radar chart */}
        <div style={{ height: 220 }}>
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart data={radarData} margin={{ top: 10, right: 20, bottom: 10, left: 20 }}>
              <PolarGrid stroke="#252a35" />
              <PolarAngleAxis dataKey="subject"
                tick={{ fill: "#8891a8", fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <Radar name="VT" dataKey="value" stroke="#00e5ff" fill="#00e5ff" fillOpacity={0.15} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

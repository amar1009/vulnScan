// Visual risk score gauge using SVG arc
import React from "react";

const SEVERITY_COLOR = {
  CRITICAL: "#ff3b5c",
  HIGH: "#ff8c00",
  MEDIUM: "#ffd600",
  LOW: "#00e676",
};

export default function RiskGauge({ score = 0, severity = "LOW" }) {
  const color = SEVERITY_COLOR[severity] || "#8891a8";
  const radius = 60;
  const stroke = 8;
  const norm = radius - stroke / 2;
  const circumference = 2 * Math.PI * norm;
  // Use 75% of the circle for the arc (270 degrees)
  const arcLength = circumference * 0.75;
  const filled = (score / 100) * arcLength;

  return (
    <div className="score-ring">
      <svg width={160} height={130} viewBox="0 0 160 130">
        {/* Background arc */}
        <circle
          cx={80}
          cy={90}
          r={norm}
          fill="none"
          stroke="#252a35"
          strokeWidth={stroke}
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform="rotate(135 80 90)"
        />
        {/* Filled arc */}
        <circle
          cx={80}
          cy={90}
          r={norm}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={`${filled} ${circumference}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform="rotate(135 80 90)"
          style={{ filter: `drop-shadow(0 0 6px ${color})` }}
        />
        {/* Score text */}
        <text x={80} y={88} textAnchor="middle" fill={color}
          style={{ fontFamily: "Syne, sans-serif", fontSize: 28, fontWeight: 800 }}>
          {Math.round(score)}
        </text>
        <text x={80} y={106} textAnchor="middle" fill="#4a5068"
          style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 9, letterSpacing: 2 }}>
          /100
        </text>
      </svg>
      <span className="risk-badge" style={{ marginTop: -8 }}
        data-severity={severity}>
        <span className={`risk-badge risk-${severity}`}>{severity}</span>
      </span>
    </div>
  );
}

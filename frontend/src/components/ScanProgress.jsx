// Displays real-time scan pipeline steps
import React from "react";

const STEPS = [
  { key: "nmap", label: "Nmap Port Scan", desc: "Scanning ports, services, and OS" },
  { key: "virustotal", label: "VirusTotal Lookup", desc: "Checking threat intelligence" },
  { key: "scoring", label: "Risk Scoring", desc: "Computing CVSS-based risk score" },
];

export default function ScanProgress({ status, currentStep }) {
  const stepOrder = STEPS.map((s) => s.key);
  const currentIdx = stepOrder.indexOf(currentStep);

  return (
    <div className="scan-progress">
      {STEPS.map((step, i) => {
        let state = "pending";
        if (status === "completed") state = "done";
        else if (i < currentIdx) state = "done";
        else if (i === currentIdx) state = "active";

        return (
          <div key={step.key} className={`progress-step ${state}`}>
            <span className={`step-dot ${state === "active" ? "pulsing" : ""}`} />
            <div>
              <div style={{ fontWeight: 600, fontSize: 12 }}>{step.label}</div>
              <div style={{ fontSize: 10, opacity: 0.7 }}>{step.desc}</div>
            </div>
            {state === "done" && <span style={{ marginLeft: "auto", fontSize: 11 }}>Done</span>}
            {state === "active" && <span style={{ marginLeft: "auto", fontSize: 11 }}>Running...</span>}
          </div>
        );
      })}
    </div>
  );
}

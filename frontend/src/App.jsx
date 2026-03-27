import React, { useState, useEffect } from "react";
import Dashboard from "./pages/Dashboard";
import ScanPage from "./pages/ScanPage";
import HistoryPage from "./pages/HistoryPage";
import AnalyticsPage from "./pages/AnalyticsPage";
import { getSenderConfig } from "./utils/api";
import "./App.css";

const PAGES = {
  dashboard: Dashboard,
  scan: ScanPage,
  analytics: AnalyticsPage,
  history: HistoryPage,
};

export default function App() {
  const [page, setPage] = useState("dashboard");
  // Global alert recipient — passed into ScanPage so every scan can auto-alert
  const [alertRecipient, setAlertRecipient] = useState("");
  const [senderEmail, setSenderEmail] = useState("");

  useEffect(() => {
    // Fetch the sender email configured in .env so the sidebar can display it
    getSenderConfig()
      .then((cfg) => { if (cfg.email) setSenderEmail(cfg.email); })
      .catch(() => {});
  }, []);

  const Page = PAGES[page];

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="brand">
          <span className="brand-icon">[ ]</span>
          <span className="brand-name">VulnScan</span>
        </div>

        <ul>
          {[
            { id: "dashboard",  label: "Dashboard" },
            { id: "scan",       label: "New Scan" },
            { id: "analytics",  label: "Analytics" },
            { id: "history",    label: "Scan History" },
          ].map(({ id, label }) => (
            <li
              key={id}
              className={page === id ? "active" : ""}
              onClick={() => setPage(id)}
            >
              {label}
            </li>
          ))}
        </ul>

        {/* ── Alert Settings ─────────────────────────────── */}
        <div className="sidebar-alert-section">
          <div className="sidebar-section-title">Alert Settings</div>

          <div style={{ marginBottom: 10 }}>
            <div className="form-label" style={{ marginBottom: 4 }}>Sender (from .env)</div>
            <div style={{
              fontSize: 11, color: senderEmail ? "var(--green)" : "var(--text-muted)",
              fontFamily: "var(--font-mono)", wordBreak: "break-all",
            }}>
              {senderEmail || "ALERT_EMAIL not set"}
            </div>
          </div>

          <div>
            <div className="form-label" style={{ marginBottom: 4 }}>Alert Recipient</div>
            <input
              className="form-input"
              style={{ fontSize: 11, padding: "7px 10px" }}
              type="email"
              placeholder="recipient@email.com"
              value={alertRecipient}
              onChange={(e) => setAlertRecipient(e.target.value)}
            />
            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
              Auto-alerts on HIGH / CRITICAL scans
            </div>
          </div>
        </div>

        <div className="sidebar-footer">Internship Project v1.0</div>
      </nav>

      <main className="content">
        {/* Pass alertRecipient into every page; ScanPage uses it */}
        <Page alertRecipient={alertRecipient} />
      </main>
    </div>
  );
}

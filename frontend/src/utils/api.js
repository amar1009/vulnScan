// Centralized API calls to the FastAPI backend
import axios from "axios";

const api = axios.create({ baseURL: "/api" });

/** Start a new scan */
export async function startScan(target, scanType = "basic", alertEmail = "") {
  const { data } = await api.post("/scan", {
    target,
    scan_type: scanType,
    alert_email: alertEmail || null,
  });
  return data;
}

/** Poll scan status by ID */
export async function getScan(scanId) {
  const { data } = await api.get(`/scan/${scanId}`);
  return data;
}

/** Fetch all scans */
export async function listScans() {
  const { data } = await api.get("/scans");
  return data;
}

/** Delete a scan record */
export async function deleteScan(scanId) {
  const { data } = await api.delete(`/scan/${scanId}`);
  return data;
}

/** Manually send an alert email for a completed scan */
export async function sendAlert(scanId, recipient) {
  const { data } = await api.post("/alert/send", { scan_id: scanId, recipient });
  return data;
}

/** Get configured sender email from backend */
export async function getSenderConfig() {
  const { data } = await api.get("/config/sender");
  return data;
}

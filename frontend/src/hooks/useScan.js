// Hook that polls a scan until it reaches a terminal state (completed | error)
import { useState, useEffect, useRef } from "react";
import { getScan } from "../utils/api";

const POLL_INTERVAL = 2000; // ms

export function useScan(scanId) {
  const [scan, setScan] = useState(null);
  const [error, setError] = useState(null);
  const timerRef = useRef(null);

  useEffect(() => {
    if (!scanId) return;

    const poll = async () => {
      try {
        const data = await getScan(scanId);
        setScan(data);
        if (data.status === "completed" || data.status === "error") {
          clearInterval(timerRef.current);
        }
      } catch (err) {
        setError(err.message);
        clearInterval(timerRef.current);
      }
    };

    poll(); // immediate first fetch
    timerRef.current = setInterval(poll, POLL_INTERVAL);

    return () => clearInterval(timerRef.current);
  }, [scanId]);

  return { scan, error };
}

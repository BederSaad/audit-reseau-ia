import { useState, useEffect, useRef, useCallback } from 'react';
import { getStatus, getResults } from '../api/client';

export function useScan(scanId) {
  const [status, setStatus]   = useState(null);
  const [results, setResults] = useState(null);
  const [error, setError]     = useState(null);
  const intervalRef = useRef(null);

  const stopPolling = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  const fetchResults = useCallback(async (id) => {
    try {
      const res = await getResults(id);
      setResults(res.data);
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to fetch results');
    }
  }, []);

  useEffect(() => {
    if (!scanId) return;

    setError(null);
    setResults(null);

    const poll = async () => {
      try {
        const res = await getStatus(scanId);
        const data = res.data;
        setStatus(data);

        if (data.status === 'done' || data.status === 'failed') {
          stopPolling();
          if (data.status === 'done') {
            await fetchResults(scanId);
          }
        }
      } catch (err) {
        if (err?.response?.status !== 202) {
          setError(err?.response?.data?.detail || 'Polling error');
          stopPolling();
        }
      }
    };

    poll(); // immediate first call
    intervalRef.current = setInterval(poll, 2000);

    return () => stopPolling();
  }, [scanId, stopPolling, fetchResults]);

  return { status, results, error };
}

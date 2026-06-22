import { useState, useEffect, useCallback } from 'react';
import { getScans } from '../api/client';

export function useScansList() {
  const [scans, setScans]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getScans();
      setScans(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      setError(err?.response?.data?.detail || 'Impossible de charger l\'historique des scans');
      setScans([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  return { scans, loading, error, refresh };
}

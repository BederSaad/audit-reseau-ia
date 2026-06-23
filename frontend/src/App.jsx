import { useState, useEffect, useCallback } from 'react';
import './App.css';
import { ToastProvider, useToast } from './components/Toast';
import ScanForm        from './components/ScanForm';
import StatusBar       from './components/StatusBar';
import KpiCards        from './components/KpiCards';
import DeviceTable     from './components/DeviceTable';
import EmptyState      from './components/EmptyState';
import WorkflowVisualizer from './components/WorkflowVisualizer';
import SeverityDonut   from './components/charts/SeverityDonut';
import TopHostsBar     from './components/charts/TopHostsBar';
import HealthGauge     from './components/charts/HealthGauge';
import TiltCard        from './components/TiltCard';
import AiAnalysisCard  from './components/AiAnalysisCard';
import PdfDownloadButton from './components/PdfDownloadButton';
import axios from 'axios';

const API = axios.create({ baseURL: 'http://localhost:8000' });

function fmtDate(dt) {
  if (!dt) return '—';
  return new Date(dt).toLocaleString('fr-FR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}
function fmtDuration(start, end) {
  if (!start || !end) return '—';
  const s = Math.round((new Date(end) - new Date(start)) / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}
function shortId(id) { return id ? id.slice(0, 8) : '—'; }

// ── Scan status poller ─────────────────────────────────────────────────────
function useScan(scanId) {
  const [status, setStatus]   = useState(null);
  const [results, setResults] = useState(null);
  const [error, setError]     = useState(null);

  useEffect(() => {
    if (!scanId) return;
    setStatus(null); setResults(null); setError(null);

    let stopped = false;
    const poll = async () => {
      try {
        const { data } = await API.get(`/scan/${scanId}/status`);
        if (stopped) return;
        setStatus(data);
        if (data.status === 'done') {
          try {
            const { data: r } = await API.get(`/scan/${scanId}/results`);
            if (!stopped) setResults(r);
          } catch (e) {
            if (!stopped) setError('Failed to fetch results');
          }
        } else if (data.status === 'failed') {
          if (!stopped) setError(`Scan failed: ${data.fail_reason || 'unknown error'}`);
        } else {
          // still running — poll again
          setTimeout(poll, 2000);
        }
      } catch (e) {
        if (!stopped) {
          setError(e?.response?.data?.detail || 'Connection error');
          setTimeout(poll, 3000);
        }
      }
    };
    poll();
    return () => { stopped = true; };
  }, [scanId]);

  return { status, results, error };
}

// ── Latest scans list ──────────────────────────────────────────────────────
function useScansList() {
  const [scans, setScans]     = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const refresh = useCallback(async () => {
    try {
      const { data } = await API.get('/scans');
      setScans(Array.isArray(data) ? data : []);
      setError(null);
    } catch (e) {
      setError(e?.response?.data?.detail || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  return { scans, loading, error, refresh };
}

// ── Main Dashboard ─────────────────────────────────────────────────────────
function Dashboard() {
  const toast = useToast();

  const [activeScanId, setActiveScanId] = useState(null);
  const { status, results, error: scanErr } = useScan(activeScanId);
  const { scans, loading: scansLoading, error: scansErr, refresh } = useScansList();

  const [dismissedErr, setDismissedErr]         = useState(false);
  const [dismissedScanErr, setDismissedScanErr] = useState(false);

  // Decide which data to show
  // Priority: live results > latest scan from /scans
  const liveData      = results;
  const historyData   = scans[0] ?? null;
  const displayData   = liveData ?? historyData;

  // Hosts array — results uses "hosts", /scans uses "discovered_ips"
  const displayHosts = liveData
    ? (liveData.hosts ?? [])
    : (historyData?.discovered_ips ?? []);

  const isRunning = status?.status === 'running';

  useEffect(() => {
    if (status?.status === 'done') {
      toast('✅ Scan terminé avec succès !', 'success');
      refresh();
    }
    if (status?.status === 'failed') {
      toast('❌ Le scan a échoué.', 'error');
    }
  }, [status?.status]);

  useEffect(() => { if (scanErr) setDismissedScanErr(false); }, [scanErr]);

  const handleScanStart = async (target) => {
    setDismissedScanErr(false);
    try {
      const { data } = await API.post('/scan', { target });
      setActiveScanId(data.scan_id);
      toast(`🚀 Scan lancé sur ${target}`, 'info');
    } catch (e) {
      toast(`❌ ${e?.response?.data?.detail || 'Impossible de lancer le scan'}`, 'error');
    }
  };

  const hasData = displayHosts.length > 0;
  const allVulns = displayHosts.flatMap(h => h.vulnerabilities ?? []);

  return (
    <div className="app">
      {/* ── Top Bar ── */}
      <header className="topbar">
        <div className="topbar__logo">
          <span className="topbar__icon">🛡️</span>
          <div>
            <div className="topbar__title">Audit Réseau IA</div>
            <div className="topbar__sub">Plateforme d'audit de sécurité réseau</div>
          </div>
        </div>
        <div className="topbar__center">
          <ScanForm onScanStart={handleScanStart} isRunning={isRunning} />
        </div>
        <div className="topbar__right">
          <StatusBar status={status} />
        </div>
      </header>

      {/* ── Main content ── */}
      <main className="main-content">

        {/* Error banners */}
        {scansErr && !dismissedErr && (
          <div className="error-banner">
            ⚠️ {scansErr}
            <button onClick={() => setDismissedErr(true)}>×</button>
          </div>
        )}
        {scanErr && !dismissedScanErr && (
          <div className="error-banner">
            ⚠️ {scanErr}
            <button onClick={() => setDismissedScanErr(true)}>×</button>
          </div>
        )}

        {/* Current scan metadata strip */}
        {displayData && (
          <div className="scan-meta glass-panel">
            <div className="scan-meta__item">
              <span className="scan-meta__label">Scan ID</span>
              <code className="scan-meta__id">{shortId(displayData.scan_id ?? displayData.id)}</code>
            </div>
            <div className="scan-meta__item">
              <span className="scan-meta__label">Cible</span>
              <code className="mono">{displayData.target ?? '—'}</code>
            </div>
            <div className="scan-meta__item">
              <span className="scan-meta__label">Statut</span>
              <span className={`scan-meta__status scan-meta__status--${displayData.status}`}>
                {displayData.status ?? '—'}
              </span>
            </div>
            <div className="scan-meta__item">
              <span className="scan-meta__label">Démarré le</span>
              <span>{fmtDate(displayData.started_at)}</span>
            </div>
            <div className="scan-meta__item">
              <span className="scan-meta__label">Terminé le</span>
              <span>{fmtDate(displayData.finished_at)}</span>
            </div>
            <div className="scan-meta__item">
              <span className="scan-meta__label">Durée</span>
              <span>{fmtDuration(displayData.started_at, displayData.finished_at)}</span>
            </div>
            <div className="scan-meta__item">
              <span className="scan-meta__label">Appareils</span>
              <span className="scan-meta__bold">{displayData.hosts_found ?? 0}</span>
            </div>
            {displayData.health_score != null && (
              <div className="scan-meta__item">
                <span className="scan-meta__label">Score Santé</span>
                <span className={`scan-meta__bold scan-meta__health--${
                  displayData.health_score >= 80 ? 'good' :
                  displayData.health_score >= 50 ? 'medium' : 'bad'
                }`}>
                  {displayData.health_score}/100
                </span>
              </div>
            )}
            {/* PDF download button */}
            {displayData.status === 'done' && (
              <div className="scan-meta__item" style={{ marginLeft: 'auto' }}>
                <PdfDownloadButton scanId={displayData.scan_id ?? displayData.id} />
              </div>
            )}
          </div>
        )}

        {/* Workflow Visualizer (show when running or if we have data) */}
        {(isRunning || hasData) && (
          <WorkflowVisualizer status={status ?? displayData} hosts={displayHosts} />
        )}

        {/* Empty state */}
        {!scansLoading && !activeScanId && scans.length === 0 && !results && (
          <EmptyState />
        )}

        {/* KPI row */}
        {(hasData || isRunning) && (
          <KpiCards
            hosts={displayHosts}
            hostsFound={displayData?.hosts_found ?? displayHosts.length}
            healthScore={displayData?.health_score ?? 100}
            loading={isRunning && !results}
          />
        )}

        {/* Charts row */}
        {hasData && allVulns.length > 0 && (
          <div className="charts-row">
            <TiltCard className="chart-card">
              <h3 className="chart-title">📊 Vulnérabilités par sévérité</h3>
              <SeverityDonut vulns={allVulns} />
            </TiltCard>
            <TiltCard className="chart-card">
              <h3 className="chart-title">📈 Top hôtes à risque</h3>
              <TopHostsBar hosts={displayHosts} />
            </TiltCard>
            <TiltCard className="chart-card">
              <h3 className="chart-title">🏥 Santé du réseau</h3>
              <HealthGauge healthScore={displayData?.health_score ?? 100} />
            </TiltCard>
          </div>
        )}

        {/* AI Audit Analysis Card */}
        {hasData && displayData?.status === 'done' && (
          <AiAnalysisCard 
            key={`${displayData.scan_id ?? displayData.id}-${displayData.status}`}
            scanId={displayData.scan_id ?? displayData.id} 
          />
        )}

        {/* Skeleton while running */}
        {isRunning && !results && (
          <div className="glass-panel" style={{ padding: 24 }}>
            <h3 className="neon-text" style={{ fontSize: '1.1rem', marginBottom: 16 }}>
              🖥️ Découverte en cours…
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {[1,2,3,4].map(i => (
                <div key={i} className="skeleton" style={{ height: 48, borderRadius: 10 }} />
              ))}
            </div>
          </div>
        )}

        {/* Device table */}
        {hasData && (
          <DeviceTable hosts={displayHosts} loading={false} />
        )}

      </main>
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <Dashboard />
    </ToastProvider>
  );
}

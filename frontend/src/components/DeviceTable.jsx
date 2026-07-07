import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import HostDetailPanel from './HostDetailPanel';
import SkeletonLoader from './SkeletonLoader';
import './DeviceTable.css';

function UnknownVal({ value, fallback }) {
  if (!value || value === 'Unknown' || value === 'Unknown Device') {
    return (
      <span className="unknown-val">
        {fallback || 'Inconnu'}
      </span>
    );
  }
  return <>{value}</>;
}

function ConfidenceBadge({ confidence }) {
  if (!confidence || confidence === 'unknown') return null;
  const colors = {
    confirmed: 'var(--neon-safe)',
    inferred: 'var(--neon-medium)',
    unknown: 'var(--color-text-muted)',
  };
  return (
    <span className="confidence-badge" style={{ background: colors[confidence] }}>
      {confidence}
    </span>
  );
}

function RiskBadge({ score, criticality }) {
  const color = score >= 61 ? 'var(--neon-critical)' : score >= 41 ? 'var(--neon-high)' : score >= 21 ? 'var(--neon-medium)' : 'var(--neon-safe)';
  return (
    <div className="risk-badge">
      <div className="risk-circle" style={{ borderColor: color, color }}>
        {Math.round(score)}
      </div>
      <span className="risk-label">{criticality}</span>
    </div>
  );
}

function HostRow({ host, index }) {
  const [open, setOpen] = useState(false);
  const isAudited = host.audit_status === 'completed';
  const vulnCount = host.vulnerabilities?.length ?? 0;
  const maxSev = getMaxSeverity(host.vulnerabilities ?? []);
  const hasCredIssues = host.vulnerabilities?.some(v => v.source === 'credential_test' && v.severity === 'critical');
  const displayName = host.hostname !== 'Unknown' ? host.hostname : host.device_classification;

  return (
    <>
      <tr
        className={`device-row ${open ? 'device-row--open' : ''} ${hasCredIssues ? 'device-row--cred-warning' : ''}`}
        onClick={() => setOpen(o => !o)}
      >
        <td>
          <span className="status-dot-pair">
            <span className={`status-dot status-dot--${host.status || 'up'}`} />
            {hasCredIssues && <span className="cred-warning-dot" title="Identifiants faibles détectés">🔑</span>}
          </span>
        </td>
        <td>
          <div className="host-ip-wrap">
            <code className="host-ip">{host.ip}</code>
            <span className="host-index">#{index + 1}</span>
          </div>
        </td>
        <td>
          <div className="hostname-wrap">
            <UnknownVal value={host.hostname} fallback={host.device_classification} />
            {host.hostname_confidence > 0 && (
              <span className="confidence-pct">({Math.round(host.hostname_confidence * 100)}%)</span>
            )}
          </div>
        </td>
        <td>
          <div className="os-wrap">
            <UnknownVal value={host.os} />
            <ConfidenceBadge confidence={host.os_confidence} />
          </div>
        </td>
        <td>
          <UnknownVal value={host.device_classification} />
        </td>
        <td>
          <span className="mac-addr"><UnknownVal value={host.mac_address} /></span>
          {host.mac_vendor && <div className="mac-vendor">{host.mac_vendor}</div>}
        </td>
        <td><RiskBadge score={host.risk_score || 0} criticality={host.criticality || 'Unknown'} /></td>
        <td>
          <span className={`badge ${isAudited ? 'badge--audited' : 'badge--detected'}`}>
            {isAudited ? 'Audité' : 'Détecté'}
          </span>
        </td>
        <td>
          {vulnCount > 0 ? (
            <span className={`badge badge--${maxSev}`}>{vulnCount} vuln{vulnCount > 1 ? 's' : ''}</span>
          ) : (
            <span className="no-vuln">—</span>
          )}
        </td>
        <td><span className="services-count">{host.services?.length ?? 0} ports</span></td>
        <td>
          <motion.span className="chevron" animate={{ rotate: open ? 180 : 0 }} transition={{ type: 'spring', stiffness: 200, damping: 20 }}>▼</motion.span>
        </td>
      </tr>
      <AnimatePresence>
        {open && (
          <tr className="detail-row">
            <td colSpan={11} style={{ padding: 0 }}>
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.35, ease: 'easeInOut' }}
                style={{ overflow: 'hidden' }}
              >
                <HostDetailPanel host={host} />
              </motion.div>
            </td>
          </tr>
        )}
      </AnimatePresence>
    </>
  );
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
function getMaxSeverity(vulns) {
  for (const s of SEV_ORDER) {
    if (vulns.some(v => (v.severity || '').toLowerCase() === s)) return s;
  }
  return 'info';
}

export default function DeviceTable({ hosts, loading }) {
  if (loading) {
    return (
      <div className="glass-panel" style={{ padding: 24 }}>
        <h3 className="neon-text" style={{ padding: '0 0 16px', fontSize: '1.2rem', margin: 0 }}>🖥️ Appareils sur le réseau</h3>
        <SkeletonLoader rows={4} />
      </div>
    );
  }

  if (!hosts || hosts.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: 24 }}>
        <h3 className="neon-text" style={{ padding: '0 0 16px', fontSize: '1.2rem', margin: 0 }}>🖥️ Appareils sur le réseau</h3>
        <p className="empty-message">Aucun appareil découvert.</p>
      </div>
    );
  }

  return (
    <div className="glass-panel device-card anim-enter anim-enter--d1">
      <div className="device-card__header">
        <h3 className="neon-text" style={{ fontSize: '1.2rem', margin: 0 }}>🖥️ Appareils sur le réseau</h3>
        <span className="device-total">{hosts.length} appareil{hosts.length > 1 ? 's' : ''}</span>
      </div>
      <div className="table-wrap">
        <table className="data-table device-table">
          <thead>
            <tr>
              <th></th>
              <th>IP</th>
              <th>Hostname</th>
              <th>OS</th>
              <th>Device</th>
              <th>MAC / Vendor</th>
              <th>Risk</th>
              <th>Status</th>
              <th>Vulnérabilités</th>
              <th>Ports</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h, i) => (
              <HostRow key={h.ip || i} host={h} index={i} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
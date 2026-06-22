import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import HostDetailPanel from './HostDetailPanel';
import SkeletonLoader from './SkeletonLoader';
import './DeviceTable.css';

function UnknownVal({ value }) {
  if (!value || value === 'Unknown') {
    return (
      <span className="unknown-val" style={{ color: 'var(--color-text-muted)', fontStyle: 'italic', fontSize: '0.85rem' }}>
        Inconnu
      </span>
    );
  }
  return <>{value}</>;
}

function HostRow({ host, index }) {
  const [open, setOpen] = useState(false);
  const isAudited = (host.services?.length ?? 0) > 0;
  const vulnCount = host.vulnerabilities?.length ?? 0;
  const maxSev    = getMaxSeverity(host.vulnerabilities ?? []);

  return (
    <>
      <tr
        className={`device-row ${open ? 'device-row--open' : ''}`}
        onClick={() => setOpen(o => !o)}
      >
        <td>
          <span className="status-dot-pair">
            <span className={`status-dot status-dot--${host.status || 'up'}`} />
          </span>
        </td>
        <td>
          <div className="host-ip-wrap">
            <code className="host-ip">{host.ip}</code>
            <span className="host-index">#{index + 1}</span>
          </div>
        </td>
        <td><UnknownVal value={host.hostname} /></td>
        <td><UnknownVal value={host.os} /></td>
        <td>
          <span className="mac-addr"><UnknownVal value={host.mac_address} /></span>
        </td>
        <td>
          <span className={`badge ${isAudited ? 'badge--audited' : 'badge--detected'}`}>
            {isAudited ? 'Audité' : 'Détecté'}
          </span>
        </td>
        <td>
          {vulnCount > 0 ? (
            <span className={`badge badge--${maxSev}`}>{vulnCount} vuln{vulnCount > 1 ? 's' : ''}</span>
          ) : (
            <span style={{ color: 'var(--color-text-muted)', fontSize: '0.8rem' }}>—</span>
          )}
        </td>
        <td>
          <span className="services-count">{host.services?.length ?? 0} ports</span>
        </td>
        <td>
          <motion.span 
            className="chevron" 
            animate={{ rotate: open ? 180 : 0 }} 
            transition={{ type: "spring", stiffness: 200, damping: 20 }}
          >
            ▼
          </motion.span>
        </td>
      </tr>
      <AnimatePresence>
        {open && (
          <tr className="detail-row">
            <td colSpan={9} style={{ padding: 0 }}>
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.3, ease: "easeInOut" }}
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
        <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.9rem', padding: '12px 0' }}>
          Aucun appareil découvert.
        </p>
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
              <th>MAC</th>
              <th>Type</th>
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

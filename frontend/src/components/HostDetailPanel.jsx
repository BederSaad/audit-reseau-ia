import { useState } from 'react';
import './HostDetailPanel.css';

const SEV_WEIGHTS = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };

function UnknownVal({ value }) {
  if (!value || value === 'Unknown') {
    return (
      <span className="unknown-val" style={{ color: 'var(--color-text-muted)', fontStyle: 'italic', fontSize: '0.85rem' }}>
        Inconnu
      </span>
    );
  }
  return <span>{value}</span>;
}

function SevBadge({ sev }) {
  const s = (sev || 'info').toLowerCase();
  return <span className={`badge badge--${s}`}>{sev}</span>;
}

function SourceBadge({ source }) {
  if (!source) return null;
  
  const sourceConfig = {
    'credential_test': { 
      label: '🔑 Credentials', 
      className: 'badge--cred',
      color: '#FF2D55' 
    },
    'nuclei': { 
      label: '🔍 Nuclei', 
      className: 'badge--nuclei',
      color: '#00E5FF' 
    },
    'nvd': { 
      label: '🌐 NVD', 
      className: 'badge--nvd',
      color: '#B500FF' 
    }
  };
  
  const config = sourceConfig[source] || { label: source, className: '', color: '#94A3B8' };
  
  return (
    <span 
      className={`badge badge--source ${config.className}`}
      style={{ 
        borderColor: config.color,
        color: config.color,
        boxShadow: `0 0 8px ${config.color}40`
      }}
      title={`Source: ${source}`}
    >
      {config.label}
    </span>
  );
}

function CvssBar({ score }) {
  if (score == null) return <span className="unknown-val"><em>N/A</em></span>;
  const pct = Math.min(100, (score / 10) * 100);
  const color = score >= 9 ? '#DC2626' : score >= 7 ? '#EA580C' : score >= 4 ? '#CA8A04' : '#2563EB';
  return (
    <div className="cvss-bar-wrap">
      <div className="cvss-bar">
        <div className="cvss-bar__fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="cvss-score">{score.toFixed(1)}</span>
    </div>
  );
}

function DescriptionCell({ text }) {
  const [expanded, setExpanded] = useState(false);
  if (!text) return <UnknownVal value={null} />;
  const short = text.length > 120;
  return (
    <span>
      {expanded || !short ? text : text.slice(0, 120) + '…'}
      {short && (
        <button className="see-more-btn" onClick={() => setExpanded(e => !e)}>
          {expanded ? ' voir moins' : ' voir plus'}
        </button>
      )}
    </span>
  );
}

export default function HostDetailPanel({ host }) {
  const services = host.services ?? [];
  const vulns    = host.vulnerabilities ?? [];

  // Sort vulns by severity weight descending
  const sortedVulns = [...vulns].sort((a, b) =>
    (SEV_WEIGHTS[(b.severity||'').toLowerCase()] ?? 0) -
    (SEV_WEIGHTS[(a.severity||'').toLowerCase()] ?? 0)
  );

  return (
    <div className="detail-panel">
      {/* ── Host summary strip ── */}
      <div className="detail-panel__summary">
        <div className="detail-summary-item">
          <span className="detail-summary-label">IP</span>
          <code>{host.ip}</code>
        </div>
        <div className="detail-summary-item">
          <span className="detail-summary-label">Hostname</span>
          <UnknownVal value={host.hostname} />
        </div>
        <div className="detail-summary-item">
          <span className="detail-summary-label">OS</span>
          <UnknownVal value={host.os} />
        </div>
        <div className="detail-summary-item">
          <span className="detail-summary-label">MAC</span>
          <UnknownVal value={host.mac_address} />
        </div>
        <div className="detail-summary-item">
          <span className="detail-summary-label">Status</span>
          <span className="status-dot-wrap">
            <span className="status-dot status-dot--up" />
            {host.status || 'up'}
          </span>
        </div>
      </div>

      {/* ── Services table ── */}
      <div className="detail-section">
        <h4 className="detail-section__title">
          🔌 Services &amp; Ports ouverts
          <span className="detail-count">{services.length}</span>
        </h4>
        {services.length === 0 ? (
          <p className="detail-empty">Aucun port ouvert détecté sur cet appareil.</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Protocole</th>
                  <th>Service</th>
                  <th>Version</th>
                  <th>État</th>
                </tr>
              </thead>
              <tbody>
                {services.map((s, i) => (
                  <tr key={i}>
                    <td><code className="port-code">{s.port}</code></td>
                    <td><span className="proto-badge">{s.protocol || 'tcp'}</span></td>
                    <td><UnknownVal value={s.name} /></td>
                    <td><UnknownVal value={s.version} /></td>
                    <td>
                      <span className={`state-badge state-badge--${(s.state || 'open').toLowerCase()}`}>
                        {s.state || 'open'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Vulnerabilities table ── */}
      <div className="detail-section">
        <h4 className="detail-section__title">
          🛡️ Vulnérabilités
          <span className="detail-count">{vulns.length}</span>
        </h4>
        {sortedVulns.length === 0 ? (
          <p className="detail-empty">✅ Aucune vulnérabilité détectée sur cet appareil.</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table vuln-table">
              <thead>
                <tr>
                  <th>Sévérité</th>
                  <th>Source</th>
                  <th>CVE / Template</th>
                  <th>Nom</th>
                  <th>CVSS</th>
                  <th>Matcher</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {sortedVulns.map((v, i) => {
                  const sev = (v.severity || 'info').toLowerCase();
                  const isCredTest = v.source === 'credential_test';
                  const isExposureOnly = v.template_id?.startsWith('exposure-');
                  
                  return (
                    <tr
                      key={i}
                      className={isCredTest ? 'vuln-row--cred' : ''}
                      style={{ 
                        borderLeft: `3px solid var(--color-${sev === 'safe' ? 'safe' : sev})`,
                        background: isCredTest ? 'rgba(255, 45, 85, 0.05)' : undefined
                      }}
                    >
                      <td><SevBadge sev={v.severity} /></td>
                      <td><SourceBadge source={v.source} /></td>
                      <td>
                        {v.cve_id ? (
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="cve-link"
                          >
                            {v.cve_id}
                          </a>
                        ) : (
                          <span className="template-id">{v.template_id || '—'}</span>
                        )}
                      </td>
                      <td className="vuln-name">
                        {v.name || '—'}
                        {isCredTest && !isExposureOnly && (
                          <span className="cred-indicator">⚠️</span>
                        )}
                      </td>
                      <td><CvssBar score={v.cvss_score} /></td>
                      <td>
                        <UnknownVal value={v.matcher_name} />
                      </td>
                      <td className="vuln-desc">
                        <DescriptionCell text={v.description} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

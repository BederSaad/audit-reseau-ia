import { useState } from 'react';
import { motion } from 'framer-motion';
import './HostDetailPanel.css';

const SEV_COLOR = {
  critical: 'var(--neon-critical)',
  high: 'var(--neon-high)',
  medium: 'var(--neon-medium)',
  low: 'var(--neon-low)',
  info: 'var(--neon-info)',
};

function TabButton({ active, label, onClick, count }) {
  return (
    <button
      onClick={onClick}
      className={`tab-btn ${active ? 'tab-btn--active' : ''}`}
    >
      {label} {count !== undefined && <span className="tab-count">{count}</span>}
    </button>
  );
}

function Section({ title, children }) {
  return (
    <div className="detail-section">
      <h4 className="detail-section__title">{title}</h4>
      {children}
    </div>
  );
}

function InfoGrid({ items }) {
  return (
    <div className="info-grid">
      {items.map(([label, value], i) => (
        <div key={i} className="info-item">
          <div className="info-label">{label}</div>
          <div className="info-value">{value || <span className="unknown-text">Inconnu</span>}</div>
        </div>
      ))}
    </div>
  );
}

export default function HostDetailPanel({ host }) {
  const [tab, setTab] = useState('overview');
  const vulns = host.vulnerabilities || [];
  const services = host.services || [];
  const apps = host.running_applications || [];

  const criticalVulns = vulns.filter(v => v.severity === 'critical');
  const highVulns = vulns.filter(v => v.severity === 'high');

  return (
    <div className="detail-panel">
      <div className="detail-panel__header">
        <div>
          <h3>{host.device_classification || 'Unknown Device'}</h3>
          <p className="detail-sub">{host.ip} {host.ipv6 ? `· IPv6: ${host.ipv6}` : ''} {host.mac_address !== 'Unknown' ? `· MAC: ${host.mac_address}` : ''}</p>
        </div>
        <div className="detail-badges">
          {host.is_gateway && <span className="badge badge--gateway">🌐 Gateway</span>}
          {host.is_local_machine && <span className="badge badge--local">💻 This Machine</span>}
          {host.is_vm && <span className="badge badge--vm">VM</span>}
          {host.is_docker && <span className="badge badge--docker">Docker</span>}
          {host.is_wsl && <span className="badge badge--wsl">WSL</span>}
        </div>
      </div>

      {(host.risk_score > 0 || criticalVulns.length > 0) && (
        <motion.div className="risk-banner" initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
          <div className="risk-banner__score">{Math.round(host.risk_score || 0)}</div>
          <div>
            <div className="risk-banner__title">Risk Score: {host.criticality || 'Unknown'}</div>
            <div className="risk-banner__stats">
              {criticalVulns.length} Critical · {highVulns.length} High · {vulns.length} Total
            </div>
          </div>
        </motion.div>
      )}

      <div className="tab-bar">
        <TabButton active={tab === 'overview'} label="Overview" onClick={() => setTab('overview')} />
        <TabButton active={tab === 'network'} label="Network" onClick={() => setTab('network')} />
        <TabButton active={tab === 'services'} label="Services" count={services.length} onClick={() => setTab('services')} />
        <TabButton active={tab === 'vulns'} label="Vulnerabilities" count={vulns.length} onClick={() => setTab('vulns')} />
        <TabButton active={tab === 'apps'} label="Apps" count={apps.length} onClick={() => setTab('apps')} />
        {host.evidence && host.evidence.length > 0 && (
          <TabButton active={tab === 'evidence'} label="Evidence" count={host.evidence.length} onClick={() => setTab('evidence')} />
        )}
      </div>

      <div className="tab-content">
        {tab === 'overview' && (
          <>
            <Section title="Host Identity">
              <InfoGrid items={[
                ['Hostname', host.hostname],
                ['Source', host.hostname_source],
                ['Confidence', `${Math.round((host.hostname_confidence || 0) * 100)}%`],
                ['Device Type', host.device_type],
                ['Classification', host.device_classification],
                ['Manufacturer', host.manufacturer],
                ['OS', host.os],
                ['OS Family', host.os_family],
                ['OS Version', host.os_version],
                ['OS Confidence', host.os_confidence],
                ['Architecture', host.architecture],
                ['Uptime', host.uptime],
              ]} />
            </Section>
            <Section title="Audit Metadata">
              <InfoGrid items={[
                ['Audit Status', host.audit_status],
                ['Last Scan', host.last_scan ? new Date(host.last_scan).toLocaleString() : 'N/A'],
                ['Discovery Method', host.discovery_method],
                ['Scanned', host.scanned ? 'Yes' : 'No'],
              ]} />
            </Section>
          </>
        )}

        {tab === 'network' && (
          <Section title="Network Identity">
            <InfoGrid items={[
              ['IPv4', host.ip],
              ['IPv6', host.ipv6],
              ['MAC Address', host.mac_address],
              ['MAC Vendor', host.mac_vendor],
              ['Network Interface', host.network_interface],
              ['Is Gateway', host.is_gateway ? 'Yes' : 'No'],
              ['Is Local Machine', host.is_local_machine ? 'Yes' : 'No'],
              ['Is VM', host.is_vm ? 'Yes' : 'No'],
              ['Is Docker', host.is_docker ? 'Yes' : 'No'],
              ['Is WSL', host.is_wsl ? 'Yes' : 'No'],
            ]} />
          </Section>
        )}

        {tab === 'services' && (
          <div className="table-wrap">
            {services.length === 0 ? (
              <p className="empty-message">No services detected.</p>
            ) : (
              <table className="data-table">
                <thead>
                  <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Banner</th></tr>
                </thead>
                <tbody>
                  {services.map((s, i) => (
                    <tr key={i}>
                      <td><code className="port-code">{s.port}</code></td>
                      <td><span className="proto-badge">{s.protocol}</span></td>
                      <td>{s.name}</td>
                      <td>{s.version}</td>
                      <td className="banner-cell">{s.banner || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === 'vulns' && (
          <div className="vuln-list">
            {vulns.length === 0 ? (
              <p className="empty-message">No vulnerabilities detected.</p>
            ) : (
              vulns.map((v, i) => (
                <motion.div
                  key={i}
                  className={`vuln-card ${v.source === 'credential_test' ? 'vuln-card--cred' : ''}`}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.03 }}
                  style={{ borderLeftColor: SEV_COLOR[v.severity] || 'var(--color-text-muted)' }}
                >
                  <div className="vuln-card__header">
                    <div className="vuln-card__name">{v.name}</div>
                    <div className="vuln-card__meta">
                      <span className="severity-badge" style={{ background: `${SEV_COLOR[v.severity]}20`, color: SEV_COLOR[v.severity] }}>
                        {v.severity}
                      </span>
                      {v.cvss_score && <span className="cvss-score">CVSS: {v.cvss_score}{v.cvss_estimated ? '*' : ''}</span>}
                      {v.exploit_available && <span className="exploit-badge">⚡ EXPLOIT</span>}
                    </div>
                  </div>
                  <div className="vuln-card__details">
                    {v.cve_id && <span className="cve-id">{v.cve_id}</span>}
                    <span className="vuln-source">Source: {v.source} · Matcher: {v.matcher_name}</span>
                  </div>
                  {v.description && <p className="vuln-desc">{v.description}</p>}
                  {v.remediation && (
                    <div className="remediation-box">
                      <strong>Remediation:</strong> {v.remediation}
                    </div>
                  )}
                  {v.references && v.references.length > 0 && (
                    <div className="refs">Refs: {v.references.join(', ')}</div>
                  )}
                </motion.div>
              ))
            )}
          </div>
        )}

        {tab === 'apps' && (
          <div className="apps-grid">
            {apps.length === 0 ? (
              <p className="empty-message">No applications detected.</p>
            ) : (
              apps.map((app, i) => (
                <div key={i} className="app-chip">
                  <span className="app-name">{app.name}</span>
                  <span className="app-version">v{app.version}</span>
                  <span className="app-port">{app.port}/{app.protocol}</span>
                </div>
              ))
            )}
          </div>
        )}

        {tab === 'evidence' && host.evidence && (
          <div className="evidence-list">
            {host.evidence.map((ev, i) => {
              if (ev.type === 'web_screenshot' || ev.type === 'auth_screenshot') {
                const pathClean = ev.path
                  .replace(/\\/g, '/')
                  .split('data/screenshots/')
                  .pop();
                const imgSrc = `http://localhost:8000/screenshots/${pathClean}`;
                return (
                  <div key={i} className="evidence-item">
                    <div className="evidence-item__title">
                      {ev.type === 'web_screenshot' ? '📷' : '🔑'} {ev.label || 'Screenshot Proof'}
                    </div>
                    <div className="evidence-item__image-wrap">
                      <a href={imgSrc} target="_blank" rel="noreferrer">
                        <img src={imgSrc} alt={ev.label} className="evidence-image" />
                      </a>
                    </div>
                  </div>
                );
              } else if (ev.type === 'text') {
                return (
                  <div key={i} className="evidence-item">
                    <div className="evidence-item__title">🖥 {ev.label || 'Connection Proof'}</div>
                    <pre className="evidence-terminal"><code>{ev.content}</code></pre>
                  </div>
                );
              }
              return null;
            })}
          </div>
        )}
      </div>
    </div>
  );
}
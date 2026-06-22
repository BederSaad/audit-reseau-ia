import React from 'react';
import TiltCard from './TiltCard';
import { useCountUp } from '../hooks/useCountUp';
import './KpiCards.css';

export default function KpiCards({ hosts = [], hostsFound = 0, healthScore = 100, loading = false }) {
  const scannedHosts   = hosts.filter(h => (h.services?.length ?? 0) > 0).length;
  const openPorts      = hosts.reduce((acc, h) => acc + (h.services?.length ?? 0), 0);
  const allVulns       = hosts.flatMap(h => h.vulnerabilities ?? []);
  const critHighVulns  = allVulns.filter(v =>
    ['critical', 'high'].includes((v.severity || '').toLowerCase())
  ).length;
  const totalVulns     = allVulns.length;

  return (
    <div className="kpi-row">
      <KpiCard label="Appareils Détectés"        value={hostsFound}    colorVar="--neon-primary"  loading={loading} delay={0}   />
      <KpiCard label="Ports Ouverts"             value={openPorts}     colorVar="--neon-low"      loading={loading} delay={0.1} />
      <KpiCard label="Vulnérabilités Totales"    value={totalVulns}    colorVar={totalVulns > 0 ? '--neon-medium' : '--neon-safe'} loading={loading} delay={0.2} />
      <KpiCard label="Crit. / Élevées"           value={critHighVulns} colorVar={critHighVulns > 0 ? '--neon-critical' : '--neon-safe'} loading={loading} delay={0.3} />
      <KpiCard label="Score Santé"               value={healthScore}   colorVar={healthScore >= 80 ? '--neon-safe' : healthScore >= 50 ? '--neon-medium' : '--neon-critical'} loading={loading} delay={0.4} suffix="/100" />
    </div>
  );
}

function KpiCard({ label, value, colorVar, loading, delay, suffix = '' }) {
  const animatedValue = useCountUp(value, 900);

  return (
    <TiltCard className="kpi-card">
      <div
        className="kpi-card__glow"
        style={{ '--card-color': `var(${colorVar})`, '--card-glow': `var(${colorVar}-glow)` }}
      />
      <div className="kpi-card__content">
        <h4 className="kpi-card__label">{label}</h4>
        <div className="kpi-card__value" style={{ color: `var(${colorVar})`, textShadow: `0 0 20px var(${colorVar}-glow)` }}>
          {loading ? (
            <span className="skeleton" style={{ width: 60, height: 40, display: 'inline-block', borderRadius: 8 }} />
          ) : (
            <>{animatedValue}{suffix}</>
          )}
        </div>
      </div>
    </TiltCard>
  );
}

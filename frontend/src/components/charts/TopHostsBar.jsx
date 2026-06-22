import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

export default function TopHostsBar({ hosts = [] }) {
  const hostScores = hosts
    .map(h => {
      const vulns = h.vulnerabilities ?? [];
      const score = vulns.reduce((acc, v) => acc + (Number(v.cvss_score) || 0), 0);
      const critCount = vulns.filter(v => (v.severity || '').toLowerCase() === 'critical').length;
      return { ip: h.ip, score: parseFloat(score.toFixed(1)), critCount, vulnCount: vulns.length };
    })
    .filter(h => h.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  if (hostScores.length === 0) {
    return (
      <div className="chart-empty">
        <span style={{ fontSize: '2.5rem' }}>🛡️</span>
        <p>Aucun hôte à risque</p>
      </div>
    );
  }

  const maxScore = hostScores[0]?.score ?? 1;

  const getColor = (score) => {
    if (score > maxScore * 0.7) return 'var(--neon-critical)';
    if (score > maxScore * 0.4) return 'var(--neon-high)';
    if (score > maxScore * 0.2) return 'var(--neon-medium)';
    return 'var(--neon-low)';
  };

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload?.length) {
      const { ip, score, critCount, vulnCount } = payload[0].payload;
      return (
        <div className="glass-tooltip">
          <div style={{ color: '#fff', fontWeight: 700, fontFamily: 'var(--font-mono)', marginBottom: 6 }}>{ip}</div>
          <div style={{ color: 'var(--neon-medium)', marginBottom: 2 }}>Score CVSS total: <strong>{score}</strong></div>
          <div style={{ color: 'var(--color-text-secondary)', fontSize: '0.8rem' }}>
            {vulnCount} vuln{vulnCount > 1 ? 's' : ''} {critCount > 0 && `· ${critCount} critique${critCount > 1 ? 's' : ''}`}
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{ width: '100%', height: 260 }}>
      <ResponsiveContainer>
        <BarChart data={hostScores} layout="vertical" margin={{ top: 5, right: 30, left: 50, bottom: 5 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category" dataKey="ip" axisLine={false} tickLine={false}
            tick={{ fill: 'var(--color-text-secondary)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
          <Bar dataKey="score" radius={[0, 6, 6, 0]} barSize={22}>
            {hostScores.map((entry, i) => (
              <Cell key={i} fill={getColor(entry.score)} style={{ filter: `drop-shadow(0 0 5px ${getColor(entry.score)})` }} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

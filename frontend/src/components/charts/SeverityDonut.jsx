import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';

const SEV_CONFIG = {
  critical: { label: 'Critique', color: '#FF2D55', glow: 'rgba(255,45,85,0.5)' },
  high:     { label: 'Élevée',   color: '#FF8A00', glow: 'rgba(255,138,0,0.5)' },
  medium:   { label: 'Moyenne',  color: '#FFD60A', glow: 'rgba(255,214,10,0.5)' },
  low:      { label: 'Faible',   color: '#0AFFEF', glow: 'rgba(10,255,239,0.5)' },
  info:     { label: 'Info',     color: '#39FF6E', glow: 'rgba(57,255,110,0.5)' },
};

export default function SeverityDonut({ vulns = [], healthScore }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  vulns.forEach(v => {
    const sev = (v.severity || 'info').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  });

  const data = Object.entries(SEV_CONFIG)
    .map(([key, cfg]) => ({ name: cfg.label, value: counts[key], color: cfg.color, glow: cfg.glow }))
    .filter(d => d.value > 0);

  const total = vulns.length;

  if (total === 0) {
    return (
      <div className="chart-empty">
        <span style={{ fontSize: '2.5rem' }}>🎉</span>
        <p>Aucune vulnérabilité détectée</p>
      </div>
    );
  }

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload?.length) {
      const { name, value, payload: pl } = payload[0];
      const pct = ((value / total) * 100).toFixed(1);
      return (
        <div className="glass-tooltip">
          <span style={{ color: pl.color, fontWeight: 800, marginRight: 8 }}>{name}</span>
          <span>{value} ({pct}%)</span>
        </div>
      );
    }
    return null;
  };

  const scoreColor = (healthScore ?? 100) < 50 ? '#FF2D55' : (healthScore ?? 100) < 80 ? '#FF8A00' : '#39FF6E';

  return (
    <div style={{ width: '100%', height: 260, position: 'relative' }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data} dataKey="value" nameKey="name"
            cx="50%" cy="50%"
            innerRadius={68} outerRadius={90}
            stroke="rgba(0,0,0,0.5)" strokeWidth={3} paddingAngle={3}
          >
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color} style={{ filter: `drop-shadow(0 0 6px ${entry.glow})` }} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend
            iconType="circle" iconSize={8}
            formatter={(value) => <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.75rem' }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>

      {/* Center label */}
      <div className="donut-center">
        <div className="donut-center__val" style={{ color: scoreColor, textShadow: `0 0 12px ${scoreColor}`, fontSize: '2rem' }}>
          {healthScore ?? '—'}
        </div>
        <div className="donut-center__lbl">Santé</div>
        <div className="donut-center__sub">{total} vulns</div>
      </div>
    </div>
  );
}

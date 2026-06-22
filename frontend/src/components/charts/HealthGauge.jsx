import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { useCountUp } from '../../hooks/useCountUp';

export default function HealthGauge({ healthScore = 100 }) {
  const score = Math.max(0, Math.min(100, healthScore));
  const animatedScore = useCountUp(score, 1200);

  let color = 'var(--neon-safe)';
  let glow  = 'var(--neon-safe-glow)';
  let label = 'Optimal';
  if (score < 50) { color = 'var(--neon-critical)'; glow = 'var(--neon-critical-glow)'; label = 'Critique'; }
  else if (score < 80) { color = 'var(--neon-high)'; glow = 'var(--neon-high-glow)'; label = 'À surveiller'; }

  const data = [
    { value: animatedScore,       color: color },
    { value: 100 - animatedScore, color: 'rgba(255,255,255,0.04)' },
  ];

  return (
    <div style={{ width: '100%', height: 260, position: 'relative' }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data} cx="50%" cy="72%"
            startAngle={180} endAngle={0}
            innerRadius={75} outerRadius={95}
            dataKey="value" stroke="none"
          >
            {data.map((entry, i) => (
              <Cell
                key={i} fill={entry.color}
                style={{ filter: i === 0 ? `drop-shadow(0 0 10px ${glow})` : 'none' }}
              />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>

      <div className="donut-center" style={{ top: '62%' }}>
        <div className="donut-center__val" style={{ color, textShadow: `0 0 20px ${glow}`, fontSize: '2.5rem', fontWeight: 800 }}>
          {animatedScore}
        </div>
        <div className="donut-center__lbl" style={{ fontSize: '0.85rem', marginTop: 2 }}>/ 100</div>
        <div className="donut-center__sub" style={{ color, marginTop: 4, fontSize: '0.75rem', fontWeight: 700 }}>{label}</div>
      </div>
    </div>
  );
}

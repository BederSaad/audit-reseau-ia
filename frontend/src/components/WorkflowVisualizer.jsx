import React from 'react';
import { motion } from 'framer-motion';
import './WorkflowVisualizer.css';

export default function WorkflowVisualizer({ status, hosts = [] }) {
  const st = status?.status;
  const hostsFound = status?.hosts_found ?? hosts.length ?? 0;
  const totalVulns = hosts.reduce((a, h) => a + (h.vulnerabilities?.length ?? 0), 0);

  let currentPhase = -1; // idle
  if (st === 'running') {
    currentPhase = hostsFound > 0 ? 1 : 0;
  } else if (st === 'done') {
    currentPhase = 3;
  } else if (st === 'failed') {
    currentPhase = -2;
  }

  const isRunning = st === 'running';
  const isFailed  = st === 'failed';

  const phases = [
    { title: 'Découverte', icon: '📡', sub: hostsFound > 0 ? `${hostsFound} hôtes` : isRunning ? 'En cours…' : '' },
    { title: 'Services',   icon: '🔍', sub: hosts.length > 0 ? `${hosts.filter(h => (h.services?.length ?? 0) > 0).length} audités` : isRunning ? 'En cours…' : '' },
    { title: 'Vulnérabilités', icon: '🛡️', sub: totalVulns > 0 ? `${totalVulns} trouvées` : st === 'done' ? '0 trouvées' : '' },
  ];

  return (
    <div className="workflow-vis">
      {phases.map((phase, i) => (
        <React.Fragment key={i}>
          <Node
            title={phase.title}
            icon={phase.icon}
            sub={phase.sub}
            active={currentPhase >= i}
            complete={currentPhase > i || (currentPhase === 3 && i <= 2)}
            error={isFailed}
            pulse={isRunning && currentPhase === i}
          />
          {i < phases.length - 1 && (
            <Connector
              active={(isRunning && currentPhase >= i) || currentPhase === 3}
              complete={currentPhase > i || currentPhase === 3}
            />
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

function Node({ title, icon, sub, active, complete, error, pulse }) {
  let cls = 'wf-node glass-panel';
  if (complete) cls += ' wf-node--complete';
  else if (error) cls += ' wf-node--error';
  else if (active) cls += ' wf-node--active';
  if (pulse) cls += ' wf-node--pulse';

  return (
    <motion.div
      className={cls}
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 300, damping: 20 }}
    >
      <div className="wf-node__icon">{icon}</div>
      <div className="wf-node__title">{title}</div>
      {sub && <div className="wf-node__sub">{sub}</div>}
    </motion.div>
  );
}

function Connector({ active, complete }) {
  let cls = 'wf-connector';
  if (complete) cls += ' wf-connector--complete';
  else if (active) cls += ' wf-connector--active';
  return (
    <div className={cls}>
      <div className="wf-connector__line" />
      {active && !complete && <div className="wf-connector__pulse" />}
    </div>
  );
}

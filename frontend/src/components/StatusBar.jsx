import React from 'react';
import { motion } from 'framer-motion';
import './StatusBar.css';

export default function StatusBar({ status }) {
  if (!status) return null;

  const isRunning = status.status === 'running';
  const isFailed = status.status === 'failed';
  
  let dotColor = '--neon-safe';
  if (isRunning) dotColor = '--neon-low';
  if (isFailed) dotColor = '--neon-critical';

  return (
    <div className="status-bar">
      <div className="status-bar__chip">
        <motion.div 
          className="status-bar__dot"
          style={{ 
            background: `var(${dotColor})`, 
            boxShadow: `0 0 10px var(${dotColor}-glow)` 
          }}
          animate={isRunning ? { scale: [1, 1.3, 1], opacity: [1, 0.6, 1] } : {}}
          transition={isRunning ? { duration: 1.5, repeat: Infinity, ease: "easeInOut" } : {}}
        />
        <span className="status-bar__text">
          {isRunning ? 'Scan en cours...' : isFailed ? 'Échec' : 'Prêt'}
        </span>
      </div>
    </div>
  );
}

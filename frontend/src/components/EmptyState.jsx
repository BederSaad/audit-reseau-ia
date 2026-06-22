import React from 'react';
import TiltCard from './TiltCard';
import { motion, AnimatePresence } from 'framer-motion';

export default function EmptyState() {
  return (
    <TiltCard className="empty-state">
      <div className="empty-radar">
        <div className="empty-radar-ring empty-radar-ring-1"></div>
        <div className="empty-radar-ring empty-radar-ring-2"></div>
        <div className="empty-radar-dot"></div>
      </div>
      <h3 className="neon-text">Aucun scan détecté</h3>
      <p>Entrez une adresse IP ou un réseau CIDR en haut pour démarrer votre premier audit réseau.</p>
    </TiltCard>
  );
}

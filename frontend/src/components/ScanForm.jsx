import React from 'react';
import './ScanForm.css';

export default function ScanForm({ onScanStart, isRunning }) {
  const handleSubmit = (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const target = fd.get('target').trim();
    if (!target) return;
    onScanStart(target);
  };

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      <input 
        name="target"
        id="scan-target-input"
        className="scan-form__input mono"
        placeholder="Cible (ex: 192.168.1.1 ou 10.0.0.0/24)"
        disabled={isRunning}
        autoComplete="off"
        required
      />
      <button 
        type="submit" 
        id="scan-submit-btn"
        className="btn-primary scan-form__btn" 
        disabled={isRunning}
      >
        <span>{isRunning ? 'Scan en cours...' : 'Lancer le scan'}</span>
        <span className="scan-form__btn-icon">🚀</span>
      </button>
    </form>
  );
}

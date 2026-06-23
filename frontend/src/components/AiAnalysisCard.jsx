import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { getAnalysis } from '../api/client';
import './AiAnalysisCard.css';

const AiAnalysisCard = ({ scanId }) => {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!scanId) return;

    console.log('[AiAnalysisCard] Component mounted with scanId:', scanId);

    let mounted = true;
    let retryCount = 0;
    const maxRetries = 15; // Try for up to 30 seconds (15 * 2s)

    const fetchAnalysis = async () => {
      if (!mounted) return;

      console.log(`[AiAnalysisCard] Fetching analysis (attempt ${retryCount + 1}/${maxRetries + 1})`);

      try {
        setLoading(true);
        setError(null);
        const { data } = await getAnalysis(scanId);
        if (mounted) {
          console.log('[AiAnalysisCard] Analysis fetched successfully');
          setAnalysis(data);
          setLoading(false);
        }
      } catch (err) {
        if (!mounted) return;

        console.log('[AiAnalysisCard] Error:', err.response?.status, err.response?.data);

        if (err.response?.status === 404 && retryCount < maxRetries) {
          retryCount++;
          console.log(`[AiAnalysisCard] Retrying in 2s... (${retryCount}/${maxRetries})`);
          setTimeout(() => fetchAnalysis(), 2000);
        } else if (err.response?.status === 404) {
          console.log('[AiAnalysisCard] Max retries reached, showing error');
          setError("L'analyse IA sera disponible une fois le scan terminé.");
          setLoading(false);
        } else {
          console.log('[AiAnalysisCard] Other error, showing error');
          setError(err.response?.data?.detail || "Erreur de chargement de l'analyse.");
          setLoading(false);
        }
      }
    };

    fetchAnalysis();

    return () => {
      console.log('[AiAnalysisCard] Component unmounting');
      mounted = false;
    };
  }, [scanId]);

  if (loading) {
    return (
      <div className="ai-analysis-card loading-skeleton glass-panel">
        <h3 className="neon-text">🤖 Génération de l'analyse IA en cours...</h3>
        <div className="skeleton-line title"></div>
        <div className="skeleton-line p1"></div>
        <div className="skeleton-line p2"></div>
        <div className="skeleton-grid">
          <div className="skeleton-box"></div>
          <div className="skeleton-box"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="ai-analysis-card error glass-panel">
        <p className="error-message">⚠️ {error}</p>
      </div>
    );
  }

  if (!analysis) return null;

  const isAi = analysis.ai_generated;
  const keyFindings = analysis.key_findings || [];
  const strategicRecs = analysis.strategic_recommendations || [];
  const securityScore = analysis.security_score || 0;
  const maturityLevel = analysis.maturity_level || 'Unknown';
  const attackVectors = analysis.attack_vectors || [];
  const businessImpact = analysis.business_impact || {};
  const likelihood = analysis.likelihood_of_compromise || 'Unknown';
  const attackerScenario = analysis.attacker_scenario || '';
  const strengths = analysis.security_strengths || [];
  const weaknesses = analysis.security_weaknesses || [];
  const globalRisk = analysis.global_risk_conclusion || '';

  const getSeverityClass = (severity) => {
    const s = (severity || '').toLowerCase();
    if (s.includes('critique') || s.includes('critical')) return 'critique';
    if (s.includes('élevé') || s.includes('high') || s.includes('eleve')) return 'elevé';
    if (s.includes('modéré') || s.includes('modere') || s.includes('medium')) return 'modere';
    return 'faible';
  };

  const getMaturityColor = (level) => {
    const l = (level || '').toLowerCase();
    if (l.includes('critical')) return '#DC2626';
    if (l.includes('weak')) return '#EA580C';
    if (l.includes('moderate')) return '#CA8A04';
    if (l.includes('good')) return '#16A34A';
    return '#64748B';
  };

  const getLikelihoodColor = (level) => {
    const l = (level || '').toLowerCase();
    if (l.includes('critical')) return '#DC2626';
    if (l.includes('high')) return '#EA580C';
    if (l.includes('medium')) return '#CA8A04';
    return '#2563EB';
  };

  return (
    <motion.div
      className="ai-analysis-card glass-panel"
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.6, delay: 0.2 }}
    >
      <div className="ai-header">
        <div className="ai-title-wrap">
          <span className="ai-logo-icon">🤖</span>
          <h2>Advanced Security Analysis</h2>
        </div>
        <span className={`ai-honesty-badge ${isAi ? 'badge-ai' : 'badge-fallback'}`}>
          {isAi ? "AI Generated" : "Automatic Analysis"}
        </span>
      </div>

      {/* Security Score & Maturity */}
      <div className="ai-section">
        <div className="sub-card score-maturity-card">
          <div className="score-maturity-grid">
            <div className="score-box">
              <h4 className="metric-label">Security Score</h4>
              <div className="score-value" style={{ color: securityScore >= 80 ? '#16A34A' : securityScore >= 60 ? '#CA8A04' : '#DC2626' }}>
                {securityScore}/100
              </div>
            </div>
            <div className="maturity-box">
              <h4 className="metric-label">Maturity Level</h4>
              <div className="maturity-value" style={{ color: getMaturityColor(maturityLevel) }}>
                {maturityLevel}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="ai-section">
        <div className="sub-card executive-summary-card">
          <h3 className="section-title">Executive Summary</h3>
          <p className="summary-text">{analysis.executive_summary}</p>
        </div>
      </div>

      {/* Attack Vectors */}
      {attackVectors.length > 0 && (
        <div className="ai-section">
          <div className="sub-card">
            <h3 className="section-title">Attack Vectors</h3>
            <ul className="vector-list">
              {attackVectors.map((vector, idx) => (
                <li key={idx} className="vector-item">⚡ {vector}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Business Impact */}
      {Object.keys(businessImpact).length > 0 && (
        <div className="ai-section">
          <div className="sub-card">
            <h3 className="section-title">Business Impact Assessment</h3>
            <div className="impact-grid">
              {Object.entries(businessImpact).map(([area, level]) => (
                <div key={area} className="impact-item">
                  <span className="impact-area">{area.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
                  <span className={`impact-level level-${level.toLowerCase()}`}>{level}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Likelihood of Compromise */}
      <div className="ai-section">
        <div className="sub-card">
          <h3 className="section-title">Likelihood of Compromise</h3>
          <div className="likelihood-badge" style={{ backgroundColor: getLikelihoodColor(likelihood) }}>
            {likelihood}
          </div>
        </div>
      </div>

      {/* Attacker Scenario */}
      {attackerScenario && (
        <div className="ai-section">
          <div className="sub-card attacker-scenario-card">
            <h3 className="section-title">Attacker Scenario</h3>
            <p className="scenario-text">{attackerScenario}</p>
          </div>
        </div>
      )}

      {/* Security Strengths & Weaknesses */}
      {(strengths.length > 0 || weaknesses.length > 0) && (
        <div className="ai-section">
          <div className="sub-card swot-card">
            <h3 className="section-title">Security Posture Analysis</h3>
            <div className="swot-grid">
              <div className="swot-column">
                <h4 className="swot-header strengths">Strengths</h4>
                <ul className="swot-list">
                  {strengths.map((s, idx) => (
                    <li key={idx} className="swot-item strength">✓ {s}</li>
                  ))}
                </ul>
              </div>
              <div className="swot-column">
                <h4 className="swot-header weaknesses">Weaknesses</h4>
                <ul className="swot-list">
                  {weaknesses.map((w, idx) => (
                    <li key={idx} className="swot-item weakness">✗ {w}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Global Risk Conclusion */}
      {globalRisk && (
        <div className="ai-section">
          <div className="sub-card risk-conclusion-card">
            <h3 className="section-title">Global Risk Conclusion</h3>
            <p className="risk-text">{globalRisk}</p>
          </div>
        </div>
      )}

      {/* Key Findings with Metrics and Remediation */}
      {keyFindings.length > 0 && (
        <div className="ai-section">
          <h3 className="section-title">Constats Clés &amp; Remédiation</h3>
          <div className="findings-stack">
            {keyFindings.map((finding, idx) => (
              <div key={idx} className={`finding-card sev-${getSeverityClass(finding.severity)}`}>
                <div className="finding-card-header">
                  <h4 className="finding-name">{finding.finding_name}</h4>
                  <div className="risk-badges">
                    <span className={`sev-badge-pill sev-${getSeverityClass(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    <span className="metric-badge">
                      Probabilité: {finding.likelihood || 'N/A'}
                    </span>
                    <span className="metric-badge">
                      Impact: {finding.impact || 'N/A'}
                    </span>
                  </div>
                </div>

                <p className="finding-desc">{finding.description}</p>

                <div className="affected-hosts">
                  <strong>Hôtes affectés: </strong>
                  {finding.affected_hosts?.map((host, i) => (
                    <span key={i} className="ip-chip mono">{host}</span>
                  ))}
                </div>

                <div className="remediation-steps">
                  <strong>Plan d'action:</strong>
                  <ol>
                    {finding.remediation_steps?.map((step, sIdx) => (
                      <li key={sIdx}>{step}</li>
                    ))}
                  </ol>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Strategic Recommendations */}
      {strategicRecs.length > 0 && (
        <div className="ai-section">
          <h3 className="section-title">Recommandations Stratégiques</h3>
          <ul className="strategic-list">
            {strategicRecs.map((rec, idx) => (
              <li key={idx}>
                <span className="priority-circle">{rec.priority}</span>
                <div className="rec-content">
                  <strong>{rec.theme}</strong>
                  <p>{rec.advice}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Overall Verdict Banner */}
      <div className={`overall-verdict-banner posture-${analysis.overall_verdict?.toLowerCase().includes('critique') ? 'critique' : analysis.overall_verdict?.toLowerCase().includes('acceptable') ? 'warning' : 'healthy'}`}>
        <span className="verdict-label">POSTURE DE SÉCURITÉ GLOBALE</span>
        <p className="verdict-text">{analysis.overall_verdict}</p>
      </div>
    </motion.div>
  );
};

export default AiAnalysisCard;

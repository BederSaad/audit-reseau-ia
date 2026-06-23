import React, { useState } from 'react';
import axios from 'axios';
import { useToast } from './Toast';
import './PdfDownloadButton.css';

export default function PdfDownloadButton({ scanId }) {
  const [downloading, setDownloading] = useState(false);
  const toast = useToast();

  const handleDownload = async () => {
    if (!scanId || downloading) return;

    setDownloading(true);
    toast("Génération du rapport PDF en cours...", "info");

    try {
      // Direct call using the backend URL (or centralized client if base URL matches)
      const response = await axios.get(`http://localhost:8000/scan/${scanId}/report.pdf`, {
        responseType: 'blob',
        timeout: 45000 // Server might take a bit to render matplotlib graphs
      });

      // Create object URL and download
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `Rapport_Audit_${scanId.slice(0, 8)}.pdf`);
      document.body.appendChild(link);
      link.click();
      
      // Clean up
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      toast("Rapport PDF téléchargé avec succès !", "success");
    } catch (error) {
      console.error("PDF Download error:", error);
      toast("Erreur lors de la génération du rapport PDF.", "error");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <button 
      className="btn-pdf-download"
      onClick={handleDownload}
      disabled={downloading || !scanId}
    >
      {downloading ? (
        <>
          <span className="pdf-btn-spinner"></span>
          Génération...
        </>
      ) : (
        <>
          <span className="pdf-btn-icon">📄</span>
          Télécharger le PDF
        </>
      )}
    </button>
  );
}

import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const API = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function App() {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [health, setHealth] = useState(null);
  const [analyzingSampleId, setAnalyzingSampleId] = useState(null);
  const [showFindings, setShowFindings] = useState(false);
  const inputRef = useRef();

  /* ── Health check ──────────────────────────────── */
  useEffect(() => {
    axios
      .get(`${API}/api/health`)
      .then(() => setHealth('ok'))
      .catch(() => setHealth('err'));
  }, []);

  /* ── Polling for results ────────────────────────── */
  useEffect(() => {
    if (!analyzingSampleId) return;

    const poll = async () => {
      try {
        const res = await axios.get(`${API}/api/samples/${analyzingSampleId}`);
        const data = res.data;
        setResult(data);

        if (data.status === 'completed' || data.status === 'failed') {
          setAnalyzingSampleId(null); // Stop polling
        }
      } catch (err) {
        console.error('Polling error:', err);
        setError('Failed to fetch analysis update.');
        setAnalyzingSampleId(null);
      }
    };

    // Run first check immediately
    poll();

    const interval = setInterval(poll, 2000);
    return () => clearInterval(interval);
  }, [analyzingSampleId]);

  /* ── Drag & Drop ───────────────────────────────── */
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    else if (e.type === 'dragleave') setDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFile(e.target.files[0]);
    }
  };

  /* ── Upload ────────────────────────────────────── */
  const handleFile = async (selectedFile) => {
    setFile(selectedFile);
    setResult(null);
    setError(null);
    setUploading(true);
    setProgress(0);
    setShowFindings(false);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const res = await axios.post(`${API}/api/upload`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (e) => {
          const pct = Math.round((e.loaded * 100) / (e.total || 1));
          setProgress(pct);
        },
      });
      setResult(res.data);
      setAnalyzingSampleId(res.data.sample_id);
    } catch (err) {
      setError(
        err.response?.data?.detail ||
          err.message ||
          'Upload failed. Is the backend running?'
      );
    } finally {
      setUploading(false);
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '—';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(2)} MB`;
  };

  /* ── Styling Helpers ─────────────────────────────── */
  const getVerdictClass = (verdict) => {
    if (verdict === 'safe') return 'verdict-badge--safe';
    if (verdict === 'suspicious') return 'verdict-badge--suspicious';
    if (verdict === 'dangerous') return 'verdict-badge--dangerous';
    return '';
  };

  const getScoreCircleClass = (verdict) => {
    if (verdict === 'safe') return 'score-circle--safe';
    if (verdict === 'suspicious') return 'score-circle--suspicious';
    if (verdict === 'dangerous') return 'score-circle--dangerous';
    return '';
  };

  const getFindingIcon = (findingText) => {
    const text = findingText.toLowerCase();
    if (text.startsWith('yara')) return '🚨';
    if (text.startsWith('permission')) return '🔑';
    if (text.startsWith('structure')) return '⚙️';
    return '•';
  };

  /* ── Render Subcomponents ──────────────────────── */
  const STAGES = ['queued', 'unpacking', 'scanning', 'scoring', 'explaining', 'completed'];

  const renderPipelineProgress = () => {
    if (!result || !result.status) return null;
    if (result.status === 'completed' || result.status === 'failed') return null;

    const currentStatus = result.status;
    const currentIndex = STAGES.indexOf(currentStatus);

    return (
      <div className="pipeline-progress">
        <h3 className="pipeline-progress__title">Analyzing APK Security Profile…</h3>
        <div className="pipeline-steps">
          {STAGES.map((stage, idx) => {
            let stepClass = 'pipeline-step';
            let indicator = idx + 1;

            if (idx < currentIndex) {
              stepClass += ' pipeline-step--completed';
              indicator = '✓';
            } else if (idx === currentIndex) {
              stepClass += ' pipeline-step--active';
              indicator = '⏳';
            } else {
              stepClass += ' pipeline-step--pending';
            }

            const label = stage.charAt(0).toUpperCase() + stage.slice(1);
            return (
              <div key={stage} className={stepClass}>
                <div className="pipeline-step__indicator">{indicator}</div>
                <div className="pipeline-step__label">{label}</div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  const renderAnalysisResult = () => {
    if (!result || (result.status !== 'completed' && result.status !== 'failed')) return null;

    if (result.status === 'failed') {
      return (
        <div className="error-banner" style={{ marginTop: '36px' }}>
          <strong>Analysis Failed:</strong> The scanning pipeline encountered a fatal error while analyzing this APK.
        </div>
      );
    }

    const {
      filename,
      original_filename,
      sha256,
      file_size,
      risk_score,
      verdict,
      findings,
      explanation,
      package_name,
      app_name,
      version_name
    } = result;

    return (
      <div className="result-card" id="result-card">
        {/* Verdict Header */}
        <div className="verdict-header">
          <h2 className="verdict-header__title">
            🛡️ {app_name || original_filename || filename}
          </h2>
          <span className={`verdict-badge ${getVerdictClass(verdict)}`}>
            {verdict}
          </span>
        </div>

        {/* Threat Score Indicator */}
        <div className="score-container">
          <div className={`score-circle ${getScoreCircleClass(verdict)}`}>
            {risk_score}
          </div>
          <div className="score-details">
            <span className="score-details__title">Risk Score</span>
            <span className="score-details__desc">
              Threat rating calculated out of 100 points
            </span>
          </div>
        </div>

        {/* Claude Plain-English Explanation */}
        {explanation && (
          <div className="explanation-card">
            <h3 className="explanation-card__title">
              💡 Security Summary (AI Interpretation)
            </h3>
            <div className="explanation-card__content">
              {explanation}
            </div>
          </div>
        )}

        {/* Technical Metadata Details */}
        <h3 className="result-card__title" style={{ marginTop: '24px', marginBottom: '12px' }}>
          📋 Technical Metadata
        </h3>
        <div className="result-card__row">
          <span className="result-card__label">Package Name</span>
          <span className="result-card__value">{package_name || '—'}</span>
        </div>
        <div className="result-card__row">
          <span className="result-card__label">Version</span>
          <span className="result-card__value">{version_name || '—'}</span>
        </div>
        <div className="result-card__row">
          <span className="result-card__label">SHA-256</span>
          <span className="result-card__value">{sha256}</span>
        </div>
        <div className="result-card__row">
          <span className="result-card__label">File Size</span>
          <span className="result-card__value">{formatBytes(file_size)}</span>
        </div>

        {/* Collapsible Findings */}
        {findings && findings.length > 0 && (
          <div className="findings-section">
            <div
              className="findings-header"
              onClick={() => setShowFindings(!showFindings)}
            >
              <div>
                <span className="findings-header__title">Flagged Threat Markers</span>
                <span className="findings-header__count">{findings.length}</span>
              </div>
              <span
                className={`findings-header__arrow ${
                  showFindings ? 'findings-header__arrow--open' : ''
                }`}
              >
                ▼
              </span>
            </div>
            {showFindings && (
              <div className="findings-list">
                {findings.map((finding, idx) => (
                  <div key={idx} className="finding-item">
                    <span className="finding-item__icon">
                      {getFindingIcon(finding)}
                    </span>
                    <span className="finding-item__text">{finding}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="app-wrapper">
      {/* Header */}
      <header className="header">
        <h1 className="header__logo">APKShield‑AI</h1>
        <p className="header__tagline">
          GenAI-Assisted Hybrid Malware Analysis for Android APKs
        </p>
      </header>

      {/* Upload Zone */}
      <div
        className={`upload-zone ${dragActive ? 'upload-zone--active' : ''}`}
        onDragEnter={handleDrag}
        onDragOver={handleDrag}
        onDragLeave={handleDrag}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        id="upload-zone"
      >
        <input
          ref={inputRef}
          type="file"
          accept=".apk"
          onChange={handleChange}
          id="file-input"
        />
        <div className="upload-zone__icon">📦</div>
        <p className="upload-zone__title">
          {file ? file.name : 'Drop an APK here or click to browse'}
        </p>
        <p className="upload-zone__hint">.apk files only</p>
      </div>

      {/* Upload Progress */}
      {uploading && (
        <div className="progress-container">
          <div className="progress-bar">
            <div
              className="progress-bar__fill"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="progress-label">Uploading… {progress}%</p>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="error-banner" id="error-banner">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Pipeline Progress Indicator */}
      {renderPipelineProgress()}

      {/* Final Analysis Report */}
      {renderAnalysisResult()}

      {/* Backend Health Check */}
      <p className="health-text">
        <span
          className={`health-dot ${
            health === 'ok' ? 'health-dot--ok' : 'health-dot--err'
          }`}
        />
        Backend {health === 'ok' ? 'connected' : 'unreachable'}
      </p>
    </div>
  );
}

export default App;

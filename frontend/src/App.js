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
  const inputRef = useRef();

  /* ── Health check ──────────────────────────────── */
  useEffect(() => {
    axios
      .get(`${API}/api/health`)
      .then(() => setHealth('ok'))
      .catch(() => setHealth('err'));
  }, []);

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

      {/* Progress */}
      {uploading && (
        <div className="progress-container">
          <div className="progress-bar">
            <div
              className="progress-bar__fill"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="progress-label">Uploading… {progress}%</p>
          <span className="status-badge status-badge--loading">
            ⏳ Analyzing
          </span>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="error-banner" id="error-banner">
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div className="result-card" id="result-card">
          <h2 className="result-card__title">📋 Analysis Result</h2>

          <div className="result-card__row">
            <span className="result-card__label">Case ID</span>
            <span className="result-card__value">{result.case_id}</span>
          </div>
          <div className="result-card__row">
            <span className="result-card__label">Filename</span>
            <span className="result-card__value">{result.filename}</span>
          </div>
          <div className="result-card__row">
            <span className="result-card__label">SHA-256</span>
            <span className="result-card__value">{result.sha256}</span>
          </div>
          <div className="result-card__row">
            <span className="result-card__label">Size</span>
            <span className="result-card__value">
              {formatBytes(result.size_bytes)}
            </span>
          </div>
          <div className="result-card__row">
            <span className="result-card__label">Status</span>
            <span className="result-card__value">
              <span className="status-badge status-badge--success">
                ✓ {result.status}
              </span>
            </span>
          </div>
        </div>
      )}

      {/* Health */}
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

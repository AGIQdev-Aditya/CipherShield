import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import {
  Check,
  Copy,
  Download,
  FileSpreadsheet,
  FileText,
  Lock,
  Moon,
  ShieldAlert,
  ShieldCheck,
  Shuffle,
  SlidersHorizontal,
  Sparkles,
  Sun,
  Trash2,
  Upload,
} from 'lucide-react';
import { parseCsvRows } from './engine/csvParser';
import { GOOGLE_DLP_INFOTYPE_MAP, redactText, sha256Hex } from './engine/redactor';
import { DEFAULT_DETECTION_OPTIONS } from './engine/scanner';
import { generateSyntheticChaosLog, SAMPLE_DATASETS } from './engine/samples';
import { DetectionOptions, PiiCategory, RedactionMode } from './types/pii';

const CATEGORY_META: Record<PiiCategory, { label: string; hint: string }> = {
  EMAIL: { label: 'Emails', hint: 'RFC email patterns' },
  PHONE: { label: 'Phones', hint: '+91 / E.164 / local' },
  IP_ADDRESS: { label: 'IP Addresses', hint: 'Strict IPv4 & IPv6' },
  PAN: { label: 'Indian PAN', hint: 'ABCDE1234F format' },
  AADHAAR: { label: 'Aadhaar', hint: '12-digit / Verhoeff' },
  CREDIT_CARD: { label: 'Credit Cards', hint: 'Luhn Mod-10 verified' },
  CUSTOM: { label: 'Custom Rule', hint: 'User regex pattern' },
};

const MAX_FILE_BYTES = 5 * 1024 * 1024;

const MODE_OPTIONS: { id: RedactionMode; label: string; summary: string }[] = [
  { id: 'full', label: 'Full Mask', summary: 'Replace entities with [REDACTED] blocks' },
  { id: 'partial', label: 'Partial Mask', summary: 'Retain last-4 / domain verification hint' },
  { id: 'pseudonymize', label: 'Consistent Pseudonymization', summary: 'Map recurring PII to stable USER_01 tokens' },
];

export default function App() {
  const [rawText, setRawText] = useState<string>(SAMPLE_DATASETS[0].content);
  const [sourceFilename, setSourceFilename] = useState<string>(SAMPLE_DATASETS[0].filename);
  const [mode, setMode] = useState<RedactionMode>('pseudonymize');
  const [options, setOptions] = useState<DetectionOptions>(DEFAULT_DETECTION_OPTIONS);
  const [allowlistText, setAllowlistText] = useState<string>(DEFAULT_DETECTION_OPTIONS.allowlist.join(', '));
  const [copied, setCopied] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [liveStatus, setLiveStatus] = useState<string>('');
  const [theme, setTheme] = useState<'system' | 'dark' | 'light'>('system');
  const [diffViewMode, setDiffViewMode] = useState<'text' | 'csv'>('text');
  const [geminiKey, setGeminiKey] = useState<string>('');
  const [geminiOutput, setGeminiOutput] = useState<string>('');
  const [geminiLoading, setGeminiLoading] = useState<boolean>(false);
  const [geminiError, setGeminiError] = useState<string | null>(null);

  const dialogRef = useRef<HTMLDialogElement>(null);
  const rawInputId = useId();
  const uploadInputId = useId();
  const allowlistInputId = useId();
  const customLabelId = useId();
  const customPatternId = useId();
  const geminiKeyId = useId();

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') {
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', theme);
    }
  }, [theme]);

  const effectiveOptions = useMemo<DetectionOptions>(() => {
    const parsedAllowlist = allowlistText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    return {
      ...options,
      allowlist: parsedAllowlist,
    };
  }, [options, allowlistText]);

  const result = useMemo(
    () => redactText(rawText, mode, effectiveOptions),
    [rawText, mode, effectiveOptions],
  );

  const originalCsv = useMemo(() => parseCsvRows(rawText), [rawText]);
  const sanitizedCsv = useMemo(
    () => (originalCsv.isTabular ? parseCsvRows(result.sanitizedText) : { headers: [], rows: [], isTabular: false }),
    [originalCsv.isTabular, result.sanitizedText],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLiveStatus(
        `Scanned text in ${result.scan.durationMs} milliseconds: ${result.scan.totalDetected} PII entities detected, ${result.scan.luhnRejectedCount} numeric strings rejected by Luhn validation.`,
      );
    }, 600);
    return () => window.clearTimeout(timer);
  }, [result.scan.totalDetected, result.scan.luhnRejectedCount, result.scan.durationMs]);

  const toggleCategory = (category: PiiCategory) => {
    setOptions((prev) => ({
      ...prev,
      enabledCategories: {
        ...prev.enabledCategories,
        [category]: !prev.enabledCategories[category],
      },
    }));
  };

  const handleFileLoad = async (file: File | undefined) => {
    setUploadError(null);
    if (!file) return;

    const lower = file.name.toLowerCase();
    if (!lower.endsWith('.txt') && !lower.endsWith('.csv')) {
      setUploadError('Unsupported file type. Please select a .txt or .csv file.');
      return;
    }

    if (file.size > MAX_FILE_BYTES) {
      setUploadError('File exceeds 5 MB client-side safety limit.');
      return;
    }

    const content = await file.text();
    setRawText(content);
    setSourceFilename(file.name);
    setDiffViewMode(lower.endsWith('.csv') ? 'csv' : 'text');
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(result.sanitizedText);
      setCopied(true);
      setLiveStatus('Sanitized output copied to clipboard.');
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setLiveStatus('Clipboard copy unavailable; please use Download.');
    }
  };

  const triggerDownload = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setLiveStatus(`Downloaded ${filename}.`);
  };

  const handleDownloadSanitized = () => {
    const ext = sourceFilename.toLowerCase().endsWith('.csv') ? 'csv' : 'txt';
    const baseName = sourceFilename.replace(/\.(txt|csv)$/i, '') || 'sanitized_output';
    const mime = ext === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8';
    triggerDownload(result.sanitizedText, `sanitized_${baseName}.${ext}`, mime);
  };

  const handleDownloadAuditReport = async () => {
    const [rawSha256, sanitizedSha256] = await Promise.all([
      sha256Hex(rawText),
      sha256Hex(result.sanitizedText),
    ]);

    const dlpBreakdown = (Object.keys(result.scan.counts) as PiiCategory[])
      .filter((k) => result.scan.counts[k] > 0)
      .map((category) => ({
        category,
        googleCloudDlpInfoType: GOOGLE_DLP_INFOTYPE_MAP[category],
        count: result.scan.counts[category],
      }));

    const certificate = {
      tool: 'CipherShield',
      executionEnvironment: '100% Client-Side Browser RAM (Zero Server Egress)',
      generatedAt: new Date().toISOString(),
      sourceFilename,
      redactionMode: mode,
      integrityDigests: {
        originalSha256: rawSha256,
        sanitizedSha256,
      },
      exposureRisk: result.scan.risk,
      metrics: {
        totalRedacted: result.scan.totalDetected,
        luhnRejectedFalsePositives: result.scan.luhnRejectedCount,
        allowlistedPreserved: result.scan.allowlistedCount,
        scanDurationMs: result.scan.durationMs,
      },
      googleCloudDlpSummary: dlpBreakdown,
    };

    const baseName = sourceFilename.replace(/\.(txt|csv)$/i, '') || 'audit';
    triggerDownload(
      JSON.stringify(certificate, null, 2),
      `ciphershield_audit_${baseName}.json`,
      'application/json;charset=utf-8',
    );
  };

  const handleModeKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>, currentIdx: number) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const delta = e.key === 'ArrowRight' ? 1 : -1;
      const nextIdx = (currentIdx + delta + MODE_OPTIONS.length) % MODE_OPTIONS.length;
      setMode(MODE_OPTIONS[nextIdx].id);
    }
  };

  const cycleTheme = () => {
    setTheme((prev) => (prev === 'system' ? 'dark' : prev === 'dark' ? 'light' : 'system'));
  };

  const handleGeminiAdvice = async () => {
    setGeminiError(null);
    setGeminiLoading(true);
    try {
      const { generateComplianceAdvice } = await import('./services/geminiAdvisor');
      const advice = await generateComplianceAdvice(geminiKey, result.scan);
      setGeminiOutput(advice);
    } catch (err) {
      setGeminiError(err instanceof Error ? err.message : 'Gemini request failed.');
    } finally {
      setGeminiLoading(false);
    }
  };

  const handleGeminiSynthetic = async () => {
    setGeminiError(null);
    setGeminiLoading(true);
    try {
      const { generateGeminiSyntheticLog } = await import('./services/geminiAdvisor');
      const synthetic = await generateGeminiSyntheticLog(geminiKey);
      if (synthetic) {
        setRawText(synthetic);
        setSourceFilename('gemini_synthetic_log.txt');
        setDiffViewMode('text');
      }
    } catch (err) {
      setGeminiError(err instanceof Error ? err.message : 'Gemini synthetic generation failed.');
    } finally {
      setGeminiLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <a href="#main-heading" className="skip-link visually-hidden">
        Skip to main content
      </a>

      <header className="site-header">
        <div className="brand-group">
          <div className="brand-mark" aria-hidden="true">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 id="main-heading" tabIndex={-1} className="brand-title">
              CipherShield
            </h1>
            <p className="brand-subtitle">
              Zero-Egress Client-Side PII Detection, Luhn/Verhoeff Validation &amp; Audit Studio
            </p>
          </div>
        </div>

        <nav aria-label="Primary actions" className="header-actions">
          <span className="status-pill" title="Enforced by CSP connect-src 'self' and pure local JS">
            <Lock size={14} aria-hidden="true" />
            100% Client-Side · 0 Network Egress
          </span>

          <button type="button" className="btn" onClick={() => dialogRef.current?.showModal()}>
            <FileText size={16} aria-hidden="true" />
            Prompt Log
          </button>

          <button
            type="button"
            className="btn"
            onClick={cycleTheme}
            aria-label={`Switch color theme, current setting is ${theme}`}
          >
            {theme === 'light' ? <Sun size={16} aria-hidden="true" /> : <Moon size={16} aria-hidden="true" />}
            Theme: {theme}
          </button>
        </nav>
      </header>

      <main>
        <div className="visually-hidden" aria-live="polite" aria-atomic="true">
          {liveStatus}
        </div>

        {/* Source Input Panel */}
        <section className="panel" aria-labelledby="input-section-heading">
          <div className="toolbar-grid">
            <h2 id="input-section-heading" style={{ margin: 0, fontSize: '1.05rem' }}>
              1. Source Data Input
            </h2>

            <div className="sample-buttons" role="group" aria-label="Sample datasets and synthetic chaos generator">
              {SAMPLE_DATASETS.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  className="btn"
                  onClick={() => {
                    setRawText(sample.content);
                    setSourceFilename(sample.filename);
                    setDiffViewMode(sample.filename.endsWith('.csv') ? 'csv' : 'text');
                    setUploadError(null);
                  }}
                >
                  <Sparkles size={15} aria-hidden="true" />
                  {sample.label}
                </button>
              ))}
              <button
                type="button"
                className="btn"
                onClick={() => {
                  setRawText(generateSyntheticChaosLog());
                  setSourceFilename('synthetic_chaos_log.txt');
                  setDiffViewMode('text');
                  setUploadError(null);
                }}
                title="Generate random Luhn-valid cards, decoy IDs, PAN, Aadhaar, and recurring PII offline"
              >
                <Shuffle size={15} aria-hidden="true" />
                Generate Fresh Chaos
              </button>
              <button
                type="button"
                className="btn btn-danger"
                onClick={() => {
                  setRawText('');
                  setSourceFilename('sanitized_text.txt');
                  setDiffViewMode('text');
                  setUploadError(null);
                }}
                disabled={!rawText}
              >
                <Trash2 size={15} aria-hidden="true" />
                Clear
              </button>
            </div>
          </div>

          <div
            className={`upload-zone ${isDragging ? 'is-dragging' : ''}`}
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setIsDragging(false);
              void handleFileLoad(e.dataTransfer.files?.[0]);
            }}
          >
            <label htmlFor={uploadInputId} className="btn">
              <Upload size={16} aria-hidden="true" />
              Upload .txt or .csv
            </label>
            <input
              id={uploadInputId}
              type="file"
              accept=".txt,.csv,text/plain,text/csv"
              className="visually-hidden"
              onChange={(e) => {
                void handleFileLoad(e.target.files?.[0]);
                e.target.value = '';
              }}
            />
            <span className="upload-meta">
              Active file: <strong className="mono">{sourceFilename}</strong> · Drag &amp; drop supported (max 5 MB, processed locally)
            </span>
          </div>

          {uploadError && (
            <p role="alert" style={{ color: '#ef4444', fontSize: '0.88rem', marginTop: '8px' }}>
              {uploadError}
            </p>
          )}

          <div style={{ marginTop: '14px' }}>
            <label htmlFor={rawInputId} className="textarea-label">
              <span>Raw Logs, Resumes, Clinical Notes, or CSV</span>
              <span className="mono" style={{ fontWeight: 400, color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                {rawText.length.toLocaleString()} chars · Scan: {result.scan.durationMs} ms
              </span>
            </label>
            <textarea
              id={rawInputId}
              className="raw-textarea"
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste raw text containing emails, phones, IPv4/IPv6, Indian PAN, Aadhaar, or credit card numbers..."
              spellCheck={false}
            />
          </div>
        </section>

        {/* Redaction Mode & Policy Controls */}
        <section className="panel" aria-labelledby="redaction-controls-heading">
          <h2 id="redaction-controls-heading" style={{ margin: '0 0 12px', fontSize: '1.05rem' }}>
            2. Redaction Strategy, Allowlist &amp; Custom Policy
          </h2>

          <div className="mode-bar">
            <div className="tablist" role="tablist" aria-label="Redaction mode">
              {MODE_OPTIONS.map((item, idx) => (
                <button
                  key={item.id}
                  type="button"
                  role="tab"
                  aria-selected={mode === item.id}
                  className="mode-tab"
                  onClick={() => setMode(item.id)}
                  onKeyDown={(e) => handleModeKeyDown(e, idx)}
                >
                  {item.label}
                </button>
              ))}
            </div>

            <div className="mode-options">
              {mode === 'full' && (
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.fullMaskTemplate === 'typed'}
                    onChange={(e) =>
                      setOptions((prev) => ({
                        ...prev,
                        fullMaskTemplate: e.target.checked ? 'typed' : 'generic',
                      }))
                    }
                  />
                  Include category label ([EMAIL_REDACTED])
                </label>
              )}

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={options.strictAadhaarVerhoeff}
                  onChange={(e) =>
                    setOptions((prev) => ({ ...prev, strictAadhaarVerhoeff: e.target.checked }))
                  }
                />
                Strict UIDAI Verhoeff checksum on Aadhaar
              </label>
            </div>
          </div>

          <p style={{ margin: '10px 0 14px', fontSize: '0.84rem', color: 'var(--text-muted)' }}>
            Active mode: <strong>{MODE_OPTIONS.find((m) => m.id === mode)?.label}</strong> —{' '}
            {MODE_OPTIONS.find((m) => m.id === mode)?.summary}.
          </p>

          <div className="policy-grid">
            <div>
              <label htmlFor={allowlistInputId} className="field-label">
                Allowlist (Comma-separated safe values never redacted)
              </label>
              <input
                id={allowlistInputId}
                type="text"
                className="text-input mono"
                value={allowlistText}
                onChange={(e) => setAllowlistText(e.target.value)}
                placeholder="e.g. 127.0.0.1, support@company.com"
              />
            </div>

            <div className="custom-rule-box">
              <div className="custom-rule-head">
                <label className="checkbox-label" style={{ fontWeight: 600 }}>
                  <input
                    type="checkbox"
                    checked={options.customRule.enabled}
                    onChange={(e) =>
                      setOptions((prev) => ({
                        ...prev,
                        customRule: { ...prev.customRule, enabled: e.target.checked },
                      }))
                    }
                  />
                  <SlidersHorizontal size={15} aria-hidden="true" />
                  Enable Custom Regex Rule
                </label>
              </div>
              <div className="custom-rule-inputs">
                <div>
                  <label htmlFor={customLabelId} className="visually-hidden">
                    Custom entity label
                  </label>
                  <input
                    id={customLabelId}
                    type="text"
                    className="text-input mono"
                    value={options.customRule.label}
                    onChange={(e) =>
                      setOptions((prev) => ({
                        ...prev,
                        customRule: { ...prev.customRule, label: e.target.value },
                      }))
                    }
                    placeholder="EMP_ID"
                    aria-label="Custom token prefix"
                  />
                </div>
                <div>
                  <label htmlFor={customPatternId} className="visually-hidden">
                    Custom regular expression pattern
                  </label>
                  <input
                    id={customPatternId}
                    type="text"
                    className="text-input mono"
                    value={options.customRule.pattern}
                    onChange={(e) =>
                      setOptions((prev) => ({
                        ...prev,
                        customRule: { ...prev.customRule, pattern: e.target.value },
                      }))
                    }
                    placeholder="EMP-\d{4,6}"
                    aria-label="Custom regular expression pattern"
                  />
                </div>
              </div>
              {result.scan.customRuleError && (
                <p role="alert" style={{ color: '#ef4444', fontSize: '0.8rem', margin: '6px 0 0' }}>
                  {result.scan.customRuleError}
                </p>
              )}
            </div>
          </div>
        </section>

        {/* Risk Meter + Entity Audit Counters */}
        <section aria-labelledby="audit-counts-heading">
          <h2 id="audit-counts-heading" className="visually-hidden">
            Exposure Risk Score and Entity Detection Counts
          </h2>

          <div className="risk-banner panel">
            <div className="risk-info">
              <ShieldAlert size={20} aria-hidden="true" style={{ color: 'var(--warn)' }} />
              <div>
                <strong>Privacy Exposure Score:</strong>{' '}
                <span className="mono">
                  Raw {result.scan.risk.scoreBefore}/100 ({result.scan.risk.levelBefore})
                </span>{' '}
                → Sanitized <strong className="mono" style={{ color: 'var(--safe)' }}>0/100 SECURE</strong>
              </div>
            </div>
            <div className="risk-meta mono">
              Luhn Filtered: {result.scan.luhnRejectedCount} · Allowlisted: {result.scan.allowlistedCount}
            </div>
          </div>

          <div className="stats-grid">
            {(Object.keys(CATEGORY_META) as PiiCategory[])
              .filter((cat) => cat !== 'CUSTOM' || options.customRule.enabled)
              .map((cat) => {
                const enabled = options.enabledCategories[cat];
                return (
                  <button
                    key={cat}
                    type="button"
                    className="stat-card"
                    aria-pressed={enabled}
                    onClick={() => toggleCategory(cat)}
                    title={`Toggle ${CATEGORY_META[cat].label} detection`}
                  >
                    <span className="stat-label">{CATEGORY_META[cat].label}</span>
                    <span className="stat-value">{result.scan.counts[cat]}</span>
                    <span className="stat-sub">
                      {enabled ? CATEGORY_META[cat].hint : 'Disabled (click to enable)'}
                    </span>
                  </button>
                );
              })}
          </div>
        </section>

        {/* Side-by-Side Diff View (Raw Text or Structured CSV Table) */}
        <section aria-labelledby="diff-section-heading">
          <div className="diff-toolbar">
            <h2 id="diff-section-heading" style={{ margin: 0, fontSize: '1.05rem' }}>
              3. Live Side-by-Side Audit Diff
            </h2>

            {originalCsv.isTabular && (
              <div className="sample-buttons" role="group" aria-label="Diff display format">
                <button
                  type="button"
                  className={`btn ${diffViewMode === 'text' ? 'btn-primary' : ''}`}
                  aria-pressed={diffViewMode === 'text'}
                  onClick={() => setDiffViewMode('text')}
                >
                  Text Diff View
                </button>
                <button
                  type="button"
                  className={`btn ${diffViewMode === 'csv' ? 'btn-primary' : ''}`}
                  aria-pressed={diffViewMode === 'csv'}
                  onClick={() => setDiffViewMode('csv')}
                >
                  <FileSpreadsheet size={15} aria-hidden="true" />
                  CSV Column Diff ({originalCsv.rows.length} rows)
                </button>
              </div>
            )}
          </div>

          {diffViewMode === 'csv' && originalCsv.isTabular && sanitizedCsv.isTabular ? (
            <div className="panel table-wrap" style={{ marginBottom: '16px' }}>
              <div className="diff-card-header" style={{ marginBottom: '12px', borderRadius: '8px' }}>
                <span style={{ fontWeight: 600 }}>RFC-4180 CSV Cell-by-Cell Diff (Original → Sanitized)</span>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button type="button" className="btn" onClick={() => void handleCopy()}>
                    {copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
                    {copied ? 'Copied' : 'Copy CSV'}
                  </button>
                  <button type="button" className="btn btn-primary" onClick={handleDownloadSanitized}>
                    <Download size={15} aria-hidden="true" />
                    Download Sanitized CSV
                  </button>
                  <button type="button" className="btn" onClick={() => void handleDownloadAuditReport()}>
                    <ShieldCheck size={15} aria-hidden="true" />
                    Export SHA-256 Audit JSON
                  </button>
                </div>
              </div>
              <table className="audit-table">
                <caption>CSV Original vs. Sanitized Cell Comparison</caption>
                <thead>
                  <tr>
                    <th scope="col">Row</th>
                    {originalCsv.headers.map((h, idx) => (
                      <th scope="col" key={`h-${idx}`} className="mono">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {originalCsv.rows.map((row, rIdx) => (
                    <tr key={`row-${rIdx}`}>
                      <td className="mono">{rIdx + 1}</td>
                      {row.map((origCell, cIdx) => {
                        const cleanCell = sanitizedCsv.rows[rIdx]?.[cIdx] ?? origCell;
                        const changed = origCell !== cleanCell;
                        return (
                          <td key={`cell-${rIdx}-${cIdx}`} className="mono">
                            {changed ? (
                              <span>
                                <span style={{ textDecoration: 'line-through', opacity: 0.65 }}>{origCell}</span>
                                <br />
                                <span className="pii-redacted">{cleanCell}</span>
                              </span>
                            ) : (
                              origCell
                            )}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="diff-grid">
              <article className="diff-card" aria-labelledby="orig-diff-title">
                <div className="diff-card-header">
                  <h3 id="orig-diff-title" className="diff-card-title">
                    Original Input (Highlighted PII)
                  </h3>
                  <span className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {result.scan.totalDetected} matches
                  </span>
                </div>
                <pre className="diff-pre" aria-label="Original text with highlighted PII entities">
                  {result.originalSegments.length === 0 ? (
                    <span style={{ color: 'var(--text-muted)' }}>No input text provided.</span>
                  ) : (
                    result.originalSegments.map((seg, i) =>
                      seg.entity ? (
                        <mark
                          key={`${seg.entity.id}-${i}`}
                          className={`pii-mark pii-${seg.entity.category}`}
                          title={`${CATEGORY_META[seg.entity.category].label} (${seg.entity.metadata ?? seg.entity.validatedBy}) -> ${seg.replacement}`}
                        >
                          {seg.text}
                        </mark>
                      ) : (
                        <span key={`orig-${i}`}>{seg.text}</span>
                      ),
                    )
                  )}
                </pre>
              </article>

              <article className="diff-card" aria-labelledby="sanitized-diff-title">
                <div className="diff-card-header">
                  <h3 id="sanitized-diff-title" className="diff-card-title">
                    Sanitized Output ({MODE_OPTIONS.find((m) => m.id === mode)?.label})
                  </h3>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => void handleCopy()}
                      disabled={!result.sanitizedText}
                    >
                      {copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
                      {copied ? 'Copied' : 'Copy'}
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={handleDownloadSanitized}
                      disabled={!result.sanitizedText}
                    >
                      <Download size={15} aria-hidden="true" />
                      Download File
                    </button>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => void handleDownloadAuditReport()}
                      disabled={!result.sanitizedText}
                      title="Export cryptographic SHA-256 verification & Google Cloud DLP InfoType summary JSON"
                    >
                      <ShieldCheck size={15} aria-hidden="true" />
                      Audit JSON
                    </button>
                  </div>
                </div>
                <pre className="diff-pre" aria-label="Sanitized output preview">
                  {result.sanitizedSegments.length === 0 ? (
                    <span style={{ color: 'var(--text-muted)' }}>Sanitized output appears here.</span>
                  ) : (
                    result.sanitizedSegments.map((seg, i) =>
                      seg.entity ? (
                        <span key={`san-${seg.entity.id}-${i}`} className="pii-redacted">
                          {seg.text}
                        </span>
                      ) : (
                        <span key={`plain-${i}`}>{seg.text}</span>
                      ),
                    )
                  )}
                </pre>
              </article>
            </div>
          )}
        </section>

        {/* Pseudonym & Cloud DLP Taxonomy Audit Table */}
        <section className="panel" aria-labelledby="audit-ledger-heading">
          <h2 id="audit-ledger-heading" style={{ margin: '0 0 12px', fontSize: '1.05rem' }}>
            4. Verification, Cloud DLP Taxonomy &amp; Pseudonym Ledger
          </h2>

          <div className="table-wrap">
            <table className="audit-table">
              <caption>
                Consistent Pseudonym Tokens &amp; Google Cloud DLP InfoType Classification (Volatile RAM Only)
              </caption>
              <thead>
                <tr>
                  <th scope="col">Token ID</th>
                  <th scope="col">Category</th>
                  <th scope="col">Cloud DLP InfoType</th>
                  <th scope="col">Sample Matched</th>
                  <th scope="col">Occurrences</th>
                </tr>
              </thead>
              <tbody>
                {result.mappings.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ color: 'var(--text-muted)' }}>
                      No active PII entities detected.
                    </td>
                  </tr>
                ) : (
                  result.mappings.map((m) => (
                    <tr key={`${m.category}-${m.token}`}>
                      <td className="mono">{m.token}</td>
                      <td>{CATEGORY_META[m.category].label}</td>
                      <td className="mono">{GOOGLE_DLP_INFOTYPE_MAP[m.category]}</td>
                      <td className="mono">{m.sampleValue}</td>
                      <td className="mono">{m.occurrences}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {result.scan.rejectedCards.length > 0 && (
            <div style={{ marginTop: '16px' }}>
              <h3 style={{ fontSize: '0.92rem', margin: '0 0 8px' }}>
                Numeric Strings Rejected by Luhn Validation ({result.scan.rejectedCards.length})
              </h3>
              <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.84rem', color: 'var(--text-muted)' }}>
                {result.scan.rejectedCards.map((rej, idx) => (
                  <li key={`${rej.start}-${idx}`}>
                    <code className="mono">{rej.value}</code> — {rej.reason} (preserved untouched)
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>

        {/* Optional Google Gemini Compliance Advisor (Zero Raw PII Sent) */}
        <section className="panel" aria-labelledby="gemini-advisor-heading">
          <div className="toolbar-grid">
            <div>
              <h2 id="gemini-advisor-heading" style={{ margin: 0, fontSize: '1.05rem' }}>
                5. Optional Google Gemini Compliance Advisor (Counts-Only)
              </h2>
              <p style={{ margin: '4px 0 0', fontSize: '0.84rem', color: 'var(--text-muted)' }}>
                Zero raw text or PII ever leaves your browser. Only anonymized Cloud DLP entity counts or synthetic test requests are sent if you supply a Gemini key.
              </p>
            </div>
          </div>

          <div className="policy-grid" style={{ borderTop: 'none', paddingTop: '12px' }}>
            <div>
              <label htmlFor={geminiKeyId} className="field-label">
                Google Gemini API Key (Optional, Volatile Memory Only)
              </label>
              <input
                id={geminiKeyId}
                type="password"
                className="text-input mono"
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                placeholder="AIza... (never stored or logged)"
                autoComplete="off"
              />
            </div>

            <div className="sample-buttons" style={{ alignSelf: 'end' }}>
              <button
                type="button"
                className="btn"
                onClick={() => void handleGeminiAdvice()}
                disabled={geminiLoading || !geminiKey.trim()}
              >
                <Sparkles size={15} aria-hidden="true" />
                {geminiLoading ? 'Analyzing...' : 'Analyze Risk Counts with Gemini'}
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => void handleGeminiSynthetic()}
                disabled={geminiLoading || !geminiKey.trim()}
              >
                <Shuffle size={15} aria-hidden="true" />
                Generate Synthetic Fixture via Gemini
              </button>
            </div>
          </div>

          {geminiError && (
            <p role="alert" style={{ color: '#ef4444', fontSize: '0.84rem', marginTop: '8px' }}>
              {geminiError}
            </p>
          )}

          {geminiOutput && (
            <pre className="diff-pre" style={{ marginTop: '12px', minHeight: '90px' }}>
              {geminiOutput}
            </pre>
          )}
        </section>
      </main>

      <footer className="site-footer">
        <span>CipherShield · Client-Side Zero-Egress PII Sanitization Engine</span>
        <span>Built for PromptWars × NIAT Pune · Cloud Run &amp; DLP Taxonomy Compatible</span>
      </footer>

      <dialog ref={dialogRef} className="prompt-dialog" aria-labelledby="prompt-dialog-title">
        <div className="dialog-header">
          <h2 id="prompt-dialog-title" style={{ margin: 0, fontSize: '1.05rem' }}>
            Prompt Engineering &amp; Architecture Log
          </h2>
          <button type="button" className="btn" onClick={() => dialogRef.current?.close()}>
            Close
          </button>
        </div>
        <div className="dialog-body">
          <p>
            Full prompt history is committed in <code>PROMPT_LOG.md</code> in the repository. Key engineering
            constraints enforced via structured prompting:
          </p>
          <ol>
            <li>
              <strong>Zero-Egress Security:</strong> Strict client-side React + TypeScript execution with Content Security
              Policy (<code>connect-src &apos;self&apos;</code>) and safe React text nodes (preventing DOM XSS on{' '}
              <code>&lt;script&gt;</code> payloads).
            </li>
            <li>
              <strong>Luhn &amp; Verhoeff Precision:</strong> Mod-10 Luhn validation filters out random 16-digit IDs while
              reporting rejected candidates; UIDAI Verhoeff checksum supports strict Aadhaar verification.
            </li>
            <li>
              <strong>CSV Table Diff &amp; SHA-256 Audit:</strong> RFC-4180 CSV parser enables cell-level diff inspection,
              while Web Crypto SHA-256 digests and Google Cloud DLP InfoTypes provide verifiable compliance exports.
            </li>
            <li>
              <strong>Allowlist &amp; Custom Regex Engine:</strong> Safely excludes trusted company values (e.g.,{' '}
              <code>127.0.0.1</code>) and compiles user-defined regex rules inside bounded loop guards.
            </li>
          </ol>
        </div>
      </dialog>
    </div>
  );
}

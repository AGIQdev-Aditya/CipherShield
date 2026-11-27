import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import {
  Check,
  Copy,
  Download,
  FileText,
  Lock,
  Moon,
  ShieldCheck,
  Sparkles,
  Sun,
  Trash2,
  Upload,
} from 'lucide-react';
import { redactText } from './engine/redactor';
import { DEFAULT_DETECTION_OPTIONS } from './engine/scanner';
import { SAMPLE_DATASETS } from './engine/samples';
import { DetectionOptions, PiiCategory, RedactionMode } from './types/pii';

const CATEGORY_META: Record<PiiCategory, { label: string; hint: string }> = {
  EMAIL: { label: 'Emails', hint: 'RFC email patterns' },
  PHONE: { label: 'Phones', hint: '+91 / E.164 / local' },
  IP_ADDRESS: { label: 'IP Addresses', hint: 'Strict IPv4 & IPv6' },
  PAN: { label: 'Indian PAN', hint: 'ABCDE1234F format' },
  AADHAAR: { label: 'Aadhaar', hint: '12-digit / Verhoeff' },
  CREDIT_CARD: { label: 'Credit Cards', hint: 'Luhn Mod-10 verified' },
};

const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB client-side guard

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
  const [copied, setCopied] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [liveStatus, setLiveStatus] = useState<string>('');
  const [theme, setTheme] = useState<'system' | 'dark' | 'light'>('system');

  const dialogRef = useRef<HTMLDialogElement>(null);
  const rawInputId = useId();
  const uploadInputId = useId();

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') {
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', theme);
    }
  }, [theme]);

  const result = useMemo(() => redactText(rawText, mode, options), [rawText, mode, options]);

  // Debounced live region announcement to avoid interrupting typing
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

  const handleDownload = () => {
    const ext = sourceFilename.toLowerCase().endsWith('.csv') ? 'csv' : 'txt';
    const baseName = sourceFilename.replace(/\.(txt|csv)$/i, '') || 'sanitized_output';
    const outName = `sanitized_${baseName}.${ext}`;
    const mime = ext === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8';

    const blob = new Blob([result.sanitizedText], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = outName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setLiveStatus(`Downloaded ${outName}.`);
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
              Zero-Egress Client-Side PII Detection, Luhn Validation &amp; Redaction Studio
            </p>
          </div>
        </div>

        <nav aria-label="Primary actions" className="header-actions">
          <span className="status-pill" title="All regex & validation executes strictly inside browser memory">
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
        {/* Single centralized polite live announcer */}
        <div className="visually-hidden" aria-live="polite" aria-atomic="true">
          {liveStatus}
        </div>

        {/* Input & File Upload Section */}
        <section className="panel" aria-labelledby="input-section-heading">
          <div className="toolbar-grid">
            <h2 id="input-section-heading" style={{ margin: 0, fontSize: '1.05rem' }}>
              1. Source Data Input
            </h2>

            <div className="sample-buttons" role="group" aria-label="Sample datasets">
              {SAMPLE_DATASETS.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  className="btn"
                  onClick={() => {
                    setRawText(sample.content);
                    setSourceFilename(sample.filename);
                    setUploadError(null);
                  }}
                >
                  <Sparkles size={15} aria-hidden="true" />
                  Load {sample.label}
                </button>
              ))}
              <button
                type="button"
                className="btn btn-danger"
                onClick={() => {
                  setRawText('');
                  setSourceFilename('sanitized_text.txt');
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

        {/* Redaction Mode & Category Filters */}
        <section className="panel" aria-labelledby="redaction-controls-heading">
          <h2 id="redaction-controls-heading" style={{ margin: '0 0 12px', fontSize: '1.05rem' }}>
            2. Redaction Strategy &amp; Validators
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

          <p style={{ margin: '10px 0 0', fontSize: '0.84rem', color: 'var(--text-muted)' }}>
            Active mode: <strong>{MODE_OPTIONS.find((m) => m.id === mode)?.label}</strong> —{' '}
            {MODE_OPTIONS.find((m) => m.id === mode)?.summary}.
          </p>
        </section>

        {/* Entity Audit Counters */}
        <section aria-labelledby="audit-counts-heading">
          <h2 id="audit-counts-heading" className="visually-hidden">
            Entity Detection Counts
          </h2>
          <div className="stats-grid">
            <div className="stat-card" style={{ cursor: 'default' }}>
              <span className="stat-label">Total Redacted</span>
              <span className="stat-value" style={{ color: 'var(--accent)' }}>
                {result.scan.totalDetected}
              </span>
              <span className="stat-sub">Luhn filtered: {result.scan.luhnRejectedCount} ignored</span>
            </div>

            {(Object.keys(CATEGORY_META) as PiiCategory[]).map((cat) => {
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

        {/* Side-by-Side Diff View */}
        <section aria-labelledby="diff-section-heading">
          <h2 id="diff-section-heading" className="visually-hidden">
            Side-by-Side Redaction Diff
          </h2>

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
              <pre className="diff-pre" tabIndex={0} aria-label="Original text with highlighted PII entities">
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
                    onClick={handleDownload}
                    disabled={!result.sanitizedText}
                  >
                    <Download size={15} aria-hidden="true" />
                    Download File
                  </button>
                </div>
              </div>
              <pre className="diff-pre" tabIndex={0} aria-label="Sanitized output preview">
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
        </section>

        {/* Pseudonym Ledger & Luhn Rejection Audit Table */}
        <section className="panel" aria-labelledby="audit-ledger-heading">
          <h2 id="audit-ledger-heading" style={{ margin: '0 0 12px', fontSize: '1.05rem' }}>
            3. Verification &amp; Pseudonymization Audit Ledger
          </h2>

          <div className="table-wrap">
            <table className="audit-table">
              <caption>
                Consistent Pseudonym Tokens &amp; Verification Status (Volatile RAM Only)
              </caption>
              <thead>
                <tr>
                  <th scope="col">Token ID</th>
                  <th scope="col">Category</th>
                  <th scope="col">Sample Matched</th>
                  <th scope="col">Occurrences</th>
                </tr>
              </thead>
              <tbody>
                {result.mappings.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ color: 'var(--text-muted)' }}>
                      No active PII entities detected.
                    </td>
                  </tr>
                ) : (
                  result.mappings.map((m) => (
                    <tr key={`${m.category}-${m.token}`}>
                      <td className="mono">{m.token}</td>
                      <td>{CATEGORY_META[m.category].label}</td>
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
      </main>

      <footer className="site-footer">
        <span>CipherShield · Client-Side PII Sanitization Engine</span>
        <span>Built for PromptWars × NIAT Pune · Ready for Google Cloud Run</span>
      </footer>

      {/* Accessible Native Dialog for Prompt Log */}
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
              Policy (<code>connect-src 'self'</code>) and safe React text nodes (preventing DOM XSS when pasting{' '}
              <code>&lt;script&gt;</code> payloads).
            </li>
            <li>
              <strong>Luhn &amp; Verhoeff Precision:</strong> Mod-10 Luhn validation filters out random 16-digit IDs while
              reporting rejected candidates; UIDAI Verhoeff checksum supports optional strict Aadhaar validation.
            </li>
            <li>
              <strong>Deterministic Conflict Resolution:</strong> Interval sweep resolves overlapping spans (Priority:{' '}
              <code>CREDIT_CARD &gt; EMAIL &gt; IP_ADDRESS &gt; AADHAAR &gt; PAN &gt; PHONE</code>) so card substrings are
              never double-redacted as phones.
            </li>
            <li>
              <strong>Normalized Pseudonymization:</strong> Lowercased email keys and digit-normalized phone keys map{' '}
              <code>+91 98765 43210</code> and <code>9876543210</code> to the identical <code>PHONE_01</code> token.
            </li>
            <li>
              <strong>WCAG Accessibility &amp; Cloud Run:</strong> Semantic landmarks, keyboard tablist navigation, high
              contrast tokens, and zero-dependency Node 20 container listening on <code>0.0.0.0:8080</code>.
            </li>
          </ol>
        </div>
      </dialog>
    </div>
  );
}

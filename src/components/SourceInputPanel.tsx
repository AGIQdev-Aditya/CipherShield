import { useId, useState } from 'react';
import { Shuffle, Sparkles, Trash2, Upload } from 'lucide-react';
import { generateSyntheticChaosLog, SAMPLE_DATASETS } from '../engine/samples';

const MAX_FILE_BYTES = 5 * 1024 * 1024;

interface SourceInputPanelProps {
  rawText: string;
  sourceFilename: string;
  scanDurationMs: number;
  onChangeText: (text: string) => void;
  onSelectFixture: (text: string, filename: string, preferCsv: boolean) => void;
  onClear: () => void;
}

/**
 * Input workbench supporting sample loaders, offline synthetic generation, .txt/.csv drag-drop upload, and raw text input.
 */
export function SourceInputPanel({
  rawText,
  sourceFilename,
  scanDurationMs,
  onChangeText,
  onSelectFixture,
  onClear,
}: SourceInputPanelProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const rawInputId = useId();
  const uploadInputId = useId();

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
    if (content.includes('\u0000')) {
      setUploadError('Binary payload rejected. Please upload plain UTF-8 .txt or .csv data.');
      return;
    }

    onSelectFixture(content, file.name, lower.endsWith('.csv'));
  };

  return (
    <section className="panel" aria-labelledby="input-section-heading">
      <div className="toolbar-grid">
        <h2 id="input-section-heading" className="section-heading">
          1. Source Data Input
        </h2>

        <div className="sample-buttons" role="group" aria-label="Sample datasets and synthetic chaos generator">
          {SAMPLE_DATASETS.map((sample) => (
            <button
              key={sample.id}
              type="button"
              className="btn"
              onClick={() => {
                setUploadError(null);
                onSelectFixture(sample.content, sample.filename, sample.filename.endsWith('.csv'));
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
              setUploadError(null);
              onSelectFixture(generateSyntheticChaosLog(), 'synthetic_chaos_log.txt', false);
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
              setUploadError(null);
              onClear();
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
        <p role="alert" className="alert-error">
          {uploadError}
        </p>
      )}

      <div className="field-block">
        <label htmlFor={rawInputId} className="textarea-label">
          <span>Raw Logs, Resumes, Clinical Notes, or CSV</span>
          <span className="mono textarea-meta">
            {rawText.length.toLocaleString()} chars · Scan: {scanDurationMs} ms
          </span>
        </label>
        <textarea
          id={rawInputId}
          className="raw-textarea"
          value={rawText}
          onChange={(e) => onChangeText(e.target.value)}
          placeholder="Paste raw text containing emails, phones, IPv4/IPv6, Indian PAN, Aadhaar, or credit card numbers..."
          spellCheck={false}
        />
      </div>
    </section>
  );
}

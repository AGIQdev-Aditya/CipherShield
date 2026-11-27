import { useId, useState } from 'react';
import { ChevronDown, Shuffle, Sparkles, Trash2, Upload } from 'lucide-react';
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

function DemoPresetDrawer({
  demoDrawerId,
  onSelectPreset,
  onSelectSynthetic,
}: {
  demoDrawerId: string;
  onSelectPreset: (content: string, filename: string) => void;
  onSelectSynthetic: () => void;
}) {
  return (
    <div id={demoDrawerId} className="demo-drawer" role="region" aria-label="Interactive demo presets">
      <span className="demo-drawer-label">Load Demo Preset:</span>
      <div className="sample-buttons">
        {SAMPLE_DATASETS.map((sample) => (
          <button
            key={sample.id}
            type="button"
            className="btn btn-compact"
            onClick={() => onSelectPreset(sample.content, sample.filename)}
          >
            <Sparkles size={14} aria-hidden="true" />
            {sample.label}
          </button>
        ))}
        <button
          type="button"
          className="btn btn-compact"
          onClick={onSelectSynthetic}
          title="Generate random Luhn-valid cards, decoy IDs, PAN, Aadhaar, and recurring PII offline"
        >
          <Shuffle size={14} aria-hidden="true" />
          Generate Fresh Chaos
        </button>
      </div>
    </div>
  );
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
  const [showDemos, setShowDemos] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const rawInputId = useId();
  const uploadInputId = useId();
  const demoDrawerId = useId();
  const uploadErrorId = useId();

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
        <div className="sample-buttons" role="group" aria-label="Source actions">
          <button
            type="button"
            className="btn btn-demo-trigger"
            aria-expanded={showDemos}
            aria-controls={demoDrawerId}
            onClick={() => setShowDemos((v) => !v)}
          >
            <Sparkles size={15} aria-hidden="true" />
            <span>Try Demo Data</span>
            <ChevronDown size={15} className={`chevron-rot ${showDemos ? 'is-open' : ''}`} aria-hidden="true" />
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

      {showDemos && (
        <DemoPresetDrawer
          demoDrawerId={demoDrawerId}
          onSelectPreset={(content, filename) => {
            setUploadError(null);
            setShowDemos(false);
            onSelectFixture(content, filename, filename.endsWith('.csv'));
          }}
          onSelectSynthetic={() => {
            setUploadError(null);
            setShowDemos(false);
            onSelectFixture(generateSyntheticChaosLog(), 'synthetic_chaos_log.txt', false);
          }}
        />
      )}

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
          aria-describedby={uploadError ? uploadErrorId : undefined}
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
        <p id={uploadErrorId} role="alert" className="alert-error">
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

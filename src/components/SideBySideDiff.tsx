import { Check, Copy, Download, FileSpreadsheet, ShieldCheck } from 'lucide-react';
import { ParsedCsv } from '../engine/csvParser';
import { CATEGORY_META, MODE_OPTIONS } from '../engine/dlpTaxonomy';
import { RedactionMode, RedactionResult } from '../types/pii';

interface SideBySideDiffProps {
  mode: RedactionMode;
  result: RedactionResult;
  diffViewMode: 'text' | 'csv';
  originalCsv: ParsedCsv;
  sanitizedCsv: ParsedCsv;
  neutralizeFormulas: boolean;
  copied: boolean;
  onChangeDiffView: (view: 'text' | 'csv') => void;
  onToggleNeutralizeFormulas: (neutralize: boolean) => void;
  onCopy: () => void;
  onDownloadSanitized: () => void;
  onDownloadAuditReport: () => void;
}

const CSV_PREVIEW_LIMIT = 200;

function CsvDiffPanel({
  originalCsv,
  sanitizedCsv,
  neutralizeFormulas,
  copied,
  onToggleNeutralizeFormulas,
  onCopy,
  onDownloadSanitized,
  onDownloadAuditReport,
}: {
  originalCsv: ParsedCsv;
  sanitizedCsv: ParsedCsv;
  neutralizeFormulas: boolean;
  copied: boolean;
  onToggleNeutralizeFormulas: (neutralize: boolean) => void;
  onCopy: () => void;
  onDownloadSanitized: () => void;
  onDownloadAuditReport: () => void;
}) {
  const previewRows = originalCsv.rows.slice(0, CSV_PREVIEW_LIMIT);
  const isTruncatedPreview = originalCsv.rows.length > CSV_PREVIEW_LIMIT;

  return (
    <div className="panel table-wrap">
      <div className="diff-card-header csv-banner">
        <div>
          <span className="csv-banner-title">RFC-4180 CSV Cell-by-Cell Diff (Original → Sanitized)</span>
          <label className="checkbox-inline formula-toggle">
            <input
              type="checkbox"
              checked={neutralizeFormulas}
              onChange={(e) => onToggleNeutralizeFormulas(e.target.checked)}
            />
            <span>Neutralize spreadsheet formulas (=, +, -, @) on export (CWE-1236)</span>
          </label>
        </div>
        <div className="action-row">
          <button type="button" className="btn" onClick={onCopy}>
            {copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
            {copied ? 'Copied' : 'Copy CSV'}
          </button>
          <button type="button" className="btn btn-primary" onClick={onDownloadSanitized}>
            <Download size={15} aria-hidden="true" />
            Download Sanitized CSV
          </button>
          <button type="button" className="btn" onClick={onDownloadAuditReport}>
            <ShieldCheck size={15} aria-hidden="true" />
            Export SHA-256 Audit JSON
          </button>
        </div>
      </div>

      {isTruncatedPreview && (
        <p className="panel-subtitle csv-preview-note">
          Showing first {CSV_PREVIEW_LIMIT} of {originalCsv.rows.length} rows in table preview — Copy &amp; Download export
          all {originalCsv.rows.length} rows intact.
        </p>
      )}

      <table className="audit-table">
        <caption>CSV Original vs. Sanitized Cell Comparison</caption>
        <thead>
          <tr>
            <th scope="col">Row</th>
            {originalCsv.headers.map((origH, idx) => {
              const cleanH = sanitizedCsv.headers[idx] ?? origH;
              return (
                <th scope="col" key={`h-${idx}`} className="mono">
                  {origH !== cleanH ? (
                    <span>
                      <span className="struck-cell">{origH}</span> → <span className="pii-redacted">{cleanH}</span>
                    </span>
                  ) : (
                    origH
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {previewRows.map((row, rIdx) => (
            <tr key={`row-${rIdx}`}>
              <td className="mono">{rIdx + 1}</td>
              {row.map((origCell, cIdx) => {
                const cleanCell = sanitizedCsv.rows[rIdx]?.[cIdx] ?? origCell;
                return (
                  <td key={`cell-${rIdx}-${cIdx}`} className="mono">
                    {origCell !== cleanCell ? (
                      <span>
                        <span className="struck-cell">{origCell}</span>
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
  );
}

function TextDiffCards({
  modeLabel,
  result,
  copied,
  onCopy,
  onDownloadSanitized,
  onDownloadAuditReport,
}: {
  modeLabel: string;
  result: RedactionResult;
  copied: boolean;
  onCopy: () => void;
  onDownloadSanitized: () => void;
  onDownloadAuditReport: () => void;
}) {
  return (
    <div className="diff-grid">
      <article className="diff-card" aria-labelledby="orig-diff-title">
        <div className="diff-card-header">
          <h3 id="orig-diff-title" className="diff-card-title">
            Original Input (Highlighted PII)
          </h3>
          <span className="mono match-count">{result.scan.totalDetected} matches</span>
        </div>
        <pre className="diff-pre" aria-label="Original text with highlighted PII entities">
          {result.originalSegments.length === 0 ? (
            <span className="muted-copy">No input text provided.</span>
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
            Sanitized Output ({modeLabel})
          </h3>
          <div className="action-row">
            <button type="button" className="btn" onClick={onCopy} disabled={!result.sanitizedText}>
              {copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <button type="button" className="btn btn-primary" onClick={onDownloadSanitized} disabled={!result.sanitizedText}>
              <Download size={15} aria-hidden="true" />
              Download File
            </button>
            <button
              type="button"
              className="btn"
              onClick={onDownloadAuditReport}
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
            <span className="muted-copy">Sanitized output appears here.</span>
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
  );
}

/**
 * Renders live side-by-side Original vs. Sanitized text diff or RFC-4180 CSV cell comparison.
 */
export function SideBySideDiff({
  mode,
  result,
  diffViewMode,
  originalCsv,
  sanitizedCsv,
  neutralizeFormulas,
  copied,
  onChangeDiffView,
  onToggleNeutralizeFormulas,
  onCopy,
  onDownloadSanitized,
  onDownloadAuditReport,
}: SideBySideDiffProps) {
  const modeLabel = MODE_OPTIONS.find((m) => m.id === mode)?.label ?? mode;

  return (
    <section aria-labelledby="diff-section-heading">
      <div className="diff-toolbar">
        <h2 id="diff-section-heading" className="section-heading">
          3. Live Side-by-Side Audit Diff
        </h2>

        {originalCsv.isTabular && (
          <div className="sample-buttons" role="group" aria-label="Diff display format">
            <button
              type="button"
              className={`btn ${diffViewMode === 'text' ? 'btn-primary' : ''}`}
              aria-pressed={diffViewMode === 'text'}
              onClick={() => onChangeDiffView('text')}
            >
              Text Diff View
            </button>
            <button
              type="button"
              className={`btn ${diffViewMode === 'csv' ? 'btn-primary' : ''}`}
              aria-pressed={diffViewMode === 'csv'}
              onClick={() => onChangeDiffView('csv')}
            >
              <FileSpreadsheet size={15} aria-hidden="true" />
              CSV Column Diff ({originalCsv.rows.length} rows)
            </button>
          </div>
        )}
      </div>

      {originalCsv.parseError && (
        <p role="alert" className="alert-error csv-parse-alert">
          {originalCsv.parseError}
        </p>
      )}

      {diffViewMode === 'csv' && originalCsv.isTabular && sanitizedCsv.isTabular ? (
        <CsvDiffPanel
          originalCsv={originalCsv}
          sanitizedCsv={sanitizedCsv}
          neutralizeFormulas={neutralizeFormulas}
          copied={copied}
          onToggleNeutralizeFormulas={onToggleNeutralizeFormulas}
          onCopy={onCopy}
          onDownloadSanitized={onDownloadSanitized}
          onDownloadAuditReport={onDownloadAuditReport}
        />
      ) : (
        <TextDiffCards
          modeLabel={modeLabel}
          result={result}
          copied={copied}
          onCopy={onCopy}
          onDownloadSanitized={onDownloadSanitized}
          onDownloadAuditReport={onDownloadAuditReport}
        />
      )}
    </section>
  );
}

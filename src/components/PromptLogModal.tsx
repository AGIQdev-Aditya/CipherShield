import { RefObject } from 'react';

interface PromptLogModalProps {
  dialogRef: RefObject<HTMLDialogElement | null>;
}

/**
 * Native modal dialog displaying architecture and prompt engineering documentation.
 */
export function PromptLogModal({ dialogRef }: PromptLogModalProps) {
  return (
    <dialog ref={dialogRef} className="prompt-dialog" aria-labelledby="prompt-dialog-title">
      <div className="dialog-header">
        <h2 id="prompt-dialog-title" className="section-heading">
          Prompt Engineering &amp; Architecture Log
        </h2>
        <button type="button" className="btn" onClick={() => dialogRef.current?.close()}>
          Close
        </button>
      </div>
      <div className="dialog-body">
        <p>
          Full prompt history is committed in <code>PROMPT_LOG.md</code> in the repository. Key engineering constraints
          enforced via structured prompting:
        </p>
        <ol>
          <li>
            <strong>Zero-Egress Security:</strong> Strict client-side React + TypeScript execution with Content Security
            Policy (zero <code>&apos;unsafe-inline&apos;</code>) and safe React text nodes preventing DOM XSS on{' '}
            <code>&lt;script&gt;</code> payloads.
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
            <strong>Allowlist &amp; ReDoS-Guarded Custom Regex:</strong> Safely excludes trusted company values (e.g.,{' '}
            <code>127.0.0.1</code>) and blocks catastrophic nested-quantifier user patterns.
          </li>
        </ol>
      </div>
    </dialog>
  );
}

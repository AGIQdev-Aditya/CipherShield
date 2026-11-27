import { useId, useState } from 'react';
import { CheckCircle2, EyeOff, FlaskConical, KeyRound, Lock, RotateCcw, Unlock, XCircle } from 'lucide-react';
import { decryptPseudonymLedger, EncryptedVaultBundle, encryptPseudonymLedger } from '../engine/cryptoVault';
import { CATEGORY_META, GOOGLE_DLP_INFOTYPE_MAP } from '../engine/dlpTaxonomy';
import { runAdversarialSelfTest, SelfTestReport } from '../engine/selfTest';
import { DiffSegment, PseudonymMapping, RejectedCandidate } from '../types/pii';

interface AuditLedgerProps {
  segments: DiffSegment[];
  mappings: PseudonymMapping[];
  rejectedCards: RejectedCandidate[];
  allowlist: string[];
  onKeepOriginal: (value: string) => void;
  onRestoreAllowlisted: (value: string) => void;
  onDownloadBundle: (content: string, filename: string, mime: string) => void;
}

/**
 * Interactive detected-entity override inspector, Cloud DLP taxonomy ledger,
 * Luhn rejections log, AES-256-GCM vault (PBKDF2 600k), and live adversarial self-test proof.
 */
export function AuditLedger({
  segments,
  mappings,
  rejectedCards,
  allowlist,
  onKeepOriginal,
  onRestoreAllowlisted,
  onDownloadBundle,
}: AuditLedgerProps) {
  const [passphrase, setPassphrase] = useState('');
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [decryptedRows, setDecryptedRows] = useState<PseudonymMapping[] | null>(null);
  const [selfTestReport, setSelfTestReport] = useState<SelfTestReport | null>(null);
  const passId = useId();
  const keyFileId = useId();

  // Group detected entity replacements cleanly so users can inspect every change & override individually
  const detectedItems = segments.filter((seg) => Boolean(seg.entity));

  const handleEncryptDownload = async () => {
    setVaultError(null);
    try {
      const bundle = await encryptPseudonymLedger(mappings, passphrase);
      onDownloadBundle(
        JSON.stringify(bundle, null, 2),
        'ciphershield_vault.key.json',
        'application/json;charset=utf-8',
      );
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : 'Encryption failed.');
    }
  };

  const handleDecryptFile = async (file: File | undefined) => {
    setVaultError(null);
    setDecryptedRows(null);
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as EncryptedVaultBundle;
      const unlocked = await decryptPseudonymLedger(parsed, passphrase);
      setDecryptedRows(unlocked);
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : 'Failed to decrypt vault file.');
    }
  };

  return (
    <section className="panel" aria-labelledby="audit-ledger-heading">
      <div className="diff-card-header entity-review-header">
        <div>
          <h2 id="audit-ledger-heading" className="section-heading">
            4. Entity Change Review, Cloud DLP Audit &amp; AES-256-GCM Vault
          </h2>
          <p className="panel-subtitle">
            Inspect every detected value before exporting and click <strong>Keep Original</strong> on any false
            positive or approved exception to exclude it immediately.
          </p>
        </div>
        <button
          type="button"
          className="btn"
          onClick={() => setSelfTestReport(runAdversarialSelfTest())}
        >
          <FlaskConical size={15} aria-hidden="true" />
          Run 10-Case Adversarial Self-Test
        </button>
      </div>

      {/* Interactive Detected Entities Inspector */}
      <div className="entity-review-box">
        <div className="table-wrap">
          <table className="audit-table">
            <caption>
              Detected Entities &amp; Exact Transformations ({detectedItems.length} occurrences caught)
            </caption>
            <thead>
              <tr>
                <th scope="col">Detected Original Data</th>
                <th scope="col">Redacted / Replaced With</th>
                <th scope="col">Category &amp; Validator</th>
                <th scope="col">Confidence</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {detectedItems.length === 0 ? (
                <tr>
                  <td colSpan={5} className="muted-copy">
                    No active PII entities detected to modify.
                  </td>
                </tr>
              ) : (
                detectedItems.slice(0, 100).map((seg) => {
                  const ent = seg.entity!;
                  return (
                    <tr key={ent.id}>
                      <td className="mono">{ent.value}</td>
                      <td className="mono pii-redacted">{seg.replacement ?? ''}</td>
                      <td>
                        {CATEGORY_META[ent.category].label}{' '}
                        <span className="muted-copy mono">({ent.metadata ?? ent.validatedBy})</span>
                      </td>
                      <td>
                        <span className={`confidence-badge confidence-${ent.confidence.toLowerCase()}`}>
                          {ent.confidence}
                        </span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-compact"
                          onClick={() => onKeepOriginal(ent.value)}
                          title={`Keep "${ent.value}" unredacted by adding it to the Allowlist`}
                        >
                          <EyeOff size={13} aria-hidden="true" />
                          Keep Original
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {allowlist.length > 0 && (
          <div className="allowlist-chips" aria-label="Kept / Allowlisted items">
            <span className="field-label allowlist-label">Kept Unredacted ({allowlist.length}):</span>
            {allowlist.map((item) => (
              <button
                key={`allow-${item}`}
                type="button"
                className="btn btn-compact chip-btn mono"
                onClick={() => onRestoreAllowlisted(item)}
                title={`Re-enable PII redaction for ${item}`}
              >
                <RotateCcw size={12} aria-hidden="true" />
                {item} ×
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Consistent Pseudonym & Cloud DLP Taxonomy Table */}
      <div className="table-wrap entity-review-box">
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
            {mappings.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted-copy">
                  No active PII entities detected.
                </td>
              </tr>
            ) : (
              mappings.map((m) => (
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

      {/* Adversarial Self-Test Proof Results */}
      {selfTestReport && (
        <div className="selftest-box" aria-live="polite">
          <div className="vault-head">
            <CheckCircle2 size={17} aria-hidden="true" className="safe-ink" />
            <strong>
              Live Adversarial Proof: {selfTestReport.passed}/{selfTestReport.total} Passed ({selfTestReport.durationMs}{' '}
              ms)
            </strong>
          </div>
          <ul className="selftest-list">
            {selfTestReport.cases.map((tc) => (
              <li key={tc.id} className={tc.passed ? 'selftest-pass' : 'selftest-fail'}>
                {tc.passed ? (
                  <CheckCircle2 size={14} aria-hidden="true" className="safe-ink" />
                ) : (
                  <XCircle size={14} aria-hidden="true" className="warn-ink" />
                )}
                <span>
                  <strong>{tc.title}</strong> — <span className="mono">{tc.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Reversible AES-256-GCM Encrypted Key Vault */}
      <div className="vault-box">
        <div className="vault-head">
          <KeyRound size={17} aria-hidden="true" className="safe-ink" />
          <strong>Reversible AES-256-GCM Pseudonym Vault (Web Crypto · PBKDF2 600k + AAD)</strong>
        </div>
        <p className="panel-subtitle">
          Encrypt your pseudonym mapping locally with a passphrase (minimum 8 characters) so authorized auditors can
          reverse tokens offline later without storing plaintext PII.
        </p>

        <div className="policy-grid policy-grid-borderless">
          <div>
            <label htmlFor={passId} className="field-label">
              Vault Passphrase (Min 8 characters, never leaves browser)
            </label>
            <input
              id={passId}
              type="password"
              className="text-input mono"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Enter 8+ char passphrase to lock/unlock..."
              autoComplete="off"
            />
          </div>

          <div className="sample-buttons align-end">
            <button
              type="button"
              className="btn btn-primary"
              disabled={mappings.length === 0 || passphrase.length < 8}
              onClick={() => void handleEncryptDownload()}
            >
              <Lock size={15} aria-hidden="true" />
              Export AES-GCM Key (.key.json)
            </button>

            <label htmlFor={keyFileId} className="btn">
              <Unlock size={15} aria-hidden="true" />
              Decrypt Vault File
            </label>
            <input
              id={keyFileId}
              type="file"
              accept=".json,application/json"
              className="visually-hidden"
              onChange={(e) => {
                void handleDecryptFile(e.target.files?.[0]);
                e.target.value = '';
              }}
            />
          </div>
        </div>

        {vaultError && (
          <p role="alert" className="alert-error">
            {vaultError}
          </p>
        )}

        {decryptedRows && (
          <div className="vault-decrypted">
            <strong>Decrypted Mapping Restored ({decryptedRows.length} entries):</strong>
            <ul className="rejected-list">
              {decryptedRows.map((entry) => (
                <li key={`dec-${entry.token}`}>
                  <code className="mono">{entry.token}</code> ↔ <code className="mono">{entry.sampleValue}</code>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {rejectedCards.length > 0 && (
        <div className="rejected-box">
          <h3 className="rejected-heading">
            Numeric Strings Rejected by Luhn Validation ({rejectedCards.length})
          </h3>
          <ul className="rejected-list">
            {rejectedCards.map((rej, idx) => (
              <li key={`${rej.start}-${idx}`}>
                <code className="mono">{rej.value}</code> — {rej.reason} (preserved untouched)
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

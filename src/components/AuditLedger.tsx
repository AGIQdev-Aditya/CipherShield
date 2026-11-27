import { useId, useState } from 'react';
import { KeyRound, Lock, Unlock } from 'lucide-react';
import { decryptPseudonymLedger, EncryptedVaultBundle, encryptPseudonymLedger } from '../engine/cryptoVault';
import { CATEGORY_META, GOOGLE_DLP_INFOTYPE_MAP } from '../engine/dlpTaxonomy';
import { PseudonymMapping, RejectedCandidate } from '../types/pii';

interface AuditLedgerProps {
  mappings: PseudonymMapping[];
  rejectedCards: RejectedCandidate[];
  onDownloadBundle: (content: string, filename: string, mime: string) => void;
}

/**
 * Semantic audit table with Cloud DLP InfoTypes, Luhn rejections,
 * and PBKDF2 + AES-256-GCM reversible key vault export/decrypt.
 */
export function AuditLedger({ mappings, rejectedCards, onDownloadBundle }: AuditLedgerProps) {
  const [passphrase, setPassphrase] = useState('');
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [decryptedRows, setDecryptedRows] = useState<PseudonymMapping[] | null>(null);
  const passId = useId();
  const keyFileId = useId();

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
      <h2 id="audit-ledger-heading" className="section-heading section-heading-spaced">
        4. Verification, Cloud DLP Taxonomy &amp; AES-256-GCM Key Vault
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

      {/* Reversible AES-256-GCM Encrypted Key Vault */}
      <div className="vault-box">
        <div className="vault-head">
          <KeyRound size={17} aria-hidden="true" className="safe-ink" />
          <strong>Reversible AES-256-GCM Pseudonym Vault (Web Crypto · PBKDF2 100k)</strong>
        </div>
        <p className="panel-subtitle">
          Encrypt your pseudonym mapping locally with a passphrase so authorized auditors can reverse tokens offline
          later without storing plaintext PII.
        </p>

        <div className="policy-grid policy-grid-borderless">
          <div>
            <label htmlFor={passId} className="field-label">
              Vault Passphrase (Min 4 characters, never leaves browser)
            </label>
            <input
              id={passId}
              type="password"
              className="text-input mono"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Enter passphrase to lock/unlock..."
              autoComplete="off"
            />
          </div>

          <div className="sample-buttons align-end">
            <button
              type="button"
              className="btn btn-primary"
              disabled={mappings.length === 0 || passphrase.length < 4}
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

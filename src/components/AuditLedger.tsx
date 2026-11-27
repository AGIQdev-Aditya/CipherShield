import { CATEGORY_META, GOOGLE_DLP_INFOTYPE_MAP } from '../engine/dlpTaxonomy';
import { PseudonymMapping, RejectedCandidate } from '../types/pii';

interface AuditLedgerProps {
  mappings: PseudonymMapping[];
  rejectedCards: RejectedCandidate[];
}

/**
 * Semantic audit table mapping consistent tokens, Cloud DLP InfoTypes, and Luhn rejections.
 */
export function AuditLedger({ mappings, rejectedCards }: AuditLedgerProps) {
  return (
    <section className="panel" aria-labelledby="audit-ledger-heading">
      <h2 id="audit-ledger-heading" className="section-heading section-heading-spaced">
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

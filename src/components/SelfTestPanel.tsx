import { FlaskConical } from 'lucide-react';
import { SelfTestReport } from '../engine/selfTest';

interface SelfTestPanelProps {
  selfTest: SelfTestReport | null;
  onRunSelfTest: () => void;
}

/**
 * Live 10-case adversarial browser self-test panel verifying Luhn, IMEI rejection, PAN,
 * UIDAI Verhoeff, atomic IPv6, Amex masking, UPI, libphonenumber, ReDoS guard, and CSV safety.
 */
export function SelfTestPanel({ selfTest, onRunSelfTest }: SelfTestPanelProps) {
  return (
    <section className="panel" aria-labelledby="selftest-heading">
      <div className="st-head">
        <div>
          <h2 id="selftest-heading" className="section-heading">
            Live 10-Case Adversarial Engine Proof
          </h2>
          <p className="panel-subtitle proof-empty">
            Deterministic probes verifying Luhn/IMEI filtering, PAN holder rules, Verhoeff UIDAI Aadhaar, IPv4-mapped
            IPv6, Amex masking, UPI separation, Google libphonenumber, ReDoS guard, and CWE-1236 CSV.
          </p>
        </div>
        <div className="action-row st-actions">
          {selfTest && (
            <span className={`st-score mono ${selfTest.passed === selfTest.total ? 'safe-ink' : 'warn-ink'}`}>
              Live Adversarial Proof: {selfTest.passed}/{selfTest.total} Passed ({selfTest.durationMs} ms)
            </span>
          )}
          <button type="button" className="btn btn-primary" onClick={onRunSelfTest}>
            <FlaskConical size={15} aria-hidden="true" />
            Run 10-Case Adversarial Self-Test
          </button>
        </div>
      </div>

      {!selfTest ? (
        <p className="muted-copy proof-empty">
          Click <strong>Run 10-Case Adversarial Self-Test</strong> to execute and inspect all verification vectors live
          inside your browser.
        </p>
      ) : (
        <div className="st-grid">
          {selfTest.cases.map((c) => (
            <article key={c.id} className={`st-case ${c.passed ? 'is-pass' : 'is-fail'}`}>
              <div className="st-title">
                <span className={`st-badge ${c.passed ? 'pass' : 'fail'}`}>{c.passed ? 'PASS' : 'FAIL'}</span>
                <span>{c.title}</span>
              </div>
              <div className="st-detail mono">{c.detail}</div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

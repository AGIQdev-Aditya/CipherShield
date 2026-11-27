import { useId, useState } from 'react';
import { Shuffle, Sparkles } from 'lucide-react';
import { ScanResult } from '../types/pii';

interface GeminiAdvisorPanelProps {
  scan: ScanResult;
  onApplySyntheticText: (text: string) => void;
}

/**
 * Lazy-loads @google/genai strictly on explicit user interaction using aggregate counts only.
 */
export function GeminiAdvisorPanel({ scan, onApplySyntheticText }: GeminiAdvisorPanelProps) {
  const [geminiKey, setGeminiKey] = useState<string>('');
  const [geminiOutput, setGeminiOutput] = useState<string>('');
  const [geminiLoading, setGeminiLoading] = useState<boolean>(false);
  const [geminiError, setGeminiError] = useState<string | null>(null);
  const geminiKeyId = useId();

  const handleGeminiAdvice = async () => {
    setGeminiError(null);
    setGeminiLoading(true);
    try {
      const { generateComplianceAdvice } = await import('../services/geminiAdvisor');
      const advice = await generateComplianceAdvice(geminiKey, scan);
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
      const { generateGeminiSyntheticLog } = await import('../services/geminiAdvisor');
      const synthetic = await generateGeminiSyntheticLog(geminiKey);
      if (synthetic) {
        onApplySyntheticText(synthetic);
      }
    } catch (err) {
      setGeminiError(err instanceof Error ? err.message : 'Gemini synthetic generation failed.');
    } finally {
      setGeminiLoading(false);
    }
  };

  return (
    <section className="panel" aria-labelledby="gemini-advisor-heading">
      <div className="toolbar-grid">
        <div>
          <h2 id="gemini-advisor-heading" className="section-heading">
            5. Optional Google Gemini Compliance Advisor (Counts-Only)
          </h2>
          <p className="panel-subtitle">
            Zero raw text or PII ever leaves your browser. Only anonymized Cloud DLP entity counts or synthetic test
            requests are sent if you supply a Gemini key.
          </p>
        </div>
      </div>

      <div className="policy-grid policy-grid-borderless">
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

        <div className="sample-buttons align-end">
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
        <p role="alert" className="alert-error">
          {geminiError}
        </p>
      )}

      {geminiOutput && <pre className="diff-pre gemini-output">{geminiOutput}</pre>}
    </section>
  );
}

import React, { useId } from 'react';
import { SlidersHorizontal } from 'lucide-react';
import { MODE_OPTIONS } from '../engine/dlpTaxonomy';
import { DetectionOptions, RedactionMode } from '../types/pii';

interface PolicyControlsProps {
  mode: RedactionMode;
  options: DetectionOptions;
  allowlistText: string;
  customRuleError: string | null;
  onChangeMode: (mode: RedactionMode) => void;
  onChangeOptions: React.Dispatch<React.SetStateAction<DetectionOptions>>;
  onChangeAllowlist: (value: string) => void;
}

/**
 * Redaction strategy selector (Full, Partial, Pseudonymize), Verhoeff toggle, allowlist, and custom regex controls.
 */
export function PolicyControls({
  mode,
  options,
  allowlistText,
  customRuleError,
  onChangeMode,
  onChangeOptions,
  onChangeAllowlist,
}: PolicyControlsProps) {
  const allowlistInputId = useId();
  const customLabelId = useId();
  const customPatternId = useId();

  const handleModeKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>, currentIdx: number) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const delta = e.key === 'ArrowRight' ? 1 : -1;
      const nextIdx = (currentIdx + delta + MODE_OPTIONS.length) % MODE_OPTIONS.length;
      onChangeMode(MODE_OPTIONS[nextIdx].id);
    }
  };

  const activeMode = MODE_OPTIONS.find((m) => m.id === mode);

  return (
    <section className="panel" aria-labelledby="redaction-controls-heading">
      <h2 id="redaction-controls-heading" className="section-heading section-heading-spaced">
        2. Redaction Strategy, Allowlist &amp; Custom Policy
      </h2>

      <div className="mode-bar">
        <div className="tablist" role="tablist" aria-label="Redaction mode">
          {MODE_OPTIONS.map((item, idx) => (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-label={item.label}
              aria-selected={mode === item.id}
              className="mode-tab"
              onClick={() => onChangeMode(item.id)}
              onKeyDown={(e) => handleModeKeyDown(e, idx)}
            >
              <span>{item.label}</span>
              <kbd className="keycap keycap-inline" aria-hidden="true">
                {idx + 1}
              </kbd>
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
                  onChangeOptions((prev) => ({
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
                onChangeOptions((prev) => ({ ...prev, strictAadhaarVerhoeff: e.target.checked }))
              }
            />
            Strict UIDAI Verhoeff checksum on Aadhaar
          </label>
        </div>
      </div>

      <p className="mode-summary">
        Active mode: <strong>{activeMode?.label}</strong> — {activeMode?.summary}.
      </p>

      <div className="policy-grid">
        <div>
          <label htmlFor={allowlistInputId} className="field-label">
            Allowlist (Comma-separated safe values never redacted)
          </label>
          <input
            id={allowlistInputId}
            type="text"
            className="text-input mono"
            value={allowlistText}
            onChange={(e) => onChangeAllowlist(e.target.value)}
            placeholder="e.g. 127.0.0.1, support@company.com"
          />
        </div>

        <div>
          <div className="custom-rule-head">
            <label className="checkbox-label bold-label">
              <input
                type="checkbox"
                checked={options.customRule.enabled}
                onChange={(e) =>
                  onChangeOptions((prev) => ({
                    ...prev,
                    customRule: { ...prev.customRule, enabled: e.target.checked },
                  }))
                }
              />
              <SlidersHorizontal size={15} aria-hidden="true" />
              Enable Custom Regex Rule
            </label>
          </div>
          <div className="custom-rule-inputs">
            <div>
              <label htmlFor={customLabelId} className="visually-hidden">
                Custom entity label
              </label>
              <input
                id={customLabelId}
                type="text"
                className="text-input mono"
                value={options.customRule.label}
                onChange={(e) =>
                  onChangeOptions((prev) => ({
                    ...prev,
                    customRule: { ...prev.customRule, label: e.target.value },
                  }))
                }
                placeholder="EMP_ID"
              />
            </div>
            <div>
              <label htmlFor={customPatternId} className="visually-hidden">
                Custom regular expression pattern
              </label>
              <input
                id={customPatternId}
                type="text"
                className="text-input mono"
                value={options.customRule.pattern}
                onChange={(e) =>
                  onChangeOptions((prev) => ({
                    ...prev,
                    customRule: { ...prev.customRule, pattern: e.target.value },
                  }))
                }
                placeholder="EMP-\d{4,6}"
              />
            </div>
          </div>
          {customRuleError && (
            <p role="alert" className="alert-error-compact">
              {customRuleError}
            </p>
          )}
        </div>
      </div>
    </section>
  );
}

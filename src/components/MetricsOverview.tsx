import { ShieldAlert } from 'lucide-react';
import { CATEGORY_META } from '../engine/dlpTaxonomy';
import { DetectionOptions, PiiCategory, ScanResult } from '../types/pii';

interface MetricsOverviewProps {
  scan: ScanResult;
  options: DetectionOptions;
  onToggleCategory: (category: PiiCategory) => void;
}

/**
 * Exposure risk banner paired with interactive per-category entity counters.
 */
export function MetricsOverview({ scan, options, onToggleCategory }: MetricsOverviewProps) {
  return (
    <section aria-labelledby="audit-counts-heading">
      <h2 id="audit-counts-heading" className="visually-hidden">
        Exposure Risk Score and Entity Detection Counts
      </h2>

      <div className="risk-banner panel">
        <div className="risk-info">
          <ShieldAlert size={20} aria-hidden="true" className="risk-icon" />
          <div>
            <strong>Privacy Exposure Score:</strong>{' '}
            <span className="mono">
              Raw {scan.risk.scoreBefore}/100 ({scan.risk.levelBefore})
            </span>{' '}
            → Sanitized <strong className="mono safe-ink">0/100 SECURE</strong>
          </div>
        </div>
        <div className="risk-meta mono">
          Luhn Filtered: {scan.luhnRejectedCount} · Allowlisted: {scan.allowlistedCount}
        </div>
      </div>

      <div className="stats-grid">
        {(Object.keys(CATEGORY_META) as PiiCategory[])
          .filter((cat) => cat !== 'CUSTOM' || options.customRule.enabled)
          .map((cat) => {
            const enabled = options.enabledCategories[cat];
            return (
              <button
                key={cat}
                type="button"
                className="stat-card"
                aria-pressed={enabled}
                onClick={() => onToggleCategory(cat)}
                title={`Toggle ${CATEGORY_META[cat].label} detection`}
              >
                <span className="stat-label">{CATEGORY_META[cat].label}</span>
                <span className="stat-value">{scan.counts[cat]}</span>
                <span className="stat-sub">
                  {enabled ? CATEGORY_META[cat].hint : 'Disabled (click to enable)'}
                </span>
              </button>
            );
          })}
      </div>
    </section>
  );
}

import { CATEGORY_META } from '../engine/dlpTaxonomy';
import { DetectionOptions, PiiCategory, ScanResult } from '../types/pii';

interface MetricsOverviewProps {
  scan: ScanResult;
  options: DetectionOptions;
  onToggleCategory: (category: PiiCategory) => void;
}

/**
 * Compact interactive category detector toggles with live match counts.
 */
export function MetricsOverview({ scan, options, onToggleCategory }: MetricsOverviewProps) {
  return (
    <section className="category-strip" aria-labelledby="audit-counts-heading">
      <div className="category-strip-head">
        <h2 id="audit-counts-heading" className="field-label category-strip-title">
          Active PII Detectors (Click to toggle)
        </h2>
        <span className="risk-meta mono">Allowlisted preserved: {scan.allowlistedCount}</span>
      </div>

      <div className="stats-grid">
        {(Object.keys(CATEGORY_META) as PiiCategory[])
          .filter((cat) => cat !== 'CUSTOM' || options.customRule.enabled)
          .map((cat) => {
            const enabled = options.enabledCategories[cat];
            const count = scan.counts[cat];
            return (
              <button
                key={cat}
                type="button"
                className={`stat-card ${count > 0 && enabled ? 'has-hits' : ''}`}
                aria-pressed={enabled}
                onClick={() => onToggleCategory(cat)}
                title={`${CATEGORY_META[cat].hint} — Click to toggle ${CATEGORY_META[cat].label}`}
              >
                <div className="stat-top-row">
                  <span className="stat-label">{CATEGORY_META[cat].label}</span>
                  <span className="stat-value mono">{count}</span>
                </div>
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

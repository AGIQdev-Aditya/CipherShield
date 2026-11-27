import { ScanResult } from '../types/pii';

interface TelemetryStripProps {
  scan: ScanResult;
  charCount: number;
  shouldUseWorker: boolean;
}

/**
 * Top telemetry KPI strip displaying detected entity counts, before/after risk score,
 * Luhn rejections, and RAM vs. Web Worker execution telemetry.
 */
export function TelemetryStrip({ scan, charCount, shouldUseWorker }: TelemetryStripProps) {
  const activeCategories = Object.values(scan.counts).filter((n) => n > 0).length;

  return (
    <section className="mc-strip" aria-label="Sanitization telemetry summary">
      <div className="mc-card mc-cyan">
        <span className="mc-label">Entities detected</span>
        <span className="mc-value mono">{scan.totalDetected}</span>
        <span className="mc-sub">{activeCategories} active categories</span>
      </div>
      <div className="mc-card mc-red">
        <span className="mc-label">Exposure before</span>
        <span className="mc-value mono">{scan.risk.scoreBefore}/100</span>
        <span className="mc-sub">{scan.risk.levelBefore}</span>
      </div>
      <div className="mc-card mc-green">
        <span className="mc-label">Residual after</span>
        <span className="mc-value mono">{scan.risk.scoreAfter}/100</span>
        <span className="mc-sub">{scan.risk.residualCount} residual entities</span>
      </div>
      <div className="mc-card mc-amber">
        <span className="mc-label">Luhn rejected</span>
        <span className="mc-value mono">{scan.luhnRejectedCount}</span>
        <span className="mc-sub">non-card IDs preserved</span>
      </div>
      <div className="mc-card mc-violet">
        <span className="mc-label">Scan speed</span>
        <span className="mc-value mono">
          {scan.durationMs}
          <span className="mc-unit"> ms</span>
        </span>
        <span className="mc-sub">
          {charCount.toLocaleString()} chars · {shouldUseWorker ? 'Web Worker' : 'Main RAM'}
        </span>
      </div>
    </section>
  );
}

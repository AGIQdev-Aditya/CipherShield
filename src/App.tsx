import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { FlaskConical } from 'lucide-react';
import { AuditLedger } from './components/AuditLedger';
import { GeminiAdvisorPanel } from './components/GeminiAdvisorPanel';
import { HeaderBar } from './components/HeaderBar';
import { MetricsOverview } from './components/MetricsOverview';
import { PolicyControls } from './components/PolicyControls';
import { PromptLogModal } from './components/PromptLogModal';
import { SideBySideDiff } from './components/SideBySideDiff';
import { SourceInputPanel } from './components/SourceInputPanel';
import { parseCsvRows, ParsedCsv, redactCsvCells } from './engine/csvParser';
import { buildCloudDlpDeidentifyConfig, buildCloudDlpSummary } from './engine/dlpTaxonomy';
import { installNetworkMonitor, NetworkMonitorState } from './engine/networkMonitor';
import { redactText, sha256Hex } from './engine/redactor';
import { DEFAULT_DETECTION_OPTIONS } from './engine/scanner';
import { SAMPLE_DATASETS } from './engine/samples';
import { runAdversarialSelfTest, SelfTestReport } from './engine/selfTest';
import type { SafeScanSummary } from './services/geminiAdvisor';
import { DetectionOptions, PiiCategory, RedactionMode, RedactionResult } from './types/pii';
import type { SanitizedCsvBundle, WorkerScanRequest, WorkerScanResponse } from './workers/scanner.worker';

const WORKER_OFFLOAD_CHARS = 8_000;

type DrawerTab = 'audit' | 'proof' | 'gemini';

interface ToastState {
  message: string;
  undoAllowlist?: string;
}

/**
 * Root CipherShield workspace coordinating deferred + Web Worker PII scanning,
 * live zero-egress network proof log, interactive drawer panels, undo toast, and audit exports.
 */
export default function App() {
  const [rawText, setRawText] = useState<string>(SAMPLE_DATASETS[0].content);
  const [sourceFilename, setSourceFilename] = useState<string>(SAMPLE_DATASETS[0].filename);
  const [mode, setMode] = useState<RedactionMode>('pseudonymize');
  const [options, setOptions] = useState<DetectionOptions>(DEFAULT_DETECTION_OPTIONS);
  const [allowlistText, setAllowlistText] = useState<string>(DEFAULT_DETECTION_OPTIONS.allowlist.join(', '));
  const [copied, setCopied] = useState(false);
  const [liveStatus, setLiveStatus] = useState<string>('');
  const [theme, setTheme] = useState<'system' | 'dark' | 'light'>('system');
  const [diffViewMode, setDiffViewMode] = useState<'text' | 'csv'>('text');
  const [neutralizeFormulas, setNeutralizeFormulas] = useState<boolean>(true);
  const [drawer, setDrawer] = useState<DrawerTab>('audit');
  const [showProofLog, setShowProofLog] = useState(false);
  const [selfTest, setSelfTest] = useState<SelfTestReport | null>(null);
  const [toast, setToast] = useState<ToastState | null>(null);
  const [networkState, setNetworkState] = useState<NetworkMonitorState>({
    externalCallsBlockedOrLogged: 0,
    geminiOptInCalls: 0,
    recentEvents: [],
  });

  const dialogRef = useRef<HTMLDialogElement>(null);
  const drawerRefs = useRef<Record<DrawerTab, HTMLButtonElement | null>>({
    audit: null,
    proof: null,
    gemini: null,
  });
  const workerRef = useRef<Worker | null>(null);
  const requestIdRef = useRef<number>(0);
  const deferredText = useDeferredValue(rawText);
  const expectCsv = sourceFilename.toLowerCase().endsWith('.csv') || diffViewMode === 'csv';

  const effectiveOptions = useMemo<DetectionOptions>(() => {
    const parsedAllowlist = allowlistText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    return {
      ...options,
      allowlist: parsedAllowlist,
    };
  }, [options, allowlistText]);

  const shouldUseWorker =
    typeof Worker !== 'undefined' &&
    (deferredText.length >= WORKER_OFFLOAD_CHARS || effectiveOptions.customRule.enabled);

  const [workerPayload, setWorkerPayload] = useState<{
    result: RedactionResult;
    originalCsv: ParsedCsv;
    sanitizedCsvBundle: SanitizedCsvBundle;
  } | null>(null);
  const [workerTimeoutError, setWorkerTimeoutError] = useState<string | null>(null);

  useEffect(() => {
    if (!shouldUseWorker) {
      return;
    }

    if (!workerRef.current) {
      workerRef.current = new Worker(new URL('./workers/scanner.worker.ts', import.meta.url), {
        type: 'module',
      });
    }

    const activeWorker = workerRef.current;
    const reqId = requestIdRef.current + 1;
    requestIdRef.current = reqId;

    const handleMessage = (event: MessageEvent<WorkerScanResponse>) => {
      if (event.data.requestId !== requestIdRef.current) return;
      window.clearTimeout(watchdog);
      setWorkerTimeoutError(null);
      setWorkerPayload({
        result: event.data.result,
        originalCsv: event.data.originalCsv,
        sanitizedCsvBundle: event.data.sanitizedCsvBundle,
      });
    };

    activeWorker.addEventListener('message', handleMessage);

    const watchdog = window.setTimeout(() => {
      if (requestIdRef.current === reqId) {
        activeWorker.terminate();
        workerRef.current = null;
        setWorkerTimeoutError('Scan aborted after 2000ms inside isolated Web Worker (ReDoS protection).');
      }
    }, 2000);

    const payload: WorkerScanRequest = {
      requestId: reqId,
      text: deferredText,
      mode,
      options: effectiveOptions,
      neutralizeFormulas,
      expectCsv,
    };
    activeWorker.postMessage(payload);

    return () => {
      window.clearTimeout(watchdog);
      activeWorker.removeEventListener('message', handleMessage);
    };
  }, [shouldUseWorker, deferredText, mode, effectiveOptions, neutralizeFormulas, expectCsv]);

  useEffect(() => {
    return () => {
      workerRef.current?.terminate();
      workerRef.current = null;
    };
  }, []);

  useEffect(() => {
    return installNetworkMonitor((event, isGemini) => {
      setNetworkState((prev) => ({
        externalCallsBlockedOrLogged: prev.externalCallsBlockedOrLogged + (isGemini ? 0 : 1),
        geminiOptInCalls: prev.geminiOptInCalls + (isGemini ? 1 : 0),
        recentEvents: [event, ...prev.recentEvents].slice(0, 10),
      }));
    });
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') {
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', theme);
    }
  }, [theme]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 6000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const result = useMemo(
    () => (shouldUseWorker && workerPayload ? workerPayload.result : redactText(deferredText, mode, effectiveOptions)),
    [shouldUseWorker, workerPayload, deferredText, mode, effectiveOptions],
  );

  const originalCsv = useMemo(
    () => (shouldUseWorker && workerPayload ? workerPayload.originalCsv : parseCsvRows(deferredText, expectCsv)),
    [shouldUseWorker, workerPayload, deferredText, expectCsv],
  );

  const sanitizedCsvBundle = useMemo<SanitizedCsvBundle>(() => {
    if (shouldUseWorker && workerPayload) {
      return workerPayload.sanitizedCsvBundle;
    }
    if (!originalCsv.isTabular) {
      return { headers: [] as string[], rows: [] as string[][], isTabular: false, parseError: null, serializedCsv: '' };
    }
    const { sanitizedHeaders, sanitizedRows, serializedCsv } = redactCsvCells(
      originalCsv,
      mode,
      effectiveOptions,
      neutralizeFormulas,
    );
    return {
      headers: sanitizedHeaders,
      rows: sanitizedRows,
      isTabular: true,
      parseError: null,
      serializedCsv,
    };
  }, [shouldUseWorker, workerPayload, originalCsv, mode, effectiveOptions, neutralizeFormulas]);

  const safeSummary = useMemo<SafeScanSummary>(
    () => ({
      totalDetected: result.scan.totalDetected,
      riskScoreBefore: result.scan.risk.scoreBefore,
      riskLevelBefore: result.scan.risk.levelBefore,
      luhnRejectedCount: result.scan.luhnRejectedCount,
      counts: result.scan.counts,
    }),
    [result.scan],
  );

  const activeExportText =
    diffViewMode === 'csv' && sanitizedCsvBundle.isTabular ? sanitizedCsvBundle.serializedCsv : result.sanitizedText;

  const triggerDownload = useCallback((content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setLiveStatus(`Downloaded ${filename}.`);
    setToast({ message: `Saved ${filename}` });
  }, []);

  const handleDownloadSanitized = useCallback(() => {
    const ext = sourceFilename.toLowerCase().endsWith('.csv') ? 'csv' : 'txt';
    const baseName = sourceFilename.replace(/\.(txt|csv)$/i, '') || 'sanitized_output';
    const mime = ext === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8';
    triggerDownload(activeExportText, `sanitized_${baseName}.${ext}`, mime);
  }, [activeExportText, sourceFilename, triggerDownload]);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(activeExportText);
      setCopied(true);
      setLiveStatus('Sanitized output copied to clipboard.');
      setToast({ message: 'Sanitized output copied to clipboard' });
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setLiveStatus('Clipboard copy unavailable; please use Download.');
    }
  }, [activeExportText]);

  const handleKeepOriginal = (value: string) => {
    const cleanVal = value.trim();
    if (!cleanVal) return;
    if (effectiveOptions.allowlist.some((existing) => existing.toLowerCase() === cleanVal.toLowerCase())) {
      return;
    }
    const previous = allowlistText;
    setAllowlistText((prev) => (prev.trim() ? `${prev.trim()}, ${cleanVal}` : cleanVal));
    setLiveStatus(`Kept "${cleanVal}" unredacted in Allowlist.`);
    setToast({ message: `Kept "${cleanVal}" unredacted`, undoAllowlist: previous });
  };

  const handleRestoreAllowlisted = (value: string) => {
    const previous = allowlistText;
    const updated = effectiveOptions.allowlist.filter((item) => item.toLowerCase() !== value.toLowerCase());
    setAllowlistText(updated.join(', '));
    setLiveStatus(`Re-enabled PII redaction for "${value}".`);
    setToast({ message: `Restored redaction for "${value}"`, undoAllowlist: previous });
  };

  const handleDownloadAuditReport = async () => {
    const [rawSha256, sanitizedSha256] = await Promise.all([
      sha256Hex(deferredText),
      sha256Hex(activeExportText),
    ]);

    const certificate = {
      tool: 'CipherShield',
      executionEnvironment: shouldUseWorker
        ? '100% Client-Side Web Worker + Browser RAM (Zero Server Egress)'
        : '100% Client-Side Browser RAM (Zero Server Egress)',
      generatedAt: new Date().toISOString(),
      sourceFilename,
      redactionMode: mode,
      integrityDigests: {
        originalSha256: rawSha256,
        sanitizedSha256,
      },
      networkMonitor: networkState,
      exposureRisk: result.scan.risk,
      metrics: {
        totalRedacted: result.scan.totalDetected,
        luhnRejectedFalsePositives: result.scan.luhnRejectedCount,
        allowlistedPreserved: result.scan.allowlistedCount,
        scanDurationMs: result.scan.durationMs,
      },
      googleCloudDlpSummary: buildCloudDlpSummary(result.scan.counts),
      googleCloudDlpDeidentifyConfig: buildCloudDlpDeidentifyConfig(result.scan.counts, mode),
    };

    const baseName = sourceFilename.replace(/\.(txt|csv)$/i, '') || 'audit';
    triggerDownload(
      JSON.stringify(certificate, null, 2),
      `ciphershield_audit_${baseName}.json`,
      'application/json;charset=utf-8',
    );
  };

  const toggleCategory = (category: PiiCategory) => {
    setOptions((prev) => ({
      ...prev,
      enabledCategories: {
        ...prev.enabledCategories,
        [category]: !prev.enabledCategories[category],
      },
    }));
  };

  const selectDrawer = (tab: DrawerTab, focus = false) => {
    setDrawer(tab);
    if (focus) drawerRefs.current[tab]?.focus();
  };

  const onDrawerKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>, idx: number) => {
    const order: DrawerTab[] = ['audit', 'proof', 'gemini'];
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') return;
    e.preventDefault();
    const next =
      e.key === 'Home'
        ? 0
        : e.key === 'End'
          ? order.length - 1
          : (idx + (e.key === 'ArrowRight' ? 1 : -1) + order.length) % order.length;
    selectDrawer(order[next], true);
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const typing =
        !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable);
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'd') {
        e.preventDefault();
        handleDownloadSanitized();
        return;
      }
      if (typing) return;
      if (e.key === '1') setMode('full');
      else if (e.key === '2') setMode('partial');
      else if (e.key === '3') setMode('pseudonymize');
      else if (e.key === '?') dialogRef.current?.showModal();
      else if (e.key === 'Escape') setShowProofLog(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [handleDownloadSanitized]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLiveStatus(
        `Scanned text in ${result.scan.durationMs} milliseconds: ${result.scan.totalDetected} PII entities detected, ${result.scan.luhnRejectedCount} numeric strings rejected by Luhn validation.`,
      );
    }, 600);
    return () => window.clearTimeout(timer);
  }, [result.scan.totalDetected, result.scan.luhnRejectedCount, result.scan.durationMs]);

  const egressClean = networkState.externalCallsBlockedOrLogged === 0;
  const activeCategories = Object.values(result.scan.counts).filter((n) => n > 0).length;

  return (
    <div className="app-shell">
      <a href="#main-heading" className="skip-link visually-hidden">
        Skip to main content
      </a>

      <HeaderBar
        theme={theme}
        networkState={networkState}
        onCycleTheme={() => setTheme((p) => (p === 'system' ? 'dark' : p === 'dark' ? 'light' : 'system'))}
        onOpenPromptLog={() => dialogRef.current?.showModal()}
      />

      <main>
        <div className="visually-hidden" aria-live="polite" aria-atomic="true">
          {liveStatus}
        </div>

        {/* Top Telemetry Strip */}
        <section className="mc-strip" aria-label="Sanitization telemetry summary">
          <div className="mc-card mc-cyan">
            <span className="mc-label">Entities detected</span>
            <span className="mc-value mono">{result.scan.totalDetected}</span>
            <span className="mc-sub">{activeCategories} active categories</span>
          </div>
          <div className="mc-card mc-red">
            <span className="mc-label">Exposure before</span>
            <span className="mc-value mono">{result.scan.risk.scoreBefore}/100</span>
            <span className="mc-sub">{result.scan.risk.levelBefore}</span>
          </div>
          <div className="mc-card mc-green">
            <span className="mc-label">Residual after</span>
            <span className="mc-value mono">{result.scan.risk.scoreAfter}/100</span>
            <span className="mc-sub">{result.scan.risk.residualCount} residual entities</span>
          </div>
          <div className="mc-card mc-amber">
            <span className="mc-label">Luhn rejected</span>
            <span className="mc-value mono">{result.scan.luhnRejectedCount}</span>
            <span className="mc-sub">non-card IDs preserved</span>
          </div>
          <div className="mc-card mc-violet">
            <span className="mc-label">Scan speed</span>
            <span className="mc-value mono">
              {result.scan.durationMs}
              <span className="mc-unit"> ms</span>
            </span>
            <span className="mc-sub">
              {rawText.length.toLocaleString()} chars · {shouldUseWorker ? 'Web Worker' : 'Main RAM'}
            </span>
          </div>
        </section>

        {/* Live Runtime Network Proof Bar */}
        <div className="proof-bar">
          <span className={`proof-dot ${egressClean ? '' : 'is-hot'}`} aria-hidden="true" />
          <strong>{egressClean ? 'Zero-Egress Runtime Active' : 'External Network Activity'}</strong>
          <span className="muted-copy">
            {networkState.externalCallsBlockedOrLogged} external · {networkState.geminiOptInCalls} opt-in Gemini · fetch
            / XHR / sendBeacon / Resource observers armed
          </span>
          <button
            type="button"
            className="btn btn-compact proof-toggle"
            aria-expanded={showProofLog}
            aria-controls="proof-log"
            onClick={() => setShowProofLog((v) => !v)}
          >
            {showProofLog ? 'Hide network log' : 'Inspect network log'}
          </button>
        </div>

        {showProofLog && (
          <div className="proof-log" id="proof-log" role="region" aria-label="Intercepted network events">
            {networkState.recentEvents.length === 0 ? (
              <p className="muted-copy proof-empty">
                No external requests intercepted. Scanning, CSV redaction, and AES-256-GCM vault operations executed in
                local memory.
              </p>
            ) : (
              <ul className="proof-events">
                {networkState.recentEvents.map((ev) => (
                  <li key={ev.id}>
                    <span className="mono">{ev.timestamp}</span>
                    <span className={ev.isAllowedOrigin ? 'log-optin' : 'log-unexpected'}>{ev.transport}</span>
                    <span className="log-url mono">{ev.url}</span>
                    <span>{ev.isAllowedOrigin ? 'opt-in' : 'unexpected'}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        <SourceInputPanel
          rawText={rawText}
          sourceFilename={sourceFilename}
          scanDurationMs={result.scan.durationMs}
          onChangeText={setRawText}
          onSelectFixture={(text, filename, preferCsv) => {
            setRawText(text);
            setSourceFilename(filename);
            setDiffViewMode(preferCsv ? 'csv' : 'text');
            setToast({ message: `Loaded ${filename}` });
          }}
          onClear={() => {
            setRawText('');
            setSourceFilename('sanitized_text.txt');
            setDiffViewMode('text');
          }}
        />

        <PolicyControls
          mode={mode}
          options={options}
          allowlistText={allowlistText}
          customRuleError={(shouldUseWorker ? workerTimeoutError : null) ?? result.scan.customRuleError}
          onChangeMode={setMode}
          onChangeOptions={setOptions}
          onChangeAllowlist={setAllowlistText}
        />

        <MetricsOverview scan={result.scan} options={effectiveOptions} onToggleCategory={toggleCategory} />

        <SideBySideDiff
          mode={mode}
          result={result}
          diffViewMode={diffViewMode}
          originalCsv={originalCsv}
          sanitizedCsv={sanitizedCsvBundle}
          neutralizeFormulas={neutralizeFormulas}
          copied={copied}
          onChangeDiffView={setDiffViewMode}
          onToggleNeutralizeFormulas={setNeutralizeFormulas}
          onCopy={() => void handleCopy()}
          onDownloadSanitized={handleDownloadSanitized}
          onDownloadAuditReport={() => void handleDownloadAuditReport()}
        />

        {/* Tabbed Inspection, Adversarial Proof & Compliance Drawer */}
        <section className="wb-drawer" aria-label="Audit, Adversarial Self-Test & Advisor">
          <div className="drawer-tabs" role="tablist" aria-label="Audit, verification and advisor panels">
            {(
              [
                ['audit', 'Entity Audit & Key Vault', result.mappings.length],
                ['proof', 'Adversarial Self-Test Proof', selfTest ? selfTest.passed : 10],
                ['gemini', 'Compliance Advisor', null],
              ] as [DrawerTab, string, number | null][]
            ).map(([id, label, count], idx) => (
              <button
                key={id}
                ref={(el) => {
                  drawerRefs.current[id] = el;
                }}
                type="button"
                role="tab"
                id={`drawer-tab-${id}`}
                aria-selected={drawer === id}
                aria-controls={`drawer-panel-${id}`}
                tabIndex={drawer === id ? 0 : -1}
                className="drawer-tab"
                onClick={() => selectDrawer(id)}
                onKeyDown={(e) => onDrawerKeyDown(e, idx)}
              >
                {label}
                {count !== null && <span className="drawer-count mono">{count}</span>}
              </button>
            ))}
          </div>

          <div
            className="drawer-panel"
            role="tabpanel"
            id="drawer-panel-audit"
            aria-labelledby="drawer-tab-audit"
            hidden={drawer !== 'audit'}
          >
            <AuditLedger
              segments={result.originalSegments}
              mappings={result.mappings}
              rejectedCards={result.scan.rejectedCards}
              allowlist={effectiveOptions.allowlist}
              onKeepOriginal={handleKeepOriginal}
              onRestoreAllowlisted={handleRestoreAllowlisted}
              onDownloadBundle={triggerDownload}
            />
          </div>

          <div
            className="drawer-panel"
            role="tabpanel"
            id="drawer-panel-proof"
            aria-labelledby="drawer-tab-proof"
            hidden={drawer !== 'proof'}
          >
            <section className="panel" aria-labelledby="selftest-heading">
              <div className="st-head">
                <div>
                  <h2 id="selftest-heading" className="section-heading">
                    Live 10-Case Adversarial Engine Proof
                  </h2>
                  <p className="panel-subtitle proof-empty">
                    Deterministic probes verifying Luhn/IMEI filtering, PAN holder rules, Verhoeff UIDAI Aadhaar,
                    IPv4-mapped IPv6, Amex masking, UPI separation, Google libphonenumber, ReDoS guard, and CWE-1236
                    CSV.
                  </p>
                </div>
                <div className="action-row st-actions">
                  {selfTest && (
                    <span
                      className={`st-score mono ${selfTest.passed === selfTest.total ? 'safe-ink' : 'warn-ink'}`}
                    >
                      Live Adversarial Proof: {selfTest.passed}/{selfTest.total} Passed ({selfTest.durationMs} ms)
                    </span>
                  )}
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => {
                      const report = runAdversarialSelfTest();
                      setSelfTest(report);
                      setLiveStatus(`Self-test complete: ${report.passed} of ${report.total} probes passed.`);
                      setToast({ message: `Adversarial proof: ${report.passed}/${report.total} passed` });
                    }}
                  >
                    <FlaskConical size={15} aria-hidden="true" />
                    {selfTest ? 'Re-run Adversarial Self-Test' : 'Run 10-Case Adversarial Self-Test'}
                  </button>
                </div>
              </div>

              {!selfTest ? (
                <p className="muted-copy proof-empty">
                  Click <strong>Run 10-Case Adversarial Self-Test</strong> to execute and inspect all verification
                  vectors live inside your browser.
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
          </div>

          <div
            className="drawer-panel"
            role="tabpanel"
            id="drawer-panel-gemini"
            aria-labelledby="drawer-tab-gemini"
            hidden={drawer !== 'gemini'}
          >
            <GeminiAdvisorPanel
              summary={safeSummary}
              onApplySyntheticText={(synthetic) => {
                setRawText(synthetic);
                setSourceFilename('gemini_synthetic_log.txt');
                setDiffViewMode('text');
                setToast({ message: 'Synthetic fixture applied' });
              }}
            />
          </div>
        </section>

        <div className="kbd-hints">
          <span>
            <kbd>1</kbd> <kbd>2</kbd> <kbd>3</kbd> redaction mode
          </span>
          <span>
            <kbd>Ctrl</kbd>+<kbd>D</kbd> download sanitized
          </span>
          <span>
            <kbd>?</kbd> prompt log
          </span>
          <span>
            <kbd>Esc</kbd> close network log
          </span>
        </div>
      </main>

      <footer className="site-footer">
        <span>CipherShield · Client-Side Zero-Egress PII Sanitization Engine</span>
        <span>Built for PromptWars × NIAT Pune · Cloud Run &amp; DLP Taxonomy Compatible</span>
      </footer>

      {toast && (
        <div className="toast" role="status">
          <span>{toast.message}</span>
          {toast.undoAllowlist !== undefined && (
            <button
              type="button"
              className="btn btn-compact"
              onClick={() => {
                setAllowlistText(toast.undoAllowlist!);
                setToast({ message: 'Allowlist change reverted' });
                setLiveStatus('Allowlist change reverted.');
              }}
            >
              Undo
            </button>
          )}
          <button
            type="button"
            className="btn btn-compact"
            onClick={() => setToast(null)}
            aria-label="Dismiss notification"
          >
            Dismiss
          </button>
        </div>
      )}

      <PromptLogModal dialogRef={dialogRef} />
    </div>
  );
}

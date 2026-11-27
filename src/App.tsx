import { useCallback, useDeferredValue, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { FlaskConical, KeyRound, ShieldCheck, Sparkles } from 'lucide-react';
import { AuditLedger } from './components/AuditLedger';
import { GeminiAdvisorPanel } from './components/GeminiAdvisorPanel';
import { HeaderBar } from './components/HeaderBar';
import { MetricsOverview } from './components/MetricsOverview';
import { PolicyControls } from './components/PolicyControls';
import { PromptLogModal } from './components/PromptLogModal';
import { SelfTestPanel } from './components/SelfTestPanel';
import { SideBySideDiff } from './components/SideBySideDiff';
import { SourceInputPanel } from './components/SourceInputPanel';
import { TelemetryStrip } from './components/TelemetryStrip';
import { buildCloudDlpDeidentifyConfig, buildCloudDlpSummary } from './engine/dlpTaxonomy';
import { installNetworkMonitor, NetworkMonitorState } from './engine/networkMonitor';
import { sha256Hex } from './engine/redactor';
import { DEFAULT_DETECTION_OPTIONS } from './engine/scanner';
import { runAdversarialSelfTest, SelfTestReport } from './engine/selfTest';
import { useScannerPipeline } from './hooks/useScannerPipeline';
import type { SafeScanSummary } from './services/geminiAdvisor';
import { DetectionOptions, PiiCategory, RedactionMode } from './types/pii';

type WorkspaceTab = 'studio' | 'vault' | 'proof' | 'gemini';

interface ToastState {
  message: string;
  undoAllowlist?: string;
}

const WORKSPACE_TABS: { id: WorkspaceTab; label: string; shortcut: string }[] = [
  { id: 'studio', label: 'Sanitize Studio', shortcut: '1' },
  { id: 'vault', label: 'Entity Review & Vault', shortcut: '2' },
  { id: 'proof', label: 'Self-Test & Proof', shortcut: '3' },
  { id: 'gemini', label: 'Compliance Advisor', shortcut: '4' },
];

/**
 * Root CipherShield workbench coordinating workspace navigation,
 * deferred Web Worker PII scanning, zero-egress network monitoring, and audit exports.
 */
export default function App() {
  const [rawText, setRawText] = useState<string>('');
  const [sourceFilename, setSourceFilename] = useState<string>('untitled.txt');
  const [mode, setMode] = useState<RedactionMode>('pseudonymize');
  const [options, setOptions] = useState<DetectionOptions>(DEFAULT_DETECTION_OPTIONS);
  const [allowlistText, setAllowlistText] = useState<string>(DEFAULT_DETECTION_OPTIONS.allowlist.join(', '));
  const [copied, setCopied] = useState(false);
  const [liveStatus, setLiveStatus] = useState<string>('');
  const [theme, setTheme] = useState<'system' | 'dark' | 'light'>('dark');
  const [diffViewMode, setDiffViewMode] = useState<'text' | 'csv'>('text');
  const [neutralizeFormulas, setNeutralizeFormulas] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('studio');
  const [showProofLog, setShowProofLog] = useState(false);
  const [selfTest, setSelfTest] = useState<SelfTestReport | null>(null);
  const [toast, setToast] = useState<ToastState | null>(null);
  const [networkState, setNetworkState] = useState<NetworkMonitorState>({
    externalCallsBlockedOrLogged: 0,
    geminiOptInCalls: 0,
    recentEvents: [],
  });

  const dialogRef = useRef<HTMLDialogElement>(null);
  const navSliderRef = useRef<HTMLSpanElement>(null);
  const tabRefs = useRef<Record<WorkspaceTab, HTMLButtonElement | null>>({
    studio: null,
    vault: null,
    proof: null,
    gemini: null,
  });

  const deferredText = useDeferredValue(rawText);
  const expectCsv = sourceFilename.toLowerCase().endsWith('.csv') || diffViewMode === 'csv';

  const effectiveOptions = useMemo<DetectionOptions>(() => {
    const parsedAllowlist = allowlistText
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    return { ...options, allowlist: parsedAllowlist };
  }, [options, allowlistText]);

  const { result, originalCsv, sanitizedCsvBundle, shouldUseWorker, workerTimeoutError } = useScannerPipeline({
    text: deferredText,
    mode,
    options: effectiveOptions,
    neutralizeFormulas,
    expectCsv,
  });

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
    if (theme === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', theme);
  }, [theme]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 6000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLiveStatus(
        `Scanned text in ${result.scan.durationMs} milliseconds: ${result.scan.totalDetected} PII entities detected, ${result.scan.luhnRejectedCount} numeric strings rejected by Luhn validation.`,
      );
    }, 600);
    return () => window.clearTimeout(timer);
  }, [result.scan.totalDetected, result.scan.luhnRejectedCount, result.scan.durationMs]);

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
    if (!cleanVal || effectiveOptions.allowlist.some((e) => e.toLowerCase() === cleanVal.toLowerCase())) {
      return;
    }
    const previous = allowlistText;
    setAllowlistText((prev) => (prev.trim() ? `${prev.trim()}, ${cleanVal}` : cleanVal));
    setLiveStatus(`Kept "${cleanVal}" unredacted in Allowlist.`);
    setToast({ message: `Kept "${cleanVal}" unredacted`, undoAllowlist: previous });
  };

  const handleRestoreAllowlisted = (value: string) => {
    const previous = allowlistText;
    setAllowlistText(effectiveOptions.allowlist.filter((i) => i.toLowerCase() !== value.toLowerCase()).join(', '));
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
      integrityDigests: { originalSha256: rawSha256, sanitizedSha256 },
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
      enabledCategories: { ...prev.enabledCategories, [category]: !prev.enabledCategories[category] },
    }));
  };

  const handleRunSelfTest = (notify = true) => {
    const report = runAdversarialSelfTest();
    setSelfTest(report);
    setLiveStatus(`Self-test complete: ${report.passed} of ${report.total} probes passed.`);
    if (notify) setToast({ message: `Adversarial proof: ${report.passed}/${report.total} passed` });
  };

  const selectTab = (tab: WorkspaceTab, focus = false) => {
    setActiveTab(tab);
    if (tab === 'proof' && !selfTest) handleRunSelfTest(false);
    if (focus) tabRefs.current[tab]?.focus();
  };

  useLayoutEffect(() => {
    const updateSlider = () => {
      const activeBtn = tabRefs.current[activeTab];
      const slider = navSliderRef.current;
      if (!activeBtn || !slider) return;
      slider.style.width = `${activeBtn.offsetWidth}px`;
      slider.style.transform = `translate3d(${activeBtn.offsetLeft}px, ${activeBtn.offsetTop}px, 0)`;
    };
    updateSlider();
    window.addEventListener('resize', updateSlider);
    return () => window.removeEventListener('resize', updateSlider);
  }, [activeTab, result.scan.totalDetected, result.mappings.length, selfTest]);

  const onTabKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>, idx: number) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') return;
    e.preventDefault();
    const next =
      e.key === 'Home'
        ? 0
        : e.key === 'End'
          ? WORKSPACE_TABS.length - 1
          : (idx + (e.key === 'ArrowRight' ? 1 : -1) + WORKSPACE_TABS.length) % WORKSPACE_TABS.length;
    selectTab(WORKSPACE_TABS[next].id, true);
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey && ['1', '2', '3', '4'].includes(e.key)) {
        e.preventDefault();
        const tab = WORKSPACE_TABS[Number(e.key) - 1];
        if (tab) setActiveTab(tab.id);
        return;
      }
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

  const egressClean = networkState.externalCallsBlockedOrLogged === 0;
  const getTabIcon = (id: WorkspaceTab) => {
    if (id === 'studio') return <ShieldCheck size={16} aria-hidden="true" />;
    if (id === 'vault') return <KeyRound size={16} aria-hidden="true" />;
    if (id === 'proof') return <FlaskConical size={16} aria-hidden="true" />;
    return <Sparkles size={16} aria-hidden="true" />;
  };
  const getTabBadge = (id: WorkspaceTab): string | null => {
    if (id === 'studio' && result.scan.totalDetected > 0) return String(result.scan.totalDetected);
    if (id === 'vault' && result.mappings.length > 0) return String(result.mappings.length);
    if (id === 'proof' && selfTest) return `${selfTest.passed}/${selfTest.total}`;
    return null;
  };

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link visually-hidden">
        Skip to main content
      </a>

      <HeaderBar
        theme={theme}
        networkState={networkState}
        onCycleTheme={() => setTheme((p) => (p === 'system' ? 'dark' : p === 'dark' ? 'light' : 'system'))}
        onOpenPromptLog={() => dialogRef.current?.showModal()}
      />

      <nav className="workspace-nav-shell" aria-label="Workspace navigation">
        <div className="workspace-tabs" role="tablist" aria-label="CipherShield workspace sections">
          <span ref={navSliderRef} className="ws-slider" aria-hidden="true" />
          {WORKSPACE_TABS.map((tab, idx) => {
            const badge = getTabBadge(tab.id);
            const selected = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                ref={(el) => {
                  tabRefs.current[tab.id] = el;
                }}
                type="button"
                role="tab"
                id={`ws-tab-${tab.id}`}
                aria-selected={selected}
                aria-controls={`ws-panel-${tab.id}`}
                tabIndex={selected ? 0 : -1}
                className={`ws-tab ${selected ? 'is-active' : ''}`}
                onClick={() => selectTab(tab.id)}
                onKeyDown={(e) => onTabKeyDown(e, idx)}
                title={`${tab.label} (Alt+${tab.shortcut})`}
              >
                {getTabIcon(tab.id)}
                <span>{tab.label}</span>
                {badge && <span className="drawer-count mono">{badge}</span>}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          className="btn btn-compact proof-pill-btn"
          aria-expanded={showProofLog}
          aria-controls="proof-log"
          onClick={() => setShowProofLog((v) => !v)}
        >
          <span className={`proof-dot ${egressClean ? '' : 'is-hot'}`} aria-hidden="true" />
          <span>{egressClean ? '0 External Egress' : `${networkState.externalCallsBlockedOrLogged} Calls`}</span>
        </button>
      </nav>

      {showProofLog && (
        <div className="proof-log" id="proof-log" role="region" aria-label="Intercepted network events">
          {networkState.recentEvents.length === 0 ? (
            <p className="muted-copy proof-empty">
              Zero external requests intercepted across fetch, XHR, sendBeacon, and Resource observers. Scanning, CSV
              redaction, and PBKDF2 600k + AES-256-GCM vault operations executed strictly in{' '}
              {shouldUseWorker ? 'Web Worker + local RAM' : 'local browser RAM'}.
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

      <main id="main-content" tabIndex={-1}>
        <div className="visually-hidden" aria-live="polite" aria-atomic="true">
          {liveStatus}
        </div>

        <TelemetryStrip scan={result.scan} charCount={rawText.length} shouldUseWorker={shouldUseWorker} />

        <div
          role="tabpanel"
          id="ws-panel-studio"
          aria-labelledby="ws-tab-studio"
          hidden={activeTab !== 'studio'}
          className={`ws-panel ${activeTab === 'studio' ? 'is-active' : ''}`}
        >
          <div className="studio-top-grid">
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
              customRuleError={workerTimeoutError ?? result.scan.customRuleError}
              onChangeMode={setMode}
              onChangeOptions={setOptions}
              onChangeAllowlist={setAllowlistText}
            />
          </div>

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
        </div>

        <div
          role="tabpanel"
          id="ws-panel-vault"
          aria-labelledby="ws-tab-vault"
          hidden={activeTab !== 'vault'}
          className={`ws-panel ${activeTab === 'vault' ? 'is-active' : ''}`}
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
          role="tabpanel"
          id="ws-panel-proof"
          aria-labelledby="ws-tab-proof"
          hidden={activeTab !== 'proof'}
          className={`ws-panel ${activeTab === 'proof' ? 'is-active' : ''}`}
        >
          <SelfTestPanel selfTest={selfTest} onRunSelfTest={() => handleRunSelfTest(true)} />
        </div>

        <div
          role="tabpanel"
          id="ws-panel-gemini"
          aria-labelledby="ws-tab-gemini"
          hidden={activeTab !== 'gemini'}
          className={`ws-panel ${activeTab === 'gemini' ? 'is-active' : ''}`}
        >
          <GeminiAdvisorPanel
            summary={safeSummary}
            onApplySyntheticText={(synthetic) => {
              setRawText(synthetic);
              setSourceFilename('gemini_synthetic_log.txt');
              setDiffViewMode('text');
              setActiveTab('studio');
              setToast({ message: 'Synthetic fixture applied in Sanitize Studio' });
            }}
          />
        </div>

        <div className="kbd-hints">
          <span>
            <kbd>Alt</kbd>+<kbd>1–4</kbd> switch workspace tab
          </span>
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

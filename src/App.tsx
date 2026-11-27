import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { HeaderBar } from './components/HeaderBar';
import { KeyboardHints } from './components/KeyboardHints';
import { PromptLogModal } from './components/PromptLogModal';
import { TelemetryStrip } from './components/TelemetryStrip';
import { ToastBanner, ToastState } from './components/ToastBanner';
import { WorkspaceNav, WorkspaceTab } from './components/WorkspaceNav';
import { WorkspacePanels } from './components/WorkspacePanels';
import { buildAuditCertificate } from './engine/auditReport';
import { installNetworkMonitor, NetworkMonitorState } from './engine/networkMonitor';
import { DEFAULT_DETECTION_OPTIONS } from './engine/scanner';
import { runAdversarialSelfTest, SelfTestReport } from './engine/selfTest';
import { useScannerPipeline } from './hooks/useScannerPipeline';
import { useWorkspaceKeyboard } from './hooks/useWorkspaceKeyboard';
import type { SafeScanSummary } from './services/geminiAdvisor';
import { DetectionOptions, PiiCategory, RedactionMode } from './types/pii';

/**
 * Root CipherShield workbench coordinating workspace navigation,
 * deferred Web Worker PII scanning, zero-egress network monitoring, and audit exports.
 */
export default function App() {
  const [rawText, setRawText] = useState('');
  const [sourceFilename, setSourceFilename] = useState('untitled.txt');
  const [mode, setMode] = useState<RedactionMode>('pseudonymize');
  const [options, setOptions] = useState<DetectionOptions>(DEFAULT_DETECTION_OPTIONS);
  const [allowlistText, setAllowlistText] = useState(DEFAULT_DETECTION_OPTIONS.allowlist.join(', '));
  const [copied, setCopied] = useState(false);
  const [liveStatus, setLiveStatus] = useState('');
  const [theme, setTheme] = useState<'system' | 'dark' | 'light'>('dark');
  const [diffViewMode, setDiffViewMode] = useState<'text' | 'csv'>('text');
  const [neutralizeFormulas, setNeutralizeFormulas] = useState(true);
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
  const deferredText = useDeferredValue(rawText);
  const expectCsv = sourceFilename.toLowerCase().endsWith('.csv') || diffViewMode === 'csv';

  const effectiveOptions = useMemo<DetectionOptions>(
    () => ({ ...options, allowlist: allowlistText.split(',').map((s) => s.trim()).filter(Boolean) }),
    [options, allowlistText],
  );

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
    triggerDownload(activeExportText, `sanitized_${baseName}.${ext}`, ext === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8');
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

  const handleDownloadAuditReport = useCallback(async () => {
    try {
      const certificate = await buildAuditCertificate({
        rawText: deferredText,
        sanitizedText: activeExportText,
        sourceFilename,
        mode,
        shouldUseWorker,
        networkState,
        scan: result.scan,
      });
      const baseName = sourceFilename.replace(/\.(txt|csv)$/i, '') || 'audit';
      triggerDownload(JSON.stringify(certificate, null, 2), `ciphershield_audit_${baseName}.json`, 'application/json;charset=utf-8');
    } catch {
      setToast({ message: 'Unable to generate SHA-256 audit certificate in this browser context.' });
    }
  }, [deferredText, activeExportText, sourceFilename, mode, shouldUseWorker, networkState, result.scan, triggerDownload]);

  const selectTab = useCallback(
    (tab: WorkspaceTab) => {
      setActiveTab(tab);
      if (tab === 'proof' && !selfTest) {
        const report = runAdversarialSelfTest();
        setSelfTest(report);
        setLiveStatus(`Self-test complete: ${report.passed} of ${report.total} probes passed.`);
      }
    },
    [selfTest],
  );

  const openPromptLog = useCallback(() => dialogRef.current?.showModal(), []);
  const closeProofLog = useCallback(() => setShowProofLog(false), []);

  useWorkspaceKeyboard({
    selectTab,
    setMode,
    onDownload: handleDownloadSanitized,
    onOpenPromptLog: openPromptLog,
    onCloseProofLog: closeProofLog,
  });

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link visually-hidden">
        Skip to main content
      </a>

      <HeaderBar
        theme={theme}
        networkState={networkState}
        onCycleTheme={() => setTheme((p) => (p === 'system' ? 'dark' : p === 'dark' ? 'light' : 'system'))}
        onOpenPromptLog={openPromptLog}
      />

      <WorkspaceNav
        activeTab={activeTab}
        detectedCount={result.scan.totalDetected}
        mappingCount={result.mappings.length}
        selfTestSummary={selfTest ? `${selfTest.passed}/${selfTest.total}` : null}
        showProofLog={showProofLog}
        shouldUseWorker={shouldUseWorker}
        networkState={networkState}
        onSelectTab={selectTab}
        onToggleProofLog={() => setShowProofLog((v) => !v)}
      />

      <main id="main-content" tabIndex={-1}>
        <div className="visually-hidden" aria-live="polite" aria-atomic="true">
          {liveStatus}
        </div>
        <TelemetryStrip scan={result.scan} charCount={rawText.length} shouldUseWorker={shouldUseWorker} />

        <WorkspacePanels
          activeTab={activeTab}
          rawText={rawText}
          sourceFilename={sourceFilename}
          mode={mode}
          options={options}
          effectiveOptions={effectiveOptions}
          allowlistText={allowlistText}
          customRuleError={workerTimeoutError ?? result.scan.customRuleError}
          result={result}
          diffViewMode={diffViewMode}
          originalCsv={originalCsv}
          sanitizedCsv={sanitizedCsvBundle}
          neutralizeFormulas={neutralizeFormulas}
          copied={copied}
          selfTest={selfTest}
          safeSummary={safeSummary}
          onChangeText={setRawText}
          onSelectFixture={(text, filename, preferCsv) => {
            setRawText(text);
            setSourceFilename(filename);
            setDiffViewMode(preferCsv ? 'csv' : 'text');
            setToast({ message: `Loaded ${filename}` });
          }}
          onClearInput={() => {
            setRawText('');
            setSourceFilename('sanitized_text.txt');
            setDiffViewMode('text');
          }}
          onChangeMode={setMode}
          onChangeOptions={setOptions}
          onChangeAllowlist={setAllowlistText}
          onToggleCategory={(category: PiiCategory) =>
            setOptions((prev) => ({
              ...prev,
              enabledCategories: { ...prev.enabledCategories, [category]: !prev.enabledCategories[category] },
            }))
          }
          onChangeDiffView={setDiffViewMode}
          onToggleNeutralizeFormulas={setNeutralizeFormulas}
          onCopy={() => void handleCopy()}
          onDownloadSanitized={handleDownloadSanitized}
          onDownloadAuditReport={() => void handleDownloadAuditReport()}
          onKeepOriginal={(value) => {
            const cleanVal = value.trim();
            if (!cleanVal || effectiveOptions.allowlist.some((e) => e.toLowerCase() === cleanVal.toLowerCase())) return;
            const previous = allowlistText;
            setAllowlistText((prev) => (prev.trim() ? `${prev.trim()}, ${cleanVal}` : cleanVal));
            setLiveStatus(`Kept "${cleanVal}" unredacted in Allowlist.`);
            setToast({ message: `Kept "${cleanVal}" unredacted`, undoAllowlist: previous });
          }}
          onRestoreAllowlisted={(value) => {
            const previous = allowlistText;
            setAllowlistText(effectiveOptions.allowlist.filter((i) => i.toLowerCase() !== value.toLowerCase()).join(', '));
            setLiveStatus(`Re-enabled PII redaction for "${value}".`);
            setToast({ message: `Restored redaction for "${value}"`, undoAllowlist: previous });
          }}
          onDownloadBundle={triggerDownload}
          onRunSelfTest={() => {
            const report = runAdversarialSelfTest();
            setSelfTest(report);
            setLiveStatus(`Self-test complete: ${report.passed} of ${report.total} probes passed.`);
            setToast({ message: `Adversarial proof: ${report.passed}/${report.total} passed` });
          }}
          onApplySyntheticText={(synthetic) => {
            setRawText(synthetic);
            setSourceFilename('gemini_synthetic_log.txt');
            setDiffViewMode('text');
            setActiveTab('studio');
            setToast({ message: 'Synthetic fixture applied in Sanitize Studio' });
          }}
        />
        <KeyboardHints />
      </main>

      <footer className="site-footer">
        <span>CipherShield · Client-Side Zero-Egress PII Sanitization Engine</span>
        <span>Built for PromptWars × NIAT Pune · Cloud Run &amp; DLP Taxonomy Compatible</span>
      </footer>

      <ToastBanner
        toast={toast}
        onUndoAllowlist={(previous) => {
          setAllowlistText(previous);
          setToast({ message: 'Allowlist change reverted' });
          setLiveStatus('Allowlist change reverted.');
        }}
        onDismiss={() => setToast(null)}
      />
      <PromptLogModal dialogRef={dialogRef} />
    </div>
  );
}

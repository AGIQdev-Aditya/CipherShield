import { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { AuditLedger } from './components/AuditLedger';
import { GeminiAdvisorPanel } from './components/GeminiAdvisorPanel';
import { HeaderBar } from './components/HeaderBar';
import { MetricsOverview } from './components/MetricsOverview';
import { PolicyControls } from './components/PolicyControls';
import { PromptLogModal } from './components/PromptLogModal';
import { SideBySideDiff } from './components/SideBySideDiff';
import { SourceInputPanel } from './components/SourceInputPanel';
import { parseCsvRows, redactCsvCells } from './engine/csvParser';
import { buildCloudDlpDeidentifyConfig, buildCloudDlpSummary } from './engine/dlpTaxonomy';
import { installNetworkMonitor, NetworkMonitorState } from './engine/networkMonitor';
import { redactText, sha256Hex } from './engine/redactor';
import { DEFAULT_DETECTION_OPTIONS } from './engine/scanner';
import { SAMPLE_DATASETS } from './engine/samples';
import type { SafeScanSummary } from './services/geminiAdvisor';
import { DetectionOptions, PiiCategory, RedactionMode } from './types/pii';

/**
 * Root CipherShield workspace coordinating deferred client-side PII scanning,
 * redaction modes, RFC-4180 CSV diff rendering, zero-egress network monitoring, and audit exports.
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
  const [networkState, setNetworkState] = useState<NetworkMonitorState>({
    externalCallsBlockedOrLogged: 0,
    geminiOptInCalls: 0,
    recentEvents: [],
  });

  const dialogRef = useRef<HTMLDialogElement>(null);
  const deferredText = useDeferredValue(rawText);

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

  const result = useMemo(
    () => redactText(deferredText, mode, effectiveOptions),
    [deferredText, mode, effectiveOptions],
  );

  const originalCsv = useMemo(() => parseCsvRows(deferredText), [deferredText]);
  const sanitizedCsvBundle = useMemo(() => {
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
  }, [originalCsv, mode, effectiveOptions, neutralizeFormulas]);

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

  const handleKeepOriginal = (value: string) => {
    const cleanVal = value.trim();
    if (!cleanVal) return;
    if (effectiveOptions.allowlist.some((existing) => existing.toLowerCase() === cleanVal.toLowerCase())) {
      return;
    }
    setAllowlistText((prev) => (prev.trim() ? `${prev.trim()}, ${cleanVal}` : cleanVal));
    setLiveStatus(`Kept "${cleanVal}" unredacted in Allowlist.`);
  };

  const handleRestoreAllowlisted = (value: string) => {
    const updated = effectiveOptions.allowlist.filter((item) => item.toLowerCase() !== value.toLowerCase());
    setAllowlistText(updated.join(', '));
    setLiveStatus(`Re-enabled PII redaction for "${value}".`);
  };

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setLiveStatus(
        `Scanned text in ${result.scan.durationMs} milliseconds: ${result.scan.totalDetected} PII entities detected, ${result.scan.luhnRejectedCount} numeric strings rejected by Luhn validation.`,
      );
    }, 600);
    return () => window.clearTimeout(timer);
  }, [result.scan.totalDetected, result.scan.luhnRejectedCount, result.scan.durationMs]);

  const toggleCategory = (category: PiiCategory) => {
    setOptions((prev) => ({
      ...prev,
      enabledCategories: {
        ...prev.enabledCategories,
        [category]: !prev.enabledCategories[category],
      },
    }));
  };

  const triggerDownload = (content: string, filename: string, mime: string) => {
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
  };

  const activeExportText =
    diffViewMode === 'csv' && sanitizedCsvBundle.isTabular ? sanitizedCsvBundle.serializedCsv : result.sanitizedText;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(activeExportText);
      setCopied(true);
      setLiveStatus('Sanitized output copied to clipboard.');
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setLiveStatus('Clipboard copy unavailable; please use Download.');
    }
  };

  const handleDownloadSanitized = () => {
    const ext = sourceFilename.toLowerCase().endsWith('.csv') ? 'csv' : 'txt';
    const baseName = sourceFilename.replace(/\.(txt|csv)$/i, '') || 'sanitized_output';
    const mime = ext === 'csv' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8';
    triggerDownload(activeExportText, `sanitized_${baseName}.${ext}`, mime);
  };

  const handleDownloadAuditReport = async () => {
    const [rawSha256, sanitizedSha256] = await Promise.all([
      sha256Hex(deferredText),
      sha256Hex(activeExportText),
    ]);

    const certificate = {
      tool: 'CipherShield',
      executionEnvironment: '100% Client-Side Browser RAM (Zero Server Egress)',
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

        <SourceInputPanel
          rawText={rawText}
          sourceFilename={sourceFilename}
          scanDurationMs={result.scan.durationMs}
          onChangeText={setRawText}
          onSelectFixture={(text, filename, preferCsv) => {
            setRawText(text);
            setSourceFilename(filename);
            setDiffViewMode(preferCsv ? 'csv' : 'text');
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
          customRuleError={result.scan.customRuleError}
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

        <AuditLedger
          segments={result.originalSegments}
          mappings={result.mappings}
          rejectedCards={result.scan.rejectedCards}
          allowlist={effectiveOptions.allowlist}
          onKeepOriginal={handleKeepOriginal}
          onRestoreAllowlisted={handleRestoreAllowlisted}
          onDownloadBundle={triggerDownload}
        />

        <GeminiAdvisorPanel
          summary={safeSummary}
          onApplySyntheticText={(synthetic) => {
            setRawText(synthetic);
            setSourceFilename('gemini_synthetic_log.txt');
            setDiffViewMode('text');
          }}
        />
      </main>

      <footer className="site-footer">
        <span>CipherShield · Client-Side Zero-Egress PII Sanitization Engine</span>
        <span>Built for PromptWars × NIAT Pune · Cloud Run &amp; DLP Taxonomy Compatible</span>
      </footer>

      <PromptLogModal dialogRef={dialogRef} />
    </div>
  );
}

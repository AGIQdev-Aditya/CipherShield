import React from 'react';
import { AuditLedger } from './AuditLedger';
import { GeminiAdvisorPanel } from './GeminiAdvisorPanel';
import { MetricsOverview } from './MetricsOverview';
import { PolicyControls } from './PolicyControls';
import { SelfTestPanel } from './SelfTestPanel';
import { SideBySideDiff } from './SideBySideDiff';
import { SourceInputPanel } from './SourceInputPanel';
import { WorkspaceTab } from './WorkspaceNav';
import { ParsedCsv } from '../engine/csvParser';
import { SelfTestReport } from '../engine/selfTest';
import type { SafeScanSummary } from '../services/geminiAdvisor';
import { DetectionOptions, PiiCategory, RedactionMode, RedactionResult } from '../types/pii';

interface WorkspacePanelsProps {
  activeTab: WorkspaceTab;
  rawText: string;
  sourceFilename: string;
  mode: RedactionMode;
  options: DetectionOptions;
  effectiveOptions: DetectionOptions;
  allowlistText: string;
  customRuleError: string | null;
  result: RedactionResult;
  diffViewMode: 'text' | 'csv';
  originalCsv: ParsedCsv;
  sanitizedCsv: ParsedCsv;
  neutralizeFormulas: boolean;
  copied: boolean;
  selfTest: SelfTestReport | null;
  safeSummary: SafeScanSummary;
  onChangeText: (text: string) => void;
  onSelectFixture: (text: string, filename: string, preferCsv: boolean) => void;
  onClearInput: () => void;
  onChangeMode: (mode: RedactionMode) => void;
  onChangeOptions: React.Dispatch<React.SetStateAction<DetectionOptions>>;
  onChangeAllowlist: (value: string) => void;
  onToggleCategory: (category: PiiCategory) => void;
  onChangeDiffView: (view: 'text' | 'csv') => void;
  onToggleNeutralizeFormulas: (neutralize: boolean) => void;
  onCopy: () => void;
  onDownloadSanitized: () => void;
  onDownloadAuditReport: () => void;
  onKeepOriginal: (value: string) => void;
  onRestoreAllowlisted: (value: string) => void;
  onDownloadBundle: (content: string, filename: string, mime: string) => void;
  onRunSelfTest: () => void;
  onApplySyntheticText: (synthetic: string) => void;
}

/**
 * Coordinates all four ARIA-labeled workspace tab panels (Studio, Entity Vault, Self-Test, Advisor).
 */
export function WorkspacePanels(props: WorkspacePanelsProps) {
  const { activeTab } = props;

  return (
    <>
      <div
        role="tabpanel"
        id="ws-panel-studio"
        aria-labelledby="ws-tab-studio"
        hidden={activeTab !== 'studio'}
        className={`ws-panel ${activeTab === 'studio' ? 'is-active' : ''}`}
      >
        <div className="studio-top-grid">
          <SourceInputPanel
            rawText={props.rawText}
            sourceFilename={props.sourceFilename}
            scanDurationMs={props.result.scan.durationMs}
            onChangeText={props.onChangeText}
            onSelectFixture={props.onSelectFixture}
            onClear={props.onClearInput}
          />
          <PolicyControls
            mode={props.mode}
            options={props.options}
            allowlistText={props.allowlistText}
            customRuleError={props.customRuleError}
            onChangeMode={props.onChangeMode}
            onChangeOptions={props.onChangeOptions}
            onChangeAllowlist={props.onChangeAllowlist}
          />
        </div>
        <MetricsOverview
          scan={props.result.scan}
          options={props.effectiveOptions}
          onToggleCategory={props.onToggleCategory}
        />
        <SideBySideDiff
          mode={props.mode}
          result={props.result}
          diffViewMode={props.diffViewMode}
          originalCsv={props.originalCsv}
          sanitizedCsv={props.sanitizedCsv}
          neutralizeFormulas={props.neutralizeFormulas}
          copied={props.copied}
          onChangeDiffView={props.onChangeDiffView}
          onToggleNeutralizeFormulas={props.onToggleNeutralizeFormulas}
          onCopy={props.onCopy}
          onDownloadSanitized={props.onDownloadSanitized}
          onDownloadAuditReport={props.onDownloadAuditReport}
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
          segments={props.result.originalSegments}
          mappings={props.result.mappings}
          rejectedCards={props.result.scan.rejectedCards}
          allowlist={props.effectiveOptions.allowlist}
          onKeepOriginal={props.onKeepOriginal}
          onRestoreAllowlisted={props.onRestoreAllowlisted}
          onDownloadBundle={props.onDownloadBundle}
        />
      </div>

      <div
        role="tabpanel"
        id="ws-panel-proof"
        aria-labelledby="ws-tab-proof"
        hidden={activeTab !== 'proof'}
        className={`ws-panel ${activeTab === 'proof' ? 'is-active' : ''}`}
      >
        <SelfTestPanel selfTest={props.selfTest} onRunSelfTest={props.onRunSelfTest} />
      </div>

      <div
        role="tabpanel"
        id="ws-panel-gemini"
        aria-labelledby="ws-tab-gemini"
        hidden={activeTab !== 'gemini'}
        className={`ws-panel ${activeTab === 'gemini' ? 'is-active' : ''}`}
      >
        <GeminiAdvisorPanel summary={props.safeSummary} onApplySyntheticText={props.onApplySyntheticText} />
      </div>
    </>
  );
}

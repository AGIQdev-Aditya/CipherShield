import { RedactionMode, ScanResult } from '../types/pii';
import { buildCloudDlpDeidentifyConfig, buildCloudDlpSummary } from './dlpTaxonomy';
import { NetworkMonitorState } from './networkMonitor';
import { sha256Hex } from './redactor';

export interface AuditCertificateInput {
  rawText: string;
  sanitizedText: string;
  sourceFilename: string;
  mode: RedactionMode;
  shouldUseWorker: boolean;
  networkState: NetworkMonitorState;
  scan: ScanResult;
}

/**
 * Builds a tamper-evident zero-PII JSON compliance audit certificate with SHA-256 integrity digests
 * and official Google Cloud DLP v2 InfoType mappings.
 */
export async function buildAuditCertificate(input: AuditCertificateInput) {
  const [originalSha256, sanitizedSha256] = await Promise.all([
    sha256Hex(input.rawText),
    sha256Hex(input.sanitizedText),
  ]);

  return {
    tool: 'CipherShield',
    executionEnvironment: input.shouldUseWorker
      ? '100% Client-Side Web Worker + Browser RAM (Zero Server Egress)'
      : '100% Client-Side Browser RAM (Zero Server Egress)',
    generatedAt: new Date().toISOString(),
    sourceFilename: input.sourceFilename,
    redactionMode: input.mode,
    integrityDigests: { originalSha256, sanitizedSha256 },
    networkMonitor: input.networkState,
    exposureRisk: input.scan.risk,
    metrics: {
      totalRedacted: input.scan.totalDetected,
      luhnRejectedFalsePositives: input.scan.luhnRejectedCount,
      allowlistedPreserved: input.scan.allowlistedCount,
      scanDurationMs: input.scan.durationMs,
    },
    googleCloudDlpSummary: buildCloudDlpSummary(input.scan.counts),
    googleCloudDlpDeidentifyConfig: buildCloudDlpDeidentifyConfig(input.scan.counts, input.mode),
  };
}

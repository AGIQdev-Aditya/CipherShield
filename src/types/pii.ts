export type PiiCategory =
  | 'EMAIL'
  | 'PHONE'
  | 'IP_ADDRESS'
  | 'PAN'
  | 'AADHAAR'
  | 'CREDIT_CARD'
  | 'CUSTOM';

export type RedactionMode = 'full' | 'partial' | 'pseudonymize';

export interface CustomPatternRule {
  enabled: boolean;
  label: string;
  pattern: string;
}

export interface DetectionOptions {
  enabledCategories: Record<PiiCategory, boolean>;
  strictAadhaarVerhoeff: boolean;
  fullMaskTemplate: 'generic' | 'typed';
  allowlist: string[];
  customRule: CustomPatternRule;
}

export interface PiiEntity {
  id: string;
  category: PiiCategory;
  value: string;
  normalizedKey: string;
  start: number;
  end: number;
  metadata?: string;
  validatedBy?: 'LUHN' | 'VERHOEFF' | 'RFC' | 'OCTET' | 'FORMAT' | 'CUSTOM';
}

export interface RejectedCandidate {
  value: string;
  reason: string;
  start: number;
  end: number;
}

export interface PseudonymMapping {
  token: string;
  category: PiiCategory;
  normalizedKey: string;
  sampleValue: string;
  occurrences: number;
}

export interface RiskSummary {
  scoreBefore: number;
  scoreAfter: number;
  levelBefore: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'NONE';
}

export interface ScanResult {
  entities: PiiEntity[];
  rejectedCards: RejectedCandidate[];
  counts: Record<PiiCategory, number>;
  totalDetected: number;
  luhnRejectedCount: number;
  allowlistedCount: number;
  customRuleError: string | null;
  risk: RiskSummary;
  durationMs: number;
}

export interface DiffSegment {
  text: string;
  entity?: PiiEntity;
  replacement?: string;
}

export interface RedactionResult {
  sanitizedText: string;
  originalSegments: DiffSegment[];
  sanitizedSegments: DiffSegment[];
  mappings: PseudonymMapping[];
  scan: ScanResult;
}

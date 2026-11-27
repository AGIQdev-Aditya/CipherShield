export type PiiCategory =
  | 'EMAIL'
  | 'PHONE'
  | 'IP_ADDRESS'
  | 'PAN'
  | 'AADHAAR'
  | 'CREDIT_CARD';

export type RedactionMode = 'full' | 'partial' | 'pseudonymize';

export interface DetectionOptions {
  enabledCategories: Record<PiiCategory, boolean>;
  strictAadhaarVerhoeff: boolean;
  fullMaskTemplate: 'generic' | 'typed';
}

export interface PiiEntity {
  id: string;
  category: PiiCategory;
  value: string;
  normalizedKey: string;
  start: number;
  end: number;
  metadata?: string;
  validatedBy?: 'LUHN' | 'VERHOEFF' | 'RFC' | 'OCTET' | 'FORMAT';
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

export interface ScanResult {
  entities: PiiEntity[];
  rejectedCards: RejectedCandidate[];
  counts: Record<PiiCategory, number>;
  totalDetected: number;
  luhnRejectedCount: number;
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

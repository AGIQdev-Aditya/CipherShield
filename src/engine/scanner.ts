import { DetectionOptions, PiiCategory, PiiEntity, RejectedCandidate, ScanResult } from '../types/pii';
import {
  detectCardNetwork,
  describePanEntity,
  isValidIPv4,
  isValidIPv6,
  isValidLuhn,
  isValidVerhoeff,
} from './validators';

export const DEFAULT_DETECTION_OPTIONS: DetectionOptions = {
  enabledCategories: {
    EMAIL: true,
    PHONE: true,
    IP_ADDRESS: true,
    PAN: true,
    AADHAAR: true,
    CREDIT_CARD: true,
  },
  strictAadhaarVerhoeff: false,
  fullMaskTemplate: 'generic',
};

const CATEGORY_PRIORITY: Record<PiiCategory, number> = {
  CREDIT_CARD: 6,
  EMAIL: 5,
  IP_ADDRESS: 4,
  AADHAAR: 3,
  PAN: 2,
  PHONE: 1,
};

// ReDoS-safe bounded regex patterns
const REGEX_EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const REGEX_PAN = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
const REGEX_AADHAAR = /(?<![\d-])\d{4}[\s-]?\d{4}[\s-]?\d{4}(?![\d-])/g;
const REGEX_CARD_FORMATTED = /(?<![\d.-])\d{4}(?:[-\s]\d{4}){2,3}(?:[-\s]\d{1,3})?(?![\d.-])/g;
const REGEX_CARD_CONTIGUOUS = /(?<![\d.])\d{13,19}(?![\d.])/g;
const REGEX_IPV4 = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)/g;
const REGEX_IPV6 = /(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])/g;
const REGEX_PHONE =
  /(?<![\d\w.])(?:\+91[\s.-]?[6-9]\d{4}[\s.-]?\d{5}|0?[6-9]\d{9}|(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4})(?![\d\w])/g;

function normalizeKey(category: PiiCategory, value: string): string {
  switch (category) {
    case 'EMAIL':
      return value.trim().toLowerCase();
    case 'PAN':
      return value.trim().toUpperCase();
    case 'CREDIT_CARD':
    case 'AADHAAR':
      return value.replace(/\D/g, '');
    case 'PHONE': {
      const digits = value.replace(/\D/g, '');
      // Normalize +91XXXXXXXXXX or 0XXXXXXXXXX to canonical 10-digit Indian key when applicable
      if (digits.length === 12 && digits.startsWith('91')) return digits.slice(2);
      if (digits.length === 11 && digits.startsWith('0')) return digits.slice(1);
      return digits;
    }
    case 'IP_ADDRESS':
      return value.trim().toLowerCase();
  }
}

/**
 * Executes a deterministic, client-side PII scan with interval conflict resolution.
 */
export function scanTextForPii(text: string, options: DetectionOptions = DEFAULT_DETECTION_OPTIONS): ScanResult {
  const startTime = performance.now();
  const rawMatches: Omit<PiiEntity, 'id'>[] = [];
  const rejectedCards: RejectedCandidate[] = [];

  if (options.enabledCategories.CREDIT_CARD) {
    const seenCardSpans = new Set<string>();
    for (const regex of [REGEX_CARD_FORMATTED, REGEX_CARD_CONTIGUOUS]) {
      regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(text)) !== null) {
        const value = m[0];
        const spanKey = `${m.index}:${m.index + value.length}`;
        if (seenCardSpans.has(spanKey)) continue;
        seenCardSpans.add(spanKey);

        if (isValidLuhn(value)) {
          rawMatches.push({
            category: 'CREDIT_CARD',
            value,
            normalizedKey: normalizeKey('CREDIT_CARD', value),
            start: m.index,
            end: m.index + value.length,
            metadata: detectCardNetwork(value),
            validatedBy: 'LUHN',
          });
        } else {
          rejectedCards.push({
            value,
            reason: 'Failed Luhn Mod-10 checksum',
            start: m.index,
            end: m.index + value.length,
          });
        }
      }
    }
  }

  if (options.enabledCategories.EMAIL) {
    REGEX_EMAIL.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REGEX_EMAIL.exec(text)) !== null) {
      rawMatches.push({
        category: 'EMAIL',
        value: m[0],
        normalizedKey: normalizeKey('EMAIL', m[0]),
        start: m.index,
        end: m.index + m[0].length,
        metadata: 'Email Address',
        validatedBy: 'RFC',
      });
    }
  }

  if (options.enabledCategories.IP_ADDRESS) {
    REGEX_IPV4.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REGEX_IPV4.exec(text)) !== null) {
      if (isValidIPv4(m[0])) {
        rawMatches.push({
          category: 'IP_ADDRESS',
          value: m[0],
          normalizedKey: normalizeKey('IP_ADDRESS', m[0]),
          start: m.index,
          end: m.index + m[0].length,
          metadata: 'IPv4 Address',
          validatedBy: 'OCTET',
        });
      }
    }

    REGEX_IPV6.lastIndex = 0;
    while ((m = REGEX_IPV6.exec(text)) !== null) {
      if (isValidIPv6(m[0])) {
        rawMatches.push({
          category: 'IP_ADDRESS',
          value: m[0],
          normalizedKey: normalizeKey('IP_ADDRESS', m[0]),
          start: m.index,
          end: m.index + m[0].length,
          metadata: 'IPv6 Address',
          validatedBy: 'FORMAT',
        });
      }
    }
  }

  if (options.enabledCategories.AADHAAR) {
    REGEX_AADHAAR.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REGEX_AADHAAR.exec(text)) !== null) {
      const verhoeffPass = isValidVerhoeff(m[0]);
      if (options.strictAadhaarVerhoeff && !verhoeffPass) {
        continue;
      }
      rawMatches.push({
        category: 'AADHAAR',
        value: m[0],
        normalizedKey: normalizeKey('AADHAAR', m[0]),
        start: m.index,
        end: m.index + m[0].length,
        metadata: verhoeffPass ? 'Aadhaar (Verhoeff OK)' : 'Aadhaar Format (12-digit)',
        validatedBy: verhoeffPass ? 'VERHOEFF' : 'FORMAT',
      });
    }
  }

  if (options.enabledCategories.PAN) {
    REGEX_PAN.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REGEX_PAN.exec(text)) !== null) {
      rawMatches.push({
        category: 'PAN',
        value: m[0],
        normalizedKey: normalizeKey('PAN', m[0]),
        start: m.index,
        end: m.index + m[0].length,
        metadata: describePanEntity(m[0]),
        validatedBy: 'FORMAT',
      });
    }
  }

  if (options.enabledCategories.PHONE) {
    REGEX_PHONE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REGEX_PHONE.exec(text)) !== null) {
      // Exclude ISO date lookalikes like 2026-11-27 if somehow matched
      if (/^\d{4}-\d{2}-\d{2}$/.test(m[0])) continue;
      rawMatches.push({
        category: 'PHONE',
        value: m[0],
        normalizedKey: normalizeKey('PHONE', m[0]),
        start: m.index,
        end: m.index + m[0].length,
        metadata: m[0].trim().startsWith('+91') ? 'IN Phone' : 'Phone Number',
        validatedBy: 'FORMAT',
      });
    }
  }

  // Deterministic conflict resolution by category priority, length, then earliest position
  rawMatches.sort((a, b) => {
    const prioDiff = CATEGORY_PRIORITY[b.category] - CATEGORY_PRIORITY[a.category];
    if (prioDiff !== 0) return prioDiff;
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return a.start - b.start;
  });

  const accepted: Omit<PiiEntity, 'id'>[] = [];
  for (const candidate of rawMatches) {
    const overlaps = accepted.some(
      (existing) => !(candidate.end <= existing.start || candidate.start >= existing.end),
    );
    if (!overlaps) {
      accepted.push(candidate);
    }
  }

  accepted.sort((a, b) => a.start - b.start);

  const entities: PiiEntity[] = accepted.map((item, idx) => ({
    ...item,
    id: `pii-${idx + 1}`,
  }));

  const counts: Record<PiiCategory, number> = {
    EMAIL: 0,
    PHONE: 0,
    IP_ADDRESS: 0,
    PAN: 0,
    AADHAAR: 0,
    CREDIT_CARD: 0,
  };

  for (const entity of entities) {
    counts[entity.category] += 1;
  }

  // Filter rejected cards that overlap accepted valid cards
  const filteredRejected = rejectedCards.filter(
    (rej) => !entities.some((e) => !(rej.end <= e.start || rej.start >= e.end)),
  );

  return {
    entities,
    rejectedCards: filteredRejected,
    counts,
    totalDetected: entities.length,
    luhnRejectedCount: filteredRejected.length,
    durationMs: Number((performance.now() - startTime).toFixed(2)),
  };
}

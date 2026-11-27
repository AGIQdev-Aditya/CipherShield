import { DetectionOptions, PiiCategory, PiiEntity, RejectedCandidate, RiskSummary, ScanResult } from '../types/pii';
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
    CUSTOM: true,
  },
  strictAadhaarVerhoeff: false,
  fullMaskTemplate: 'generic',
  allowlist: ['127.0.0.1'],
  customRule: {
    enabled: false,
    label: 'EMP_ID',
    pattern: 'EMP-\\d{4,6}',
  },
};

const CATEGORY_PRIORITY: Record<PiiCategory, number> = {
  CREDIT_CARD: 7,
  EMAIL: 6,
  IP_ADDRESS: 5,
  AADHAAR: 4,
  PAN: 3,
  PHONE: 2,
  CUSTOM: 1,
};

const CATEGORY_RISK_WEIGHT: Record<PiiCategory, number> = {
  CREDIT_CARD: 25,
  AADHAAR: 22,
  PAN: 18,
  PHONE: 10,
  EMAIL: 8,
  IP_ADDRESS: 6,
  CUSTOM: 12,
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
    case 'CUSTOM':
      return value.trim().toUpperCase();
    case 'CREDIT_CARD':
    case 'AADHAAR':
      return value.replace(/\D/g, '');
    case 'PHONE': {
      const digits = value.replace(/\D/g, '');
      if (digits.length === 12 && digits.startsWith('91')) return digits.slice(2);
      if (digits.length === 11 && digits.startsWith('0')) return digits.slice(1);
      return digits;
    }
    case 'IP_ADDRESS':
      return value.trim().toLowerCase();
  }
}

function calculateRisk(counts: Record<PiiCategory, number>): RiskSummary {
  let rawScore = 0;
  for (const cat of Object.keys(counts) as PiiCategory[]) {
    rawScore += counts[cat] * CATEGORY_RISK_WEIGHT[cat];
  }
  const scoreBefore = Math.min(100, rawScore);
  let levelBefore: RiskSummary['levelBefore'] = 'NONE';
  if (scoreBefore >= 75) levelBefore = 'CRITICAL';
  else if (scoreBefore >= 45) levelBefore = 'HIGH';
  else if (scoreBefore >= 20) levelBefore = 'MODERATE';
  else if (scoreBefore > 0) levelBefore = 'LOW';

  return {
    scoreBefore,
    scoreAfter: 0,
    levelBefore,
  };
}

/**
 * Executes a deterministic, client-side PII scan with Luhn/Verhoeff checks,
 * allowlist filtering, optional custom regex rules, and non-overlapping interval merging.
 */
export function scanTextForPii(text: string, options: DetectionOptions = DEFAULT_DETECTION_OPTIONS): ScanResult {
  const startTime = performance.now();
  const rawMatches: Omit<PiiEntity, 'id'>[] = [];
  const rejectedCards: RejectedCandidate[] = [];
  let customRuleError: string | null = null;

  const allowSet = new Set(
    options.allowlist.map((entry) => entry.trim().toLowerCase()).filter(Boolean),
  );

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

  if (options.customRule.enabled && options.customRule.pattern.trim()) {
    try {
      const customRegex = new RegExp(options.customRule.pattern.trim(), 'g');
      let m: RegExpExecArray | null;
      let guard = 0;
      while ((m = customRegex.exec(text)) !== null && guard < 2000) {
        guard += 1;
        if (m[0].length === 0) {
          customRegex.lastIndex += 1;
          continue;
        }
        rawMatches.push({
          category: 'CUSTOM',
          value: m[0],
          normalizedKey: normalizeKey('CUSTOM', m[0]),
          start: m.index,
          end: m.index + m[0].length,
          metadata: options.customRule.label.trim() || 'Custom Pattern',
          validatedBy: 'CUSTOM',
        });
      }
    } catch {
      customRuleError = 'Invalid custom RegExp syntax.';
    }
  }

  // Filter allowlisted items before conflict resolution
  let allowlistedCount = 0;
  const nonAllowlisted = rawMatches.filter((item) => {
    const valLower = item.value.trim().toLowerCase();
    const keyLower = item.normalizedKey.toLowerCase();
    const isAllowed = allowSet.has(valLower) || allowSet.has(keyLower);
    if (isAllowed) {
      allowlistedCount += 1;
      return false;
    }
    return true;
  });

  nonAllowlisted.sort((a, b) => {
    const prioDiff = CATEGORY_PRIORITY[b.category] - CATEGORY_PRIORITY[a.category];
    if (prioDiff !== 0) return prioDiff;
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return a.start - b.start;
  });

  const accepted: Omit<PiiEntity, 'id'>[] = [];
  for (const candidate of nonAllowlisted) {
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
    CUSTOM: 0,
  };

  for (const entity of entities) {
    counts[entity.category] += 1;
  }

  const filteredRejected = rejectedCards.filter(
    (rej) => !entities.some((e) => !(rej.end <= e.start || rej.start >= e.end)),
  );

  return {
    entities,
    rejectedCards: filteredRejected,
    counts,
    totalDetected: entities.length,
    luhnRejectedCount: filteredRejected.length,
    allowlistedCount,
    customRuleError,
    risk: calculateRisk(counts),
    durationMs: Number((performance.now() - startTime).toFixed(2)),
  };
}

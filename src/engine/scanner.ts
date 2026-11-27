import { DetectionOptions, PiiCategory, PiiEntity, RejectedCandidate, RiskSummary, ScanResult } from '../types/pii';
import {
  canonicalizeIPv6,
  describePanEntity,
  detectCardNetwork,
  hasValidPanEntityCode,
  isValidEmailStrict,
  isValidIPv4,
  isValidIPv6,
  isValidLuhn,
  isValidVerhoeff,
  validatePhoneWithGoogleLib,
} from './validators';

export const DEFAULT_DETECTION_OPTIONS: DetectionOptions = {
  enabledCategories: {
    EMAIL: true,
    PHONE: true,
    IP_ADDRESS: true,
    PAN: true,
    AADHAAR: true,
    CREDIT_CARD: true,
    UPI_ID: true,
    CUSTOM: true,
  },
  strictAadhaarVerhoeff: true,
  fullMaskTemplate: 'generic',
  allowlist: ['127.0.0.1'],
  customRule: {
    enabled: false,
    label: 'EMP_ID',
    pattern: 'EMP-\\d{4,6}',
  },
};

// Priority order ensures EMAIL > UPI > CREDIT_CARD > IP_ADDRESS > AADHAAR > PAN > PHONE > CUSTOM
const CATEGORY_PRIORITY: Record<PiiCategory, number> = {
  EMAIL: 8,
  UPI_ID: 7,
  CREDIT_CARD: 6,
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
  UPI_ID: 14,
  PHONE: 10,
  EMAIL: 8,
  IP_ADDRESS: 6,
  CUSTOM: 12,
};

// Horizontal whitespace only (prevent regexes bleeding across newlines)
const REGEX_EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const REGEX_UPI =
  /\b[A-Za-z0-9._-]{2,64}@(?:ok(?:hdfcbank|icici|sbi|axis)|ybl|ibl|axl|apl|paytm|upi|freecharge|jupiteraxis|fam|razorpay)\b(?!\.[A-Za-z])/gi;
const REGEX_PAN = /(?<![A-Za-z0-9])[A-Za-z]{5}[0-9]{4}[A-Za-z](?![A-Za-z0-9])/g;
const REGEX_AADHAAR = /(?<![\d-])[2-9]\d{3}(?:[ \t\u00A0-]?\d{4}){2}(?![\d-])/g;
const REGEX_CARD_FORMATTED =
  /(?<![\d.])(?:\d{4}(?:[- \t.\u00A0]\d{4}){2}[- \t.\u00A0]\d{1,4}(?:[- \t.\u00A0]\d{1,3})?|\d{4}[ \t-]\d{6}[ \t-]\d{5}|\d{4}[ \t-]\d{6}[ \t-]\d{4})(?![\d.])/g;
const REGEX_CARD_CONTIGUOUS = /(?<![\d.])\d{13,19}(?![\d.])/g;
const REGEX_IPV4 =
  /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)/g;
const REGEX_IPV6 =
  /(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{1,4}|:)(?:%[A-Za-z0-9._-]+)?(?![\w:.])/g;
const REGEX_PHONE_CANDIDATE =
  /(?<![\d\w.-])(?:\+91[ \t.-]?(?:[6-9]\d{4}[ \t.-]?\d{5}|[6-9]\d{3}[ \t.-]?\d{3}[ \t.-]?\d{3}|[1-9]\d{1,3}[ \t.-]?\d{6,8})|0?[6-9]\d{9}|[6-9]\d{4}[ \t.-]\d{5}|0[1-9]\d{1,3}[ \t.-]\d{6,8}|1[ \t.-]?800[ \t.-]?\d{3,4}[ \t.-]?\d{4}|(?:\+\d{1,3}[ \t.-]?)?\(?\d{2,4}\)?[ \t.-]\d{2,4}[ \t.-]\d{4}(?:[ \t.-]\d{2,4})?)(?:[ \t]*(?:x|ext\.?)[ \t]*\d{2,5})?(?![\d\w-])/gi;

/**
 * Depth-aware static analyzer rejecting catastrophic backtracking (ReDoS),
 * nested quantifiers, quantified alternations, lookarounds, and backreferences.
 */
export function hasUnsafeRegexConstruct(pattern: string): string | null {
  if (pattern.length > 120) {
    return 'Custom RegExp exceeds 120-character safety limit.';
  }
  if (/\\[1-9]/.test(pattern)) {
    return 'Potential ReDoS: backreferences are disallowed in custom RegExp rules.';
  }
  if (/\(\?[=!<]/.test(pattern)) {
    return 'Potential ReDoS: lookaround assertions are disallowed in custom RegExp rules.';
  }
  if (/(\.\*|\.\+|\\s\*|\\w\+)\s*\1|(?:\.\*|\.\+){2}/.test(pattern)) {
    return 'Potential ReDoS: adjacent unbounded wildcards rejected.';
  }

  // Track group stack for nested quantifiers ((a+)+, (a|aa)+, (?:[a-z]+\s?)+, (a+){2,})
  const stack: Array<{ hasQuantifier: boolean; hasAlternation: boolean }> = [
    { hasQuantifier: false, hasAlternation: false },
  ];
  let inCharClass = false;

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '\\') {
      i += 1;
      continue;
    }
    if (inCharClass) {
      if (ch === ']') inCharClass = false;
      continue;
    }
    if (ch === '[') {
      inCharClass = true;
      continue;
    }
    if (ch === '(') {
      stack.push({ hasQuantifier: false, hasAlternation: false });
      continue;
    }
    if (ch === ')') {
      const closed = stack.length > 1 ? stack.pop()! : { hasQuantifier: false, hasAlternation: false };
      const next = pattern[i + 1] ?? '';
      const hasOuterQuantifier = next === '+' || next === '*' || next === '{';
      if (hasOuterQuantifier && (closed.hasQuantifier || closed.hasAlternation)) {
        return 'Potential catastrophic backtracking (ReDoS) nested quantifier/alternation rejected.';
      }
      const parent = stack[stack.length - 1];
      if (hasOuterQuantifier || closed.hasQuantifier) {
        parent.hasQuantifier = true;
      }
      if (closed.hasAlternation) {
        parent.hasAlternation = true;
      }
      continue;
    }
    if (ch === '|') {
      stack[stack.length - 1].hasAlternation = true;
      continue;
    }
    if (ch === '+' || ch === '*' || (ch === '?' && pattern[i - 1] !== '(') || ch === '{') {
      if (ch === '{' && !/^\{\d+(?:,\d*)?\}/.test(pattern.slice(i))) {
        continue;
      }
      stack[stack.length - 1].hasQuantifier = true;
    }
  }

  return null;
}

function normalizeKey(category: PiiCategory, value: string, precomputedPhoneE164?: string): string {
  switch (category) {
    case 'EMAIL':
    case 'UPI_ID':
      return value.trim().toLowerCase();
    case 'PAN':
    case 'CUSTOM':
      return value.trim().toUpperCase();
    case 'CREDIT_CARD':
    case 'AADHAAR':
      return value.replace(/\D/g, '');
    case 'PHONE': {
      if (precomputedPhoneE164) return precomputedPhoneE164;
      const digits = value.replace(/\D/g, '');
      if (digits.length === 12 && digits.startsWith('91')) return digits.slice(2);
      if (digits.length === 11 && digits.startsWith('0')) return digits.slice(1);
      return digits;
    }
    case 'IP_ADDRESS':
      return value.includes(':') ? canonicalizeIPv6(value) : value.trim().toLowerCase();
  }
}

export function calculateRiskScore(counts: Record<PiiCategory, number>): {
  score: number;
  level: RiskSummary['levelBefore'];
} {
  let rawScore = 0;
  for (const cat of Object.keys(counts) as PiiCategory[]) {
    rawScore += counts[cat] * CATEGORY_RISK_WEIGHT[cat];
  }
  const score = Math.min(100, rawScore);
  let level: RiskSummary['levelBefore'] = 'NONE';
  if (score >= 75) level = 'CRITICAL';
  else if (score >= 45) level = 'HIGH';
  else if (score >= 20) level = 'MODERATE';
  else if (score > 0) level = 'LOW';
  return { score, level };
}

type RawMatch = Omit<PiiEntity, 'id'>;
type TextSpan = { start: number; end: number };

function isInsideBlockedSpan(spans: TextSpan[], start: number, end: number): boolean {
  return spans.some((b) => start >= b.start && end <= b.end);
}

function collectCardMatches(
  text: string,
  rawMatches: RawMatch[],
  rejectedCards: RejectedCandidate[],
  blockedSubSpans: TextSpan[],
): void {
  const seenCardSpans = new Set<string>();
  for (const regex of [REGEX_CARD_FORMATTED, REGEX_CARD_CONTIGUOUS]) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      if (m[0].includes('\n') || m[0].includes('\r')) continue;

      let value = m[0];
      const start = m.index;
      let end = start + value.length;

      const contextBefore = text.slice(Math.max(0, start - 24), start).toLowerCase();
      if (/\bimei\b|\biccid\b|\bserial\b/.test(contextBefore)) {
        rejectedCards.push({ value, reason: 'Device IMEI/ICCID context excluded', start, end });
        blockedSubSpans.push({ start, end });
        continue;
      }

      if (!isValidLuhn(value) && /[-\s.\u00A0]\d{1,3}$/.test(value)) {
        const trimmedVal = value.replace(/[-\s.\u00A0]\d{1,3}$/, '');
        if (isValidLuhn(trimmedVal)) {
          value = trimmedVal;
          end = start + value.length;
        }
      }

      const spanKey = `${start}:${end}`;
      if (seenCardSpans.has(spanKey)) continue;
      seenCardSpans.add(spanKey);

      if (!isValidLuhn(value)) {
        rejectedCards.push({ value, reason: 'Failed Luhn Mod-10 checksum', start, end });
        blockedSubSpans.push({ start, end });
        continue;
      }

      const network = detectCardNetwork(value);
      if (!network) {
        rejectedCards.push({ value, reason: 'Passed Luhn but unmatched card network IIN', start, end });
        blockedSubSpans.push({ start, end });
        continue;
      }

      rawMatches.push({
        category: 'CREDIT_CARD',
        value,
        normalizedKey: normalizeKey('CREDIT_CARD', value),
        start,
        end,
        confidence: 'HIGH',
        metadata: network,
        validatedBy: 'LUHN',
      });
    }
  }
}

function collectPatternMatches(
  text: string,
  regex: RegExp,
  category: PiiCategory,
  metadata: string,
  validatedBy: PiiEntity['validatedBy'],
  rawMatches: RawMatch[],
  validate?: (val: string) => boolean,
): void {
  regex.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(text)) !== null) {
    if (validate && !validate(m[0])) continue;
    rawMatches.push({
      category,
      value: m[0],
      normalizedKey: normalizeKey(category, m[0]),
      start: m.index,
      end: m.index + m[0].length,
      confidence: 'HIGH',
      metadata,
      validatedBy,
    });
  }
}

function collectIpMatches(text: string, rawMatches: RawMatch[]): void {
  collectPatternMatches(text, REGEX_IPV6, 'IP_ADDRESS', 'IPv6 Address', 'IPV6_PARSER', rawMatches, isValidIPv6);

  REGEX_IPV4.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REGEX_IPV4.exec(text)) !== null) {
    const prevChar = m.index > 0 ? text[m.index - 1] : '';
    if ((prevChar === 'v' || prevChar === 'V') && /[\s:/([]/.test(text[m.index - 2] ?? ' ')) {
      continue;
    }
    if (!isValidIPv4(m[0])) continue;
    rawMatches.push({
      category: 'IP_ADDRESS',
      value: m[0],
      normalizedKey: normalizeKey('IP_ADDRESS', m[0]),
      start: m.index,
      end: m.index + m[0].length,
      confidence: 'HIGH',
      metadata: 'IPv4 Address',
      validatedBy: 'OCTET',
    });
  }
}

function collectAadhaarMatches(
  text: string,
  options: DetectionOptions,
  blockedSubSpans: TextSpan[],
  rawMatches: RawMatch[],
): void {
  REGEX_AADHAAR.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REGEX_AADHAAR.exec(text)) !== null) {
    const start = m.index;
    const end = start + m[0].length;
    if (isInsideBlockedSpan(blockedSubSpans, start, end)) continue;

    const compact = m[0].replace(/\D/g, '');
    const contextBefore = text.slice(Math.max(0, start - 20), start).toLowerCase();
    // Contiguous 91 + 10-digit Indian mobile should be classified as PHONE, not Aadhaar
    if (!m[0].includes(' ') && !m[0].includes('-') && /^91[6-9]\d{9}$/.test(compact) && !/aadhaar|uid/.test(contextBefore)) {
      const phoneCheck = validatePhoneWithGoogleLib(`+${compact}`);
      if (phoneCheck && options.enabledCategories.PHONE) {
        rawMatches.push({
          category: 'PHONE',
          value: m[0],
          normalizedKey: normalizeKey('PHONE', m[0], phoneCheck.e164),
          start,
          end,
          confidence: 'MEDIUM',
          metadata: phoneCheck.metadata,
          validatedBy: phoneCheck.validatedBy,
        });
        continue;
      }
    }

    const verhoeffPass = isValidVerhoeff(m[0]);
    if (options.strictAadhaarVerhoeff && !verhoeffPass) continue;

    rawMatches.push({
      category: 'AADHAAR',
      value: m[0],
      normalizedKey: normalizeKey('AADHAAR', m[0]),
      start,
      end,
      confidence: verhoeffPass ? 'HIGH' : 'MEDIUM',
      metadata: verhoeffPass ? 'Aadhaar (Verhoeff OK)' : 'Aadhaar Format (Unverified)',
      validatedBy: verhoeffPass ? 'VERHOEFF' : 'FORMAT',
    });
  }
}

function collectPanMatches(text: string, rawMatches: RawMatch[]): void {
  REGEX_PAN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REGEX_PAN.exec(text)) !== null) {
    const value = m[0];
    const isUpper = value === value.toUpperCase();
    const validCode = hasValidPanEntityCode(value);
    const rawWindow = text.slice(Math.max(0, m.index - 24), m.index);
    const localClause = (rawWindow.split(/[\n,;|]/).pop() ?? '').toLowerCase();
    const hasPanContext = /\b(?:pan|tax|kyc|tin|nsdl|income)\b/.test(localClause);

    if (isUpper) {
      if (!validCode && !hasPanContext) continue;
    } else if (!validCode || !hasPanContext) {
      continue;
    }

    rawMatches.push({
      category: 'PAN',
      value,
      normalizedKey: normalizeKey('PAN', value),
      start: m.index,
      end: m.index + value.length,
      confidence: validCode ? 'HIGH' : 'MEDIUM',
      metadata: validCode ? describePanEntity(value) : 'PAN Context Match (Non-standard 4th char)',
      validatedBy: 'FORMAT',
    });
  }
}

function collectPhoneMatches(text: string, blockedSubSpans: TextSpan[], rawMatches: RawMatch[]): void {
  REGEX_PHONE_CANDIDATE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REGEX_PHONE_CANDIDATE.exec(text)) !== null) {
    const start = m.index;
    const end = start + m[0].length;
    if (/^(?:\d{4}[-.]\d{2}[-.]\d{2}|\d{2}[-./]\d{2}[-./]\d{4})$/.test(m[0])) continue;
    if (isInsideBlockedSpan(blockedSubSpans, start, end)) continue;

    const validated = validatePhoneWithGoogleLib(m[0]);
    if (!validated) continue;

    rawMatches.push({
      category: 'PHONE',
      value: m[0],
      normalizedKey: normalizeKey('PHONE', m[0], validated.e164),
      start,
      end,
      confidence: 'HIGH',
      metadata: validated.metadata,
      validatedBy: validated.validatedBy,
    });
  }
}

function collectCustomRuleMatches(
  text: string,
  options: DetectionOptions,
  rawMatches: RawMatch[],
): string | null {
  const patternStr = options.customRule.pattern.trim();
  if (!patternStr) return null;

  const safetyIssue = hasUnsafeRegexConstruct(patternStr);
  if (safetyIssue) return safetyIssue;

  try {
    const customRegex = new RegExp(patternStr, 'g');
    const customStart = performance.now();
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = customRegex.exec(text)) !== null && guard < 2000) {
      guard += 1;
      if (guard % 25 === 0 && performance.now() - customStart > 40) {
        return 'Custom RegExp aborted: exceeded 40ms ReDoS execution budget.';
      }
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
        confidence: 'HIGH',
        metadata: options.customRule.label.trim() || 'Custom Pattern',
        validatedBy: 'CUSTOM',
      });
    }
  } catch {
    return 'Invalid custom RegExp syntax.';
  }
  return null;
}

function resolveNonOverlappingEntities(
  textLength: number,
  rawMatches: RawMatch[],
  allowSet: Set<string>,
): { entities: PiiEntity[]; allowlistedCount: number } {
  let allowlistedCount = 0;
  const nonAllowlisted = rawMatches.filter((item) => {
    const isAllowed =
      allowSet.has(item.value.trim().toLowerCase()) || allowSet.has(item.normalizedKey.toLowerCase());
    if (isAllowed) {
      allowlistedCount += 1;
      return false;
    }
    return true;
  });

  // Sort by category priority desc, span length desc, start asc
  nonAllowlisted.sort((a, b) => {
    const prioDiff = CATEGORY_PRIORITY[b.category] - CATEGORY_PRIORITY[a.category];
    if (prioDiff !== 0) return prioDiff;
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    return a.start - b.start;
  });

  // O(span_length) interval bitmap avoids O(N^2) slowdown on multi-MB logs
  const covered = new Uint8Array(textLength);
  const accepted: RawMatch[] = [];
  for (const candidate of nonAllowlisted) {
    let overlaps = false;
    for (let i = candidate.start; i < candidate.end; i++) {
      if (covered[i]) {
        overlaps = true;
        break;
      }
    }
    if (!overlaps) {
      covered.fill(1, candidate.start, candidate.end);
      accepted.push(candidate);
    }
  }

  accepted.sort((a, b) => a.start - b.start);
  const entities = accepted.map((item, idx) => ({ ...item, id: `pii-${idx + 1}` }));
  return { entities, allowlistedCount };
}

/**
 * Executes a deterministic, client-side PII scan with Luhn/Verhoeff/Google libphonenumber checks,
 * context disambiguation, allowlisting, and linear-time overlap resolution.
 */
export function scanTextForPii(
  text: string,
  options: DetectionOptions = DEFAULT_DETECTION_OPTIONS,
  skipResidualCheck = false,
): ScanResult {
  const startTime = performance.now();
  const rawMatches: RawMatch[] = [];
  const rejectedCards: RejectedCandidate[] = [];
  const blockedSubSpans: TextSpan[] = [];

  const allowSet = new Set(options.allowlist.map((entry) => entry.trim().toLowerCase()).filter(Boolean));
  const enabled = options.enabledCategories;

  if (enabled.CREDIT_CARD) collectCardMatches(text, rawMatches, rejectedCards, blockedSubSpans);
  if (enabled.EMAIL) collectPatternMatches(text, REGEX_EMAIL, 'EMAIL', 'Email Address', 'RFC', rawMatches, isValidEmailStrict);
  if (enabled.UPI_ID) collectPatternMatches(text, REGEX_UPI, 'UPI_ID', 'Indian UPI Handle', 'FORMAT', rawMatches);
  if (enabled.IP_ADDRESS) collectIpMatches(text, rawMatches);
  if (enabled.AADHAAR) collectAadhaarMatches(text, options, blockedSubSpans, rawMatches);
  if (enabled.PAN) collectPanMatches(text, rawMatches);
  if (enabled.PHONE) collectPhoneMatches(text, blockedSubSpans, rawMatches);

  const customRuleError = options.customRule.enabled ? collectCustomRuleMatches(text, options, rawMatches) : null;
  const { entities, allowlistedCount } = resolveNonOverlappingEntities(text.length, rawMatches, allowSet);

  const counts: Record<PiiCategory, number> = {
    EMAIL: 0,
    PHONE: 0,
    IP_ADDRESS: 0,
    PAN: 0,
    AADHAAR: 0,
    CREDIT_CARD: 0,
    UPI_ID: 0,
    CUSTOM: 0,
  };
  for (const entity of entities) {
    counts[entity.category] += 1;
  }

  const filteredRejected = rejectedCards.filter(
    (rej) => !entities.some((e) => !(rej.end <= e.start || rej.start >= e.end)),
  );
  const beforeRisk = calculateRiskScore(counts);

  return {
    entities,
    rejectedCards: filteredRejected,
    counts,
    totalDetected: entities.length,
    luhnRejectedCount: filteredRejected.length,
    allowlistedCount,
    customRuleError,
    risk: {
      scoreBefore: beforeRisk.score,
      scoreAfter: skipResidualCheck ? beforeRisk.score : 0,
      levelBefore: beforeRisk.level,
      levelAfter: skipResidualCheck ? beforeRisk.level : 'NONE',
      residualCount: skipResidualCheck ? entities.length : 0,
    },
    durationMs: Number((performance.now() - startTime).toFixed(2)),
  };
}

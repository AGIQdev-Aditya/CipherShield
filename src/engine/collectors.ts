import { DetectionOptions, PiiCategory, PiiEntity, RejectedCandidate } from '../types/pii';
import {
  normalizeEntityKey,
  REGEX_AADHAAR,
  REGEX_CARD_CONTIGUOUS,
  REGEX_CARD_FORMATTED,
  REGEX_IPV4,
  REGEX_IPV6,
  REGEX_PAN,
  REGEX_PHONE_CANDIDATE,
} from './patterns';
import {
  hasUnsafeRegexConstruct,
  SAFE_REGEX_MAX_MATCHES,
  SAFE_REGEX_TIME_BUDGET_MS,
} from './regexSafety';
import {
  describePanEntity,
  detectCardNetwork,
  hasValidPanEntityCode,
  isValidIPv4,
  isValidIPv6,
  isValidLuhn,
  isValidVerhoeff,
  validatePhoneWithGoogleLib,
} from './validators';

export type RawMatch = Omit<PiiEntity, 'id'>;
export type TextSpan = { start: number; end: number };

function isInsideBlockedSpan(spans: TextSpan[], start: number, end: number): boolean {
  return spans.some((b) => start >= b.start && end <= b.end);
}

function trimTrailingNumericSuffix(value: string, start: number): { value: string; end: number } {
  if (!isValidLuhn(value) && /[-\s.\u00A0]\d{1,3}$/.test(value)) {
    const trimmed = value.replace(/[-\s.\u00A0]\d{1,3}$/, '');
    if (isValidLuhn(trimmed)) {
      return { value: trimmed, end: start + trimmed.length };
    }
  }
  return { value, end: start + value.length };
}

/** Collects Luhn + IIN verified payment cards and records rejected non-card numbers (IMEI, order refs). */
export function collectCardMatches(
  text: string,
  rawMatches: RawMatch[],
  rejectedCards: RejectedCandidate[],
  blockedSubSpans: TextSpan[],
): void {
  const seenSpans = new Set<string>();
  for (const regex of [REGEX_CARD_FORMATTED, REGEX_CARD_CONTIGUOUS]) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      if (m[0].includes('\n') || m[0].includes('\r')) continue;

      const start = m.index;
      const contextBefore = text.slice(Math.max(0, start - 24), start).toLowerCase();
      if (/\bimei\b|\biccid\b|\bserial\b/.test(contextBefore)) {
        const end = start + m[0].length;
        rejectedCards.push({ value: m[0], reason: 'Device IMEI/ICCID context excluded', start, end });
        blockedSubSpans.push({ start, end });
        continue;
      }

      const resolved = trimTrailingNumericSuffix(m[0], start);
      const spanKey = `${start}:${resolved.end}`;
      if (seenSpans.has(spanKey)) continue;
      seenSpans.add(spanKey);

      if (!isValidLuhn(resolved.value)) {
        rejectedCards.push({ value: resolved.value, reason: 'Failed Luhn Mod-10 checksum', start, end: resolved.end });
        blockedSubSpans.push({ start, end: resolved.end });
        continue;
      }

      const network = detectCardNetwork(resolved.value);
      if (!network) {
        rejectedCards.push({
          value: resolved.value,
          reason: 'Passed Luhn but unmatched card network IIN',
          start,
          end: resolved.end,
        });
        blockedSubSpans.push({ start, end: resolved.end });
        continue;
      }

      rawMatches.push({
        category: 'CREDIT_CARD',
        value: resolved.value,
        normalizedKey: normalizeEntityKey('CREDIT_CARD', resolved.value),
        start,
        end: resolved.end,
        confidence: 'HIGH',
        metadata: network,
        validatedBy: 'LUHN',
      });
    }
  }
}

/** Executes a single global regex collector with optional strict predicate validation. */
export function collectPatternMatches(
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
      normalizedKey: normalizeEntityKey(category, m[0]),
      start: m.index,
      end: m.index + m[0].length,
      confidence: 'HIGH',
      metadata,
      validatedBy,
    });
  }
}

/** Collects strict IPv6 (including IPv4-mapped) and non-semver IPv4 addresses. */
export function collectIpMatches(text: string, rawMatches: RawMatch[]): void {
  collectPatternMatches(text, REGEX_IPV6, 'IP_ADDRESS', 'IPv6 Address', 'IPV6_PARSER', rawMatches, isValidIPv6);

  REGEX_IPV4.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REGEX_IPV4.exec(text)) !== null) {
    const prevChar = text[m.index - 1] ?? '';
    const beforePrefix = text[m.index - 2] ?? ' ';
    if ((prevChar === 'v' || prevChar === 'V') && /[\s:/([]/.test(beforePrefix)) continue;
    if (!isValidIPv4(m[0])) continue;

    rawMatches.push({
      category: 'IP_ADDRESS',
      value: m[0],
      normalizedKey: normalizeEntityKey('IP_ADDRESS', m[0]),
      start: m.index,
      end: m.index + m[0].length,
      confidence: 'HIGH',
      metadata: 'IPv4 Address',
      validatedBy: 'OCTET',
    });
  }
}

/** Collects UIDAI Verhoeff Aadhaar identifiers while routing contiguous 91+10d Indian mobiles to PHONE. */
export function collectAadhaarMatches(
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
    if (!m[0].includes(' ') && !m[0].includes('-') && /^91[6-9]\d{9}$/.test(compact) && !/aadhaar|uid/.test(contextBefore)) {
      const phoneCheck = validatePhoneWithGoogleLib(`+${compact}`);
      if (phoneCheck && options.enabledCategories.PHONE) {
        rawMatches.push({
          category: 'PHONE',
          value: m[0],
          normalizedKey: normalizeEntityKey('PHONE', m[0], phoneCheck.e164),
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
      normalizedKey: normalizeEntityKey('AADHAAR', m[0]),
      start,
      end,
      confidence: verhoeffPass ? 'HIGH' : 'MEDIUM',
      metadata: verhoeffPass ? 'Aadhaar (Verhoeff OK)' : 'Aadhaar Format (Unverified)',
      validatedBy: verhoeffPass ? 'VERHOEFF' : 'FORMAT',
    });
  }
}

/** Collects Indian PAN identifiers guarded by 4th-char holder code and local KYC context checks. */
export function collectPanMatches(text: string, rawMatches: RawMatch[]): void {
  REGEX_PAN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REGEX_PAN.exec(text)) !== null) {
    const value = m[0];
    const isUpper = value === value.toUpperCase();
    const validCode = hasValidPanEntityCode(value);
    const localClause = (text.slice(Math.max(0, m.index - 24), m.index).split(/[\n,;|]/).pop() ?? '').toLowerCase();
    const hasPanContext = /\b(?:pan|tax|kyc|tin|nsdl|income)\b/.test(localClause);

    const accepted = isUpper ? validCode || hasPanContext : validCode && hasPanContext;
    if (!accepted) continue;

    rawMatches.push({
      category: 'PAN',
      value,
      normalizedKey: normalizeEntityKey('PAN', value),
      start: m.index,
      end: m.index + value.length,
      confidence: validCode ? 'HIGH' : 'MEDIUM',
      metadata: validCode ? describePanEntity(value) : 'PAN Context Match (Non-standard 4th char)',
      validatedBy: 'FORMAT',
    });
  }
}

/** Collects international and Indian phones validated via Google libphonenumber. */
export function collectPhoneMatches(text: string, blockedSubSpans: TextSpan[], rawMatches: RawMatch[]): void {
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
      normalizedKey: normalizeEntityKey('PHONE', m[0], validated.e164),
      start,
      end,
      confidence: 'HIGH',
      metadata: validated.metadata,
      validatedBy: validated.validatedBy,
    });
  }
}

/** Executes a ReDoS-screened user RegExp rule within strict time and match count budgets. */
export function collectCustomRuleMatches(
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
    const startedAt = performance.now();
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = customRegex.exec(text)) !== null && guard < SAFE_REGEX_MAX_MATCHES) {
      guard += 1;
      if (guard % 25 === 0 && performance.now() - startedAt > SAFE_REGEX_TIME_BUDGET_MS) {
        return `Custom RegExp aborted: exceeded ${SAFE_REGEX_TIME_BUDGET_MS}ms ReDoS execution budget.`;
      }
      if (m[0].length === 0) {
        customRegex.lastIndex += 1;
        continue;
      }
      rawMatches.push({
        category: 'CUSTOM',
        value: m[0],
        normalizedKey: normalizeEntityKey('CUSTOM', m[0]),
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

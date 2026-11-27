import pkg from 'google-libphonenumber';

const { PhoneNumberFormat, PhoneNumberUtil } = pkg;
const phoneUtil = PhoneNumberUtil.getInstance();

/**
 * Computes the Luhn Mod-10 check digit (0-9) for an incomplete card payload prefix.
 */
export function calculateLuhnCheckDigit(prefixDigits: string): number {
  let sum = 0;
  let shouldDouble = true;
  for (let i = prefixDigits.length - 1; i >= 0; i--) {
    let digit = prefixDigits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return (10 - (sum % 10)) % 10;
}

/**
 * Validates a payment card digit sequence using the Luhn (Mod-10) algorithm.
 * Rejects sequences shorter than 13 digits, longer than 19 digits,
 * and trivial repeated-digit strings.
 */
export function isValidLuhn(rawValue: string): boolean {
  const digits = rawValue.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }
  if (/^(\d)\1+$/.test(digits)) {
    return false;
  }

  let sum = 0;
  let shouldDouble = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

/**
 * Identifies common payment card networks from leading IIN/BIN digits.
 */
export function detectCardNetwork(rawValue: string): string | null {
  const d = rawValue.replace(/\D/g, '');
  if (/^4/.test(d)) return 'Visa';
  if (/^(5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)/.test(d)) return 'Mastercard';
  if (/^3[47]/.test(d) && d.length === 15) return 'Amex';
  if (/^(30[0-5]|36|38)/.test(d) && d.length === 14) return 'Diners Club';
  if (/^(60|6521|6522|81|82|508)/.test(d)) return 'RuPay';
  if (/^(6011|65|64[4-9])/.test(d)) return 'Discover';
  return null;
}

const VERHOEFF_D: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/**
 * Validates a 12-digit Indian Aadhaar number using UIDAI Verhoeff checksum and leading-digit policy.
 */
export function isValidVerhoeff(rawValue: string): boolean {
  const digits = rawValue.replace(/\D/g, '');
  if (!/^[2-9]\d{11}$/.test(digits) || /^(\d)\1+$/.test(digits)) {
    return false;
  }

  let checksum = 0;
  const len = digits.length;
  for (let i = 0; i < len; i++) {
    const digit = digits.charCodeAt(len - 1 - i) - 48;
    const permRow = VERHOEFF_P[i % 8];
    const permDigit = permRow?.[digit];
    const dRow = VERHOEFF_D[checksum];
    if (permDigit === undefined || dRow === undefined) return false;
    const nextChecksum = dRow[permDigit];
    if (nextChecksum === undefined) return false;
    checksum = nextChecksum;
  }
  return checksum === 0;
}

const PAN_ENTITY_MAP: Record<string, string> = {
  P: 'Individual',
  C: 'Company',
  H: 'HUF',
  F: 'Firm',
  A: 'AOP',
  T: 'Trust',
  B: 'BOI',
  L: 'Local Authority',
  J: 'Artificial Juridical Person',
  G: 'Government',
};

/**
 * Checks whether the 4th PAN character matches an official Income Tax holder classification.
 */
export function hasValidPanEntityCode(pan: string): boolean {
  return Boolean(PAN_ENTITY_MAP[pan.charAt(3).toUpperCase()]);
}

/**
 * Returns a human-readable PAN holder description from its 4th character code.
 */
export function describePanEntity(pan: string): string {
  const holder = PAN_ENTITY_MAP[pan.charAt(3).toUpperCase()];
  return holder ? `PAN (${holder})` : 'PAN (Unverified Holder Type)';
}

/**
 * Validates email structure rejecting consecutive dots or invalid TLD boundaries.
 */
export function isValidEmailStrict(email: string): boolean {
  if (email.includes('..')) return false;
  const [local, domain] = email.split('@');
  if (!local || !domain) return false;
  if (local.startsWith('.') || local.endsWith('.')) return false;
  if (domain.startsWith('.') || domain.startsWith('-') || domain.endsWith('-')) return false;
  return true;
}

/**
 * Validates IPv4 octets are strictly 0..255 with no octal leading zeros.
 */
export function isValidIPv4(candidate: string): boolean {
  const parts = candidate.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
}

function convertTrailingIPv4ToHextets(segments: string[]): string[] | null {
  const last = segments[segments.length - 1];
  if (!last || !last.includes('.')) {
    return [];
  }
  segments.pop();
  if (!isValidIPv4(last)) return null;
  const [a = 0, b = 0, c = 0, d = 0] = last.split('.').map(Number);
  return [((a << 8) | b).toString(16), ((c << 8) | d).toString(16)];
}

function parseExpandedIPv6Groups(rawCandidate: string): string[] | null {
  const withoutZone = rawCandidate.split('%')[0];
  if (!withoutZone || !withoutZone.includes(':')) return null;

  const parts = withoutZone.split('::');
  if (parts.length > 2) return null;

  const isCompressed = parts.length === 2;
  const left = parts[0] ? parts[0].split(':') : [];
  const right = isCompressed && parts[1] ? parts[1].split(':') : [];

  const tailTarget = right.length > 0 ? right : !isCompressed ? left : [];
  const ipv4Tail = convertTrailingIPv4ToHextets(tailTarget);
  if (ipv4Tail === null) return null;

  const hexGroup = /^[0-9a-fA-F]{1,4}$/;
  if (!left.every((g) => hexGroup.test(g)) || !right.every((g) => hexGroup.test(g))) {
    return null;
  }

  const fixedCount = left.length + right.length + ipv4Tail.length;
  if (isCompressed) {
    if (fixedCount > 7) return null;
    const missing = Array<string>(8 - fixedCount).fill('0000');
    return [...left, ...missing, ...right, ...ipv4Tail].map((g) => g.padStart(4, '0').toLowerCase());
  }

  if (fixedCount !== 8) return null;
  return [...left, ...ipv4Tail].map((g) => g.padStart(4, '0').toLowerCase());
}

/**
 * Validates strict IPv6 addresses including ::1, ::, ::ffff:192.0.2.1, and zone IDs,
 * while rejecting timestamps (10:24:19) and MAC addresses.
 */
export function isValidIPv6(candidate: string): boolean {
  return parseExpandedIPv6Groups(candidate) !== null;
}

/**
 * Normalizes IPv6 variants (e.g. 2001:db8::1 == 2001:0db8:0:0::1) to canonical 8-hextet form.
 */
export function canonicalizeIPv6(candidate: string): string {
  const groups = parseExpandedIPv6Groups(candidate);
  return groups ? groups.join(':') : candidate.trim().toLowerCase();
}

export interface ValidatedPhone {
  e164: string;
  coreText: string;
  extension: string | null;
  metadata: string;
  validatedBy: 'LIBPHONENUMBER' | 'FORMAT';
}

/**
 * Strips trailing phone extension before validation and masking.
 */
export function splitPhoneExtension(raw: string): { core: string; extension: string | null } {
  const extMatch = raw.match(/^(.*?)\s*(?:x|ext\.?)\s*(\d{2,5})$/i);
  if (extMatch && extMatch[1] !== undefined) {
    return { core: extMatch[1].trim(), extension: extMatch[2] ?? null };
  }
  return { core: raw.trim(), extension: null };
}

const MAX_PHONE_CACHE = 512;
const phoneValidationCache = new Map<string, ValidatedPhone | null>();

function tryParseLibPhoneNumber(core: string, extension: string | null): ValidatedPhone | null {
  const regionsToTry = core.startsWith('+') ? [undefined] : ['IN', 'US', 'GB'];
  for (const region of regionsToTry) {
    try {
      const parsed = phoneUtil.parse(core, region);
      if (phoneUtil.isValidNumber(parsed)) {
        const e164 = phoneUtil.format(parsed, PhoneNumberFormat.E164);
        const rc = phoneUtil.getRegionCodeForNumber(parsed) || 'INTL';
        return {
          e164,
          coreText: core,
          extension,
          metadata: `${rc} Phone (Google libphonenumber)`,
          validatedBy: 'LIBPHONENUMBER',
        };
      }
    } catch {
      // Try next fallback region
    }
  }
  return null;
}

/**
 * Validates phone numbers using Google's libphonenumber (with FIFO-bounded memoization & toll-free fallback).
 */
export function validatePhoneWithGoogleLib(rawValue: string): ValidatedPhone | null {
  const cached = phoneValidationCache.get(rawValue);
  if (cached !== undefined) return cached;

  const { core, extension } = splitPhoneExtension(rawValue);
  const digitsOnly = core.replace(/\D/g, '');
  let result: ValidatedPhone | null = null;

  if (/^(?:1800|1[-.\s]?800)/.test(core) && (digitsOnly.length === 10 || digitsOnly.length === 11)) {
    result = {
      e164: `+${digitsOnly}`,
      coreText: core,
      extension,
      metadata: 'Toll-Free Number',
      validatedBy: 'FORMAT',
    };
  } else {
    result = tryParseLibPhoneNumber(core, extension);
    if (!result && /^0[1-9]\d{1,3}[\s.-]?\d{6,8}$/.test(core) && digitsOnly.length >= 10 && digitsOnly.length <= 11) {
      result = {
        e164: `+91${digitsOnly.replace(/^0/, '')}`,
        coreText: core,
        extension,
        metadata: 'IN STD Landline',
        validatedBy: 'FORMAT',
      };
    }
  }

  if (phoneValidationCache.size >= MAX_PHONE_CACHE) {
    const oldestKey = phoneValidationCache.keys().next().value;
    if (oldestKey !== undefined) phoneValidationCache.delete(oldestKey);
  }
  phoneValidationCache.set(rawValue, result);
  return result;
}

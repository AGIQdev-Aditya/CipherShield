/**
 * Validates a payment card digit sequence using the Luhn (Mod-10) algorithm.
 * Rejects sequences shorter than 13 digits, longer than 19 digits,
 * and trivial repeated-digit strings (e.g., 0000...0000).
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
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

/**
 * Identifies common payment card networks from leading IIN/BIN digits.
 */
export function detectCardNetwork(rawValue: string): string {
  const d = rawValue.replace(/\D/g, '');
  if (/^4/.test(d)) return 'Visa';
  if (/^(5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)/.test(d)) return 'Mastercard';
  if (/^3[47]/.test(d)) return 'Amex';
  if (/^(6011|65|64[4-9])/.test(d)) return 'Discover/RuPay';
  if (/^(60|6521|6522|81|82|508)/.test(d)) return 'RuPay';
  return 'Payment Card';
}

// UIDAI Verhoeff multiplication, permutation, and inverse tables
const VERHOEFF_D: readonly number[][] = [
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

const VERHOEFF_P: readonly number[][] = [
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
 * Validates a 12-digit Indian Aadhaar number using UIDAI Verhoeff checksum.
 */
export function isValidVerhoeff(rawValue: string): boolean {
  const digits = rawValue.replace(/\D/g, '');
  if (!/^[2-9]\d{11}$/.test(digits)) {
    return false;
  }

  let checksum = 0;
  const len = digits.length;
  for (let i = 0; i < len; i++) {
    const digit = digits.charCodeAt(len - 1 - i) - 48;
    checksum = VERHOEFF_D[checksum][VERHOEFF_P[i % 8][digit]];
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

export function describePanEntity(pan: string): string {
  const code = pan.charAt(3).toUpperCase();
  return PAN_ENTITY_MAP[code] ? `PAN (${PAN_ENTITY_MAP[code]})` : 'Indian PAN';
}

/**
 * Validates strict IPv6 format (including :: compression) while rejecting timestamps like 10:24:19.
 */
export function isValidIPv6(candidate: string): boolean {
  if (!candidate.includes(':')) return false;
  const doubleColonParts = candidate.split('::');
  if (doubleColonParts.length > 2) return false;

  const isCompressed = doubleColonParts.length === 2;
  const leftGroups = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
  const rightGroups = isCompressed && doubleColonParts[1] ? doubleColonParts[1].split(':') : [];
  const totalGroups = leftGroups.length + rightGroups.length;

  if (isCompressed) {
    if (totalGroups > 7) return false;
  } else {
    if (totalGroups !== 8) return false;
  }

  const hexGroup = /^[0-9a-fA-F]{1,4}$/;
  return [...leftGroups, ...rightGroups].every((g) => hexGroup.test(g));
}

/**
 * Validates IPv4 octets are strictly 0..255.
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

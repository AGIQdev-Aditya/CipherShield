import { DetectionOptions, PiiCategory, RiskSummary } from '../types/pii';
import { canonicalizeIPv6 } from './validators';

/**
 * Default client-side detection configuration enforcing strict UIDAI Verhoeff validation.
 */
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

/** Overlap resolution precedence: EMAIL > UPI > CREDIT_CARD > IP_ADDRESS > AADHAAR > PAN > PHONE > CUSTOM. */
export const CATEGORY_PRIORITY: Record<PiiCategory, number> = {
  EMAIL: 8,
  UPI_ID: 7,
  CREDIT_CARD: 6,
  IP_ADDRESS: 5,
  AADHAAR: 4,
  PAN: 3,
  PHONE: 2,
  CUSTOM: 1,
};

export const CATEGORY_RISK_WEIGHT: Record<PiiCategory, number> = {
  CREDIT_CARD: 25,
  AADHAAR: 22,
  PAN: 18,
  UPI_ID: 14,
  PHONE: 10,
  EMAIL: 8,
  IP_ADDRESS: 6,
  CUSTOM: 12,
};

// Horizontal whitespace prevents regex bleeding across separate log records
export const REGEX_EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
export const REGEX_UPI =
  /\b[A-Za-z0-9._-]{2,64}@(?:ok(?:hdfcbank|icici|sbi|axis)|ybl|ibl|axl|apl|paytm|upi|freecharge|jupiteraxis|fam|razorpay)\b(?!\.[A-Za-z])/gi;
export const REGEX_PAN = /(?<![A-Za-z0-9])[A-Za-z]{5}[0-9]{4}[A-Za-z](?![A-Za-z0-9])/g;
export const REGEX_AADHAAR = /(?<![\d-])[2-9]\d{3}(?:[ \t\u00A0-]?\d{4}){2}(?![\d-])/g;
export const REGEX_CARD_FORMATTED =
  /(?<![\d.])(?:\d{4}(?:[- \t.\u00A0]\d{4}){2}[- \t.\u00A0]\d{1,4}(?:[- \t.\u00A0]\d{1,3})?|\d{4}[ \t-]\d{6}[ \t-]\d{5}|\d{4}[ \t-]\d{6}[ \t-]\d{4})(?![\d.])/g;
export const REGEX_CARD_CONTIGUOUS = /(?<![\d.])\d{13,19}(?![\d.])/g;
export const REGEX_IPV4 =
  /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)/g;
export const REGEX_IPV6 =
  /(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{1,4}|:)(?:%[A-Za-z0-9._-]+)?(?![\w:.])/g;
export const REGEX_PHONE_CANDIDATE =
  /(?<![\d\w.-])(?:\+91[ \t.-]?(?:[6-9]\d{4}[ \t.-]?\d{5}|[6-9]\d{3}[ \t.-]?\d{3}[ \t.-]?\d{3}|[1-9]\d{1,3}[ \t.-]?\d{6,8})|0?[6-9]\d{9}|[6-9]\d{4}[ \t.-]\d{5}|0[1-9]\d{1,3}[ \t.-]\d{6,8}|1[ \t.-]?800[ \t.-]?\d{3,4}[ \t.-]?\d{4}|(?:\+\d{1,3}[ \t.-]?)?\(?\d{2,4}\)?[ \t.-]\d{2,4}[ \t.-]\d{4}(?:[ \t.-]\d{2,4})?)(?:[ \t]*(?:x|ext\.?)[ \t]*\d{2,5})?(?![\d\w-])/gi;

/**
 * Normalizes entity values across equivalent formatting or case variants for deduplicated pseudonym mapping.
 */
export function normalizeEntityKey(
  category: PiiCategory,
  value: string,
  precomputedPhoneE164?: string,
): string {
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

/**
 * Computes exposure risk score (0-100) and qualitative tier from category entity counts.
 */
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

import { PiiCategory, RedactionMode } from '../types/pii';

export const CATEGORY_META: Record<PiiCategory, { label: string; hint: string }> = {
  EMAIL: { label: 'Emails', hint: 'RFC email patterns' },
  PHONE: { label: 'Phones', hint: '+91 / E.164 / local' },
  IP_ADDRESS: { label: 'IP Addresses', hint: 'Strict IPv4 & IPv6' },
  PAN: { label: 'Indian PAN', hint: 'ABCDE1234F format' },
  AADHAAR: { label: 'Aadhaar', hint: '12-digit / Verhoeff' },
  CREDIT_CARD: { label: 'Credit Cards', hint: 'Luhn Mod-10 verified' },
  CUSTOM: { label: 'Custom Rule', hint: 'User regex pattern' },
};

export const GOOGLE_DLP_INFOTYPE_MAP: Record<PiiCategory, string> = {
  EMAIL: 'EMAIL_ADDRESS',
  PHONE: 'PHONE_NUMBER',
  IP_ADDRESS: 'IP_ADDRESS',
  PAN: 'INDIA_PAN_INDIVIDUAL',
  AADHAAR: 'INDIA_AADHAAR_INDIVIDUAL',
  CREDIT_CARD: 'CREDIT_CARD_NUMBER',
  CUSTOM: 'CUSTOM_REGEX_ENTITY',
};

export const MODE_OPTIONS: { id: RedactionMode; label: string; summary: string }[] = [
  { id: 'full', label: 'Full Mask', summary: 'Replace entities with [REDACTED] blocks' },
  { id: 'partial', label: 'Partial Mask', summary: 'Retain last-4 / domain verification hint' },
  { id: 'pseudonymize', label: 'Consistent Pseudonymization', summary: 'Map recurring PII to stable USER_01 tokens' },
];

/**
 * Generates a Google Cloud DLP InspectConfig-compatible manifest matching detected categories.
 */
export function buildCloudDlpSummary(counts: Record<PiiCategory, number>) {
  return (Object.keys(counts) as PiiCategory[])
    .filter((cat) => counts[cat] > 0)
    .map((category) => ({
      category,
      googleCloudDlpInfoType: GOOGLE_DLP_INFOTYPE_MAP[category],
      minLikelihood: category === 'CREDIT_CARD' || category === 'EMAIL' ? 'VERY_LIKELY' : 'LIKELY',
      count: counts[category],
    }));
}

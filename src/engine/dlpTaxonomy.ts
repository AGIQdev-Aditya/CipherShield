import { PiiCategory, RedactionMode } from '../types/pii';

export const CATEGORY_META: Record<PiiCategory, { label: string; hint: string }> = {
  EMAIL: { label: 'Emails', hint: 'Strict email validator' },
  PHONE: { label: 'Phones', hint: 'Google libphonenumber' },
  IP_ADDRESS: { label: 'IP Addresses', hint: 'Strict IPv4 & IPv6' },
  PAN: { label: 'Indian PAN', hint: 'Case-insensitive + type' },
  AADHAAR: { label: 'Aadhaar', hint: 'Verhoeff / UIDAI 12d' },
  CREDIT_CARD: { label: 'Credit Cards', hint: 'Luhn + network IIN' },
  UPI_ID: { label: 'UPI VPA', hint: 'PSP handle whitelist' },
  CUSTOM: { label: 'Custom Rule', hint: 'User regex pattern' },
};

export const GOOGLE_DLP_INFOTYPE_MAP: Record<PiiCategory, string> = {
  EMAIL: 'EMAIL_ADDRESS',
  PHONE: 'PHONE_NUMBER',
  IP_ADDRESS: 'IP_ADDRESS',
  PAN: 'INDIA_PAN_INDIVIDUAL',
  AADHAAR: 'INDIA_AADHAAR_INDIVIDUAL',
  CREDIT_CARD: 'CREDIT_CARD_NUMBER',
  UPI_ID: 'INDIA_UPI_VPA',
  CUSTOM: 'CUSTOM_REGEX_ENTITY',
};

export const MODE_OPTIONS: { id: RedactionMode; label: string; summary: string }[] = [
  { id: 'full', label: 'Full Mask', summary: 'Replace entities with [REDACTED] blocks' },
  { id: 'partial', label: 'Partial Mask', summary: 'Retain safe verification context' },
  { id: 'pseudonymize', label: 'Consistent Pseudonymization', summary: 'Map recurring PII to stable USER_01 tokens' },
];

/**
 * Generates an official Google Cloud Sensitive Data Protection (DLP v2) compatible
 * InspectConfig + DeidentifyConfig JSON template strictly from anonymized category counts.
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

export function buildCloudDlpDeidentifyConfig(counts: Record<PiiCategory, number>, mode: RedactionMode) {
  const activeInfoTypes = (Object.keys(counts) as PiiCategory[])
    .filter((cat) => counts[cat] > 0)
    .map((cat) => ({ name: GOOGLE_DLP_INFOTYPE_MAP[cat] }));

  return {
    schema: 'google.privacy.dlp.v2.DeidentifyConfig',
    inspectConfig: {
      infoTypes: activeInfoTypes,
      minLikelihood: 'LIKELY',
    },
    infoTypeTransformations: {
      transformations: [
        {
          infoTypes: activeInfoTypes,
          primitiveTransformation:
            mode === 'partial'
              ? {
                  characterMaskConfig: {
                    maskingCharacter: 'X',
                    charactersToIgnore: [{ charactersToSkip: '-@.' }],
                  },
                }
              : {
                  replaceWithInfoTypeConfig: {},
                },
        },
      ],
    },
  };
}

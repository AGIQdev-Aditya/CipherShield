import {
  DetectionOptions,
  DiffSegment,
  PiiCategory,
  PiiEntity,
  PseudonymMapping,
  RedactionMode,
  RedactionResult,
} from '../types/pii';
import { DEFAULT_DETECTION_OPTIONS, scanTextForPii } from './scanner';

const PSEUDONYM_PREFIX: Record<PiiCategory, string> = {
  EMAIL: 'USER',
  PHONE: 'PHONE',
  IP_ADDRESS: 'IP',
  PAN: 'PAN',
  AADHAAR: 'AADHAAR',
  CREDIT_CARD: 'CARD',
  CUSTOM: 'CUSTOM',
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

function partialMaskValue(entity: PiiEntity): string {
  const { category, value } = entity;

  switch (category) {
    case 'CREDIT_CARD': {
      const digits = value.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      const separator = value.includes('-') ? '-' : value.includes(' ') ? ' ' : '-';
      return `XXXX${separator}XXXX${separator}XXXX${separator}${last4}`;
    }

    case 'AADHAAR': {
      const digits = value.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      const sep = value.includes('-') ? '-' : ' ';
      return `XXXX${sep}XXXX${sep}${last4}`;
    }

    case 'EMAIL': {
      const [local, domain] = value.split('@');
      if (!domain) return '[REDACTED]';
      const head = local.length > 1 ? local[0] : '*';
      return `${head}***@${domain}`;
    }

    case 'PHONE': {
      const trimmed = value.trim();
      const digits = trimmed.replace(/\D/g, '');
      const last4 = digits.slice(-4);
      if (trimmed.startsWith('+91')) {
        return `+91 XXXXXX${last4}`;
      }
      return `XXXXXX${last4}`;
    }

    case 'PAN':
      return `${value.slice(0, 2)}XXX${value.slice(5, 9)}X`;

    case 'IP_ADDRESS': {
      if (value.includes(':')) {
        const head = value.split(':').slice(0, 2).join(':');
        return `${head}:XXXX::XXXX`;
      }
      const octets = value.split('.');
      return `${octets[0]}.${octets[1]}.XXX.XXX`;
    }

    case 'CUSTOM':
      return value.length > 3 ? `${value.slice(0, 2)}***${value.slice(-1)}` : '***';
  }
}

function fullMaskValue(entity: PiiEntity, template: 'generic' | 'typed'): string {
  if (template === 'typed') {
    return `[${entity.category}_REDACTED]`;
  }
  return '[REDACTED]';
}

/**
 * Redacts detected PII entities in a single deterministic pass and builds
 * synchronized side-by-side diff segments without writing raw HTML.
 */
export function redactText(
  text: string,
  mode: RedactionMode,
  options: DetectionOptions = DEFAULT_DETECTION_OPTIONS,
): RedactionResult {
  const scan = scanTextForPii(text, options);
  const { entities } = scan;

  const categoryCounters: Record<PiiCategory, number> = {
    EMAIL: 0,
    PHONE: 0,
    IP_ADDRESS: 0,
    PAN: 0,
    AADHAAR: 0,
    CREDIT_CARD: 0,
    CUSTOM: 0,
  };

  const tokenLedger = new Map<string, PseudonymMapping>();
  const originalSegments: DiffSegment[] = [];
  const sanitizedSegments: DiffSegment[] = [];
  let cursor = 0;
  let sanitizedOutput = '';

  for (const entity of entities) {
    if (entity.start > cursor) {
      const unchanged = text.slice(cursor, entity.start);
      originalSegments.push({ text: unchanged });
      sanitizedSegments.push({ text: unchanged });
      sanitizedOutput += unchanged;
    }

    const ledgerKey = `${entity.category}:${entity.normalizedKey}`;
    let existingMapping = tokenLedger.get(ledgerKey);

    if (!existingMapping) {
      categoryCounters[entity.category] += 1;
      const serial = String(categoryCounters[entity.category]).padStart(2, '0');
      const customPrefix =
        entity.category === 'CUSTOM' && options.customRule.label.trim()
          ? options.customRule.label.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_')
          : PSEUDONYM_PREFIX[entity.category];

      existingMapping = {
        token: `${customPrefix}_${serial}`,
        category: entity.category,
        normalizedKey: entity.normalizedKey,
        sampleValue: entity.value,
        occurrences: 0,
      };
      tokenLedger.set(ledgerKey, existingMapping);
    }
    existingMapping.occurrences += 1;

    let replacement: string;
    if (mode === 'full') {
      replacement = fullMaskValue(entity, options.fullMaskTemplate);
    } else if (mode === 'partial') {
      replacement = partialMaskValue(entity);
    } else {
      replacement = existingMapping.token;
    }

    originalSegments.push({ text: entity.value, entity, replacement });
    sanitizedSegments.push({ text: replacement, entity, replacement });
    sanitizedOutput += replacement;
    cursor = entity.end;
  }

  if (cursor < text.length) {
    const tail = text.slice(cursor);
    originalSegments.push({ text: tail });
    sanitizedSegments.push({ text: tail });
    sanitizedOutput += tail;
  }

  return {
    sanitizedText: sanitizedOutput,
    originalSegments,
    sanitizedSegments,
    mappings: Array.from(tokenLedger.values()),
    scan,
  };
}

/**
 * Computes a SHA-256 hex digest using the browser Web Crypto API for tamper-evident audit logs.
 */
export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

import {
  DetectionOptions,
  DiffSegment,
  PiiCategory,
  PiiEntity,
  PseudonymMapping,
  RedactionMode,
  RedactionResult,
} from '../types/pii';
import { calculateRiskScore, DEFAULT_DETECTION_OPTIONS, scanTextForPii } from './scanner';
import { splitPhoneExtension } from './validators';

const PSEUDONYM_PREFIX: Record<PiiCategory, string> = {
  EMAIL: 'USER',
  PHONE: 'PHONE',
  IP_ADDRESS: 'IP',
  PAN: 'PAN',
  AADHAAR: 'AADHAAR',
  CREDIT_CARD: 'CARD',
  UPI_ID: 'UPI',
  CUSTOM: 'CUSTOM',
};

export interface SharedPseudonymSession {
  ledger: Map<string, PseudonymMapping>;
  counters: Record<PiiCategory, number>;
}

/**
 * Creates an isolated volatile pseudonym ledger spanning either one document or all cells of a CSV.
 */
export function createPseudonymSession(): SharedPseudonymSession {
  return {
    ledger: new Map<string, PseudonymMapping>(),
    counters: {
      EMAIL: 0,
      PHONE: 0,
      IP_ADDRESS: 0,
      PAN: 0,
      AADHAAR: 0,
      CREDIT_CARD: 0,
      UPI_ID: 0,
      CUSTOM: 0,
    },
  };
}

function maskEmailHandle(value: string): string {
  const [local = '', domain] = value.split('@');
  if (!domain) return '[REDACTED]';
  const head = local.length > 1 ? local.charAt(0) : '*';
  return `${head}***@${domain}`;
}

function maskIpValue(value: string): string {
  if (value.includes(':')) {
    const head = value.split(':').slice(0, 2).join(':') || '::';
    return `${head}:XXXX::XXXX`;
  }
  const [a = 'XXX', b = 'XXX'] = value.split('.');
  return `${a}.${b}.XXX.XXX`;
}

function maskPhoneValue(value: string): string {
  const { core } = splitPhoneExtension(value);
  const last4 = core.replace(/\D/g, '').slice(-4);
  return core.startsWith('+91') ? `+91 XXXXXX${last4}` : `XXXXXX${last4}`;
}

function maskAadhaarValue(value: string): string {
  const digits = value.replace(/\D/g, '');
  const sep = value.includes('-') ? '-' : ' ';
  return `XXXX${sep}XXXX${sep}${digits.slice(-4)}`;
}

function partialMaskValue(entity: PiiEntity): string {
  const { category, value } = entity;
  switch (category) {
    case 'CREDIT_CARD':
      return value.replace(/\d(?=(?:\D*\d){4})/g, 'X');
    case 'AADHAAR':
      return maskAadhaarValue(value);
    case 'EMAIL':
    case 'UPI_ID':
      return maskEmailHandle(value);
    case 'PHONE':
      return maskPhoneValue(value);
    case 'PAN':
      return `${value.charAt(0).toUpperCase()}****${value.slice(5, 9)}${value.charAt(9).toUpperCase()}`;
    case 'IP_ADDRESS':
      return maskIpValue(value);
    case 'CUSTOM':
      return value.length > 3 ? `${value.slice(0, 2)}***${value.slice(-1)}` : '***';
  }
}

function assignPseudonymMapping(
  session: SharedPseudonymSession,
  entity: PiiEntity,
  customLabel: string,
): PseudonymMapping {
  const ledgerKey = `${entity.category}:${entity.normalizedKey}`;
  let mapping = session.ledger.get(ledgerKey);

  if (!mapping) {
    session.counters[entity.category] += 1;
    const serial = String(session.counters[entity.category]).padStart(2, '0');
    const sanitizedCustom = customLabel.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
    const prefix = entity.category === 'CUSTOM' && sanitizedCustom ? sanitizedCustom : PSEUDONYM_PREFIX[entity.category];

    mapping = {
      token: `${prefix}_${serial}`,
      category: entity.category,
      normalizedKey: entity.normalizedKey,
      sampleValue: entity.value,
      occurrences: 0,
    };
    session.ledger.set(ledgerKey, mapping);
  }

  mapping.occurrences += 1;
  return mapping;
}

function resolveReplacement(
  entity: PiiEntity,
  mode: RedactionMode,
  options: DetectionOptions,
  token: string,
): string {
  if (mode === 'full') {
    return options.fullMaskTemplate === 'typed' ? `[${entity.category}_REDACTED]` : '[REDACTED]';
  }
  return mode === 'partial' ? partialMaskValue(entity) : token;
}

/**
 * Redacts detected PII entities in a single deterministic forward pass and re-scans output
 * to verify true post-redaction residual exposure.
 */
export function redactText(
  text: string,
  mode: RedactionMode,
  options: DetectionOptions = DEFAULT_DETECTION_OPTIONS,
  sharedSession?: SharedPseudonymSession,
  skipPostScan = false,
): RedactionResult {
  const scan = scanTextForPii(text, options, true);
  const { entities } = scan;

  const session = sharedSession ?? createPseudonymSession();
  const originalSegments: DiffSegment[] = [];
  const sanitizedSegments: DiffSegment[] = [];
  const outputChunks: string[] = [];
  let cursor = 0;

  for (const entity of entities) {
    if (entity.start > cursor) {
      const unchanged = text.slice(cursor, entity.start);
      originalSegments.push({ text: unchanged });
      sanitizedSegments.push({ text: unchanged });
      outputChunks.push(unchanged);
    }

    const mapping = assignPseudonymMapping(session, entity, options.customRule.label);
    const replacement = resolveReplacement(entity, mode, options, mapping.token);

    originalSegments.push({ text: entity.value, entity, replacement });
    sanitizedSegments.push({ text: replacement, entity, replacement });
    outputChunks.push(replacement);
    cursor = entity.end;
  }

  if (cursor < text.length) {
    const tail = text.slice(cursor);
    originalSegments.push({ text: tail });
    sanitizedSegments.push({ text: tail });
    outputChunks.push(tail);
  }

  const sanitizedText = outputChunks.join('');
  const postScan = skipPostScan || entities.length === 0 ? null : scanTextForPii(sanitizedText, options, true);
  const afterRisk = postScan ? calculateRiskScore(postScan.counts) : { score: 0, level: 'NONE' as const };

  return {
    sanitizedText,
    originalSegments,
    sanitizedSegments,
    mappings: Array.from(session.ledger.values()),
    scan: {
      ...scan,
      risk: {
        ...scan.risk,
        scoreAfter: afterRisk.score,
        levelAfter: afterRisk.level,
        residualCount: postScan ? postScan.totalDetected : 0,
      },
    },
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

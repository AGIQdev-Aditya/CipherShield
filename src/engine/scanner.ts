import { DetectionOptions, PiiCategory, PiiEntity, RejectedCandidate, ScanResult } from '../types/pii';
import {
  collectAadhaarMatches,
  collectCardMatches,
  collectCustomRuleMatches,
  collectIpMatches,
  collectPanMatches,
  collectPatternMatches,
  collectPhoneMatches,
  RawMatch,
  TextSpan,
} from './collectors';
import {
  calculateRiskScore,
  CATEGORY_PRIORITY,
  DEFAULT_DETECTION_OPTIONS,
  REGEX_EMAIL,
  REGEX_UPI,
} from './patterns';
import { hasUnsafeRegexConstruct } from './regexSafety';
import { isValidEmailStrict } from './validators';

export { calculateRiskScore, DEFAULT_DETECTION_OPTIONS, hasUnsafeRegexConstruct };

function createEmptyCounts(): Record<PiiCategory, number> {
  return {
    EMAIL: 0,
    PHONE: 0,
    IP_ADDRESS: 0,
    PAN: 0,
    AADHAAR: 0,
    CREDIT_CARD: 0,
    UPI_ID: 0,
    CUSTOM: 0,
  };
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

  nonAllowlisted.sort((a, b) => {
    const prioDiff = CATEGORY_PRIORITY[b.category] - CATEGORY_PRIORITY[a.category];
    if (prioDiff !== 0) return prioDiff;
    const lenDiff = b.end - b.start - (a.end - a.start);
    return lenDiff !== 0 ? lenDiff : a.start - b.start;
  });

  // Linear Uint8Array bitmap avoids O(N^2) interval overlap scans on multi-MB logs
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
  return {
    entities: accepted.map((item, idx) => ({ ...item, id: `pii-${idx + 1}` })),
    allowlistedCount,
  };
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
  if (enabled.EMAIL) {
    collectPatternMatches(text, REGEX_EMAIL, 'EMAIL', 'Email Address', 'RFC', rawMatches, isValidEmailStrict);
  }
  if (enabled.UPI_ID) collectPatternMatches(text, REGEX_UPI, 'UPI_ID', 'Indian UPI Handle', 'FORMAT', rawMatches);
  if (enabled.IP_ADDRESS) collectIpMatches(text, rawMatches);
  if (enabled.AADHAAR) collectAadhaarMatches(text, options, blockedSubSpans, rawMatches);
  if (enabled.PAN) collectPanMatches(text, rawMatches);
  if (enabled.PHONE) collectPhoneMatches(text, blockedSubSpans, rawMatches);

  const customRuleError = options.customRule.enabled ? collectCustomRuleMatches(text, options, rawMatches) : null;
  const { entities, allowlistedCount } = resolveNonOverlappingEntities(text.length, rawMatches, allowSet);

  const counts = createEmptyCounts();
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

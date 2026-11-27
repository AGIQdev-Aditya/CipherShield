import { parseCsvRows, redactCsvCells } from './csvParser';
import { redactText } from './redactor';
import { DEFAULT_DETECTION_OPTIONS, scanTextForPii } from './scanner';

export interface SelfTestCaseResult {
  id: string;
  title: string;
  passed: boolean;
  detail: string;
}

export interface SelfTestReport {
  passed: number;
  total: number;
  durationMs: number;
  cases: SelfTestCaseResult[];
}

/**
 * Runs 10 deterministic browser-side adversarial verification probes across
 * Luhn, IMEI rejection, Verhoeff UIDAI, PAN context, IPv6, UPI, libphonenumber, and RFC-4180 CSV.
 */
export function runAdversarialSelfTest(): SelfTestReport {
  const start = performance.now();
  const opts = DEFAULT_DETECTION_OPTIONS;
  const cases: SelfTestCaseResult[] = [];

  // 1. Luhn-valid Visa card vs 15-digit IMEI device ID
  const cardText = 'card 4539-1488-0343-6467 and imei 490154203237518';
  const cardScan = scanTextForPii(cardText, opts);
  const imeiRejected = cardScan.rejectedCards.some((r) => r.value === '490154203237518');
  cases.push({
    id: 'luhn-imei',
    title: 'Luhn + Card IIN vs. 15-digit IMEI Rejection',
    passed: cardScan.counts.CREDIT_CARD === 1 && imeiRejected,
    detail: `Cards=${cardScan.counts.CREDIT_CARD}, IMEI rejected=${imeiRejected}`,
  });

  // 2. Lowercase PAN with tax context vs ordinary alphanumeric token
  const panScan = scanTextForPii('pan: awfpd4412m ok, ignore order2024a', opts);
  cases.push({
    id: 'pan-context',
    title: 'Lowercase PAN Detection + False-Positive Guard',
    passed: panScan.counts.PAN === 1 && panScan.entities[0]?.value === 'awfpd4412m',
    detail: `Detected PAN count=${panScan.counts.PAN}`,
  });

  // 3. Aadhaar UIDAI Verhoeff validation discrimination (strict by default)
  const aadhaarScan = scanTextForPii('valid 2341 5678 9120 invalid 2341 5678 9121', opts);
  cases.push({
    id: 'verhoeff-uidai',
    title: 'Aadhaar Verhoeff Checksum Discrimination',
    passed: aadhaarScan.counts.AADHAAR === 1 && aadhaarScan.entities[0]?.value === '2341 5678 9120',
    detail: `Matched=${aadhaarScan.entities.map((e) => e.value).join(', ')}`,
  });

  // 4. IPv4-mapped IPv6 canonicalization (atomic, no split IPv4)
  const ipv6Scan = scanTextForPii('peer=::ffff:192.0.2.1', opts);
  cases.push({
    id: 'ipv4-mapped-v6',
    title: 'Atomic IPv4-Mapped IPv6 (::ffff:192.0.2.1)',
    passed: ipv6Scan.counts.IP_ADDRESS === 1 && ipv6Scan.entities[0]?.value === '::ffff:192.0.2.1',
    detail: `IP count=${ipv6Scan.counts.IP_ADDRESS}, value=${ipv6Scan.entities[0]?.value ?? 'none'}`,
  });

  // 5. Partial Amex 15-digit mask + non-redetectable PAN mask + 0/100 residual score
  const redactOut = redactText('amex 3782-822463-10005 pan: ABCDE1234F', 'partial', opts);
  const amexOk = redactOut.sanitizedText.includes('XXXX-XXXXXX-X0005');
  const panOk = redactOut.sanitizedText.includes('A****1234F');
  cases.push({
    id: 'partial-idempotent',
    title: 'Amex Format-Preserving Mask + Post-Redaction Residual Rescan',
    passed: amexOk && panOk && redactOut.scan.risk.scoreAfter === 0,
    detail: `scoreAfter=${redactOut.scan.risk.scoreAfter}, text="${redactOut.sanitizedText}"`,
  });

  // 6. UPI VPA vs Email separation
  const upiScan = scanTextForPii('pay to aarav.kulkarni@okaxis or mail admin@company.in', opts);
  cases.push({
    id: 'upi-vs-email',
    title: 'UPI Handle (@okaxis) vs. Email Separation',
    passed: upiScan.counts.UPI_ID === 1 && upiScan.counts.EMAIL === 1,
    detail: `UPI=${upiScan.counts.UPI_ID}, EMAIL=${upiScan.counts.EMAIL}`,
  });

  // 7. Indian 5+5 spaced mobile via google-libphonenumber
  const phoneScan = scanTextForPii('call 98765 43210 urgent', opts);
  cases.push({
    id: 'india-mobile-5x5',
    title: 'Indian 5+5 Mobile Format (libphonenumber)',
    passed: phoneScan.counts.PHONE === 1 && phoneScan.entities[0]?.validatedBy === 'LIBPHONENUMBER',
    detail: `Phones=${phoneScan.counts.PHONE}, validator=${phoneScan.entities[0]?.validatedBy ?? 'none'}`,
  });

  // 8. ReDoS guard on unsafe nested/backreference custom regexes
  const redosScan = scanTextForPii('hello world', {
    ...opts,
    customRule: { enabled: true, label: 'EVIL', pattern: '(?:[a-z]+\\s?)+$' },
  });
  cases.push({
    id: 'redos-guard',
    title: 'Custom Regex ReDoS Rejection Guard',
    passed: Boolean(redosScan.customRuleError),
    detail: redosScan.customRuleError ?? 'No error',
  });

  // 9. CSV formula injection neutralization (CWE-1236) + header redaction
  const csvParsed = parseCsvRows('owner_admin@corp.in,note\nrahul@corp.in,"=CMD()"\n');
  const csvRedacted = redactCsvCells(csvParsed, 'pseudonymize', opts, true);
  const formulaSafe = csvRedacted.serializedCsv.includes('"\'=CMD()"') || csvRedacted.serializedCsv.includes("'=CMD()");
  const headerSafe = !csvRedacted.serializedCsv.includes('owner_admin@corp.in');
  cases.push({
    id: 'csv-cwe1236',
    title: 'RFC-4180 CSV Header Redaction & CWE-1236 Formula Guard',
    passed: formulaSafe && headerSafe,
    detail: `headerSafe=${headerSafe}, formulaSafe=${formulaSafe}`,
  });

  // 10. Multi-line non-bleeding boundary across newlines
  const multiLineScan = scanTextForPii('phone +91\n9876543210', opts);
  cases.push({
    id: 'newline-isolation',
    title: 'Horizontal Whitespace Isolation Across Newlines',
    passed: multiLineScan.counts.PHONE === 1 && !multiLineScan.entities[0]?.value.includes('\n'),
    detail: `Matched="${multiLineScan.entities[0]?.value ?? ''}"`,
  });

  const passed = cases.filter((c) => c.passed).length;
  return {
    passed,
    total: cases.length,
    durationMs: Number((performance.now() - start).toFixed(2)),
    cases,
  };
}

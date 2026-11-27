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

function runFinancialAndIdentityProbes(): SelfTestCaseResult[] {
  const opts = DEFAULT_DETECTION_OPTIONS;
  const cardScan = scanTextForPii('card 4539-1488-0343-6467 and imei 490154203237518', opts);
  const imeiRejected = cardScan.rejectedCards.some((r) => r.value === '490154203237518');

  const panScan = scanTextForPii('pan: awfpd4412m ok, ignore order2024a', opts);
  const aadhaarScan = scanTextForPii('valid 2341 5678 9120 invalid 2341 5678 9121', opts);
  const ipv6Scan = scanTextForPii('peer=::ffff:192.0.2.1', opts);

  const redactOut = redactText('amex 3782-822463-10005 pan: ABCDE1234F', 'partial', opts);
  const partialOk =
    redactOut.sanitizedText.includes('XXXX-XXXXXX-X0005') &&
    redactOut.sanitizedText.includes('A****1234F') &&
    redactOut.scan.risk.scoreAfter === 0;

  return [
    {
      id: 'luhn-imei',
      title: 'Luhn + Card IIN vs. 15-digit IMEI Rejection',
      passed: cardScan.counts.CREDIT_CARD === 1 && imeiRejected,
      detail: `Cards=${cardScan.counts.CREDIT_CARD}, IMEI rejected=${imeiRejected}`,
    },
    {
      id: 'pan-context',
      title: 'Lowercase PAN Detection + False-Positive Guard',
      passed: panScan.counts.PAN === 1 && panScan.entities[0]?.value === 'awfpd4412m',
      detail: `Detected PAN count=${panScan.counts.PAN}`,
    },
    {
      id: 'verhoeff-uidai',
      title: 'Aadhaar Verhoeff Checksum Discrimination',
      passed: aadhaarScan.counts.AADHAAR === 1 && aadhaarScan.entities[0]?.value === '2341 5678 9120',
      detail: `Matched=${aadhaarScan.entities.map((e) => e.value).join(', ')}`,
    },
    {
      id: 'ipv4-mapped-v6',
      title: 'Atomic IPv4-Mapped IPv6 (::ffff:192.0.2.1)',
      passed: ipv6Scan.counts.IP_ADDRESS === 1 && ipv6Scan.entities[0]?.value === '::ffff:192.0.2.1',
      detail: `IP count=${ipv6Scan.counts.IP_ADDRESS}, value=${ipv6Scan.entities[0]?.value ?? 'none'}`,
    },
    {
      id: 'partial-idempotent',
      title: 'Amex Format-Preserving Mask + Post-Redaction Residual Rescan',
      passed: partialOk,
      detail: `scoreAfter=${redactOut.scan.risk.scoreAfter}, text="${redactOut.sanitizedText}"`,
    },
  ];
}

function runTelecomAndSecurityProbes(): SelfTestCaseResult[] {
  const opts = DEFAULT_DETECTION_OPTIONS;
  const upiScan = scanTextForPii('pay to aarav.kulkarni@okaxis or mail admin@company.in', opts);
  const phoneScan = scanTextForPii('call 98765 43210 urgent', opts);
  const redosScan = scanTextForPii('hello world', {
    ...opts,
    customRule: { enabled: true, label: 'EVIL', pattern: '(?:[a-z]+\\s?)+$' },
  });

  const csvParsed = parseCsvRows('owner_admin@corp.in,note\nrahul@corp.in,"=CMD()"\n');
  const csvRedacted = redactCsvCells(csvParsed, 'pseudonymize', opts, true);
  const formulaSafe = csvRedacted.serializedCsv.includes("'=CMD()");
  const headerSafe = !csvRedacted.serializedCsv.includes('owner_admin@corp.in');
  const multiLineScan = scanTextForPii('phone +91\n9876543210', opts);

  return [
    {
      id: 'upi-vs-email',
      title: 'UPI Handle (@okaxis) vs. Email Separation',
      passed: upiScan.counts.UPI_ID === 1 && upiScan.counts.EMAIL === 1,
      detail: `UPI=${upiScan.counts.UPI_ID}, EMAIL=${upiScan.counts.EMAIL}`,
    },
    {
      id: 'india-mobile-5x5',
      title: 'Indian 5+5 Mobile Format (libphonenumber)',
      passed: phoneScan.counts.PHONE === 1 && phoneScan.entities[0]?.validatedBy === 'LIBPHONENUMBER',
      detail: `Phones=${phoneScan.counts.PHONE}, validator=${phoneScan.entities[0]?.validatedBy ?? 'none'}`,
    },
    {
      id: 'redos-guard',
      title: 'Custom Regex ReDoS Rejection Guard',
      passed: Boolean(redosScan.customRuleError),
      detail: redosScan.customRuleError ?? 'No error',
    },
    {
      id: 'csv-cwe1236',
      title: 'RFC-4180 CSV Header Redaction & CWE-1236 Formula Guard',
      passed: formulaSafe && headerSafe,
      detail: `headerSafe=${headerSafe}, formulaSafe=${formulaSafe}`,
    },
    {
      id: 'newline-isolation',
      title: 'Horizontal Whitespace Isolation Across Newlines',
      passed: multiLineScan.counts.PHONE === 1 && !multiLineScan.entities[0]?.value.includes('\n'),
      detail: `Matched="${multiLineScan.entities[0]?.value ?? ''}"`,
    },
  ];
}

/**
 * Runs 10 deterministic browser-side adversarial verification probes across
 * Luhn, IMEI rejection, Verhoeff UIDAI, PAN context, IPv6, UPI, libphonenumber, ReDoS guard, and CSV safety.
 */
export function runAdversarialSelfTest(): SelfTestReport {
  const start = performance.now();
  const cases = [...runFinancialAndIdentityProbes(), ...runTelecomAndSecurityProbes()];
  const passed = cases.filter((c) => c.passed).length;

  return {
    passed,
    total: cases.length,
    durationMs: Number((performance.now() - start).toFixed(2)),
    cases,
  };
}

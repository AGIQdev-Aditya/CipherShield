import { describe, expect, it } from 'vitest';
import { isValidIPv4, isValidIPv6, isValidLuhn, isValidVerhoeff } from '../src/engine/validators';
import { DEFAULT_DETECTION_OPTIONS, scanTextForPii } from '../src/engine/scanner';
import { redactText } from '../src/engine/redactor';
import { buildCloudDlpSummary } from '../src/engine/dlpTaxonomy';
import { generateSyntheticChaosLog, SAMPLE_DATASETS } from '../src/engine/samples';
import { parseCsvRows, redactCsvCells, serializeCsvRows } from '../src/engine/csvParser';
import { decryptPseudonymLedger, encryptPseudonymLedger } from '../src/engine/cryptoVault';

describe('Luhn & Financial Validators', () => {
  it('validates standard Luhn credit card numbers', () => {
    expect(isValidLuhn('4532-0151-1283-0366')).toBe(true);
    expect(isValidLuhn('5425233430109903')).toBe(true);
    expect(isValidLuhn('4539148803436467')).toBe(true);
    expect(isValidLuhn('4916-4321-8765-4322')).toBe(true);
  });

  it('rejects random 16-digit non-Luhn numbers and trivial repeated zeros', () => {
    expect(isValidLuhn('4111-2222-3333-4444')).toBe(false);
    expect(isValidLuhn('1234-5678-9012-3456')).toBe(false);
    expect(isValidLuhn('0000-0000-0000-0000')).toBe(false);
    expect(isValidLuhn('12345')).toBe(false);
  });

  it('validates strict IPv4 octets and IPv6 addresses without timestamp false positives', () => {
    expect(isValidIPv4('192.168.1.254')).toBe(true);
    expect(isValidIPv4('10.0.0.1')).toBe(true);
    expect(isValidIPv4('256.100.1.1')).toBe(false);
    expect(isValidIPv4('01.100.1.1')).toBe(false);

    expect(isValidIPv6('2001:0db8:85a3::8a2e:0370:7334')).toBe(true);
    expect(isValidIPv6('fe80::1ff:fe23:4567:890a')).toBe(true);
    expect(isValidIPv6('10:24:19')).toBe(false);
  });

  it('validates UIDAI Verhoeff checksums for Aadhaar', () => {
    expect(isValidVerhoeff('234156789120')).toBe(true);
    expect(isValidVerhoeff('2341 5678 9120')).toBe(true);
    expect(isValidVerhoeff('000000000000')).toBe(false);
    expect(isValidVerhoeff('123456789012')).toBe(false);
  });
});

describe('PII Scanner Precision, Allowlist & Custom Regex', () => {
  it('detects all 6 PII categories accurately, respects allowlist 127.0.0.1, and tracks Luhn rejections', () => {
    const sample = SAMPLE_DATASETS[0].content;
    const result = scanTextForPii(sample);

    expect(result.counts.EMAIL).toBe(4);
    expect(result.counts.PHONE).toBe(3);
    expect(result.counts.IP_ADDRESS).toBe(4); // 127.0.0.1 excluded by default allowlist
    expect(result.allowlistedCount).toBe(1);
    expect(result.counts.PAN).toBe(2);
    expect(result.counts.AADHAAR).toBe(1);
    expect(result.counts.CREDIT_CARD).toBe(2);
    expect(result.luhnRejectedCount).toBe(1);
    expect(result.risk.scoreBefore).toBeGreaterThan(70);
  });

  it('does not double-count phone substrings inside valid credit cards or Aadhaar', () => {
    const text = 'Card: 4532-0151-1283-0366 Aadhaar: 2341 5678 9123';
    const scan = scanTextForPii(text);
    expect(scan.counts.CREDIT_CARD).toBe(1);
    expect(scan.counts.AADHAAR).toBe(1);
    expect(scan.counts.PHONE).toBe(0);
  });

  it('supports custom regex rules and handles invalid regex gracefully without crashing', () => {
    const validCustom = scanTextForPii('Staff EMP-10421 logged in with EMP-10422.', {
      ...DEFAULT_DETECTION_OPTIONS,
      customRule: { enabled: true, label: 'EMP_ID', pattern: 'EMP-\\d{4,6}' },
    });
    expect(validCustom.counts.CUSTOM).toBe(2);
    expect(validCustom.customRuleError).toBeNull();

    const invalidCustom = scanTextForPii('test', {
      ...DEFAULT_DETECTION_OPTIONS,
      customRule: { enabled: true, label: 'BAD', pattern: '[unclosed(' },
    });
    expect(invalidCustom.customRuleError).toBeTruthy();

    const redosCustom = scanTextForPii('aaaaaaaaaaaaaaaaaaaaaaaa!', {
      ...DEFAULT_DETECTION_OPTIONS,
      customRule: { enabled: true, label: 'REDOS', pattern: '(a+)+' },
    });
    expect(redosCustom.customRuleError).toContain('ReDoS');
  });

  it('detects lowercase/mixed-case PANs, toll-free 1800 numbers, and international phones', () => {
    const sample =
      'PANs: abcde1234f and AbCdE9876k | Toll-free: 1800-419-0155 | UK: +44 20 7946 0958 | IN: +91 9876 543 210';
    const scan = scanTextForPii(sample);
    expect(scan.counts.PAN).toBe(2);
    expect(scan.counts.PHONE).toBe(3);
  });

  it('masks variable-length credit cards including 15-digit Amex cleanly', () => {
    const amex = redactText('Amex: 3782-822463-10005', 'partial');
    expect(amex.sanitizedText).toBe('Amex: XXXX-XXXXXX-X0005');
  });

  it('serializes RFC-4180 CSV cells containing commas and quotes without breaking columns', () => {
    const csv = 'name,note,email\n"Sharma, Aditya","Quote ""here""",aditya@test.in';
    const parsed = parseCsvRows(csv);
    const out = redactCsvCells(parsed, 'full', DEFAULT_DETECTION_OPTIONS);
    expect(out.sanitizedRows[0]).toEqual(['Sharma, Aditya', 'Quote "here"', '[REDACTED]']);
    const reparsed = parseCsvRows(out.serializedCsv);
    expect(reparsed.isTabular).toBe(true);
    expect(reparsed.rows[0][0]).toBe('Sharma, Aditya');
    expect(serializeCsvRows(['a'], [['x,y']])).toBe('a\n"x,y"');
  });

  it('encrypts and decrypts pseudonym ledgers with PBKDF2 + AES-256-GCM and rejects wrong passphrases', async () => {
    const res = redactText('User aarav@corp.in charged 4532-0151-1283-0366', 'pseudonymize');
    const bundle = await encryptPseudonymLedger(res.mappings, 'strong-pass-2026');
    expect(bundle.algorithm).toBe('AES-GCM');
    expect(bundle.iterations).toBe(100_000);

    const restored = await decryptPseudonymLedger(bundle, 'strong-pass-2026');
    expect(restored.length).toBe(2);
    expect(restored[0].sampleValue).toBe('aarav@corp.in');

    await expect(decryptPseudonymLedger(bundle, 'wrong-pass')).rejects.toThrow(/Decryption failed/);
  });

  it('maps detected counts to Google Cloud DLP InfoTypes cleanly', () => {
    const scan = scanTextForPii(SAMPLE_DATASETS[0].content);
    const dlp = buildCloudDlpSummary(scan.counts);
    expect(dlp.some((entry) => entry.googleCloudDlpInfoType === 'CREDIT_CARD_NUMBER')).toBe(true);
    expect(dlp.some((entry) => entry.googleCloudDlpInfoType === 'INDIA_AADHAAR_INDIVIDUAL')).toBe(true);
  });
});

describe('Three Redaction Modes, CSV Parsing & Performance', () => {
  const input =
    'User aarav@corp.in (AARAV@CORP.IN) paid with 4532-0151-1283-0366 from 192.168.1.10; PAN ABCDE1234F; Aadhaar 2341 5678 9123; Phone +91 98765 43210 (9876543210).';

  it('applies Full Mask cleanly', () => {
    const res = redactText(input, 'full');
    expect(res.sanitizedText).not.toContain('aarav@corp.in');
    expect(res.sanitizedText).not.toContain('4532-0151-1283-0366');
    expect(res.sanitizedText).toContain('[REDACTED]');
  });

  it('applies Partial Mask preserving verification suffix/prefix', () => {
    const res = redactText(input, 'partial');
    expect(res.sanitizedText).toContain('a***@corp.in');
    expect(res.sanitizedText).toContain('XXXX-XXXX-XXXX-0366');
    expect(res.sanitizedText).toContain('192.168.XXX.XXX');
    expect(res.sanitizedText).toContain('ABXXX1234X');
    expect(res.sanitizedText).toContain('XXXX XXXX 9123');
    expect(res.sanitizedText).toContain('+91 XXXXXX3210');
  });

  it('applies Consistent Pseudonymization across repeated normalized entities', () => {
    const res = redactText(input, 'pseudonymize');
    const userMatches = res.sanitizedText.match(/USER_01/g);
    const phoneMatches = res.sanitizedText.match(/PHONE_01/g);
    expect(userMatches?.length).toBe(2);
    expect(phoneMatches?.length).toBe(2);
    expect(res.sanitizedText).toContain('CARD_01');
    expect(res.sanitizedText).toContain('IP_01');
    expect(res.sanitizedText).toContain('PAN_01');
    expect(res.sanitizedText).toContain('AADHAAR_01');
  });

  it('parses quoted RFC-4180 CSV rows and preserves columns during redaction', () => {
    const csv = SAMPLE_DATASETS[1].content;
    const parsed = parseCsvRows(csv);
    expect(parsed.isTabular).toBe(true);
    expect(parsed.rows.length).toBe(3);
    expect(parsed.rows[0][1]).toBe('Deshmukh, Rohan');

    const res = redactText(csv, 'pseudonymize');
    const sanitizedParsed = parseCsvRows(res.sanitizedText);
    expect(sanitizedParsed.isTabular).toBe(true);
    expect(sanitizedParsed.rows[2][2]).toBe('USER_01');
    expect(sanitizedParsed.rows[2][6]).toBe('1234-5678-9012-3456'); // Luhn-invalid preserved
  });

  it('generates offline synthetic chaos logs with 1 valid Luhn card and 1 rejected decoy', () => {
    const chaos = generateSyntheticChaosLog();
    const scan = scanTextForPii(chaos);
    expect(scan.counts.CREDIT_CARD).toBe(1);
    expect(scan.luhnRejectedCount).toBe(1);
    expect(scan.counts.EMAIL).toBe(4);
  });

  it('processes 100 KB of log text in under 150ms', () => {
    const chunk = SAMPLE_DATASETS[0].content + '\n';
    const largePayload = chunk.repeat(120); // ~105 KB
    const t0 = performance.now();
    const res = redactText(largePayload, 'pseudonymize');
    const elapsed = performance.now() - t0;
    expect(res.scan.totalDetected).toBeGreaterThan(1000);
    expect(elapsed).toBeLessThan(150);
  });
});

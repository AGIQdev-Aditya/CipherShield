import { describe, expect, it } from 'vitest';
import { isValidIPv4, isValidIPv6, isValidLuhn, isValidVerhoeff } from '../src/engine/validators';
import { DEFAULT_DETECTION_OPTIONS, scanTextForPii } from '../src/engine/scanner';
import { redactText } from '../src/engine/redactor';
import { SAMPLE_DATASETS } from '../src/engine/samples';

describe('Luhn & Financial Validators', () => {
  it('validates standard Luhn credit card numbers', () => {
    expect(isValidLuhn('4532-0151-1283-0366')).toBe(true);
    expect(isValidLuhn('5425233430109903')).toBe(true);
    expect(isValidLuhn('4539148803436467')).toBe(true);
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

  it('validates real UIDAI Verhoeff checksums for Aadhaar', () => {
    // 23415678912 + Verhoeff check digit
    expect(isValidVerhoeff('000000000000')).toBe(false);
    expect(isValidVerhoeff('123456789012')).toBe(false);
  });
});

describe('PII Scanner Precision & Conflict Resolution', () => {
  it('detects all 6 PII categories accurately and tracks Luhn rejections', () => {
    const sample = SAMPLE_DATASETS[0].content;
    const result = scanTextForPii(sample);

    expect(result.counts.EMAIL).toBe(4);
    expect(result.counts.PHONE).toBe(3);
    expect(result.counts.IP_ADDRESS).toBe(4); // 3 IPv4 + 1 IPv6
    expect(result.counts.PAN).toBe(2);
    expect(result.counts.AADHAAR).toBe(1);
    expect(result.counts.CREDIT_CARD).toBe(2);
    expect(result.luhnRejectedCount).toBe(1); // 4111-2222-3333-4444
  });

  it('does not double-count phone substrings inside valid credit cards or Aadhaar', () => {
    const text = 'Card: 4532-0151-1283-0366 Aadhaar: 2341 5678 9123';
    const scan = scanTextForPii(text);
    expect(scan.counts.CREDIT_CARD).toBe(1);
    expect(scan.counts.AADHAAR).toBe(1);
    expect(scan.counts.PHONE).toBe(0);
  });

  it('handles overlapping category filters cleanly', () => {
    const text = 'Email: test@example.com IP: 10.1.2.3';
    const scan = scanTextForPii(text, {
      ...DEFAULT_DETECTION_OPTIONS,
      enabledCategories: {
        ...DEFAULT_DETECTION_OPTIONS.enabledCategories,
        IP_ADDRESS: false,
      },
    });
    expect(scan.counts.EMAIL).toBe(1);
    expect(scan.counts.IP_ADDRESS).toBe(0);
  });
});

describe('Three Redaction Modes', () => {
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
    expect(userMatches?.length).toBe(2); // aarav@corp.in and AARAV@CORP.IN map identically
    expect(phoneMatches?.length).toBe(2); // +91 98765 43210 and 9876543210 map identically
    expect(res.sanitizedText).toContain('CARD_01');
    expect(res.sanitizedText).toContain('IP_01');
    expect(res.sanitizedText).toContain('PAN_01');
    expect(res.sanitizedText).toContain('AADHAAR_01');
  });

  it('preserves CSV delimiters and safely avoids executing HTML/XSS text', () => {
    const csv = SAMPLE_DATASETS[1].content;
    const res = redactText(csv, 'pseudonymize');
    const lines = res.sanitizedText.trim().split('\n');
    expect(lines.length).toBe(4);
    expect(lines[1].split(',').length).toBe(8);
    expect(lines[3]).toContain('USER_01'); // E103 shares Rohan's email with E101
    expect(lines[3]).toContain('1234-5678-9012-3456'); // Luhn-invalid card left unredacted & flagged
  });
});

export interface SampleDataset {
  id: string;
  label: string;
  filename: string;
  description: string;
  content: string;
}

export const SAMPLE_DATASETS: SampleDataset[] = [
  {
    id: 'incident-log',
    label: 'FinTech Incident Log',
    filename: 'incident_support_log.txt',
    description:
      'Includes recurring user emails, Indian +91/US phones, valid Luhn cards, a fake 16-digit order ID (Luhn rejected), PAN, Aadhaar, IPv4/IPv6, allowlisted localhost 127.0.0.1, and a benign XSS test string.',
    content: `[2026-11-27 09:42:11 IST] TICKET #INC-8841 - Billing Escalation
Reporter: Aarav Kulkarni <aarav.kulkarni@fintech-corp.in> | Backup: AARAV.KULKARNI@FINTECH-CORP.IN
Callback Mobile: +91 98765 43210 (alt: 9876543210) | US Escalation: (415) 890-4412
Client Source IP: 192.168.42.108 -> Gateway: 10.0.14.22 | Loopback: 127.0.0.1 | Edge IPv6: 2001:0db8:85a3::8a2e:0370:7334

KYC Verification Payload:
- Primary PAN: ABCDE1234F (Verified holder)
- Secondary PAN: BNZPM9087K
- Aadhaar Ref: 2341 5678 9120

Payment Audit Trail:
- Charged Visa Card: 4532-0151-1283-0366 (Luhn Valid)
- Repeat Refund Target: aarav.kulkarni@fintech-corp.in on Card 4532-0151-1283-0366
- Order Batch Reference (NOT a card - fails Luhn): 4111-2222-3333-4444
- Raw XSS Injection Probe inside log note: <script>alert('xss_test')</script>

Auditor Notes: Priyam Nair (priyam.nair@secops.org) verified from workstation 172.16.8.14.`,
  },
  {
    id: 'hr-csv',
    label: 'HR Payroll CSV',
    filename: 'employee_onboarding_export.csv',
    description: 'Multi-row CSV dataset with quoted fields, recurring emails, PANs, Aadhaar, and Luhn/non-Luhn cards.',
    content: `emp_id,full_name,email,phone,pan_id,aadhaar_no,corporate_card,workstation_ip
EMP-10421,"Deshmukh, Rohan",rohan.d@niat-labs.in,+91-9823011223,AWFPD4412M,3412-8891-4402,5425233430109903,10.24.1.15
EMP-10422,"Iyer, Meera",meera.iyer@niat-labs.in,+91 97654 32109,CHJPI7721Q,7812 9043 1185,4539148803436467,10.24.1.19
EMP-10421,"Deshmukh, Rohan (Re-audit)",rohan.d@niat-labs.in,9823011223,AWFPD4412M,3412-8891-4402,1234-5678-9012-3456,192.168.10.55`,
  },
  {
    id: 'clinical-note',
    label: 'Clinical Intake Note',
    filename: 'clinical_intake_note.txt',
    description: 'Healthcare triage record containing patient identity, Aadhaar, emergency contact, and copay billing card.',
    content: `CLINICAL TRIAGE SUMMARY - OPD WARD 4B
Patient Contact: ananya.joshi@carehealth.in | Guardian Email: ananya.joshi@carehealth.in
Emergency Phone: +91 99220 44551 | Clinic Desk Alt: 09822113344
Aadhaar UID: 6512 4409 8821 | Insurance PAN: DFGPA5510L
Copay Authorization Card: 4916-4321-8765-4322 (Verify Luhn) | Non-Card Auth Ref: 9999-8888-7777-6666
Telehealth Session IP: 103.21.124.88`,
  },
];

function buildLuhnValidCard(prefix: string): string {
  const digits = prefix.split('').map(Number);
  while (digits.length < 15) {
    digits.push(Math.floor(Math.random() * 10));
  }
  let sum = 0;
  let shouldDouble = true;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i];
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  const checkDigit = (10 - (sum % 10)) % 10;
  digits.push(checkDigit);
  return `${digits.slice(0, 4).join('')}-${digits.slice(4, 8).join('')}-${digits.slice(8, 12).join('')}-${digits.slice(12, 16).join('')}`;
}

function buildLuhnInvalid16(): string {
  const valid = buildLuhnValidCard('4111').replace(/-/g, '');
  const last = (Number(valid[15]) + 3) % 10;
  const invalid = valid.slice(0, 15) + String(last);
  return `${invalid.slice(0, 4)}-${invalid.slice(4, 8)}-${invalid.slice(8, 12)}-${invalid.slice(12, 16)}`;
}

/**
 * Generates fresh offline synthetic noisy logs containing guaranteed Luhn-valid cards,
 * non-Luhn decoys, Indian PAN, Aadhaar, IPv4, phones, and duplicated identities.
 */
export function generateSyntheticChaosLog(): string {
  const names = ['kiran.rao', 'siddharth.patil', 'neha.verma', 'vikram.menon', 'tanvi.joshi'];
  const domains = ['cloudpay.in', 'meridian-ops.org', 'medvault.co.in'];
  const nameA = names[Math.floor(Math.random() * names.length)];
  const nameB = names[(names.indexOf(nameA) + 2) % names.length];
  const domain = domains[Math.floor(Math.random() * domains.length)];

  const emailA = `${nameA}@${domain}`;
  const emailB = `${nameB}@${domain}`;
  const phoneA = `+91 ${Math.floor(70000 + Math.random() * 29000)} ${Math.floor(10000 + Math.random() * 89999)}`;
  const rawPhoneA = phoneA.replace('+91 ', '').replace(' ', '');
  const panA = `${String.fromCharCode(65 + Math.floor(Math.random() * 20))}BCPK${Math.floor(1000 + Math.random() * 8999)}M`;
  const aadhaarA = `${Math.floor(2000 + Math.random() * 7000)} ${Math.floor(1000 + Math.random() * 8999)} ${Math.floor(1000 + Math.random() * 8999)}`;
  const validCard = buildLuhnValidCard(Math.random() > 0.5 ? '4532' : '5425');
  const fakeOrder = buildLuhnInvalid16();
  const ipA = `192.168.${Math.floor(1 + Math.random() * 200)}.${Math.floor(2 + Math.random() * 240)}`;
  const ipB = `10.${Math.floor(1 + Math.random() * 200)}.${Math.floor(1 + Math.random() * 200)}.${Math.floor(2 + Math.random() * 240)}`;

  return `[SYNTHETIC AUDIT FIXTURE] SESSION #${Math.floor(1000 + Math.random() * 9000)}
Primary Actor: ${emailA} (normalized duplicate: ${emailA.toUpperCase()})
Secondary Escalation: ${emailB} | Contact: ${phoneA} (short: ${rawPhoneA})
Source Network: ${ipA} -> Bastion ${ipB}
Tax & Identity Docs: PAN=${panA} | Aadhaar=${aadhaarA}
Valid Luhn Payment Card: ${validCard} (re-charged for ${emailA})
Decoy Order Reference (Fails Luhn): ${fakeOrder}`;
}

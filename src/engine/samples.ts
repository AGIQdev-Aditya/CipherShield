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
    label: 'Incident & FinTech Support Log',
    filename: 'incident_support_log.txt',
    description:
      'Includes recurring user emails, Indian +91/US phones, valid Luhn cards, a fake 16-digit order ID (Luhn rejected), PAN, Aadhaar, IPv4/IPv6, and a benign XSS test string.',
    content: `[2026-11-27 09:42:11 IST] TICKET #INC-8841 - Billing Escalation
Reporter: Aarav Kulkarni <aarav.kulkarni@fintech-corp.in> | Backup: AARAV.KULKARNI@FINTECH-CORP.IN
Callback Mobile: +91 98765 43210 (alt: 9876543210) | US Escalation: (415) 890-4412
Client Source IP: 192.168.42.108 -> Gateway: 10.0.14.22 | Edge IPv6: 2001:0db8:85a3::8a2e:0370:7334

KYC Verification Payload:
- Primary PAN: ABCDE1234F (Verified holder)
- Secondary PAN: BNZPM9087K
- Aadhaar Ref: 2341 5678 9123

Payment Audit Trail:
- Charged Visa Card: 4532-0151-1283-0366 (Luhn Valid)
- Repeat Refund Target: aarav.kulkarni@fintech-corp.in on Card 4532-0151-1283-0366
- Order Batch Reference (NOT a card - fails Luhn): 4111-2222-3333-4444
- Raw XSS Injection Probe inside log note: <script>alert('xss_test')</script>

Auditor Notes: Priyam Nair (priyam.nair@secops.org) verified from workstation 172.16.8.14.`,
  },
  {
    id: 'hr-csv',
    label: 'HR Onboarding & Payroll CSV',
    filename: 'employee_onboarding_export.csv',
    description: 'Multi-row CSV dataset with emails, PANs, Aadhaar numbers, phones, and corporate cards.',
    content: `emp_id,full_name,email,phone,pan_id,aadhaar_no,corporate_card,workstation_ip
E101,Rohan Deshmukh,rohan.d@niat-labs.in,+91-9823011223,AWFPD4412M,3412-8891-4402,5425233430109903,10.24.1.15
E102,Meera Iyer,meera.iyer@niat-labs.in,+91 97654 32109,CHJPI7721Q,7812 9043 1185,4539148803436467,10.24.1.19
E103,Rohan Deshmukh (Dup),rohan.d@niat-labs.in,9823011223,AWFPD4412M,3412-8891-4402,1234-5678-9012-3456,192.168.10.55`,
  },
];

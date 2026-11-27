# Prompt Engineering Log — CipherShield

**Event:** PromptWars × NIAT Pune (Google for Developers × H2S)  
**Domain:** Cybersecurity & Data Privacy  
**Author:** Aditya Sharma (`AGIQdev-Aditya`)

---

## Prompt 1 — Problem Decomposition & Security Architecture
**Prompt Objective:**
> Design a 100% client-side browser PII sanitization web application in React + TypeScript + Vite that detects Emails, Phone numbers, IPv4/IPv6 addresses, Indian PAN, Aadhaar, and Credit Card numbers, validates cards via Luhn Mod-10 checksum, and guarantees zero external server data transmission.

**Key Design Decisions:**
- Enforced React text-node rendering instead of `innerHTML` or `dangerouslySetInnerHTML` so pasted `<script>` XSS probes render harmlessly as literal strings.
- Built a zero-dependency Node 22 static server (`server.js`) enforcing CSP (`object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `style-src 'self'`, zero `'unsafe-inline'`), `Strict-Transport-Security`, genuine `404` on missing `/assets/*`, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`.

---

## Prompt 2 — Deterministic Scanner & Adversarial Edge-Case Audit
**Prompt Objective:**
> Harden `src/engine/validators.ts`, `src/engine/scanner.ts`, `src/engine/redactor.ts`, and `src/engine/csvParser.ts` against IMEI/ICCID Luhn collisions, lowercase PAN false positives, IPv4-mapped IPv6, UPI VPA vs email separation, Indian 5+5 mobile formats, ReDoS patterns, and RFC-4180 CSV CWE-1236 formula injection.

**Refinements Applied:**
- Integrated `google-libphonenumber` for strict international/Indian phone validation and added card network IIN filtering (`Visa`, `Mastercard`, `Amex`, `Diners Club`, `RuPay`, `Discover`) so 15-digit IMEIs are rejected cleanly.
- Guarded lowercase PAN detection with taxpayer 4th-char entity code + context keyword check, updated PAN partial mask to `A****1234F` to guarantee post-redaction rescan reaches `0/100`, and updated CSV export to redact headers + rows cleanly without row caps and with CWE-1236 formula neutralization.

---

## Prompt 3 — Zero-Egress Proof, Web Crypto Vault & Interactive Override UI
**Prompt Objective:**
> Upgrade PBKDF2-SHA256 to 600,000 iterations + AES-GCM AAD (`src/engine/cryptoVault.ts`), add `sendBeacon`/`PerformanceObserver` monitoring + self-hosted `@fontsource` fonts, enforce structural `SafeScanSummary` isolation with offline DPDP/PCI-DSS brief fallback (`src/services/geminiAdvisor.ts`), and add an interactive entity inspector with one-click **Keep Original** override + 10-case adversarial self-test proof.

**Verification Results:**
- Verified with `npm run lint`, `npm test`, and `npm run build` plus HTTP response header and Chromium visual inspection against `server.js`.

# Prompt Engineering Log — CipherShield

**Event:** PromptWars × NIAT Pune (Google for Developers × H2S)  
**Domain:** Cybersecurity & Data Privacy  
**Author:** Aditya Sharma (`AGIQdev-Aditya`)

---

## Prompt 1 — Problem Decomposition & Security Architecture
**Prompt Objective:**
> Design a 100% client-side browser PII sanitization web application in React + TypeScript + Vite that detects Emails, Phone numbers (+91 & international), IPv4/IPv6 addresses, Indian PAN, Aadhaar, and Credit Card numbers, validates cards via Luhn Mod-10 checksum, and guarantees zero external server data transmission.

**Key Design Decisions:**
- Enforced strict React text-node rendering (`<span>` slices) instead of `innerHTML` or `dangerouslySetInnerHTML` so pasted logs containing malicious `<script>` payloads render harmlessly as literal strings.
- Built a zero-dependency Node.js production static server (`server.js`) with explicit security headers (`Content-Security-Policy` with `connect-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`).

---

## Prompt 2 — Deterministic Scanner & Interval Conflict Resolution
**Prompt Objective:**
> Write a modular PII scanning engine in `src/engine/validators.ts` and `src/engine/scanner.ts` using ReDoS-safe regular expressions, strict IPv4/IPv6 validation, Luhn Mod-10 filtering (tracking rejected non-Luhn numbers), UIDAI Verhoeff checksum support, allowlisting, user-defined custom regex rules, and non-overlapping interval prioritization.

**Refinements Applied:**
- Fixed sentence-trailing IPv4 boundary lookahead (`(?!\d|\.\d)`) so IPs ending a sentence (`172.16.8.14.`) match accurately without matching invalid 5-octet strings.
- Prevented 16-digit credit card numbers from partially matching 10-digit phone or 12-digit Aadhaar patterns via priority interval sweeps (`CREDIT_CARD > EMAIL > IP_ADDRESS > AADHAAR > PAN > PHONE > CUSTOM`).
- Excluded timestamps (`10:24:19`) from IPv6 matching via strict hex-group validation (`isValidIPv6`) and blocked trivial all-zero `0000-0000-0000-0000` Luhn bypasses.

---

## Prompt 3 — Multi-Mode Redaction, CSV Diff & SHA-256 Audit Compliance
**Prompt Objective:**
> Implement `redactText()` (`src/engine/redactor.ts`), RFC-4180 CSV parser (`src/engine/csvParser.ts`), offline Luhn-valid synthetic chaos generator (`src/engine/samples.ts`), Privacy Exposure Risk scoring, and Web Crypto SHA-256 Audit JSON export mapped to Google Cloud DLP InfoTypes.

**Verification:**
- Verified normalized pseudonymization maps `aarav@corp.in` vs `AARAV.KULKARNI@FINTECH-CORP.IN` and `+91 98765 43210` vs `9876543210` identically (`USER_01`, `PHONE_01`).
- Verified quoted CSV rows preserve structure and support side-by-side cell diff inspection.

---

## Prompt 4 — Accessibility, Automated Testing & Cloud Run Packaging
**Prompt Objective:**
> Harden UI against WCAG AA accessibility standards (`eslint-plugin-jsx-a11y`, semantic landmarks, `<dialog>.showModal()`, keyboard `tablist`, `prefers-color-scheme` dark/light tokens), verify `100 KB` scanning under `150ms` in Vitest, and prepare multi-stage `Dockerfile` + `cloudbuild.yaml` for Google Cloud Run (`PORT=8080`).

**Verification Results:**
- Passed `npm run lint` (`eslint .` with zero errors/warnings across TypeScript and `jsx-a11y`).
- Passed `npm test` (13 Vitest unit & performance tests).
- Verified `npm run build`, live HTTP security headers, and headless Chromium render.

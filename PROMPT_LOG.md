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
- Built a Node.js production static server (`server.js`) with explicit security headers (`Content-Security-Policy` with `connect-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`).

---

## Prompt 2 — Deterministic Scanner & Interval Conflict Resolution
**Prompt Objective:**
> Write a modular PII scanning engine in `src/engine/validators.ts` and `src/engine/scanner.ts` using ReDoS-safe regular expressions, strict IPv4/IPv6 validation, Luhn Mod-10 filtering (with tracking of rejected non-Luhn numbers), UIDAI Verhoeff checksum support, and non-overlapping interval prioritization.

**Refinements Applied:**
- Prevented 16-digit credit card numbers from partially matching 10-digit phone or 12-digit Aadhaar patterns by resolving intervals using category priority (`CREDIT_CARD > EMAIL > IP_ADDRESS > AADHAAR > PAN > PHONE`).
- Excluded timestamps (`10:24:19`) from IPv6 matching via strict hex-group and double-colon validation (`isValidIPv6`).
- Blocked trivial all-zero `0000-0000-0000-0000` Luhn Mod-10 bypasses.

---

## Prompt 3 — Multi-Mode Redaction & Consistent Pseudonymization
**Prompt Objective:**
> Implement `redactText()` in `src/engine/redactor.ts` supporting Full Mask (`[REDACTED]`), Partial Mask (`XXXX-XXXX-XXXX-0366`, `a***@corp.in`, `+91 XXXXXX3210`), and Consistent Pseudonymization (`USER_01`, `PHONE_01`), normalizing email casing and phone country prefixes so duplicates receive identical tokens across the entire document and CSV rows.

**Verification:**
- Verified normalization handles `aarav@corp.in` vs `AARAV@CORP.IN` and `+91 98765 43210` vs `9876543210`.

---

## Prompt 4 — Accessibility, UI Workbench & Cloud Run Packaging
**Prompt Objective:**
> Build an accessible side-by-side diff UI (`src/App.tsx`, `src/index.css`) with skip links, semantic HTML5 landmarks, keyboard-navigable `role="tablist"`, high-contrast light/dark color-scheme tokens, 1-click sample loaders, `.txt`/`.csv` upload/download, Vitest unit tests, and a multi-stage `Dockerfile` for Google Cloud Run (`PORT=8080`).

**Verification Results:**
- Executed `npm test` (`vitest run`) covering Luhn rejection, IPv4/IPv6 boundaries, overlap priority, CSV integrity, and all 3 redaction modes.
- Verified TypeScript strict compilation (`tsc --noEmit`), Vite production build (`npm run build`), and HTTP headers via local server check.

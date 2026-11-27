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
- Built a zero-dependency Node.js static server (`server.js`) enforcing CSP (`object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, zero `'unsafe-inline'`), `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`.

---

## Prompt 2 — Deterministic Scanner & Adversarial Edge-Case Audit
**Prompt Objective:**
> Harden `src/engine/validators.ts`, `src/engine/scanner.ts`, `src/engine/redactor.ts`, and `src/engine/csvParser.ts` against case variants, variable card lengths, toll-free/international phones, ReDoS patterns, and RFC-4180 CSV escaping.

**Refinements Applied:**
- Updated PAN regex to case-insensitive (`[A-Za-z]{5}[0-9]{4}[A-Za-z]`) with uppercase normalization.
- Updated Credit Card partial masking to preserve exact digit counts and separators across 13–19 digits (including 15-digit Amex `4-6-5`).
- Added RFC-4180 `escapeCsvCell()`, `serializeCsvRows()`, and `redactCsvCells()` so downloaded `.csv` files preserve quoting and commas.
- Added toll-free (`1800-XXX-XXXX`), international (`+44 ...`), and space-separated `+91` phone support plus strict date exclusion and ReDoS nested-quantifier rejection.

---

## Prompt 3 — Zero-Egress Proof, Web Crypto Vault & Cloud Run Hardening
**Prompt Objective:**
> Implement runtime Zero-Egress network telemetry (`src/engine/networkMonitor.ts`), client-side PBKDF2 + AES-256-GCM reversible key vault (`src/engine/cryptoVault.ts`), lazy-loaded `@google/genai` counts-only compliance advisor (`src/services/geminiAdvisor.ts`), and async Brotli/gzip + structured Cloud Logging JSON (`server.js`).

**Verification Results:**
- Passed `npm run lint` (`eslint .` with zero errors/warnings across TypeScript and `jsx-a11y`).
- Passed `npm test` (25 Vitest unit, AES-GCM crypto, CSV serialization, `100 KB` perf benchmark, React UI, and `axe-core` WCAG tests).
- Verified production `npm run build` and HTTP `br` compression / CSP headers via `server.js`.

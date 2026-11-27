# CipherShield — Client-Side PII Sanitization & Audit Studio

**CipherShield** is a zero-egress, browser-based data sanitization workbench built for **PromptWars × NIAT Pune (Google for Developers × Build with AI)**. It enables users to paste raw logs, clinical notes, resumes, or upload `.txt`/`.csv` files and automatically detect, validate, classify, and redact sensitive Personally Identifiable Information (PII) strictly on the client side.

---

## Key Capabilities

1. **Multi-Category PII Detection & Checksum Validation**
   - **Emails & UPI VPAs**: Strict RFC-aware email validation separating emails from **India UPI Handles** (`@okaxis`, `@ybl`, `@oksbi`, `@paytm`, etc.).
   - **Phone Numbers**: Validated with **`google-libphonenumber`** covering Indian (`+91`, `98765 43210` 5+5 mobile, landlines), toll-free (`1800-XXX-XXXX`), and international E.164/UK/US formats.
   - **IP Addresses**: Strict IPv4 (`0–255` octet bounds) and canonical IPv6 including **IPv4-mapped IPv6** (`::ffff:192.0.2.1`) without timestamp or semver false positives.
   - **Indian PAN**: Case-insensitive `[A-Za-z]{5}[0-9]{4}[A-Za-z]` guarded by valid Income Tax 4th-char entity code (`P/C/H/A/B/G/J/L/F/T`) or tax/KYC context.
   - **Indian Aadhaar**: UIDAI 12-digit detection (`[2-9]...`) with **Verhoeff** checksum validation and 16-digit card collision suppression.
   - **Credit Cards**: Variable-length 13–19 digit sequences (Visa, Mastercard 2-series/5-series, 15-digit Amex, Diners Club, RuPay, Discover) validated via **Luhn (Mod-10) + Card Network IIN**, filtering IMEIs and non-card IDs into a rejected audit list.
2. **Interactive Entity Review & Three Redaction Modes**
   - **Entity Change Inspector & Selective Override**: Inspect every detected value → proposed replacement alongside confidence/validator metadata, and click **Keep Original** to whitelist any item cleanly.
   - **Full Mask**: `[REDACTED]` (or category-tagged `[EMAIL_REDACTED]`).
   - **Partial Mask**: Preserves exact card length/delimiters (`XXXX-XXXXXX-X0005` for Amex, `XXXX-XXXX-XXXX-0366` for Visa), `A****1234F` (non-re-detectable PAN mask), `a***@domain.com`, `+91 XXXXXX3210`, `192.168.XXX.XXX`.
   - **Consistent Pseudonymization**: Normalizes email casing and `+91`/leading `0` phone prefixes so recurring values map identically (`USER_01`, `PHONE_01`, `CARD_01`) across documents and CSV headers/rows, backed by real **post-redaction residual rescanning (`scoreAfter`)**.
3. **Network Monitor, Web Crypto Vault & Adversarial Self-Test**
   - **Live Network Monitor**: Intercepts `fetch`, `XHR`, `navigator.sendBeacon`, and `PerformanceObserver` (`resource`) to verify `0 External Calls` during local scanning; self-hosted `@fontsource/inter` & `@fontsource/jetbrains-mono` ensure zero external font requests.
   - **Reversible AES-256-GCM Key Vault**: Client-side Web Crypto **PBKDF2-SHA256 (600k iterations, min 8-char passphrase) + AES-256-GCM with AAD binding** encrypted `.key.json` export & decryptor.
   - **RFC-4180 CSV Column Diff, BOM Stripping & CWE-1236 Guard**: Full non-truncated CSV redaction (headers + rows via shared pseudonym session) with formula injection neutralization (`=`, `+`, `-`, `@`).
   - **10-Case Adversarial Self-Test Proof**: Built-in browser self-test verifies Luhn/IMEI rejection, PAN context, Verhoeff UIDAI, `::ffff:192.0.2.1`, Amex masking, UPI separation, ReDoS guard, and CSV CWE-1236 in real time.
   - **Google Ecosystem Integration**: Cloud Run Node 22 container (`PORT=8080`, `/healthz`, async Brotli/gzip, Cloud Logging trace JSON, Artifact Registry `cloudbuild.yaml`), Google `libphonenumber`, Google Cloud DLP `DeidentifyConfig` + `InfoTypes` export, and lazy-loaded `@google/genai` (`gemini-3.8-flash`) with `SafeScanSummary` + offline fallback.

---

## Verification & Quality Checks

```bash
npm run lint    # ESLint + TypeScript + eslint-plugin-jsx-a11y (0 errors)
npm test        # 28 Vitest unit, ReDoS, crypto, CSV, UI & axe-core WCAG tests
npm run build   # Strict tsc --noEmit + Vite production + Web Worker build
npm start       # Serves dist/ on 0.0.0.0:8080 with async Brotli/gzip & strict CSP
```

---

## Deploying to Google Cloud Run

```bash
gcloud run deploy ciphershield \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated
```

---

## Prompt Log

See [`PROMPT_LOG.md`](./PROMPT_LOG.md) or click **Prompt Log** in the application header.

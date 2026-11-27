# CipherShield — Client-Side PII Sanitization & Audit Studio

**CipherShield** is a zero-egress, browser-based data sanitization workbench built for **PromptWars × NIAT Pune (Google for Developers × Build with AI)**. It enables users to paste raw logs, clinical notes, resumes, or upload `.txt`/`.csv` files and automatically detect, validate, classify, and redact sensitive Personally Identifiable Information (PII) strictly on the client side.

---

## Key Capabilities

1. **Multi-Category PII Detection & Checksum Validation**
   - **Emails**: RFC-compatible email extraction.
   - **Phone Numbers**: Indian (`+91`, 10-digit mobile, space-separated), toll-free (`1800-XXX-XXXX`), and international E.164/UK/US formats.
   - **IP Addresses**: Strict IPv4 (`0–255` octet bounds) and IPv6 detection without timestamp false positives.
   - **Indian PAN**: Case-insensitive `[A-Za-z]{5}[0-9]{4}[A-Za-z]` with taxpayer entity metadata.
   - **Indian Aadhaar**: 12-digit detection with toggleable **UIDAI Verhoeff** checksum validation.
   - **Credit Cards**: Variable-length 13–19 digit sequences (Visa, Mastercard, 15-digit Amex, RuPay, Discover) validated via **Luhn (Mod-10)** with rejected decoy logging.
2. **Three Redaction Modes**
   - **Full Mask**: `[REDACTED]` (or category-tagged `[EMAIL_REDACTED]`).
   - **Partial Mask**: Preserves exact card length/delimiters (`XXXX-XXXXXX-X0005` for Amex, `XXXX-XXXX-XXXX-0366` for Visa), `a***@domain.com`, `+91 XXXXXX3210`, `192.168.XXX.XXX`.
   - **Consistent Pseudonymization**: Normalizes email casing and `+91`/leading `0` phone prefixes so recurring values map identically (`USER_01`, `PHONE_01`, `CARD_01`) across documents and CSV rows.
3. **Zero-Egress Proof, Encrypted Vault & Verification**
   - **Zero-Egress Network Interceptor**: Runtime `fetch`/`XHR` telemetry badge proves `0 External Calls` during PII scanning and redaction.
   - **Reversible AES-256-GCM Key Vault**: Client-side Web Crypto **PBKDF2-SHA256 (100k iterations) + AES-256-GCM** encrypted `.key.json` export & decryptor.
   - **RFC-4180 CSV Column Diff & Serializer**: Safe quoting/serialization prevents column shifting on CSV export.
   - **Exposure Risk Score, Allowlist & ReDoS-Safe Custom Regex Rules**.
   - **Google Ecosystem Integration**: Cloud Run container (`PORT=8080`, `/healthz`, async Brotli/gzip, structured Cloud Logging JSON), Google Cloud DLP InfoTypes export, Google Fonts, and lazy-loaded `@google/genai` counts-only compliance advisor.

---

## Verification & Quality Checks

```bash
npm run lint    # ESLint + TypeScript + eslint-plugin-jsx-a11y (0 errors)
npm test        # 25 Vitest unit, crypto, CSV, UI & axe-core WCAG tests
npm run build   # Strict tsc --noEmit + Vite production build
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

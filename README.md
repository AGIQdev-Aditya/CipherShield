# CipherShield — Client-Side PII Sanitization & Audit Studio

**CipherShield** is a zero-egress, browser-based data sanitization workbench built for **PromptWars × NIAT Pune (Google for Developers × Build with AI)**. It enables users to paste raw logs, clinical notes, resumes, or upload `.txt`/`.csv` files and automatically detect, validate, classify, and redact sensitive Personally Identifiable Information (PII) strictly on the client side.

---

## Key Capabilities

1. **Multi-Category PII Detection & Checksum Validation**
   - **Emails**: RFC-compatible email extraction.
   - **Phone Numbers**: Indian (`+91`, 10-digit mobile) and international E.164 / US formats.
   - **IP Addresses**: Strict IPv4 (`0–255` octet bounds) and IPv6 detection without timestamp false positives.
   - **Indian PAN**: `[A-Z]{5}[0-9]{4}[A-Z]` with taxpayer category classification.
   - **Indian Aadhaar**: 12-digit detection with toggleable **UIDAI Verhoeff** checksum validation.
   - **Credit Cards**: Formatted & contiguous 13–19 digit sequences validated by **Luhn (Mod-10)** (rejects random 16-digit IDs and logs them separately).
2. **Three Redaction Modes**
   - **Full Mask**: `[REDACTED]` (or category-tagged `[EMAIL_REDACTED]`).
   - **Partial Mask**: Preserves safe context (`XXXX-XXXX-XXXX-0366`, `a***@domain.com`, `+91 XXXXXX3210`, `192.168.XXX.XXX`).
   - **Consistent Pseudonymization**: Normalizes email casing and `+91`/leading `0` phone prefixes so recurring values map identically (`USER_01`, `PHONE_01`, `CARD_01`) across documents and CSV rows.
3. **Enterprise Policy & Verification Tools**
   - **Exposure Risk Score**: Tracks raw exposure (`0–100`) dropping to `0/100 SECURE` after redaction.
   - **Allowlist & Custom Regex Rules**: Exclude safe domains/IPs (`127.0.0.1`) and add custom entity regex patterns safely.
   - **RFC-4180 CSV Column Diff**: Interactive cell-by-cell comparison view when `.csv` data is loaded.
   - **1-Click Samples & Synthetic Chaos Generator**: FinTech Incident Log, HR Payroll CSV, Clinical Note, plus randomized offline Luhn-valid chaos generator.
   - **Export Options**: 1-click Copy, 1-click Sanitized `.txt`/`.csv` Download, and **SHA-256 Compliance Audit JSON** mapped to **Google Cloud DLP InfoTypes**.

---

## Verification & Quality Checks

```bash
npm run lint    # ESLint + TypeScript + eslint-plugin-jsx-a11y
npm test        # 13 Vitest tests (validators, overlap resolution, CSV, 100KB benchmark)
npm run build   # Strict tsc --noEmit + Vite production build
npm start       # Serves dist/ on 0.0.0.0:8080 with strict CSP & security headers
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

See [`PROMPT_LOG.md`](./PROMPT_LOG.md) or open **Prompt Log** inside the application header.

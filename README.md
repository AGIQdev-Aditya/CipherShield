# CipherShield — Client-Side PII Sanitization & Audit Studio

**CipherShield** is a zero-egress, browser-based data sanitization web application built for **PromptWars × NIAT Pune (Google for Developers × Build with AI)**. It enables users to paste raw logs, clinical notes, resumes, or upload `.txt`/`.csv` files and automatically detect, validate, classify, and redact sensitive Personally Identifiable Information (PII) entirely inside browser memory.

---

## Key Capabilities

1. **Multi-Category PII Pattern Detection**
   - **Emails**: RFC-compatible email extraction.
   - **Phone Numbers**: Indian (`+91`, 10-digit mobile) and international formats.
   - **IP Addresses**: Strict IPv4 (`0–255` octet bounds) and IPv6 (compressed & full) detection without timestamp false positives.
   - **Indian PAN**: `[A-Z]{5}[0-9]{4}[A-Z]` with entity type metadata.
   - **Indian Aadhaar**: 12-digit formatting detection with optional strict **UIDAI Verhoeff** checksum validation.
   - **Credit Cards**: Formatted & contiguous 13–19 digit sequences filtered by **Luhn (Mod-10)** validation.
2. **False-Positive Protection**
   - Credit card candidates failing Luhn Mod-10 (e.g., 16-digit order IDs like `4111-2222-3333-4444`) are automatically excluded from redaction and reported in the audit log.
   - Deterministic interval resolution prevents overlapping double-redaction (e.g., card digits overlapping phone matches).
3. **Three Redaction Modes**
   - **Full Mask**: `[REDACTED]` (or typed `[EMAIL_REDACTED]`).
   - **Partial Mask**: Preserves safe verification context (`XXXX-XXXX-XXXX-0366`, `a***@domain.com`, `+91 XXXXXX3210`, `192.168.XXX.XXX`).
   - **Consistent Pseudonymization**: Normalizes casing and `+91`/leading `0` prefixes so recurring values map consistently to identical tokens (`USER_01`, `PHONE_01`, `CARD_01`) throughout documents and CSV files.
4. **Live Side-by-Side Diff, Audit & Export**
   - 1-click sample loaders (Incident Log & HR Onboarding CSV).
   - Color-coded original highlights vs. sanitized output rendered via safe React text nodes (XSS-safe).
   - 1-click copy & 1-click `.txt`/`.csv` file download.

---

## Architecture & Security

- **100% Client-Side Processing**: All regex matching, Luhn/Verhoeff checks, and file exports run locally in browser RAM using the Web File/Blob APIs.
- **Hardened HTTP Server (`server.js`)**: Enforces `Content-Security-Policy` (`connect-src 'self'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and `Permissions-Policy`.

---

## Local Development & Testing

```bash
npm install
npm test        # Run Vitest unit suite
npm run build   # Typecheck + Vite production bundle
npm start       # Serve production dist/ on http://0.0.0.0:8080
```

---

## Deploying to Google Cloud Run

CipherShield includes a multi-stage `Dockerfile` and `cloudbuild.yaml` configured for Cloud Run (`0.0.0.0:${PORT:-8080}` with `/healthz`):

```bash
gcloud run deploy ciphershield \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated
```

---

## Prompt Log

See [`PROMPT_LOG.md`](./PROMPT_LOG.md) or click the **Prompt Log** button in the app header.

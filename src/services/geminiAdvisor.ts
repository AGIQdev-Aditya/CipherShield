import { GoogleGenAI, Type } from '@google/genai';
import { PiiCategory } from '../types/pii';
import { GOOGLE_DLP_INFOTYPE_MAP } from '../engine/dlpTaxonomy';

/**
 * Structurally isolated summary — prevents raw document text or PII strings from ever reaching Gemini API calls.
 */
export interface SafeScanSummary {
  totalDetected: number;
  riskScoreBefore: number;
  riskLevelBefore: string;
  luhnRejectedCount: number;
  counts: Record<PiiCategory, number>;
}

/**
 * Deterministic built-in compliance recommendations available completely offline with zero API key.
 */
export function buildOfflineComplianceBrief(summary: SafeScanSummary): string {
  const bullets: string[] = [];

  if (summary.counts.CREDIT_CARD > 0) {
    bullets.push(
      `PCI-DSS Req 3.4: Detected ${summary.counts.CREDIT_CARD} Luhn-verified payment card(s). Export using Full Mask or Consistent Pseudonymization before storing logs outside CDE.`,
    );
  }
  if (summary.counts.AADHAAR > 0 || summary.counts.PAN > 0) {
    bullets.push(
      `India DPDP Act / UIDAI: Detected ${summary.counts.AADHAAR} Aadhaar and ${summary.counts.PAN} PAN identifiers. Store only masked tokens (XXXX-XXXX-1234 / A****1234F) in analytical logs.`,
    );
  }
  if (summary.counts.EMAIL > 0 || summary.counts.PHONE > 0 || summary.counts.UPI_ID > 0) {
    bullets.push(
      `Contact & Payment Linkage: Detected ${summary.counts.EMAIL} emails, ${summary.counts.PHONE} phones, and ${summary.counts.UPI_ID} UPI handles. Export the PBKDF2 + AES-256-GCM encrypted vault if audit reversal is required.`,
    );
  }
  if (summary.luhnRejectedCount > 0) {
    bullets.push(
      `Noise Hygiene: Luhn Mod-10 checksum preserved ${summary.luhnRejectedCount} non-card numeric reference(s) untouched so debugging traceability stays intact.`,
    );
  }

  return bullets.length > 0
    ? bullets.map((b, i) => `${i + 1}. ${b}`).join('\n')
    : 'No active high-risk PII exposure detected in the current document.';
}

/**
 * Optional Google Gemini Compliance Advisor using structured JSON schema output.
 * Receives ONLY aggregate anonymized counts (zero raw text or PII).
 * Falls back to the offline brief on any API error.
 */
export async function generateComplianceAdvice(
  apiKey: string,
  summary: SafeScanSummary,
): Promise<string> {
  const cleanKey = apiKey.trim();
  if (!cleanKey) {
    return buildOfflineComplianceBrief(summary);
  }

  const summaryLines = (Object.keys(summary.counts) as PiiCategory[])
    .filter((cat) => summary.counts[cat] > 0)
    .map((cat) => `- ${GOOGLE_DLP_INFOTYPE_MAP[cat]}: ${summary.counts[cat]} entity(ies)`)
    .join('\n');

  const prompt = `Analyze this anonymized PII aggregate telemetry (zero raw values provided):
Exposure Score: ${summary.riskScoreBefore}/100 (${summary.riskLevelBefore})
Luhn-Rejected Non-Card Numeric Candidates Ignored: ${summary.luhnRejectedCount}
Detected Cloud DLP InfoType Counts:
${summaryLines || '- None detected'}`;

  let rawText = '';
  try {
    const ai = new GoogleGenAI({ apiKey: cleanKey });
    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        systemInstruction:
          'You are a strict cybersecurity compliance architect specializing in India DPDP Act, UIDAI Aadhaar guidelines, PCI-DSS, and log sanitization.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            severity: { type: Type.STRING },
            recommendations: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
            },
          },
          required: ['severity', 'recommendations'],
        },
      },
    });
    rawText = response.text?.trim() ?? '';
  } catch {
    return buildOfflineComplianceBrief(summary);
  }
  if (!rawText) return buildOfflineComplianceBrief(summary);

  try {
    const parsed = JSON.parse(rawText) as { severity?: string; recommendations?: string[] };
    if (Array.isArray(parsed.recommendations) && parsed.recommendations.length > 0) {
      return `Gemini Assessment (${parsed.severity ?? summary.riskLevelBefore}):\n` +
        parsed.recommendations.map((rec, i) => `${i + 1}. ${rec}`).join('\n');
    }
  } catch {
    // Return raw formatted text if JSON parsing falls back
  }
  return rawText;
}

/**
 * Optional Google Gemini Synthetic Test Fixture Generator.
 * Generates strictly FICTIONAL dirty log samples for benchmarking.
 */
export async function generateGeminiSyntheticLog(apiKey: string): Promise<string> {
  const cleanKey = apiKey.trim();
  if (!cleanKey) {
    throw new Error('Provide a Google Gemini API key to generate synthetic fixtures.');
  }

  const ai = new GoogleGenAI({ apiKey: cleanKey });
  const response = await ai.models.generateContent({
    model: 'gemini-3.8-flash',
    contents:
      'Generate a short 10-line fictional customer support incident log containing fake Indian phone numbers (+91), fake emails (with one uppercase duplicate), 1 fake IPv4 address, 1 fake PAN format (ABCDE1234F style), and 1 fake Aadhaar 12-digit number so I can test a client-side redaction tool. Output raw log lines only, no markdown fences.',
  });

  return response.text?.trim() || '';
}
import { GoogleGenAI } from '@google/genai';
import { PiiCategory, ScanResult } from '../types/pii';
import { GOOGLE_DLP_INFOTYPE_MAP } from '../engine/redactor';

/**
 * Optional Google Gemini Compliance Advisor.
 * STRICT PRIVACY GUARANTEE: Never receives raw document text or any PII values.
 * Only anonymized aggregate entity counts and risk scores are sent when explicitly invoked by the user.
 */
export async function generateComplianceAdvice(
  apiKey: string,
  scan: ScanResult,
): Promise<string> {
  const cleanKey = apiKey.trim();
  if (!cleanKey) {
    throw new Error('Provide a Google Gemini API key to fetch AI compliance notes.');
  }

  const summaryLines = (Object.keys(scan.counts) as PiiCategory[])
    .filter((cat) => scan.counts[cat] > 0)
    .map((cat) => `- ${GOOGLE_DLP_INFOTYPE_MAP[cat]}: ${scan.counts[cat]} entity(ies)`)
    .join('\n');

  const prompt = `You are a cybersecurity and privacy compliance advisor.
Based ONLY on these aggregate anonymized PII entity counts (zero raw values provided), give 4 concise bullet points on DPDP Act (India), PCI-DSS, and logging hygiene recommendations:

Exposure Score Before Redaction: ${scan.risk.scoreBefore}/100 (${scan.risk.levelBefore})
Luhn-Rejected Non-Card Numeric Candidates Ignored: ${scan.luhnRejectedCount}
Detected Entity Categories:
${summaryLines || '- None detected'}`;

  const ai = new GoogleGenAI({ apiKey: cleanKey });
  const response = await ai.models.generateContent({
    model: 'gemini-2.5-flash',
    contents: prompt,
  });

  return response.text?.trim() || 'No compliance recommendations returned.';
}

/**
 * Optional Google Gemini Synthetic Test Fixture Generator.
 * Generates strictly FICTIONAL, synthetic dirty text samples locally for redaction benchmarking.
 */
export async function generateGeminiSyntheticLog(apiKey: string): Promise<string> {
  const cleanKey = apiKey.trim();
  if (!cleanKey) {
    throw new Error('Provide a Google Gemini API key to generate synthetic samples.');
  }

  const ai = new GoogleGenAI({ apiKey: cleanKey });
  const response = await ai.models.generateContent({
    model: 'gemini-2.5-flash',
    contents:
      'Generate a short 10-line fictional customer support incident log containing fake Indian phone numbers (+91), fake emails (with one uppercase duplicate), 1 fake IPv4 address, 1 fake PAN format (ABCDE1234F style), and 1 fake Aadhaar 12-digit number so I can test a client-side redaction tool. Output raw log lines only, no markdown fences.',
  });

  return response.text?.trim() || '';
}

import { DetectionOptions, RedactionMode, RedactionResult } from '../types/pii';
import { ParsedCsv, parseCsvRows, redactCsvCells } from './csvParser';
import { redactText } from './redactor';

export interface SanitizedCsvBundle extends ParsedCsv {
  serializedCsv: string;
}

export interface PipelineInput {
  text: string;
  mode: RedactionMode;
  options: DetectionOptions;
  neutralizeFormulas: boolean;
  expectCsv: boolean;
}

export interface PipelineOutput {
  result: RedactionResult;
  originalCsv: ParsedCsv;
  sanitizedCsvBundle: SanitizedCsvBundle;
}

export const EMPTY_CSV_BUNDLE: SanitizedCsvBundle = {
  headers: [],
  rows: [],
  isTabular: false,
  parseError: null,
  serializedCsv: '',
};

/**
 * Pure sanitization pipeline executed identically inside browser main RAM or isolated Web Workers.
 */
export function executeSanitizationPipeline({
  text,
  mode,
  options,
  neutralizeFormulas,
  expectCsv,
}: PipelineInput): PipelineOutput {
  const result = redactText(text, mode, options);
  const originalCsv = parseCsvRows(text, expectCsv);

  if (!originalCsv.isTabular) {
    return { result, originalCsv, sanitizedCsvBundle: EMPTY_CSV_BUNDLE };
  }

  const { sanitizedHeaders, sanitizedRows, serializedCsv } = redactCsvCells(
    originalCsv,
    mode,
    options,
    neutralizeFormulas,
  );

  return {
    result,
    originalCsv,
    sanitizedCsvBundle: {
      headers: sanitizedHeaders,
      rows: sanitizedRows,
      isTabular: true,
      parseError: null,
      serializedCsv,
    },
  };
}

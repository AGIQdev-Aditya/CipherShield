import { ParsedCsv, parseCsvRows, redactCsvCells } from '../engine/csvParser';
import { redactText } from '../engine/redactor';
import { DetectionOptions, RedactionMode, RedactionResult } from '../types/pii';

export interface WorkerScanRequest {
  requestId: number;
  text: string;
  mode: RedactionMode;
  options: DetectionOptions;
  neutralizeFormulas: boolean;
  expectCsv: boolean;
}

export interface SanitizedCsvBundle extends ParsedCsv {
  serializedCsv: string;
}

export interface WorkerScanResponse {
  requestId: number;
  result: RedactionResult;
  originalCsv: ParsedCsv;
  sanitizedCsvBundle: SanitizedCsvBundle;
}

globalThis.addEventListener('message', (event: MessageEvent<WorkerScanRequest>) => {
  const { requestId, text, mode, options, neutralizeFormulas, expectCsv } = event.data;
  const result = redactText(text, mode, options);
  const originalCsv = parseCsvRows(text, expectCsv);

  let sanitizedCsvBundle: SanitizedCsvBundle = {
    headers: [],
    rows: [],
    isTabular: false,
    parseError: null,
    serializedCsv: '',
  };

  if (originalCsv.isTabular) {
    const { sanitizedHeaders, sanitizedRows, serializedCsv } = redactCsvCells(
      originalCsv,
      mode,
      options,
      neutralizeFormulas,
    );
    sanitizedCsvBundle = {
      headers: sanitizedHeaders,
      rows: sanitizedRows,
      isTabular: true,
      parseError: null,
      serializedCsv,
    };
  }

  const response: WorkerScanResponse = {
    requestId,
    result,
    originalCsv,
    sanitizedCsvBundle,
  };

  globalThis.postMessage(response);
});

import { DetectionOptions, RedactionMode } from '../types/pii';
import { createPseudonymSession, redactText } from './redactor';

export interface ParsedCsv {
  headers: string[];
  rows: string[][];
  isTabular: boolean;
  parseError: string | null;
}

interface CsvScanState {
  lines: string[][];
  row: string[];
  cell: string;
  inQuotes: boolean;
  justClosedQuote: boolean;
  quoteError: string | null;
}

const EMPTY_CSV: ParsedCsv = { headers: [], rows: [], isTabular: false, parseError: null };

function buildCsvError(parseError: string | null): ParsedCsv {
  return { headers: [], rows: [], isTabular: false, parseError };
}

function consumeLineBreak(ch: string, next: string | undefined): number {
  if (ch === '\r' && next === '\n') return 2;
  if (ch === '\n' || ch === '\r') return 1;
  return 0;
}

function stepCsvParser(state: CsvScanState, ch: string, next: string | undefined): number {
  if (state.inQuotes) {
    if (ch === '"' && next === '"') {
      state.cell += '"';
      return 2;
    }
    if (ch === '"') {
      state.inQuotes = false;
      state.justClosedQuote = true;
    } else {
      state.cell += ch;
    }
    return 1;
  }

  const newlineStep = consumeLineBreak(ch, next);
  if (newlineStep > 0) {
    state.justClosedQuote = false;
    state.row.push(state.cell);
    state.lines.push(state.row);
    state.row = [];
    state.cell = '';
    return newlineStep;
  }

  if (ch === ',') {
    state.justClosedQuote = false;
    state.row.push(state.cell);
    state.cell = '';
    return 1;
  }

  if (state.justClosedQuote) {
    state.quoteError ??= `Malformed CSV: unexpected character "${ch}" after closing quote on row ${state.lines.length + 1}.`;
    state.justClosedQuote = false;
    state.cell += ch;
    return 1;
  }

  if (ch === '"') {
    if (state.cell.length > 0) {
      state.quoteError ??= `Malformed CSV: unexpected unescaped quote inside unquoted field on row ${state.lines.length + 1}.`;
      state.cell += ch;
    } else {
      state.inQuotes = true;
    }
    return 1;
  }

  state.cell += ch;
  return 1;
}

function validateTabularGrid(lines: string[][], quoteError: string | null, expectCsv: boolean): ParsedCsv {
  const resolvedHeader = lines[0];
  if (lines.length < 2 || !resolvedHeader || resolvedHeader.length < 2) {
    return buildCsvError(expectCsv ? quoteError : null);
  }
  if (quoteError) return buildCsvError(quoteError);

  const colCount = resolvedHeader.length;
  const badRowIdx = lines.findIndex((r) => r.length !== colCount);
  if (badRowIdx !== -1) {
    const actualLen = lines[badRowIdx]?.length ?? 0;
    return buildCsvError(
      expectCsv ? `Malformed CSV: row ${badRowIdx + 1} has ${actualLen} columns (expected ${colCount}).` : null,
    );
  }
  return { headers: resolvedHeader, rows: lines.slice(1), isTabular: true, parseError: null };
}

function finalizeParsedCsv(state: CsvScanState, expectCsv: boolean): ParsedCsv {
  const headerRow = state.lines[0];
  if (state.inQuotes) {
    const shouldReport = expectCsv || (headerRow !== undefined && headerRow.length >= 2);
    return buildCsvError(shouldReport ? 'Malformed CSV: unclosed quote detected.' : null);
  }

  if (state.cell.length > 0 || state.row.length > 0) {
    state.row.push(state.cell);
    state.lines.push(state.row);
  }

  return validateTabularGrid(state.lines, state.quoteError, expectCsv);
}

/**
 * Parses all CSV records strictly per RFC-4180 while preserving cell whitespace
 * (strips UTF-8 BOM + trailing line endings only, validates quotes & column parity).
 */
export function parseCsvRows(input: string, expectCsv = false): ParsedCsv {
  const cleaned = input.replace(/^\uFEFF/, '').replace(/(?:\r\n|\n|\r)+$/, '');
  if (!cleaned) return EMPTY_CSV;

  const state: CsvScanState = {
    lines: [],
    row: [],
    cell: '',
    inQuotes: false,
    justClosedQuote: false,
    quoteError: null,
  };

  for (let i = 0; i < cleaned.length; ) {
    i += stepCsvParser(state, cleaned.charAt(i), cleaned[i + 1]);
  }

  return finalizeParsedCsv(state, expectCsv);
}

/**
 * Neutralizes spreadsheet formula injection (CWE-1236) if enabled before RFC-4180 quoting.
 */
export function sanitizeFormulaCell(value: string, neutralizeFormulas: boolean): string {
  if (neutralizeFormulas && /^[\t\r ]*[=+\-@]/.test(value)) {
    return `'${value}`;
  }
  return value;
}

/**
 * Escapes and serializes a single cell per RFC-4180.
 */
export function escapeCsvCell(value: string): string {
  if (/[",\r\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/**
 * Serializes headers and rows into a valid RFC-4180 CSV string.
 */
export function serializeCsvRows(headers: string[], rows: string[][], neutralizeFormulas = false): string {
  const allRows = [headers, ...rows];
  return allRows
    .map((r) => r.map((c) => escapeCsvCell(sanitizeFormulaCell(c, neutralizeFormulas))).join(','))
    .join('\n');
}

/**
 * Redacts all CSV headers and rows cell-by-cell using a shared PseudonymSession
 * so control characters inside cells never corrupt column structure and no rows are truncated.
 */
export function redactCsvCells(
  parsed: ParsedCsv,
  mode: RedactionMode,
  options: DetectionOptions,
  neutralizeFormulas = true,
): { sanitizedHeaders: string[]; sanitizedRows: string[][]; serializedCsv: string } {
  if (!parsed.isTabular) {
    return { sanitizedHeaders: [], sanitizedRows: [], serializedCsv: '' };
  }

  const sharedSession = createPseudonymSession();
  const sanitizedHeaders = parsed.headers.map((h) => redactText(h, mode, options, sharedSession, true).sanitizedText);
  const sanitizedRows = parsed.rows.map((row) =>
    row.map((cell) => redactText(cell, mode, options, sharedSession, true).sanitizedText),
  );

  return {
    sanitizedHeaders,
    sanitizedRows,
    serializedCsv: serializeCsvRows(sanitizedHeaders, sanitizedRows, neutralizeFormulas),
  };
}

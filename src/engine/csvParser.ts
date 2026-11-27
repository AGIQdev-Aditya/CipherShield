import { DetectionOptions, RedactionMode } from '../types/pii';
import { createPseudonymSession, redactText } from './redactor';

export interface ParsedCsv {
  headers: string[];
  rows: string[][];
  isTabular: boolean;
  parseError: string | null;
}

/**
 * Parses all CSV records strictly per RFC-4180 while preserving cell whitespace
 * (strips UTF-8 BOM + trailing line endings only, validates quotes & column parity).
 */
export function parseCsvRows(input: string, expectCsv = false): ParsedCsv {
  const cleaned = input.replace(/^\uFEFF/, '').replace(/(?:\r\n|\n|\r)+$/, '');
  if (!cleaned) {
    return { headers: [], rows: [], isTabular: false, parseError: null };
  }

  const lines: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;
  let justClosedQuote = false;
  let quoteError: string | null = null;

  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];
    const next = cleaned[i + 1];

    if (inQuotes) {
      if (ch === '"' && next === '"') {
        cell += '"';
        i += 1;
      } else if (ch === '"') {
        inQuotes = false;
        justClosedQuote = true;
      } else {
        cell += ch;
      }
      continue;
    }

    if (justClosedQuote) {
      if (ch === ',') {
        justClosedQuote = false;
        row.push(cell);
        cell = '';
        continue;
      }
      if (ch === '\r' && next === '\n') {
        justClosedQuote = false;
        row.push(cell);
        lines.push(row);
        row = [];
        cell = '';
        i += 1;
        continue;
      }
      if (ch === '\n' || ch === '\r') {
        justClosedQuote = false;
        row.push(cell);
        lines.push(row);
        row = [];
        cell = '';
        continue;
      }
      if (!quoteError) {
        quoteError = `Malformed CSV: unexpected character "${ch}" after closing quote on row ${lines.length + 1}.`;
      }
      justClosedQuote = false;
      cell += ch;
      continue;
    }

    if (ch === '"') {
      if (cell.length > 0) {
        if (!quoteError) {
          quoteError = `Malformed CSV: unexpected unescaped quote inside unquoted field on row ${lines.length + 1}.`;
        }
        cell += ch;
      } else {
        inQuotes = true;
      }
    } else if (ch === ',') {
      row.push(cell);
      cell = '';
    } else if (ch === '\r' && next === '\n') {
      row.push(cell);
      lines.push(row);
      row = [];
      cell = '';
      i += 1;
    } else if (ch === '\n' || ch === '\r') {
      row.push(cell);
      lines.push(row);
      row = [];
      cell = '';
    } else {
      cell += ch;
    }
  }

  if (inQuotes) {
    if (expectCsv || (lines.length > 0 && lines[0].length >= 2)) {
      return { headers: [], rows: [], isTabular: false, parseError: 'Malformed CSV: unclosed quote detected.' };
    }
    return { headers: [], rows: [], isTabular: false, parseError: null };
  }

  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    lines.push(row);
  }

  if (lines.length < 2) {
    if (expectCsv && quoteError) {
      return { headers: [], rows: [], isTabular: false, parseError: quoteError };
    }
    return { headers: [], rows: [], isTabular: false, parseError: null };
  }

  const colCount = lines[0].length;
  if (colCount < 2) {
    return { headers: [], rows: [], isTabular: false, parseError: expectCsv && quoteError ? quoteError : null };
  }

  if (quoteError && (expectCsv || colCount >= 2)) {
    return { headers: [], rows: [], isTabular: false, parseError: quoteError };
  }

  const badRowIdx = lines.findIndex((r) => r.length !== colCount);
  if (badRowIdx !== -1) {
    return {
      headers: [],
      rows: [],
      isTabular: false,
      parseError: expectCsv
        ? `Malformed CSV: row ${badRowIdx + 1} has ${lines[badRowIdx].length} columns (expected ${colCount}).`
        : null,
    };
  }

  return {
    headers: lines[0],
    rows: lines.slice(1),
    isTabular: true,
    parseError: null,
  };
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
  const sanitizedHeaders = parsed.headers.map((h) => redactText(h, mode, options, sharedSession).sanitizedText);
  const sanitizedRows = parsed.rows.map((row) =>
    row.map((cell) => redactText(cell, mode, options, sharedSession).sanitizedText),
  );

  return {
    sanitizedHeaders,
    sanitizedRows,
    serializedCsv: serializeCsvRows(sanitizedHeaders, sanitizedRows, neutralizeFormulas),
  };
}

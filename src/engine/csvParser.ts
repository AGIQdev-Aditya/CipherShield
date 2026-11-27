import { DetectionOptions, RedactionMode } from '../types/pii';
import { createPseudonymSession, redactText } from './redactor';

export interface ParsedCsv {
  headers: string[];
  rows: string[][];
  isTabular: boolean;
  parseError: string | null;
}

/**
 * Parses all CSV records cleanly per RFC-4180 (stripping UTF-8 BOM, detecting unclosed quotes, no silent row truncation).
 */
export function parseCsvRows(input: string): ParsedCsv {
  const cleaned = input.replace(/^\uFEFF/, '').trim();
  if (!cleaned) {
    return { headers: [], rows: [], isTabular: false, parseError: null };
  }

  const lines: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;

  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];
    const next = cleaned[i + 1];

    if (inQuotes) {
      if (ch === '"' && next === '"') {
        cell += '"';
        i += 1;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        cell += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
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
    return { headers: [], rows: [], isTabular: false, parseError: 'Malformed CSV: unclosed quote detected.' };
  }

  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    lines.push(row);
  }

  if (lines.length < 2) {
    return { headers: [], rows: [], isTabular: false, parseError: null };
  }

  const colCount = lines[0].length;
  const consistent = colCount >= 2 && lines.every((r) => r.length === colCount);
  if (!consistent) {
    return { headers: [], rows: [], isTabular: false, parseError: null };
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

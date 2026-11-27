import { DetectionOptions, RedactionMode } from '../types/pii';
import { redactText } from './redactor';

export interface ParsedCsv {
  headers: string[];
  rows: string[][];
  isTabular: boolean;
}

/**
 * Parses CSV text cleanly according to RFC-4180 quoted field semantics.
 */
export function parseCsvRows(input: string, maxRows = 500): ParsedCsv {
  const trimmed = input.trim();
  if (!trimmed) {
    return { headers: [], rows: [], isTabular: false };
  }

  const lines: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;

  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i];
    const next = trimmed[i + 1];

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

    if (lines.length >= maxRows + 1) break;
  }

  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    lines.push(row);
  }

  if (lines.length < 2) {
    return { headers: [], rows: [], isTabular: false };
  }

  const colCount = lines[0].length;
  const consistent = colCount >= 2 && lines.every((r) => r.length === colCount);
  if (!consistent) {
    return { headers: [], rows: [], isTabular: false };
  }

  return {
    headers: lines[0],
    rows: lines.slice(1),
    isTabular: true,
  };
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
export function serializeCsvRows(headers: string[], rows: string[][]): string {
  const allRows = [headers, ...rows];
  return allRows.map((r) => r.map(escapeCsvCell).join(',')).join('\n');
}

/**
 * Redacts a CSV document cell-by-cell while preserving column boundaries and RFC-4180 quoting.
 */
export function redactCsvCells(
  parsed: ParsedCsv,
  mode: RedactionMode,
  options: DetectionOptions,
): { sanitizedRows: string[][]; serializedCsv: string } {
  if (!parsed.isTabular) {
    return { sanitizedRows: [], serializedCsv: '' };
  }

  // Run single-document redaction per cell using consistent counter state via joined sentinel?
  // Wait: running redactText on each cell individually would reset pseudonym counters per row!
  // Instead, redact row cells directly with a safe ASCII Record Separator (\u001E) & Unit Separator (\u001F),
  // then split cleanly and re-serialize with RFC-4180 escaping so USER_01 stays globally consistent!
  const ROW_SEP = '\u001E';
  const COL_SEP = '\u001F';
  const packed = parsed.rows.map((r) => r.join(COL_SEP)).join(ROW_SEP);
  const redacted = redactText(packed, mode, options);
  const sanitizedRows = redacted.sanitizedText
    .split(ROW_SEP)
    .map((line) => line.split(COL_SEP));

  return {
    sanitizedRows,
    serializedCsv: serializeCsvRows(parsed.headers, sanitizedRows),
  };
}

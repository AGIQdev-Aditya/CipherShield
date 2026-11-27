export interface ParsedCsv {
  headers: string[];
  rows: string[][];
  isTabular: boolean;
}

/**
 * Parses CSV text cleanly according to RFC-4180 quoted field semantics.
 */
export function parseCsvRows(input: string, maxRows = 250): ParsedCsv {
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

// Minimal, dependency-free RFC 4180-ish CSV parser. Deliberately tolerant
// of malformed input (T16): an unterminated quote, a ragged row (too few
// or too many columns), or a trailing newline never throws — the parser
// always returns whatever rows it could recover rather than crashing or
// silently truncating without indication (the caller normalizers turn
// row-shape irregularities into NormalizeIssues).

export function parseCsv(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let i = 0;
  const n = input.length;

  function endField() {
    row.push(field);
    field = "";
  }
  function endRow() {
    endField();
    rows.push(row);
    row = [];
  }

  while (i < n) {
    const c = input[i];
    if (inQuotes) {
      if (c === '"') {
        if (input[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      field += c;
      i += 1;
      continue;
    }
    if (c === '"' && field.length === 0) {
      inQuotes = true;
      i += 1;
      continue;
    }
    if (c === ",") {
      endField();
      i += 1;
      continue;
    }
    if (c === "\r") {
      i += 1;
      continue;
    }
    if (c === "\n") {
      endRow();
      i += 1;
      continue;
    }
    field += c;
    i += 1;
  }
  // Flush a trailing unterminated quote/field/row rather than dropping it —
  // an oversized or truncated file still yields whatever data preceded the
  // truncation point.
  if (field.length > 0 || row.length > 0) {
    endRow();
  }
  // Drop fully empty trailing rows produced by a trailing newline.
  return rows.filter((r) => !(r.length === 1 && r[0] === ""));
}

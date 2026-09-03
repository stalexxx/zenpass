import type { NormalizeResult } from "@zkpm/domain";
import { normalizeCsv } from "./csv.ts";

// 1Password's classic CSV export template (Title,Website,Username,
// Password,Notes — headers vary slightly across 1Password versions, e.g.
// "Website"/"URL", all covered by the generic CSV header-alias table)
// normalizes cleanly through the same engine as any other CSV export; only
// the item `source` tag differs.
//
// 1Password's newer 1PUX export format is a zip archive of JSON plus
// attachments, not a flat text file — parsing it needs zip/streaming
// support this package deliberately does not add as a new dependency
// (see the C02 completion report's Follow-up tasks). 1PUX import is
// therefore deferred; use a 1Password CSV export in the meantime.

export function normalizeOnePasswordCsv(input: string): NormalizeResult {
  const result = normalizeCsv(input);
  return {
    items: result.items.map((item) => ({ ...item, source: "1password" as const })),
    issues: result.issues,
  };
}

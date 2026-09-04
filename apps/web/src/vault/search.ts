// In-memory search over decrypted item metadata. Pure functions over a
// plain array/map the caller (VaultSession) owns and clears on lock — this
// module has no state and persists nothing itself.
export interface SearchEntry {
  itemId: string;
  title: string;
  username?: string;
  url?: string;
  type: string;
}

export function searchItems(entries: SearchEntry[], query: string): SearchEntry[] {
  const q = query.trim().toLowerCase();
  if (q.length === 0) return entries;
  return entries.filter((e) =>
    e.title.toLowerCase().includes(q) ||
    (e.username?.toLowerCase().includes(q) ?? false) ||
    (e.url?.toLowerCase().includes(q) ?? false),
  );
}

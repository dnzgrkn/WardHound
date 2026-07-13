import type { ActionAuditRecord } from "@/lib/types";

const CACHE_KEY = "wardhound.action-records.v1";

export function loadActionRecords(): ActionAuditRecord[] {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ActionAuditRecord[]) : [];
  } catch {
    return [];
  }
}

export function cacheActionRecords(records: ActionAuditRecord[]): void {
  localStorage.setItem(CACHE_KEY, JSON.stringify(records));
}

export function upsertActionRecord(
  records: ActionAuditRecord[],
  incoming: ActionAuditRecord,
): ActionAuditRecord[] {
  const exists = records.some((record) => record.id === incoming.id);
  return exists
    ? records.map((record) => (record.id === incoming.id ? incoming : record))
    : [incoming, ...records];
}

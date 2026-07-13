import type { NormalizedEntity } from "@/lib/types";

export function label(value: string): string {
  return value
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

export function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

export function entityName(entity: NormalizedEntity): string {
  if (entity.username) return entity.domain ? `${entity.domain}\\${entity.username}` : entity.username;
  return entity.hostname ?? entity.mac_address ?? entity.ip_address ?? "Unknown entity";
}

export function confidenceBand(confidence: number): string {
  if (confidence >= 0.8) return "High confidence";
  if (confidence >= 0.55) return "Moderate confidence";
  return "Low confidence";
}

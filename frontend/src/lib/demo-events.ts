import type { NormalizedEntity, NormalizedEvent } from "@/lib/types";

export function createSyntheticDemoEvents(): NormalizedEvent[] {
  const now = Date.now();
  const user: NormalizedEntity = {
    entity_type: "user",
    username: "jdoe",
    domain: "CORP",
    mac_address: null,
    hostname: null,
    ip_address: null,
  };
  const workstation: NormalizedEntity = {
    entity_type: "device",
    username: null,
    domain: null,
    mac_address: "AA:BB:CC:DD:EE:FF",
    hostname: "WKSTN-0042",
    ip_address: "10.20.30.40",
  };
  const privilegedTarget: NormalizedEntity = {
    entity_type: "device",
    username: null,
    domain: null,
    mac_address: null,
    hostname: "SRV-T0-0042",
    ip_address: "10.20.30.42",
  };

  return [
    event("active_directory", "auth_failed", "medium", user, [], now - 8 * 60_000),
    event(
      "packetfence",
      "device_quarantined",
      "high",
      workstation,
      [user],
      now - 4 * 60_000,
      { isolation_reason: "synthetic_auth_policy" },
    ),
    event(
      "jumpserver",
      "session_started",
      "medium",
      user,
      [privilegedTarget, workstation],
      now - 60_000,
      { id: `session-synthetic-${crypto.randomUUID().slice(0, 8)}`, remote_addr: "10.20.30.40" },
    ),
  ];
}

function event(
  sourceSystem: NormalizedEvent["source_system"],
  eventType: string,
  severity: NormalizedEvent["severity"],
  primaryEntity: NormalizedEntity,
  relatedEntities: NormalizedEntity[],
  occurredAt: number,
  extraAttributes: Record<string, unknown> = {},
): NormalizedEvent {
  return {
    id: crypto.randomUUID(),
    raw_event_id: crypto.randomUUID(),
    source_system: sourceSystem,
    event_type: eventType,
    severity,
    primary_entity: primaryEntity,
    related_entities: relatedEntities,
    occurred_at: new Date(occurredAt).toISOString(),
    normalized_at: new Date().toISOString(),
    extra_attributes: extraAttributes,
  };
}

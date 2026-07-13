import type {
  ActionAuditRecord,
  Incident,
  IncidentDetail,
  NormalizedEntity,
  NormalizedEvent,
  RecommendedAction,
  RootCauseAnalysis,
} from "@/lib/types";

export const userEntity: NormalizedEntity = {
  entity_type: "user",
  username: "jdoe",
  domain: "CORP",
  mac_address: null,
  hostname: null,
  ip_address: null,
};

export const deviceEntity: NormalizedEntity = {
  entity_type: "device",
  username: null,
  domain: null,
  mac_address: "AA:BB:CC:DD:EE:FF",
  hostname: "WKSTN-0042",
  ip_address: "10.20.30.40",
};

export const incident: Incident = {
  id: "11111111-1111-4111-8111-111111111111",
  title: "Cross-system access after authentication failure and isolation",
  summary: "Synthetic identity failure, NAC containment, and privileged session evidence correlated.",
  event_ids: ["22222222-2222-4222-8222-222222222222"],
  entities: [userEntity, deviceEntity],
  severity: "critical",
  risk_score: 76,
  status: "open",
  created_at: "2026-07-13T09:08:00Z",
  correlation_rule_id: "cross_system_auth_quarantine_session",
  policy_violations: [],
};

export const event: NormalizedEvent = {
  id: "22222222-2222-4222-8222-222222222222",
  raw_event_id: "33333333-3333-4333-8333-333333333333",
  source_system: "packetfence",
  event_type: "device_quarantined",
  severity: "high",
  primary_entity: deviceEntity,
  related_entities: [userEntity],
  occurred_at: "2026-07-13T09:04:00Z",
  normalized_at: "2026-07-13T09:04:01Z",
  extra_attributes: {},
};

export const recommendation: RecommendedAction = {
  action_type: "quarantine_device",
  rationale: "Retain synthetic NAC isolation while an operator validates the access chain.",
  requires_approval: true,
};

export const analysis: RootCauseAnalysis = {
  probable_cause: "A synthetic endpoint continued toward privileged access after identity failure.",
  confidence: 0.87,
  evidence: [{ event_id: event.id, description: "PacketFence isolated the synthetic endpoint." }],
  recommended_actions: [recommendation],
  side_effects: "Isolation may interrupt an authorized administrative workflow.",
};

export const detail: IncidentDetail = { incident, evidence: [event], analysis };

export const pendingRecord: ActionAuditRecord = {
  id: "44444444-4444-4444-8444-444444444444",
  action: recommendation,
  incident_id: incident.id,
  context: { entities: [userEntity, deviceEntity], session_id: null },
  approval_status: "pending",
  decided_by: null,
  decided_at: null,
  reason: null,
  execution_status: "not_executed",
  result: null,
  requested_at: "2026-07-13T09:10:00Z",
};

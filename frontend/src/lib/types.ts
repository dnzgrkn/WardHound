export type Severity = "low" | "medium" | "high" | "critical";
export type IncidentStatus = "open" | "acknowledged" | "resolved";
export type SourceSystem =
  | "packetfence"
  | "jumpserver"
  | "active_directory"
  | "firewall";
export type EntityType = "user" | "device" | "ip_address";

export interface NormalizedEntity {
  entity_type: EntityType;
  username: string | null;
  domain: string | null;
  mac_address: string | null;
  hostname: string | null;
  ip_address: string | null;
}

export interface NormalizedEvent {
  id: string;
  raw_event_id: string;
  source_system: SourceSystem;
  event_type: string;
  severity: Severity;
  primary_entity: NormalizedEntity;
  related_entities: NormalizedEntity[];
  occurred_at: string;
  normalized_at: string;
  extra_attributes: Record<string, unknown>;
}

export interface PolicyViolation {
  rule_id: string;
  title: string;
  description: string;
  event_ids: string[];
  entities: NormalizedEntity[];
  severity: Severity;
}

export interface Incident {
  id: string;
  title: string;
  summary: string;
  event_ids: string[];
  entities: NormalizedEntity[];
  severity: Severity;
  risk_score: number;
  status: IncidentStatus;
  created_at: string;
  correlation_rule_id: string;
  policy_violations: PolicyViolation[];
}

export type ResponseActionType =
  | "quarantine_device"
  | "disable_user"
  | "block_ip"
  | "close_session"
  | "require_mfa"
  | "notify_administrator"
  | "create_incident"
  | "require_manual_approval";

export interface RecommendedAction {
  action_type: ResponseActionType;
  rationale: string;
  requires_approval: boolean;
}

export interface AnalysisEvidence {
  event_id: string;
  description: string;
}

export interface RootCauseAnalysis {
  probable_cause: string;
  confidence: number;
  evidence: AnalysisEvidence[];
  recommended_actions: RecommendedAction[];
  side_effects: string;
}

export interface IncidentDetail {
  incident: Incident;
  evidence: NormalizedEvent[];
  analysis: RootCauseAnalysis | null;
}

export type ApprovalStatus = "pending" | "approved" | "rejected" | "auto_approved";
export type ExecutionStatus = "not_executed" | "simulated" | "failed";

export interface ActionAuditRecord {
  id: string;
  action: RecommendedAction;
  incident_id: string | null;
  context: {
    entities: NormalizedEntity[];
    session_id: string | null;
  };
  approval_status: ApprovalStatus;
  decided_by: string | null;
  decided_at: string | null;
  reason: string | null;
  execution_status: ExecutionStatus;
  result: {
    description: string;
    target_identifier: string | null;
    details: Record<string, unknown>;
  } | null;
  requested_at: string;
}

export interface IncidentFilters {
  severity?: Severity;
  status?: IncidentStatus;
  sortBy: "created_at" | "risk_score";
  order: "asc" | "desc";
}

export type RealtimeMessage =
  | { type: "incident_created" | "incident_updated"; payload: Incident }
  | { type: "action_updated"; payload: ActionAuditRecord };

export type RealtimeStatus = "connecting" | "live" | "reconnecting" | "offline";

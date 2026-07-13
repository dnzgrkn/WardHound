import type {
  ActionAuditRecord,
  Incident,
  IncidentDetail,
  IncidentFilters,
  NormalizedEvent,
  RecommendedAction,
  RootCauseAnalysis,
} from "@/lib/types";

interface ApiErrorPayload {
  code?: string;
  message?: string;
  detail?: string;
}

export class ApiClientError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
    this.name = "ApiClientError";
  }
}

export interface WardHoundApi {
  listIncidents(filters: IncidentFilters): Promise<Incident[]>;
  getIncident(incidentId: string): Promise<IncidentDetail>;
  listIncidentActions(incidentId: string): Promise<ActionAuditRecord[]>;
  analyzeIncident(incidentId: string): Promise<RootCauseAnalysis>;
  ingestEvents(events: NormalizedEvent[]): Promise<Incident[]>;
  requestAction(incidentId: string, action: RecommendedAction): Promise<ActionAuditRecord>;
  approveAction(recordId: string, decidedBy: string): Promise<ActionAuditRecord>;
  rejectAction(recordId: string, decidedBy: string, reason: string): Promise<ActionAuditRecord>;
}

interface ClientOptions {
  baseUrl?: string;
  apiKey?: string;
}

export class WardHoundApiClient implements WardHoundApi {
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor(options: ClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? import.meta.env.VITE_API_BASE_URL ?? "/api/v1").replace(
      /\/$/,
      "",
    );
    this.apiKey = options.apiKey ?? import.meta.env.VITE_API_KEY ?? "";
  }

  listIncidents(filters: IncidentFilters): Promise<Incident[]> {
    const query = new URLSearchParams({ sort_by: filters.sortBy, order: filters.order });
    if (filters.severity) query.set("severity", filters.severity);
    if (filters.status) query.set("status", filters.status);
    return this.request<Incident[]>(`/incidents?${query.toString()}`);
  }

  getIncident(incidentId: string): Promise<IncidentDetail> {
    return this.request<IncidentDetail>(`/incidents/${incidentId}`);
  }

  listIncidentActions(incidentId: string): Promise<ActionAuditRecord[]> {
    return this.request<ActionAuditRecord[]>(`/incidents/${incidentId}/actions`);
  }

  analyzeIncident(incidentId: string): Promise<RootCauseAnalysis> {
    return this.request<RootCauseAnalysis>(`/incidents/${incidentId}/analyze`, {
      method: "POST",
    });
  }

  ingestEvents(events: NormalizedEvent[]): Promise<Incident[]> {
    return this.request<Incident[]>("/events", {
      method: "POST",
      body: JSON.stringify({ events }),
    });
  }

  requestAction(
    incidentId: string,
    action: RecommendedAction,
  ): Promise<ActionAuditRecord> {
    return this.request<ActionAuditRecord>(`/incidents/${incidentId}/actions`, {
      method: "POST",
      body: JSON.stringify(action),
    });
  }

  approveAction(recordId: string, decidedBy: string): Promise<ActionAuditRecord> {
    return this.request<ActionAuditRecord>(`/actions/${recordId}/approve`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy }),
    });
  }

  rejectAction(
    recordId: string,
    decidedBy: string,
    reason: string,
  ): Promise<ActionAuditRecord> {
    return this.request<ActionAuditRecord>(`/actions/${recordId}/reject`, {
      method: "POST",
      body: JSON.stringify({ decided_by: decidedBy, reason }),
    });
  }

  private async request<Response>(path: string, init: RequestInit = {}): Promise<Response> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-API-Key": this.apiKey,
        ...init.headers,
      },
    });
    if (!response.ok) {
      const payload = await parseErrorPayload(response);
      throw new ApiClientError(
        payload.message ?? payload.detail ?? `API request failed with status ${response.status}`,
        response.status,
        payload.code ?? "api_request_failed",
      );
    }
    return (await response.json()) as Response;
  }
}

async function parseErrorPayload(response: Response): Promise<ApiErrorPayload> {
  try {
    const payload: unknown = await response.json();
    return isObject(payload) ? payload : {};
  } catch {
    return {};
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export const apiClient = new WardHoundApiClient();

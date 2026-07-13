import type { Incident, RealtimeMessage, RealtimeStatus } from "@/lib/types";

export interface RealtimeConnection {
  close(): void;
}

export function upsertIncident(incidents: Incident[], incoming: Incident): Incident[] {
  const index = incidents.findIndex((incident) => incident.id === incoming.id);
  if (index < 0) return [incoming, ...incidents];
  return incidents.map((incident) => (incident.id === incoming.id ? incoming : incident));
}

export function applyIncidentMessage(
  incidents: Incident[],
  message: RealtimeMessage,
): Incident[] {
  return message.type === "action_updated"
    ? incidents
    : upsertIncident(incidents, message.payload);
}

export function connectRealtime(
  onMessage: (message: RealtimeMessage) => void,
  onStatus: (status: RealtimeStatus) => void,
): RealtimeConnection {
  let websocket: WebSocket | null = null;
  let reconnectTimer: number | null = null;
  let attempts = 0;
  let closed = false;

  const connect = (): void => {
    onStatus(attempts === 0 ? "connecting" : "reconnecting");
    websocket = new WebSocket(websocketUrl());
    websocket.addEventListener("open", () => {
      attempts = 0;
      onStatus("live");
    });
    websocket.addEventListener("message", (event) => {
      const message = parseRealtimeMessage(event.data);
      if (message) onMessage(message);
    });
    websocket.addEventListener("close", () => {
      if (closed) return;
      onStatus("reconnecting");
      attempts += 1;
      const delay = Math.min(1_000 * 2 ** (attempts - 1), 15_000);
      reconnectTimer = window.setTimeout(connect, delay);
    });
    websocket.addEventListener("error", () => websocket?.close());
  };

  connect();
  return {
    close: () => {
      closed = true;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      websocket?.close();
      onStatus("offline");
    },
  };
}

function websocketUrl(): string {
  const configured = import.meta.env.VITE_WS_BASE_URL;
  const defaultOrigin = window.location.origin.replace(/^http/, "ws");
  const base = (configured ?? `${defaultOrigin}/api/v1`).replace(/\/$/, "");
  const query = new URLSearchParams({ api_key: import.meta.env.VITE_API_KEY ?? "" });
  return `${base}/ws/incidents?${query.toString()}`;
}

function parseRealtimeMessage(value: unknown): RealtimeMessage | null {
  if (typeof value !== "string") return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!isObject(parsed) || typeof parsed.type !== "string" || !isObject(parsed.payload)) {
      return null;
    }
    if (
      parsed.type !== "incident_created" &&
      parsed.type !== "incident_updated" &&
      parsed.type !== "action_updated"
    ) {
      return null;
    }
    return parsed as RealtimeMessage;
  } catch {
    return null;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

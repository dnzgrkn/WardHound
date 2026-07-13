import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { App } from "@/App";
import type { WardHoundApi } from "@/lib/api";
import type { RealtimeConnection } from "@/lib/realtime";
import { analysis, detail, incident, pendingRecord } from "@/test/fixtures";

const client: WardHoundApi = {
  listIncidents: () => Promise.resolve([incident]),
  getIncident: () => Promise.resolve(detail),
  analyzeIncident: () => Promise.resolve(analysis),
  ingestEvents: () => Promise.resolve([incident]),
  requestAction: () => Promise.resolve(pendingRecord),
  approveAction: () => Promise.resolve({ ...pendingRecord, approval_status: "approved", execution_status: "simulated" }),
  rejectAction: () => Promise.resolve({ ...pendingRecord, approval_status: "rejected" }),
};

function noRealtime(): RealtimeConnection {
  return { close: () => undefined };
}

describe("incident dashboard", () => {
  it("renders the incident queue from typed mocked API data", async () => {
    render(<App client={client} realtimeConnector={noRealtime} />);

    expect(await screen.findByText(incident.title)).toBeInTheDocument();
    expect(screen.getAllByText("76")).not.toHaveLength(0);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });
});

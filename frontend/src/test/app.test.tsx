import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "@/App";
import type { WardHoundApi } from "@/lib/api";
import type { PrivilegedIdentity } from "@/lib/auth";
import type { RealtimeConnection } from "@/lib/realtime";
import { analysis, detail, incident, pendingRecord } from "@/test/fixtures";

const client: WardHoundApi = {
  listIncidents: () => Promise.resolve([incident]),
  getIncident: () => Promise.resolve(detail),
  listIncidentActions: () => Promise.resolve([]),
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

  it("loads server-side action history when incident detail opens", async () => {
    const user = userEvent.setup();
    const listIncidentActions = vi.fn(() => Promise.resolve([pendingRecord]));
    render(
      <App
        client={{ ...client, listIncidentActions }}
        realtimeConnector={noRealtime}
      />,
    );

    await user.click(await screen.findByText(incident.title));

    expect(await screen.findByText("Awaiting human")).toBeInTheDocument();
    expect(listIncidentActions).toHaveBeenCalledWith(incident.id);
  });

  it("prompts for Auth0 login before an approval request", async () => {
    const user = userEvent.setup();
    const login = vi.fn(() => Promise.resolve());
    const approveAction = vi.fn(() => Promise.resolve(pendingRecord));
    const identity: PrivilegedIdentity = {
      configured: true,
      authenticated: false,
      login,
      accessToken: () => Promise.resolve("synthetic-access-token"),
    };
    render(
      <App
        client={{
          ...client,
          listIncidentActions: () => Promise.resolve([pendingRecord]),
          approveAction,
        }}
        realtimeConnector={noRealtime}
        identity={identity}
      />,
    );

    await user.click(await screen.findByText(incident.title));
    await user.click(await screen.findByRole("button", { name: "Approve" }));
    await user.click(screen.getByRole("button", { name: "Confirm approval" }));

    expect(login).toHaveBeenCalledOnce();
    expect(approveAction).not.toHaveBeenCalled();
  });
});

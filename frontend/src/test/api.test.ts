import { afterEach, describe, expect, it, vi } from "vitest";

import { WardHoundApiClient } from "@/lib/api";
import { pendingRecord } from "@/test/fixtures";

describe("WardHoundApiClient decisions", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("sends approve and reject decisions to their typed endpoints", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      void input;
      void init;
      return Promise.resolve(new Response(JSON.stringify(pendingRecord), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new WardHoundApiClient({ baseUrl: "http://api.test/api/v1", apiKey: "synthetic-key" });

    await client.approveAction(pendingRecord.id, "synthetic-access-token");
    await client.rejectAction(
      pendingRecord.id,
      "Expected synthetic activity.",
      "synthetic-access-token",
    );

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      `http://api.test/api/v1/actions/${pendingRecord.id}/approve`,
    );
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toMatchObject({
      Authorization: "Bearer synthetic-access-token",
    });
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      `http://api.test/api/v1/actions/${pendingRecord.id}/reject`,
    );
    expect(fetchMock.mock.calls[1]?.[1]?.body).toBe(
      JSON.stringify({ reason: "Expected synthetic activity." }),
    );
    expect(fetchMock.mock.calls[1]?.[1]?.headers).toMatchObject(
      { Authorization: "Bearer synthetic-access-token" },
    );
  });

  it("loads current action snapshots for an incident", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      void input;
      void init;
      return Promise.resolve(new Response(JSON.stringify([pendingRecord]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = new WardHoundApiClient({
      baseUrl: "http://api.test/api/v1",
      apiKey: "synthetic-key",
    });

    await client.listIncidentActions(pendingRecord.incident_id ?? "");

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      `http://api.test/api/v1/incidents/${pendingRecord.incident_id}/actions`,
    );
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toMatchObject({
      "X-API-Key": "synthetic-key",
    });
  });
});

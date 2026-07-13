import { afterEach, describe, expect, it, vi } from "vitest";

import { WardHoundApiClient } from "@/lib/api";
import { pendingRecord } from "@/test/fixtures";

describe("WardHoundApiClient decisions", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("sends approve and reject decisions to their typed endpoints", async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(pendingRecord), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })));
    vi.stubGlobal("fetch", fetchMock);
    const client = new WardHoundApiClient({ baseUrl: "http://api.test/api/v1", apiKey: "synthetic-key" });

    await client.approveAction(pendingRecord.id, "analyst-01");
    await client.rejectAction(pendingRecord.id, "analyst-01", "Expected synthetic activity.");

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      `http://api.test/api/v1/actions/${pendingRecord.id}/approve`,
      expect.objectContaining({ body: JSON.stringify({ decided_by: "analyst-01" }) }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `http://api.test/api/v1/actions/${pendingRecord.id}/reject`,
      expect.objectContaining({
        body: JSON.stringify({ decided_by: "analyst-01", reason: "Expected synthetic activity." }),
      }),
    );
  });
});

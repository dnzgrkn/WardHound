import { describe, expect, it } from "vitest";

import { applyIncidentMessage } from "@/lib/realtime";
import { incident } from "@/test/fixtures";

describe("realtime incident state", () => {
  it("merges an incident update without refetching the queue", () => {
    const updated = { ...incident, risk_score: 91, severity: "critical" as const };

    const result = applyIncidentMessage(
      [incident],
      { type: "incident_updated", payload: updated },
    );

    expect(result).toHaveLength(1);
    expect(result[0]?.risk_score).toBe(91);
  });
});

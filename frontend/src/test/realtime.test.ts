import { describe, expect, it } from "vitest";

import { applyAnalysisMessage, applyIncidentMessage } from "@/lib/realtime";
import { analysis, detail, incident } from "@/test/fixtures";

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

  it("applies a completed analysis to the open incident detail", () => {
    const completed = {
      ...analysis,
      probable_cause: "A second operator completed the structured analysis.",
    };

    const result = applyAnalysisMessage(
      { ...detail, analysis: null },
      {
        type: "analysis_completed",
        payload: { incident_id: incident.id, analysis: completed },
      },
    );

    expect(result?.analysis).toEqual(completed);
  });
});

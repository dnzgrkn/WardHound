import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ActionCard } from "@/components/action-card";
import { pendingRecord, recommendation } from "@/test/fixtures";

describe("human approval controls", () => {
  it("requires a rejection reason before submitting the decision", async () => {
    const user = userEvent.setup();
    const onReject = vi.fn(() => Promise.resolve());
    render(
      <ActionCard
        action={recommendation}
        record={pendingRecord}
        busy={false}
        onSubmit={() => Promise.resolve()}
        onApprove={() => Promise.resolve()}
        onReject={onReject}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Reject" }));
    const confirm = screen.getByRole("button", { name: "Confirm rejection" });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText("Rejection reason"), "Expected synthetic activity.");
    expect(confirm).toBeEnabled();
    await user.click(confirm);

    expect(onReject).toHaveBeenCalledWith(
      pendingRecord.id,
      "analyst-01",
      "Expected synthetic activity.",
    );
  });
});

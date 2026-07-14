import { Gavel } from "lucide-react";

import { ActionCard } from "@/components/action-card";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ActionAuditRecord, RecommendedAction } from "@/lib/types";

export function ActionSection({
  incidentId,
  recommendations,
  records,
  busyId,
  onSubmit,
  onApprove,
  onReject,
}: {
  incidentId: string;
  recommendations: RecommendedAction[];
  records: ActionAuditRecord[];
  busyId: string | null;
  onSubmit: (action: RecommendedAction) => Promise<void>;
  onApprove: (recordId: string) => Promise<void>;
  onReject: (recordId: string, reason: string) => Promise<void>;
}) {
  const incidentRecords = records.filter((record) => record.incident_id === incidentId);
  const actions = recommendations.length > 0 ? recommendations : incidentRecords.map((record) => record.action);
  if (actions.length === 0) return <></>;
  return (
    <Card className="border-amber-300/15 bg-card/75 panel-glow">
      <CardHeader>
        <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.15em] text-amber-200"><Gavel className="h-3.5 w-3.5" />Human-in-the-loop control</div>
        <CardTitle>Recommended response actions</CardTitle>
        <CardDescription>Every action is simulated. Privileged responses remain blocked until a human explicitly approves them.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        {actions.map((action, index) => {
          const record = incidentRecords.find((candidate) => candidate.action.action_type === action.action_type && candidate.action.rationale === action.rationale);
          return (
            <ActionCard
              key={`${action.action_type}-${index}`}
              action={action}
              record={record}
              busy={busyId === (record?.id ?? action.action_type)}
              onSubmit={onSubmit}
              onApprove={onApprove}
              onReject={onReject}
            />
          );
        })}
      </CardContent>
    </Card>
  );
}

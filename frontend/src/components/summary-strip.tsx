import { AlertOctagon, Gauge, ListChecks, ShieldAlert } from "lucide-react";

import type { ActionAuditRecord, Incident } from "@/lib/types";

export function SummaryStrip({
  incidents,
  actions,
}: {
  incidents: Incident[];
  actions: ActionAuditRecord[];
}) {
  const critical = incidents.filter((incident) => incident.severity === "critical").length;
  const averageRisk = incidents.length
    ? Math.round(incidents.reduce((total, incident) => total + incident.risk_score, 0) / incidents.length)
    : 0;
  const pending = actions.filter((record) => record.approval_status === "pending").length;
  const values = [
    { label: "Visible incidents", value: incidents.length, icon: ListChecks, tone: "text-slate-200" },
    { label: "Critical", value: critical, icon: AlertOctagon, tone: "text-red-300" },
    { label: "Mean risk", value: averageRisk, icon: Gauge, tone: "text-amber-200" },
    { label: "Awaiting decision", value: pending, icon: ShieldAlert, tone: "text-primary" },
  ];
  return (
    <div className="grid grid-cols-2 overflow-hidden rounded-lg border border-border bg-card/75 panel-glow lg:grid-cols-4">
      {values.map(({ label: itemLabel, value, icon: Icon, tone }, index) => (
        <div
          key={itemLabel}
          className={`flex items-center gap-4 p-4 sm:p-5 ${index > 0 ? "border-l border-border/70" : ""}`}
        >
          <div className={`flex h-9 w-9 items-center justify-center rounded-md bg-muted ${tone}`}>
            <Icon className="h-4 w-4" />
          </div>
          <div>
            <div className="font-mono-data text-xl font-bold leading-none">{value}</div>
            <div className="mt-1 text-[10px] font-semibold uppercase tracking-[0.13em] text-muted-foreground">{itemLabel}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

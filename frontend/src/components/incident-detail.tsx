import { ArrowLeft, Boxes, Braces, Fingerprint, LoaderCircle, ShieldCheck, TriangleAlert } from "lucide-react";

import { ActionSection } from "@/components/action-section";
import { AnalysisPanel } from "@/components/analysis-panel";
import { EvidenceTimeline } from "@/components/evidence-timeline";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { entityName, formatTimestamp, label } from "@/lib/format";
import type { ActionAuditRecord, IncidentDetail as Detail, RecommendedAction } from "@/lib/types";

export function IncidentDetailView({
  detail,
  loading,
  analysisLoading,
  analysisError,
  actionError,
  actionBusyId,
  actionRecords,
  onBack,
  onAnalyze,
  onSubmitAction,
  onApprove,
  onReject,
}: {
  detail: Detail | null;
  loading: boolean;
  analysisLoading: boolean;
  analysisError: string | null;
  actionError: string | null;
  actionBusyId: string | null;
  actionRecords: ActionAuditRecord[];
  onBack: () => void;
  onAnalyze: () => void;
  onSubmitAction: (action: RecommendedAction) => Promise<void>;
  onApprove: (recordId: string, decidedBy: string) => Promise<void>;
  onReject: (recordId: string, decidedBy: string, reason: string) => Promise<void>;
}) {
  if (loading || !detail) {
    return (
      <div className="flex min-h-[55vh] items-center justify-center text-muted-foreground">
        <LoaderCircle className="mr-3 h-5 w-5 animate-spin text-primary" /> Loading incident evidence…
      </div>
    );
  }
  const { incident, evidence, analysis } = detail;
  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" className="-ml-3 text-muted-foreground" onClick={onBack}><ArrowLeft className="h-4 w-4" />Back to incident queue</Button>
      <div className="flex flex-col justify-between gap-5 border-b border-border/70 pb-6 lg:flex-row lg:items-end">
        <div className="max-w-4xl">
          <div className="mb-3 flex flex-wrap items-center gap-2"><SeverityBadge severity={incident.severity} /><span className="rounded-full border border-border bg-card px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.12em]">{label(incident.status)}</span></div>
          <h1 className="text-balance font-display text-3xl font-bold leading-tight sm:text-4xl">{incident.title}</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-muted-foreground">{incident.summary}</p>
        </div>
        <div className="flex items-center gap-5 rounded-lg border border-border bg-card/65 px-5 py-4 panel-glow">
          <div><div className="text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">Risk score</div><div className="font-mono-data text-3xl font-bold">{Math.round(incident.risk_score)}<span className="text-sm text-muted-foreground">/100</span></div></div>
          <div className="h-10 w-px bg-border" />
          <div><div className="text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">Created</div><div className="mt-1 font-mono-data text-xs">{formatTimestamp(incident.created_at)}</div></div>
        </div>
      </div>

      {actionError && <div className="flex items-start gap-2 rounded-md border border-red-400/25 bg-red-500/10 p-4 text-sm text-red-200" role="alert"><TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />{actionError}</div>}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-6">
          <AnalysisPanel analysis={analysis} loading={analysisLoading} error={analysisError} onAnalyze={onAnalyze} />
          <ActionSection
            incidentId={incident.id}
            recommendations={analysis?.recommended_actions ?? []}
            records={actionRecords}
            busyId={actionBusyId}
            onSubmit={onSubmitAction}
            onApprove={onApprove}
            onReject={onReject}
          />
          <EvidenceTimeline events={evidence} />
        </div>
        <aside className="space-y-5">
          <Card className="bg-card/70">
            <CardHeader className="pb-3"><CardTitle className="flex items-center gap-2 text-base"><Boxes className="h-4 w-4 text-primary" />Involved entities</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {incident.entities.map((entity, index) => (
                <div key={`${entityName(entity)}-${index}`} className="rounded-md border border-border/70 bg-background/45 p-3">
                  <div className="text-sm font-semibold">{entityName(entity)}</div>
                  <div className="mt-1 text-[10px] font-bold uppercase tracking-[0.13em] text-muted-foreground">{label(entity.entity_type)}</div>
                </div>
              ))}
            </CardContent>
          </Card>
          <Card className="bg-card/70">
            <CardHeader className="pb-3"><CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="h-4 w-4 text-primary" />Policy findings</CardTitle></CardHeader>
            <CardContent>
              {incident.policy_violations.length === 0 ? <p className="text-sm leading-6 text-muted-foreground">No configured policy rule added an independent violation.</p> : incident.policy_violations.map((violation) => (
                <div key={violation.rule_id} className="mb-3 rounded-md border border-amber-400/20 bg-amber-400/[0.06] p-3 last:mb-0"><div className="text-sm font-semibold">{violation.title}</div><p className="mt-1 text-xs leading-5 text-muted-foreground">{violation.description}</p></div>
              ))}
            </CardContent>
          </Card>
          <Card className="bg-card/70">
            <CardContent className="space-y-3 p-4">
              <MetaRow icon={Fingerprint} label="Incident ID" value={`${incident.id.slice(0, 12)}…`} />
              <MetaRow icon={Braces} label="Correlation rule" value={incident.correlation_rule_id} />
            </CardContent>
          </Card>
        </aside>
      </div>
    </div>
  );
}

function MetaRow({ icon: Icon, label: itemLabel, value }: { icon: typeof Fingerprint; label: string; value: string }) {
  return <div className="flex items-start gap-3"><Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" /><div className="min-w-0"><div className="text-[9px] font-bold uppercase tracking-[0.13em] text-muted-foreground">{itemLabel}</div><div className="mt-1 break-all font-mono-data text-[11px] text-foreground/80">{value}</div></div></div>;
}

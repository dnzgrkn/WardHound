import { ArrowRight, Clock3, Radar } from "lucide-react";

import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/severity-badge";
import { formatTimestamp, label } from "@/lib/format";
import type { Incident } from "@/lib/types";

export function IncidentTable({
  incidents,
  loading,
  onSelect,
}: {
  incidents: Incident[];
  loading: boolean;
  onSelect: (incidentId: string) => void;
}) {
  if (loading) return <IncidentTableSkeleton />;
  if (incidents.length === 0) {
    return (
      <Card className="flex min-h-80 flex-col items-center justify-center border-dashed bg-card/45 px-6 text-center">
        <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-full border border-primary/25 bg-primary/10 text-primary">
          <Radar className="h-6 w-6" />
        </div>
        <h3 className="font-display text-xl font-semibold">No incidents in this view</h3>
        <p className="mt-2 max-w-md text-sm leading-6 text-muted-foreground">
          Incidents appear here once the correlation pipeline receives a complete evidence chain. Adjust filters to review retained incidents.
        </p>
      </Card>
    );
  }
  return (
    <Card className="overflow-hidden bg-card/75 panel-glow">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead>Incident</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Risk</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="w-14"><span className="sr-only">Open</span></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {incidents.map((incident) => (
            <TableRow
              key={incident.id}
              className="group cursor-pointer"
              onClick={() => onSelect(incident.id)}
              tabIndex={0}
              onKeyDown={(event) => { if (event.key === "Enter") onSelect(incident.id); }}
            >
              <TableCell>
                <div className="max-w-xl">
                  <div className="font-display font-semibold text-foreground group-hover:text-primary">{incident.title}</div>
                  <div className="mt-1 truncate text-xs text-muted-foreground">{incident.summary}</div>
                </div>
              </TableCell>
              <TableCell><SeverityBadge severity={incident.severity} /></TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <span className="font-mono-data text-base font-bold">{Math.round(incident.risk_score)}</span>
                  <div className="h-1.5 w-14 overflow-hidden rounded-full bg-muted">
                    <div className="h-full rounded-full bg-gradient-to-r from-amber-400 to-red-500" style={{ width: `${incident.risk_score}%` }} />
                  </div>
                </div>
              </TableCell>
              <TableCell><span className="rounded-full border border-border bg-muted/60 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.12em]">{label(incident.status)}</span></TableCell>
              <TableCell>
                <div className="flex items-center gap-2 whitespace-nowrap font-mono-data text-xs text-muted-foreground"><Clock3 className="h-3.5 w-3.5" />{formatTimestamp(incident.created_at)}</div>
              </TableCell>
              <TableCell><ArrowRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-1 group-hover:text-primary" /></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  );
}

function IncidentTableSkeleton() {
  return (
    <Card className="overflow-hidden bg-card/75">
      <div className="space-y-px">
        {[0, 1, 2, 3].map((item) => (
          <div key={item} className="flex h-20 animate-pulse items-center gap-6 border-b border-border/60 px-5 last:border-0">
            <div className="h-4 w-2/5 rounded bg-muted" /><div className="h-6 w-20 rounded-full bg-muted" /><div className="h-4 w-24 rounded bg-muted" />
          </div>
        ))}
      </div>
    </Card>
  );
}

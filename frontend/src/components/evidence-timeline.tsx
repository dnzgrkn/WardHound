import { ArrowDown, Fingerprint, Network, UserRound } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/severity-badge";
import { entityName, formatTimestamp, label } from "@/lib/format";
import type { NormalizedEvent } from "@/lib/types";

export function EvidenceTimeline({ events }: { events: NormalizedEvent[] }) {
  return (
    <Card className="bg-card/75 panel-glow">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle>Correlated evidence</CardTitle>
          <span className="font-mono-data text-xs text-muted-foreground">{events.length} immutable events</span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="relative ml-3 border-l border-border/90 pl-7">
          {events.map((event, index) => (
            <article key={event.id} id={`event-${event.id}`} className="relative pb-8 last:pb-1 scroll-mt-28">
              <span className="absolute -left-[35px] top-1 flex h-4 w-4 items-center justify-center rounded-full border-2 border-card bg-primary shadow-[0_0_0_4px_hsl(var(--card))]">
                <span className="h-1.5 w-1.5 rounded-full bg-primary-foreground" />
              </span>
              <div className="rounded-lg border border-border/80 bg-background/45 p-4 transition-colors target:border-primary/50 target:bg-primary/5">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-primary">{label(event.source_system)}</span>
                      <span className="text-muted-foreground/50">/</span>
                      <span className="font-mono-data text-xs text-muted-foreground">{label(event.event_type)}</span>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
                      <span className="flex items-center gap-1.5 font-medium"><UserRound className="h-3.5 w-3.5 text-muted-foreground" />{entityName(event.primary_entity)}</span>
                      {event.related_entities.map((entity, entityIndex) => (
                        <span key={`${event.id}-${entityIndex}`} className="flex items-center gap-1.5 text-muted-foreground"><Network className="h-3.5 w-3.5" />{entityName(entity)}</span>
                      ))}
                    </div>
                  </div>
                  <SeverityBadge severity={event.severity} />
                </div>
                <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-border/60 pt-3 text-[11px] text-muted-foreground">
                  <span className="font-mono-data">{formatTimestamp(event.occurred_at)}</span>
                  <span className="flex items-center gap-1.5 font-mono-data"><Fingerprint className="h-3 w-3" />{event.id.slice(0, 8)}…</span>
                </div>
              </div>
              {index < events.length - 1 && <ArrowDown className="absolute -left-[37px] bottom-2 h-3.5 w-3.5 text-muted-foreground" />}
            </article>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

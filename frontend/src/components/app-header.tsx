import { Activity, DatabaseZap, Dog, Radio, ShieldCheck, WifiOff } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { RealtimeStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

const statusCopy: Record<RealtimeStatus, string> = {
  connecting: "Connecting",
  live: "Realtime live",
  reconnecting: "Reconnecting",
  offline: "Offline",
};

export function AppHeader({
  status,
  onLoadDemo,
  demoBusy,
}: {
  status: RealtimeStatus;
  onLoadDemo: () => void;
  demoBusy: boolean;
}) {
  const StatusIcon = status === "live" ? Radio : status === "offline" ? WifiOff : Activity;
  return (
    <header className="sticky top-0 z-40 border-b border-border/80 bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex h-[72px] max-w-[1500px] items-center justify-between px-4 sm:px-6 lg:px-8">
        <div className="flex items-center gap-3">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
            <Dog className="h-5 w-5" />
            <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-primary shadow-[0_0_12px_rgba(35,202,164,0.9)]" />
          </div>
          <div>
            <div className="flex items-baseline gap-2">
              <span className="font-display text-lg font-bold tracking-tight">WardHound</span>
              <span className="hidden font-mono-data text-[10px] uppercase tracking-[0.18em] text-muted-foreground sm:inline">SOC console</span>
            </div>
            <p className="text-xs text-muted-foreground">Tracing incidents back to root cause</p>
          </div>
        </div>
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="hidden items-center gap-2 rounded-md border border-border bg-card/70 px-3 py-2 text-xs text-muted-foreground md:flex">
            <ShieldCheck className="h-3.5 w-3.5 text-primary" />
            Human approval enforced
          </div>
          <div className="flex items-center gap-2 rounded-md border border-border bg-card/70 px-3 py-2 text-xs">
            <StatusIcon
              className={cn("h-3.5 w-3.5", status === "live" ? "text-primary" : "text-amber-300")}
            />
            <span className="hidden sm:inline">{statusCopy[status]}</span>
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                status === "live" ? "animate-pulse-ring bg-primary" : "bg-amber-300",
              )}
            />
          </div>
          <Button variant="outline" size="sm" onClick={onLoadDemo} disabled={demoBusy}>
            <DatabaseZap className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">{demoBusy ? "Loading…" : "Load demo"}</span>
          </Button>
        </div>
      </div>
    </header>
  );
}

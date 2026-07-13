import { AlertTriangle, CircleAlert, CircleDot } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

const styles: Record<Severity, string> = {
  critical: "border-red-400/30 bg-red-500/15 text-red-300",
  high: "border-orange-400/30 bg-orange-500/15 text-orange-300",
  medium: "border-amber-400/30 bg-amber-500/15 text-amber-200",
  low: "border-sky-400/30 bg-sky-500/15 text-sky-300",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const Icon = severity === "critical" ? CircleAlert : severity === "high" ? AlertTriangle : CircleDot;
  return (
    <Badge variant="outline" className={cn("gap-1.5 py-1", styles[severity], className)}>
      <Icon className="h-3 w-3" />
      {severity}
    </Badge>
  );
}

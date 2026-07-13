import { confidenceBand } from "@/lib/format";
import { cn } from "@/lib/utils";

export function ConfidenceMeter({ confidence }: { confidence: number }) {
  const percentage = Math.round(confidence * 100);
  const tone = confidence >= 0.8 ? "from-primary to-emerald-300" : confidence >= 0.55 ? "from-amber-400 to-yellow-200" : "from-orange-500 to-red-400";
  return (
    <div className="rounded-lg border border-border bg-background/50 p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">Analytical confidence</div>
          <div className="mt-1 text-sm font-semibold">{confidenceBand(confidence)}</div>
        </div>
        <div className="font-mono-data text-2xl font-bold">{percentage}<span className="text-sm text-muted-foreground">%</span></div>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-muted">
        <div
          className={cn("h-full rounded-full bg-gradient-to-r transition-all duration-700", tone)}
          style={{ width: `${percentage}%` }}
          role="progressbar"
          aria-valuenow={percentage}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="AI analysis confidence"
        />
      </div>
    </div>
  );
}

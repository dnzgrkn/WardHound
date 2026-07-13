import { AlertCircle, BrainCircuit, ExternalLink, LoaderCircle, ShieldQuestion } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfidenceMeter } from "@/components/confidence-meter";
import type { RootCauseAnalysis } from "@/lib/types";

export function AnalysisPanel({
  analysis,
  loading,
  error,
  onAnalyze,
}: {
  analysis: RootCauseAnalysis | null;
  loading: boolean;
  error: string | null;
  onAnalyze: () => void;
}) {
  if (!analysis) {
    return (
      <Card className="overflow-hidden border-primary/20 bg-gradient-to-br from-primary/[0.07] via-card to-card panel-glow">
        <CardContent className="flex min-h-64 flex-col items-center justify-center p-8 text-center">
          <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-full border border-primary/25 bg-primary/10 text-primary">
            <BrainCircuit className="h-6 w-6" />
          </div>
          <h3 className="font-display text-xl font-semibold">Root-cause analysis not generated</h3>
          <p className="mt-2 max-w-lg text-sm leading-6 text-muted-foreground">Invoke the constrained AI analyst on demand. The response stays structured, cites only retained evidence, and cannot execute remediation.</p>
          {error && (
            <div className="mt-5 flex max-w-xl items-start gap-2 rounded-md border border-red-400/25 bg-red-500/10 px-4 py-3 text-left text-sm text-red-200" role="alert">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{error}
            </div>
          )}
          <Button className="mt-6" size="lg" onClick={onAnalyze} disabled={loading}>
            {loading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <BrainCircuit className="h-4 w-4" />}
            {loading ? "Analyzing evidence…" : "Run AI analysis"}
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-primary/20 bg-gradient-to-br from-primary/[0.055] via-card to-card panel-glow">
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.15em] text-primary"><BrainCircuit className="h-3.5 w-3.5" />Structured AI assessment</div>
            <CardTitle>Probable root cause</CardTitle>
            <CardDescription className="mt-2 max-w-3xl text-sm leading-6 text-foreground/80">{analysis.probable_cause}</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        <ConfidenceMeter confidence={analysis.confidence} />
        <div>
          <h4 className="mb-3 text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">Cited evidence</h4>
          <div className="grid gap-2">
            {analysis.evidence.map((item) => (
              <a key={item.event_id} href={`#event-${item.event_id}`} className="group flex items-start gap-3 rounded-md border border-border bg-background/45 p-3 text-sm transition-colors hover:border-primary/35 hover:bg-primary/5">
                <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded bg-primary/10 text-primary"><ExternalLink className="h-3 w-3" /></span>
                <span className="leading-5 text-foreground/85">{item.description}<span className="mt-1 block font-mono-data text-[10px] text-muted-foreground">event {item.event_id.slice(0, 8)}…</span></span>
              </a>
            ))}
          </div>
        </div>
        <div className="flex items-start gap-3 rounded-md border border-amber-400/20 bg-amber-400/[0.07] p-4">
          <ShieldQuestion className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <div><div className="text-[10px] font-bold uppercase tracking-[0.14em] text-amber-200">Operational side effects</div><p className="mt-1 text-sm leading-6 text-foreground/75">{analysis.side_effects}</p></div>
        </div>
      </CardContent>
    </Card>
  );
}

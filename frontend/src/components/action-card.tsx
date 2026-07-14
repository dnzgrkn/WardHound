import { Check, CircleCheck, Clock3, LoaderCircle, Play, ShieldAlert, XCircle } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { label } from "@/lib/format";
import type { ActionAuditRecord, RecommendedAction } from "@/lib/types";

interface ActionCardProps {
  action: RecommendedAction;
  record?: ActionAuditRecord;
  busy: boolean;
  onSubmit: (action: RecommendedAction) => Promise<void>;
  onApprove: (recordId: string) => Promise<void>;
  onReject: (recordId: string, reason: string) => Promise<void>;
}

export function ActionCard({ action, record, busy, onSubmit, onApprove, onReject }: ActionCardProps) {
  const [approveOpen, setApproveOpen] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);
  const [reason, setReason] = useState("");

  const approve = async (): Promise<void> => {
    if (!record) return;
    await onApprove(record.id);
    setApproveOpen(false);
  };
  const reject = async (): Promise<void> => {
    if (!record || !reason.trim()) return;
    await onReject(record.id, reason.trim());
    setRejectOpen(false);
    setReason("");
  };

  return (
    <div className="rounded-lg border border-border bg-background/45 p-4">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h4 className="font-display text-sm font-semibold">{label(action.action_type)}</h4>
            {action.requires_approval && !record && <Badge variant="outline" className="border-amber-400/30 bg-amber-400/10 text-amber-200">Human gate</Badge>}
            {record && <ActionStatus record={record} />}
          </div>
          <p className="mt-2 text-sm leading-5 text-muted-foreground">{action.rationale}</p>
          {record?.result && <p className="mt-3 rounded-md border border-border/70 bg-card px-3 py-2 text-xs leading-5 text-foreground/75">{record.result.description}</p>}
          {record?.reason && <p className="mt-3 text-xs text-red-200"><span className="font-bold uppercase tracking-wider">Rejected:</span> {record.reason}</p>}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {!record && (
            <Button size="sm" variant={action.requires_approval ? "outline" : "secondary"} disabled={busy} onClick={() => void onSubmit(action)}>
              {busy ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              Submit simulation
            </Button>
          )}
          {record?.approval_status === "pending" && (
            <>
              <Button size="sm" disabled={busy} onClick={() => setApproveOpen(true)}><Check className="h-3.5 w-3.5" />Approve</Button>
              <Button size="sm" variant="destructive" disabled={busy} onClick={() => setRejectOpen(true)}><XCircle className="h-3.5 w-3.5" />Reject</Button>
            </>
          )}
        </div>
      </div>

      <Dialog open={approveOpen} onOpenChange={setApproveOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Approve simulated response?</DialogTitle>
            <DialogDescription>This records a human decision, then runs only the simulated handler. No external security control is changed.</DialogDescription>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">Your verified Auth0 identity will be recorded as the decision maker.</p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setApproveOpen(false)}>Cancel</Button>
            <Button onClick={() => void approve()} disabled={busy}>{busy && <LoaderCircle className="h-4 w-4 animate-spin" />}Confirm approval</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={rejectOpen} onOpenChange={setRejectOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject response action</DialogTitle>
            <DialogDescription>Rejection is final for this audit record. The simulated handler will not run.</DialogDescription>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">Your verified Auth0 identity will be recorded as the decision maker.</p>
          <label className="grid gap-2 text-sm font-medium" htmlFor={`reason-${record?.id ?? action.action_type}`}>
            Rejection reason
            <Textarea id={`reason-${record?.id ?? action.action_type}`} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Explain why this action should not proceed…" />
          </label>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRejectOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={() => void reject()} disabled={busy || !reason.trim()}>{busy && <LoaderCircle className="h-4 w-4 animate-spin" />}Confirm rejection</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function ActionStatus({ record }: { record: ActionAuditRecord }) {
  if (record.approval_status === "pending") return <Badge variant="outline" className="gap-1.5 border-amber-400/30 bg-amber-400/10 text-amber-200"><Clock3 className="h-3 w-3" />Awaiting human</Badge>;
  if (record.approval_status === "rejected") return <Badge variant="outline" className="gap-1.5 border-red-400/30 bg-red-400/10 text-red-200"><XCircle className="h-3 w-3" />Rejected · not executed</Badge>;
  if (record.execution_status === "failed") return <Badge variant="outline" className="gap-1.5 border-red-400/30 bg-red-400/10 text-red-200"><ShieldAlert className="h-3 w-3" />Simulation failed</Badge>;
  return <Badge variant="outline" className="gap-1.5 border-primary/30 bg-primary/10 text-primary"><CircleCheck className="h-3 w-3" />{record.approval_status === "auto_approved" ? "Auto-approved · simulated" : "Approved · simulated"}</Badge>;
}

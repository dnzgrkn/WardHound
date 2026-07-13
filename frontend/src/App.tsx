import { AlertCircle, ChevronsUp, Search } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { AppHeader } from "@/components/app-header";
import { IncidentDetailView } from "@/components/incident-detail";
import { IncidentFilters } from "@/components/incident-filters";
import { IncidentTable } from "@/components/incident-table";
import { SummaryStrip } from "@/components/summary-strip";
import { Button } from "@/components/ui/button";
import { apiClient, ApiClientError, type WardHoundApi } from "@/lib/api";
import { cacheActionRecords, loadActionRecords, upsertActionRecord } from "@/lib/action-cache";
import { createSyntheticDemoEvents } from "@/lib/demo-events";
import { applyIncidentMessage, connectRealtime, upsertIncident, type RealtimeConnection } from "@/lib/realtime";
import type {
  ActionAuditRecord,
  Incident,
  IncidentDetail,
  IncidentFilters as Filters,
  RealtimeMessage,
  RealtimeStatus,
  RecommendedAction,
} from "@/lib/types";

const DEFAULT_FILTERS: Filters = { sortBy: "created_at", order: "desc" };

export interface AppProps {
  client?: WardHoundApi;
  realtimeConnector?: (
    onMessage: (message: RealtimeMessage) => void,
    onStatus: (status: RealtimeStatus) => void,
  ) => RealtimeConnection;
}

export function App({ client = apiClient, realtimeConnector = connectRealtime }: AppProps) {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [actionRecords, setActionRecords] = useState<ActionAuditRecord[]>(loadActionRecords);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionBusyId, setActionBusyId] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [realtimeStatus, setRealtimeStatus] = useState<RealtimeStatus>("connecting");
  const [demoBusy, setDemoBusy] = useState(false);

  useEffect(() => cacheActionRecords(actionRecords), [actionRecords]);

  useEffect(() => {
    let active = true;
    void client
      .listIncidents(filters)
      .then((result) => { if (active) { setIncidents(result); setPageError(null); } })
      .catch((error: unknown) => { if (active) setPageError(errorMessage(error)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [client, filters]);

  const onRealtimeMessage = useCallback((message: RealtimeMessage) => {
    if (message.type === "action_updated") {
      setActionRecords((current) => upsertActionRecord(current, message.payload));
      return;
    }
    setIncidents((current) => {
      const updated = applyIncidentMessage(current, message);
      return updated.filter((incident) => matchesFilters(incident, filters));
    });
    setDetail((current) => current?.incident.id === message.payload.id ? { ...current, incident: message.payload } : current);
  }, [filters]);

  useEffect(() => {
    const connection = realtimeConnector(onRealtimeMessage, setRealtimeStatus);
    return () => connection.close();
  }, [onRealtimeMessage, realtimeConnector]);

  const selectIncident = useCallback((incidentId: string) => {
    setSelectedId(incidentId);
    setDetailLoading(true);
    setAnalysisError(null);
    setActionError(null);
    void client.getIncident(incidentId)
      .then((result) => { setDetail(result); setPageError(null); })
      .catch((error: unknown) => setPageError(errorMessage(error)))
      .finally(() => setDetailLoading(false));
  }, [client]);

  const loadDemo = useCallback(() => {
    setDemoBusy(true);
    void client.ingestEvents(createSyntheticDemoEvents())
      .then((result) => {
        setIncidents((current) => result.reduce(upsertIncident, current));
        setPageError(null);
      })
      .catch((error: unknown) => setPageError(errorMessage(error)))
      .finally(() => setDemoBusy(false));
  }, [client]);

  const analyze = useCallback(() => {
    if (!selectedId) return;
    setAnalysisLoading(true);
    setAnalysisError(null);
    void client.analyzeIncident(selectedId)
      .then((analysis) => setDetail((current) => current ? { ...current, analysis } : current))
      .catch((error: unknown) => setAnalysisError(analysisErrorMessage(error)))
      .finally(() => setAnalysisLoading(false));
  }, [client, selectedId]);

  const submitAction = useCallback(async (action: RecommendedAction): Promise<void> => {
    if (!selectedId) return;
    setActionBusyId(action.action_type);
    setActionError(null);
    try {
      const record = await client.requestAction(selectedId, action);
      setActionRecords((current) => upsertActionRecord(current, record));
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setActionBusyId(null);
    }
  }, [client, selectedId]);

  const approveAction = useCallback(async (recordId: string, decidedBy: string): Promise<void> => {
    setActionBusyId(recordId);
    setActionError(null);
    try {
      const record = await client.approveAction(recordId, decidedBy);
      setActionRecords((current) => upsertActionRecord(current, record));
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setActionBusyId(null);
    }
  }, [client]);

  const rejectAction = useCallback(async (recordId: string, decidedBy: string, reason: string): Promise<void> => {
    setActionBusyId(recordId);
    setActionError(null);
    try {
      const record = await client.rejectAction(recordId, decidedBy, reason);
      setActionRecords((current) => upsertActionRecord(current, record));
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setActionBusyId(null);
    }
  }, [client]);

  const sortedIncidents = useMemo(() => sortIncidents(incidents, filters), [incidents, filters]);

  return (
    <div className="min-h-screen">
      <AppHeader status={realtimeStatus} onLoadDemo={loadDemo} demoBusy={demoBusy} />
      <main className="mx-auto max-w-[1500px] px-4 py-7 sm:px-6 lg:px-8 lg:py-9">
        {pageError && (
          <div className="mb-6 flex items-start justify-between gap-4 rounded-lg border border-red-400/25 bg-red-500/10 p-4 text-sm text-red-200" role="alert">
            <span className="flex items-start gap-2"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{pageError}</span>
            <Button variant="ghost" size="sm" onClick={() => setPageError(null)}>Dismiss</Button>
          </div>
        )}
        {selectedId ? (
          <IncidentDetailView
            detail={detail}
            loading={detailLoading}
            analysisLoading={analysisLoading}
            analysisError={analysisError}
            actionError={actionError}
            actionBusyId={actionBusyId}
            actionRecords={actionRecords}
            onBack={() => { setSelectedId(null); setDetail(null); }}
            onAnalyze={analyze}
            onSubmitAction={submitAction}
            onApprove={approveAction}
            onReject={rejectAction}
          />
        ) : (
          <div className="space-y-6">
            <section className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
              <div>
                <div className="mb-3 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.16em] text-primary"><Search className="h-3.5 w-3.5" />Incident operations</div>
                <h1 className="font-display text-3xl font-bold tracking-tight sm:text-4xl">Security incident queue</h1>
                <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">Correlated NAC, PAM, identity, and network evidence ranked for operator triage.</p>
              </div>
              <IncidentFilters filters={filters} onChange={(nextFilters) => { setLoading(true); setFilters(nextFilters); }} />
            </section>
            <SummaryStrip incidents={sortedIncidents} actions={actionRecords} />
            <IncidentTable incidents={sortedIncidents} loading={loading} onSelect={selectIncident} onLoadDemo={loadDemo} />
            <div className="flex items-center justify-center gap-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground"><ChevronsUp className="h-3.5 w-3.5 text-primary" />Realtime updates are merged into this queue</div>
          </div>
        )}
      </main>
    </div>
  );
}

function matchesFilters(incident: Incident, filters: Filters): boolean {
  return (!filters.severity || incident.severity === filters.severity) && (!filters.status || incident.status === filters.status);
}

function sortIncidents(incidents: Incident[], filters: Filters): Incident[] {
  const direction = filters.order === "desc" ? -1 : 1;
  return [...incidents].sort((left, right) => {
    const comparison = filters.sortBy === "risk_score"
      ? left.risk_score - right.risk_score
      : new Date(left.created_at).getTime() - new Date(right.created_at).getTime();
    return comparison * direction;
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "An unexpected dashboard error occurred.";
}

function analysisErrorMessage(error: unknown): string {
  if (error instanceof ApiClientError && error.code === "analysis_not_configured") {
    return "AI analysis is unavailable because ANTHROPIC_API_KEY is not configured on the API service.";
  }
  return errorMessage(error);
}

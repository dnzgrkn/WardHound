import { ArrowDownAZ, SlidersHorizontal } from "lucide-react";

import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { IncidentFilters as Filters, IncidentStatus, Severity } from "@/lib/types";

export function IncidentFilters({
  filters,
  onChange,
}: {
  filters: Filters;
  onChange: (filters: Filters) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="mr-1 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
        <SlidersHorizontal className="h-3.5 w-3.5" /> Filters
      </div>
      <Select
        value={filters.severity ?? "all"}
        onValueChange={(value) => onChange({ ...filters, severity: value === "all" ? undefined : (value as Severity) })}
      >
        <SelectTrigger aria-label="Filter by severity"><SelectValue placeholder="All severities" /></SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All severities</SelectItem>
          <SelectItem value="critical">Critical</SelectItem>
          <SelectItem value="high">High</SelectItem>
          <SelectItem value="medium">Medium</SelectItem>
          <SelectItem value="low">Low</SelectItem>
        </SelectContent>
      </Select>
      <Select
        value={filters.status ?? "all"}
        onValueChange={(value) => onChange({ ...filters, status: value === "all" ? undefined : (value as IncidentStatus) })}
      >
        <SelectTrigger aria-label="Filter by status"><SelectValue placeholder="All statuses" /></SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All statuses</SelectItem>
          <SelectItem value="open">Open</SelectItem>
          <SelectItem value="acknowledged">Acknowledged</SelectItem>
          <SelectItem value="resolved">Resolved</SelectItem>
        </SelectContent>
      </Select>
      <Select
        value={filters.sortBy}
        onValueChange={(value) => onChange({ ...filters, sortBy: value as Filters["sortBy"] })}
      >
        <SelectTrigger aria-label="Sort incidents"><ArrowDownAZ className="h-3.5 w-3.5 text-muted-foreground" /><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="created_at">Created time</SelectItem>
          <SelectItem value="risk_score">Risk score</SelectItem>
        </SelectContent>
      </Select>
      <Select
        value={filters.order}
        onValueChange={(value) => onChange({ ...filters, order: value as Filters["order"] })}
      >
        <SelectTrigger aria-label="Sort direction"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="desc">Descending</SelectItem>
          <SelectItem value="asc">Ascending</SelectItem>
        </SelectContent>
      </Select>
    </div>
  );
}

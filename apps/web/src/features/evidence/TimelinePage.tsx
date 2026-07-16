import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Clock3, LoaderCircle } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { getCase, getTimeline } from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";

export function TimelinePage() {
  const { caseId = "" } = useParams();
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const timeline = useQuery({
    queryKey: caseKeys.timeline(caseId),
    queryFn: () => getTimeline(caseId),
    enabled: Boolean(caseId),
  });
  return (
    <div className="mx-auto max-w-5xl">
      <Link to={`/cases/${caseId}`} className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200">
        <ArrowLeft size={15} /> Back to case
      </Link>
      <header className="mt-6 border-b border-white/8 pb-7">
        <p className="font-mono text-xs text-cyan-300/65">{caseQuery.data?.case_number ?? "Case timeline"}</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Timeline</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Deterministic timestamp claims linked to their source artifacts. No missing device-side timestamps are inferred.
        </p>
      </header>
      {timeline.isPending && <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500"><LoaderCircle size={16} className="animate-spin" /> Building timeline view...</p>}
      {timeline.isError && <div className="mt-6"><CaseError error={timeline.error} /></div>}
      {caseQuery.isError && <div className="mt-6"><CaseError error={caseQuery.error} /></div>}
      {timeline.data?.items.length === 0 && <p className="mt-8 text-sm text-slate-500">No normalized timestamp claims are available.</p>}
      <ol className="mt-7 space-y-3">
        {timeline.data?.items.map((event) => (
          <li key={event.id} className="grid gap-4 rounded-xl border border-white/8 bg-white/[0.025] p-5 sm:grid-cols-[180px_1fr]">
            <time className="font-mono text-[11px] text-cyan-200">{new Date(event.event_time).toLocaleString()}</time>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <Clock3 size={14} className="text-cyan-300" />
                <p className="text-sm font-semibold text-white">{event.summary}</p>
                <span className="rounded-full border border-white/10 px-2 py-0.5 text-[9px] uppercase text-slate-500">{event.category}</span>
              </div>
              <p className="mt-2 text-[11px] text-slate-500">{event.timestamp_type.replaceAll("_", " ")} · {event.confidence} confidence</p>
              <p className="mt-1 text-[10px] text-slate-600">{event.timezone_basis}</p>
              <Link to={`/cases/${caseId}/evidence`} className="mt-3 inline-block text-[11px] text-cyan-200 hover:underline">Open source evidence</Link>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

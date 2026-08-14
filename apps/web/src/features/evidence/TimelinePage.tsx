import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Clock3, LoaderCircle, Calendar as CalendarIcon, Filter } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { getCase, getTimeline, TimelineEvent } from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";

// Helper to get local date string YYYY-MM-DD
function toDateString(isoString: string) {
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return "";
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

export function TimelinePage() {
  const { caseId = "" } = useParams();
  const [selectedDate, setSelectedDate] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);

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

  // Calculate heatmap data
  const heatmap = useMemo(() => {
    const items = timeline.data?.items || [];
    const counts = new Map<string, number>();
    
    let minTime = Infinity;
    let maxTime = -Infinity;

    for (const item of items) {
      if (!item.event_time) continue;
      const dStr = toDateString(item.event_time);
      if (!dStr) continue;
      
      counts.set(dStr, (counts.get(dStr) || 0) + 1);
      
      const t = new Date(item.event_time).getTime();
      if (t < minTime) minTime = t;
      if (t > maxTime) maxTime = t;
    }

    if (minTime === Infinity) return { days: [], maxCount: 0 };

    // Create a continuous array of days from min to max (capped at 1 year max for sanity)
    const MAX_DAYS = 365;
    const end = new Date(maxTime);
    const start = new Date(minTime);
    
    if ((end.getTime() - start.getTime()) > MAX_DAYS * 86400000) {
      start.setTime(end.getTime() - (MAX_DAYS * 86400000));
    }

    // Align start to Sunday
    start.setDate(start.getDate() - start.getDay());
    // Align end to Saturday
    end.setDate(end.getDate() + (6 - end.getDay()));

    const days = [];
    let maxCount = 0;
    
    const curr = new Date(start);
    while (curr <= end) {
      const dStr = toDateString(curr.toISOString());
      const count = counts.get(dStr) || 0;
      if (count > maxCount) maxCount = count;
      
      days.push({
        date: dStr,
        count,
        label: curr.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })
      });
      curr.setDate(curr.getDate() + 1);
    }

    return { days, maxCount };
  }, [timeline.data]);

  // Filter items
  const filteredItems = useMemo(() => {
    const items = timeline.data?.items || [];
    return items.filter(item => {
      if (selectedDate && toDateString(item.event_time) !== selectedDate) return false;
      if (selectedCategory && item.category !== selectedCategory) return false;
      return true;
    });
  }, [timeline.data, selectedDate, selectedCategory]);

  return (
    <div className="mx-auto max-w-5xl">
      <Link to={`/cases/${caseId}`} className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200">
        <ArrowLeft size={15} /> Back to case
      </Link>
      
      <header className="mt-6 border-b border-white/8 pb-7">
        <p className="font-mono text-xs text-cyan-300/65">{caseQuery.data?.case_number ?? "Case timeline"}</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Timeline</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Deterministic timestamp claims linked to their source artifacts.
        </p>
      </header>

      {timeline.isPending && <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500"><LoaderCircle size={16} className="animate-spin" /> Building timeline view...</p>}
      {timeline.isError && <div className="mt-6"><CaseError error={timeline.error} /></div>}
      {caseQuery.isError && <div className="mt-6"><CaseError error={caseQuery.error} /></div>}

      {heatmap.days.length > 0 && (
        <section className="mt-8 rounded-xl border border-white/8 bg-white/[0.02] p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-white">
              <CalendarIcon size={15} className="text-cyan-400" />
              Event Heatmap
            </h2>
            {selectedDate && (
              <button 
                onClick={() => setSelectedDate(null)}
                className="text-xs text-cyan-400 hover:underline"
              >
                Clear date filter
              </button>
            )}
          </div>
          
          <div className="overflow-x-auto pb-4 custom-scrollbar">
            <div className="min-w-max">
              <div className="grid grid-flow-col gap-1" style={{ gridTemplateRows: 'repeat(7, 1fr)' }}>
                {heatmap.days.map((day, i) => {
                  let intensity = 0;
                  if (day.count > 0) {
                    intensity = Math.max(0.2, day.count / heatmap.maxCount);
                  }
                  const isSelected = selectedDate === day.date;
                  
                  return (
                    <button
                      key={day.date}
                      onClick={() => setSelectedDate(isSelected ? null : day.date)}
                      title={`${day.label}: ${day.count} events`}
                      className={`h-3 w-3 rounded-[2px] transition-all hover:ring-1 hover:ring-white/50 ${isSelected ? 'ring-2 ring-cyan-400 z-10 scale-125' : ''}`}
                      style={{
                        backgroundColor: day.count > 0 ? `rgba(34, 211, 238, ${intensity})` : 'rgba(255, 255, 255, 0.05)',
                      }}
                    />
                  );
                })}
              </div>
            </div>
          </div>
        </section>
      )}

      {timeline.data?.category_facets && Object.keys(timeline.data.category_facets).length > 0 && (
        <div className="mt-6 flex flex-wrap items-center gap-2">
          <Filter size={14} className="text-slate-500 mr-2" />
          <button
            onClick={() => setSelectedCategory(null)}
            className={`rounded-full border px-3 py-1 text-xs transition-colors ${!selectedCategory ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300' : 'border-white/10 text-slate-400 hover:border-white/20'}`}
          >
            All
          </button>
          {Object.entries(timeline.data.category_facets).map(([cat, count]) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(selectedCategory === cat ? null : cat)}
              className={`rounded-full border px-3 py-1 text-xs transition-colors ${selectedCategory === cat ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300' : 'border-white/10 text-slate-400 hover:border-white/20'}`}
            >
              {cat} <span className="ml-1 opacity-50">{count}</span>
            </button>
          ))}
        </div>
      )}

      {timeline.data?.items.length === 0 && <p className="mt-8 text-sm text-slate-500">No normalized timestamp claims are available.</p>}
      
      <div className="mt-6">
        <h3 className="mb-4 text-sm font-medium text-slate-300">
          {filteredItems.length} {filteredItems.length === 1 ? 'Event' : 'Events'}
          {selectedDate && <span className="ml-2 font-normal text-slate-500">on {selectedDate}</span>}
        </h3>
        <ol className="space-y-3">
          {filteredItems.map((event) => (
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
    </div>
  );
}

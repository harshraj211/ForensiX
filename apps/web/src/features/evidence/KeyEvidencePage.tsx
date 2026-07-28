import { useDeferredValue, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  BookOpenText,
  CheckCircle2,
  Clock3,
  Database,
  FileSearch,
  Fingerprint,
  Flag,
  Hash,
  LoaderCircle,
  Search,
  ShieldCheck,
  Tag,
  Trash2,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";

import {
  getCase,
  listKeyEvidence,
  removeKeyEvidence,
  type KeyEvidenceItem,
  type KeyEvidencePriority,
} from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";

const PRIORITIES: Array<{ value: KeyEvidencePriority | ""; label: string }> = [
  { value: "", label: "All priorities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "normal", label: "Normal" },
];

export function KeyEvidencePage() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search.trim());
  const [priority, setPriority] = useState<KeyEvidencePriority | "">("");
  const [category, setCategory] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const filters = useMemo(
    () => ({
      ...(deferredSearch ? { q: deferredSearch } : {}),
      ...(priority ? { priority } : {}),
      ...(category ? { category } : {}),
    }),
    [category, deferredSearch, priority],
  );
  const filterKey = useMemo(
    () => Object.fromEntries(Object.entries(filters).map(([key, value]) => [key, value])),
    [filters],
  );
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const findingsQuery = useQuery({
    queryKey: caseKeys.keyEvidence(caseId, filterKey),
    queryFn: () => listKeyEvidence(caseId, filters),
    enabled: Boolean(caseId),
  });
  const removeFinding = useMutation({
    mutationFn: (findingId: string) => removeKeyEvidence(caseId, findingId),
    onSuccess: async (_, findingId) => {
      if (selectedId === findingId) setSelectedId(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["cases", caseId, "key-evidence"] }),
        queryClient.invalidateQueries({ queryKey: caseKeys.commandCenter(caseId) }),
      ]);
    },
  });

  if (caseQuery.isPending) {
    return (
      <div role="status" className="grid min-h-[50vh] place-items-center">
        <LoaderCircle className="animate-spin text-cyan-300" aria-hidden="true" />
      </div>
    );
  }
  if (caseQuery.isError) return <CaseError error={caseQuery.error} />;
  const result = findingsQuery.data;
  const selected =
    result?.items.find((item) => item.id === selectedId) ?? result?.items[0] ?? null;
  const categories = Object.keys(result?.category_facets ?? {});

  return (
    <div className="mx-auto max-w-[1320px]">
      <Link
        to={`/cases/${caseId}/command-center`}
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"
      >
        <ArrowLeft size={15} aria-hidden="true" /> Back to Command Center
      </Link>
      <header className="mt-6 flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div>
          <p className="font-mono text-xs text-cyan-300/65">{caseQuery.data.case_number}</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Key Evidence</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
            Curate the strongest findings from acquired files and parsed Android artifacts. Every
            promotion and removal is recorded in the audit chain.
          </p>
        </div>
        <Link
          to={`/cases/${caseId}/artifact-search`}
          className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg bg-cyan-300 px-4 text-sm font-semibold text-slate-950"
        >
          <Search size={16} aria-hidden="true" /> Find more evidence
        </Link>
      </header>

      <section aria-label="Key evidence metrics" className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <SummaryCard
          label="Selected findings"
          value={result?.total ?? 0}
          detail="Unified across both artifact families"
          icon={Flag}
          tone="cyan"
        />
        <SummaryCard
          label="Critical"
          value={result?.priority_counts.critical ?? 0}
          detail="Immediate examiner attention"
          icon={AlertTriangle}
          tone="rose"
        />
        <SummaryCard
          label="High priority"
          value={result?.priority_counts.high ?? 0}
          detail="Material to the working theory"
          icon={ShieldCheck}
          tone="amber"
        />
        <SummaryCard
          label="Evidence categories"
          value={categories.length}
          detail="Distinct artifact categories represented"
          icon={Database}
          tone="violet"
        />
      </section>

      <section className="mt-5 rounded-2xl border border-white/8 bg-white/[0.025] p-4">
        <div className="grid gap-3 lg:grid-cols-[1fr_180px_190px_auto]">
          <label className="relative">
            <span className="sr-only">Search key evidence</span>
            <Search
              size={16}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-600"
              aria-hidden="true"
            />
            <input
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
              }}
              placeholder="Search titles, reasons, paths, tags, and notes"
              className="min-h-11 w-full rounded-xl border border-white/8 bg-black/15 pl-10 pr-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-cyan-300/25"
            />
          </label>
          <label>
            <span className="sr-only">Priority</span>
            <select
              value={priority}
              onChange={(event) => {
                setPriority(event.target.value as KeyEvidencePriority | "");
                setSelectedId(null);
              }}
              className="min-h-11 w-full rounded-xl border border-white/8 bg-[#09151d] px-3 text-sm text-slate-300"
            >
              {PRIORITIES.map((item) => (
                <option key={item.value || "all"} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="sr-only">Category</span>
            <select
              value={category}
              onChange={(event) => {
                setCategory(event.target.value);
                setSelectedId(null);
              }}
              className="min-h-11 w-full rounded-xl border border-white/8 bg-[#09151d] px-3 text-sm capitalize text-slate-300"
            >
              <option value="">All categories</option>
              {categories.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() => {
              setSearch("");
              setPriority("");
              setCategory("");
              setSelectedId(null);
            }}
            className="min-h-11 rounded-xl border border-white/8 px-4 text-sm text-slate-500 hover:text-slate-200"
          >
            Clear filters
          </button>
        </div>
      </section>

      {findingsQuery.isError && (
        <div className="mt-5">
          <CaseError error={findingsQuery.error} />
        </div>
      )}

      <section className="mt-5 grid min-h-[620px] overflow-hidden rounded-2xl border border-white/8 bg-white/[0.02] lg:grid-cols-[minmax(0,0.9fr)_minmax(360px,1.1fr)]">
        <div className="min-w-0 border-b border-white/8 lg:border-b-0 lg:border-r">
          <div className="flex items-center justify-between border-b border-white/8 px-5 py-4">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
              Findings
            </p>
            <span className="text-xs text-slate-700">
              {findingsQuery.isFetching ? "Refreshing…" : `${String(result?.total ?? 0)} visible`}
            </span>
          </div>
          {findingsQuery.isPending ? (
            <div className="grid min-h-[400px] place-items-center" role="status">
              <LoaderCircle className="animate-spin text-cyan-300" aria-hidden="true" />
            </div>
          ) : result?.items.length ? (
            <ol className="max-h-[720px] overflow-y-auto p-2">
              {result.items.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedId(item.id);
                    }}
                    className={`w-full rounded-xl border p-4 text-left transition ${
                      selected?.id === item.id
                        ? "border-cyan-300/20 bg-cyan-300/[0.055]"
                        : "border-transparent hover:border-white/8 hover:bg-white/[0.025]"
                    }`}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <PriorityBadge priority={item.priority} />
                      <span className="rounded-full border border-white/8 px-2 py-0.5 text-[10px] uppercase tracking-wider text-slate-600">
                        {item.category}
                      </span>
                      <span className="ml-auto text-[10px] text-slate-700">
                        {item.target_type === "source_artifact" ? "parsed artifact" : "acquired file"}
                      </span>
                    </div>
                    <h2 className="mt-3 line-clamp-2 text-sm font-semibold leading-5 text-slate-100">
                      {item.title}
                    </h2>
                    <p className="mt-2 line-clamp-2 text-xs leading-5 text-slate-600">
                      {item.reason || item.summary}
                    </p>
                    <div className="mt-3 flex items-center gap-3 text-[10px] text-slate-700">
                      <span>{item.subtype.replaceAll("_", " ")}</span>
                      {item.tags.length > 0 && <span>{String(item.tags.length)} tags</span>}
                      {item.note_count > 0 && <span>{String(item.note_count)} notes</span>}
                    </div>
                  </button>
                </li>
              ))}
            </ol>
          ) : (
            <EmptyState filtered={Boolean(deferredSearch || priority || category)} caseId={caseId} />
          )}
        </div>
        <div className="min-w-0">
          {selected ? (
            <FindingDetail
              item={selected}
              isRemoving={removeFinding.isPending}
              onRemove={() => {
                removeFinding.mutate(selected.id);
              }}
            />
          ) : (
            <div className="grid h-full min-h-[420px] place-items-center p-8 text-center">
              <div>
                <Fingerprint className="mx-auto text-slate-700" size={30} aria-hidden="true" />
                <p className="mt-4 text-sm text-slate-500">Select a finding to review its provenance.</p>
              </div>
            </div>
          )}
        </div>
      </section>
      {removeFinding.isError && (
        <div className="mt-5">
          <CaseError error={removeFinding.error} />
        </div>
      )}
    </div>
  );
}

function FindingDetail({
  item,
  isRemoving,
  onRemove,
}: {
  item: KeyEvidenceItem;
  isRemoving: boolean;
  onRemove: () => void;
}) {
  return (
    <article className="p-6 lg:p-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex flex-wrap gap-2">
          <PriorityBadge priority={item.priority} />
          <span className="rounded-full border border-white/8 px-2.5 py-1 text-[10px] uppercase tracking-wider text-slate-500">
            {item.status}
          </span>
          <span className="rounded-full border border-white/8 px-2.5 py-1 text-[10px] uppercase tracking-wider text-slate-500">
            {item.confidence} confidence
          </span>
        </div>
        <button
          type="button"
          disabled={isRemoving}
          onClick={onRemove}
          className="inline-flex min-h-9 items-center gap-2 rounded-lg border border-rose-300/15 px-3 text-xs text-rose-300 disabled:opacity-40"
        >
          <Trash2 size={14} aria-hidden="true" /> Remove
        </button>
      </div>
      <h2 className="mt-6 text-2xl font-semibold leading-tight text-white">{item.title}</h2>
      <p className="mt-3 text-sm leading-6 text-slate-400">{item.summary}</p>

      <section className="mt-6 rounded-xl border border-cyan-300/12 bg-cyan-300/[0.035] p-5">
        <div className="flex gap-3">
          <Flag size={17} className="mt-0.5 shrink-0 text-cyan-300" aria-hidden="true" />
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.15em] text-cyan-300">
              Examiner rationale
            </p>
            <p className="mt-2 text-sm leading-6 text-slate-300">
              {item.reason || "No promotion rationale was recorded."}
            </p>
          </div>
        </div>
      </section>

      <dl className="mt-6 grid gap-4 sm:grid-cols-2">
        <Detail icon={Clock3} label="Relevant time" value={item.event_time ? new Date(item.event_time).toLocaleString() : "Not available"} />
        <Detail icon={Database} label="Artifact type" value={`${item.category} / ${item.subtype.replaceAll("_", " ")}`} />
        <Detail icon={FileSearch} label="Source locator" value={item.source_locator} />
        <Detail icon={ShieldCheck} label="Parser" value={`${item.parser_id} v${item.parser_version}`} />
      </dl>

      <section className="mt-6 border-t border-white/8 pt-5">
        <div className="flex items-start gap-3">
          <Hash size={16} className="mt-0.5 shrink-0 text-slate-600" aria-hidden="true" />
          <div className="min-w-0">
            <p className="text-[10px] uppercase tracking-[0.14em] text-slate-600">Integrity reference</p>
            <p className="mt-1 break-all font-mono text-[11px] leading-5 text-slate-400">
              {item.integrity_hash}
            </p>
          </div>
        </div>
      </section>

      {item.tags.length > 0 && (
        <section className="mt-6 border-t border-white/8 pt-5">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <Tag size={14} className="text-cyan-300" aria-hidden="true" /> Analyst tags
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {item.tags.map((tag) => (
              <span key={tag} className="rounded-full bg-cyan-300/8 px-2.5 py-1 text-xs text-cyan-100">
                {tag}
              </span>
            ))}
          </div>
        </section>
      )}

      {item.latest_note && (
        <section className="mt-6 border-t border-white/8 pt-5">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <BookOpenText size={14} className="text-cyan-300" aria-hidden="true" /> Latest analyst note
          </div>
          <blockquote className="mt-3 rounded-xl border border-white/7 bg-black/10 p-4 text-sm leading-6 text-slate-400">
            {item.latest_note}
          </blockquote>
        </section>
      )}
    </article>
  );
}

function Detail({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Clock3;
  label: string;
  value: string;
}) {
  return (
    <div className="min-w-0 rounded-xl border border-white/7 bg-black/10 p-4">
      <dt className="flex items-center gap-2 text-[10px] uppercase tracking-[0.14em] text-slate-600">
        <Icon size={13} aria-hidden="true" /> {label}
      </dt>
      <dd className="mt-2 break-all text-xs leading-5 text-slate-300">{value}</dd>
    </div>
  );
}

function PriorityBadge({ priority }: { priority: KeyEvidencePriority }) {
  const tones: Record<KeyEvidencePriority, string> = {
    critical: "border-rose-300/20 bg-rose-300/8 text-rose-300",
    high: "border-amber-300/20 bg-amber-300/8 text-amber-300",
    normal: "border-cyan-300/15 bg-cyan-300/6 text-cyan-200",
  };
  return (
    <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider ${tones[priority]}`}>
      {priority}
    </span>
  );
}

function SummaryCard({
  label,
  value,
  detail,
  icon: Icon,
  tone,
}: {
  label: string;
  value: number;
  detail: string;
  icon: typeof Flag;
  tone: "cyan" | "rose" | "amber" | "violet";
}) {
  const tones = {
    cyan: "text-cyan-300",
    rose: "text-rose-300",
    amber: "text-amber-300",
    violet: "text-violet-300",
  };
  return (
    <article className="rounded-2xl border border-white/8 bg-white/[0.025] p-5">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">{label}</p>
        <Icon size={17} className={tones[tone]} aria-hidden="true" />
      </div>
      <p className="mt-3 text-2xl font-semibold text-white">{new Intl.NumberFormat().format(value)}</p>
      <p className="mt-2 text-[11px] leading-5 text-slate-700">{detail}</p>
    </article>
  );
}

function EmptyState({ filtered, caseId }: { filtered: boolean; caseId: string }) {
  return (
    <div className="grid min-h-[500px] place-items-center p-8 text-center">
      <div>
        <CheckCircle2 className="mx-auto text-slate-700" size={30} aria-hidden="true" />
        <h2 className="mt-4 text-base font-semibold text-slate-300">
          {filtered ? "No findings match these filters" : "No key evidence selected yet"}
        </h2>
        <p className="mx-auto mt-2 max-w-xs text-xs leading-5 text-slate-600">
          {filtered
            ? "Clear one or more filters to widen the review."
            : "Promote findings from the evidence explorer or parsed artifact browser."}
        </p>
        {!filtered && (
          <Link
            to={`/cases/${caseId}/evidence`}
            className="mt-5 inline-flex min-h-9 items-center rounded-lg border border-cyan-300/15 px-3 text-xs text-cyan-200"
          >
            Open evidence explorer
          </Link>
        )}
      </div>
    </div>
  );
}

import { useState } from "react";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { ArrowLeft, LoaderCircle, Search } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { getCase, searchSourceArtifacts, type EvidenceSourceArtifact } from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";

const CATEGORY_LABELS: Record<string, string> = {
  contact: "Contacts",
  communication: "Communications",
  application: "Application data",
  location: "Locations",
  system: "System",
  file: "Files",
};

const PAGE_SIZE = 50;

export function ArtifactSearchPage() {
  const { caseId = "" } = useParams();
  const [rawQuery, setRawQuery] = useState("");
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<string | null>(null);
  const [page, setPage] = useState(0);

  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });

  const filters = {
    q: query,
    category: category ?? "",
    page: String(page),
  };
  const results = useQuery({
    queryKey: caseKeys.artifactSearch(caseId, filters),
    queryFn: () =>
      searchSourceArtifacts(caseId, {
        query,
        category: category ?? undefined,
        offset: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      }),
    enabled: Boolean(caseId),
    placeholderData: keepPreviousData,
  });

  const facets = results.data?.category_facets ?? {};
  const total = results.data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="mx-auto max-w-5xl">
      <Link
        to={`/cases/${caseId}`}
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"
      >
        <ArrowLeft size={15} /> Back to case
      </Link>
      <header className="mt-6 border-b border-white/8 pb-7">
        <p className="font-mono text-xs text-cyan-300/65">
          {caseQuery.data?.case_number ?? "Cross-artifact search"}
        </p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Artifact search</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          Search parsed messages, calls, contacts, and app data across every sealed source in the
          case at once. Matching runs over titles and summaries; no source content is altered.
        </p>
      </header>

      <form
        onSubmit={(event) => {
          event.preventDefault();
          setQuery(rawQuery);
          setPage(0);
        }}
        className="mt-6 flex gap-2"
      >
        <div className="relative flex-1">
          <Search
            size={16}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
          />
          <input
            type="search"
            value={rawQuery}
            onChange={(e) => { setRawQuery(e.target.value); }}
            placeholder="Search across all artifacts…"
            className="w-full rounded-lg border border-white/10 bg-white/4 py-2.5 pl-9 pr-3 text-sm text-white placeholder:text-slate-600 focus:border-cyan-300/30 focus:outline-none"
          />
        </div>
        <button
          type="submit"
          className="rounded-lg bg-cyan-300 px-5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200"
        >
          Search
        </button>
      </form>

      <CategoryFilters facets={facets} active={category} onSelect={(c) => { setCategory(c); setPage(0); }} />

      {results.isError && <div className="mt-6"><CaseError error={results.error} /></div>}
      {caseQuery.isError && <div className="mt-6"><CaseError error={caseQuery.error} /></div>}

      <ResultsList
        caseId={caseId}
        items={results.data?.items ?? []}
        isPending={results.isPending}
        query={query}
        total={total}
      />

      {pageCount > 1 && (
        <Pager page={page} pageCount={pageCount} onChange={setPage} disabled={results.isFetching} />
      )}
    </div>
  );
}

function CategoryFilters({
  facets,
  active,
  onSelect,
}: {
  facets: Record<string, number>;
  active: string | null;
  onSelect: (category: string | null) => void;
}) {
  const entries = Object.entries(facets).sort((a, b) => b[1] - a[1]);
  const totalAll = entries.reduce((sum, [, count]) => sum + count, 0);
  return (
    <div className="mt-4 flex flex-wrap gap-2">
      <FilterChip label="All" count={totalAll} active={active === null} onClick={() => { onSelect(null); }} />
      {entries.map(([cat, count]) => (
        <FilterChip
          key={cat}
          label={CATEGORY_LABELS[cat] ?? cat}
          count={count}
          active={active === cat}
          onClick={() => { onSelect(cat); }}
        />
      ))}
    </div>
  );
}

function FilterChip({
  label,
  count,
  active,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs transition ${
        active
          ? "border-cyan-300/40 bg-cyan-300/10 text-cyan-100"
          : "border-white/10 text-slate-400 hover:border-white/20 hover:text-slate-200"
      }`}
    >
      {label}
      <span className="tabular-nums text-[10px] text-slate-500">{count}</span>
    </button>
  );
}

function ResultsList({
  caseId,
  items,
  isPending,
  query,
  total,
}: {
  caseId: string;
  items: EvidenceSourceArtifact[];
  isPending: boolean;
  query: string;
  total: number;
}) {
  if (isPending) {
    return (
      <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500">
        <LoaderCircle size={16} className="animate-spin" /> Searching artifacts…
      </p>
    );
  }
  if (items.length === 0) {
    return (
      <p className="mt-8 text-sm text-slate-500">
        {query ? `No artifacts match "${query}".` : "No parsed artifacts in this case yet."}
      </p>
    );
  }
  return (
    <>
      <p className="mt-6 text-[11px] uppercase tracking-wider text-slate-600">
        {total} match{total !== 1 ? "es" : ""}
      </p>
      <ol className="mt-3 space-y-2">
        {items.map((artifact) => (
          <li
            key={artifact.id}
            className="rounded-xl border border-white/8 bg-white/[0.025] p-4"
          >
            <div className="flex items-start justify-between gap-3">
              <p className="text-sm font-semibold leading-snug text-white">
                <Highlight text={artifact.title} query={query} />
              </p>
              <span className="shrink-0 rounded-full border border-white/10 px-2 py-0.5 text-[9px] uppercase tracking-wider text-slate-500">
                {artifact.subtype.replaceAll("_", " ")}
              </span>
            </div>
            <p className="mt-1.5 text-xs leading-5 text-slate-400">
              <Highlight text={artifact.summary} query={query} />
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-[10px] text-slate-600">
              <span>{CATEGORY_LABELS[artifact.category] ?? artifact.category}</span>
              {artifact.event_time && (
                <span className="font-mono text-cyan-300/60">
                  {new Date(artifact.event_time).toLocaleString()}
                </span>
              )}
              {artifact.status !== "active" && (
                <span className="rounded border border-rose-300/20 px-1.5 py-0.5 uppercase text-rose-300">
                  {artifact.status}
                </span>
              )}
              <Link
                to={`/cases/${caseId}/artifacts`}
                className="ml-auto text-cyan-200 hover:underline"
              >
                Open in browser
              </Link>
            </div>
          </li>
        ))}
      </ol>
    </>
  );
}

function Highlight({ text, query }: { text: string; query: string }) {
  const trimmed = query.trim();
  if (!trimmed) return <>{text}</>;
  const index = text.toLowerCase().indexOf(trimmed.toLowerCase());
  if (index === -1) return <>{text}</>;
  return (
    <>
      {text.slice(0, index)}
      <mark className="rounded bg-cyan-300/25 px-0.5 text-cyan-100">
        {text.slice(index, index + trimmed.length)}
      </mark>
      {text.slice(index + trimmed.length)}
    </>
  );
}

function Pager({
  page,
  pageCount,
  onChange,
  disabled,
}: {
  page: number;
  pageCount: number;
  onChange: (page: number) => void;
  disabled: boolean;
}) {
  return (
    <div className="mt-6 flex items-center justify-center gap-4 text-sm">
      <button
        type="button"
        disabled={disabled || page === 0}
        onClick={() => { onChange(page - 1); }}
        className="rounded-lg border border-white/10 px-3 py-1.5 text-slate-300 disabled:opacity-40"
      >
        Previous
      </button>
      <span className="tabular-nums text-slate-500">
        Page {page + 1} of {pageCount}
      </span>
      <button
        type="button"
        disabled={disabled || page >= pageCount - 1}
        onClick={() => { onChange(page + 1); }}
        className="rounded-lg border border-white/10 px-3 py-1.5 text-slate-300 disabled:opacity-40"
      >
        Next
      </button>
    </div>
  );
}

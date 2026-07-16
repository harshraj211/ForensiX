import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, FileSearch, LoaderCircle, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import {
  getArtifact,
  getCase,
  listCases,
  searchArtifacts,
  type Artifact,
  type ArtifactCategory,
  type ArtifactStatus,
} from "../../lib/api";

const categories: Array<{ value: ArtifactCategory | ""; label: string }> = [
  { value: "", label: "All categories" },
  { value: "image", label: "Images" },
  { value: "video", label: "Videos" },
  { value: "audio", label: "Audio" },
  { value: "document", label: "Documents" },
  { value: "archive", label: "Archives" },
  { value: "other", label: "Other" },
];

export function EvidenceCasesPage() {
  const casesQuery = useQuery({ queryKey: caseKeys.all, queryFn: listCases });
  return (
    <div className="mx-auto max-w-5xl">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">Case-scoped analysis</p>
      <h1 className="mt-2 text-3xl font-semibold text-white">Evidence</h1>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
        Choose an authorized case. Evidence searches never cross case boundaries.
      </p>
      {casesQuery.isPending && <p role="status" className="mt-8 text-sm text-slate-500">Loading accessible cases...</p>}
      {casesQuery.isError && <div className="mt-6"><CaseError error={casesQuery.error} /></div>}
      <ul className="mt-7 grid gap-3 sm:grid-cols-2">
        {casesQuery.data?.items.map((item) => (
          <li key={item.id}>
            <Link to={`/cases/${item.id}/evidence`} className="block rounded-xl border border-white/8 bg-white/[0.025] p-5 transition hover:border-cyan-300/20 hover:bg-cyan-300/5">
              <p className="font-mono text-[10px] text-cyan-300/65">{item.case_number}</p>
              <h2 className="mt-2 text-base font-semibold text-white">{item.title}</h2>
              <p className="mt-2 text-xs uppercase tracking-wide text-slate-600">{item.status}</p>
            </Link>
          </li>
        ))}
      </ul>
      {casesQuery.data?.items.length === 0 && <p className="mt-8 text-sm text-slate-500">No accessible cases are available.</p>}
    </div>
  );
}

export function EvidenceExplorerPage() {
  const { caseId = "" } = useParams();
  const [parameters, setParameters] = useSearchParams();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const filters = useMemo(
    () => ({
      q: parameters.get("q") ?? "",
      category: (parameters.get("category") ?? "") as ArtifactCategory | "",
      status: (parameters.get("status") ?? "active") as ArtifactStatus,
      extension: parameters.get("extension") ?? "",
    }),
    [parameters],
  );
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const artifactsQuery = useQuery({
    queryKey: caseKeys.artifacts(caseId, filters),
    queryFn: () =>
      searchArtifacts(caseId, {
        ...(filters.q ? { q: filters.q } : {}),
        ...(filters.category ? { category: filters.category } : {}),
        status: filters.status,
        ...(filters.extension ? { extension: filters.extension } : {}),
      }),
    enabled: Boolean(caseId),
  });
  const effectiveSelectedId = selectedId ?? artifactsQuery.data?.items[0]?.id ?? null;
  const detailQuery = useQuery({
    queryKey: ["artifact", caseId, effectiveSelectedId],
    queryFn: () => getArtifact(caseId, effectiveSelectedId ?? ""),
    enabled: Boolean(caseId && effectiveSelectedId),
  });

  const updateFilter = (name: string, value: string) => {
    const next = new URLSearchParams(parameters);
    if (value) next.set(name, value);
    else next.delete(name);
    setSelectedId(null);
    setParameters(next, { replace: true });
  };

  return (
    <div className="mx-auto max-w-7xl">
      <Link to={`/cases/${caseId}`} className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200">
        <ArrowLeft size={15} aria-hidden="true" /> Back to case
      </Link>
      <header className="mt-6 border-b border-white/8 pb-7">
        <p className="font-mono text-xs text-cyan-300/65">{caseQuery.data?.case_number ?? "Case evidence"}</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Evidence explorer</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
          Search extension-classified metadata and inspect the acquisition provenance of sealed files.
        </p>
      </header>
      <div className="mt-6 flex gap-3 rounded-xl border border-amber-200/15 bg-amber-200/5 p-4 text-xs leading-5 text-amber-100/75">
        <ShieldAlert size={18} className="mt-0.5 shrink-0" aria-hidden="true" />
        Content preview is intentionally disabled in this milestone. Media types come from filename extensions; file bytes are not opened, executed, or rendered.
      </div>
      <div className="mt-6 grid gap-3 md:grid-cols-[1fr_180px_140px]">
        <label className="text-xs text-slate-400">
          Search title or source path
          <input
            type="search"
            value={filters.q}
            onChange={(event) => {
              updateFilter("q", event.target.value);
            }}
            className="mt-2 min-h-11 w-full rounded-lg border border-white/10 bg-black/20 px-3 text-sm text-white outline-none focus:border-cyan-300/40"
            placeholder="timeline or Camera"
          />
        </label>
        <label className="text-xs text-slate-400">
          Category
          <select
            value={filters.category}
            onChange={(event) => {
              updateFilter("category", event.target.value);
            }}
            className="mt-2 min-h-11 w-full rounded-lg border border-white/10 bg-[#0b1820] px-3 text-sm text-white"
          >
            {categories.map((category) => <option key={category.value} value={category.value}>{category.label}</option>)}
          </select>
        </label>
        <label className="text-xs text-slate-400">
          Extension
          <input
            value={filters.extension}
            onChange={(event) => {
              updateFilter("extension", event.target.value);
            }}
            className="mt-2 min-h-11 w-full rounded-lg border border-white/10 bg-black/20 px-3 text-sm text-white"
            placeholder="pdf"
          />
        </label>
      </div>
      {artifactsQuery.isPending && <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500"><LoaderCircle size={16} className="animate-spin" /> Searching evidence...</p>}
      {artifactsQuery.isError && <div className="mt-6"><CaseError error={artifactsQuery.error} /></div>}
      {caseQuery.isError && <div className="mt-6"><CaseError error={caseQuery.error} /></div>}
      {artifactsQuery.data && (
        <div className="mt-6 grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(320px,0.8fr)]">
          <section aria-label="Evidence results" className="min-w-0 rounded-2xl border border-white/8 bg-white/[0.025] p-4">
            <div className="flex items-center justify-between gap-3 px-2 pb-3">
              <h2 className="text-sm font-semibold text-white">{artifactsQuery.data.total} normalized artifacts</h2>
              <span className="text-[10px] text-slate-600">Newest collected first</span>
            </div>
            {artifactsQuery.data.items.length === 0 && <p className="p-6 text-sm text-slate-500">No evidence matches these filters.</p>}
            <ul className="max-h-[620px] space-y-2 overflow-y-auto">
              {artifactsQuery.data.items.map((artifact) => (
                <li key={artifact.id}>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedId(artifact.id);
                    }}
                    className={`w-full rounded-xl border p-4 text-left transition ${effectiveSelectedId === artifact.id ? "border-cyan-300/25 bg-cyan-300/7" : "border-white/7 bg-black/10 hover:border-white/15"}`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="truncate text-sm font-semibold text-slate-100">{artifact.title}</span>
                      <span className="rounded-full border border-white/10 px-2 py-1 text-[9px] uppercase text-slate-400">{artifact.category}</span>
                    </div>
                    <p className="mt-2 truncate font-mono text-[10px] text-slate-500">{artifact.source_relative_path}</p>
                    <p className="mt-2 text-[10px] text-slate-600">{formatBytes(artifact.size_bytes)} · {artifact.detected_mime}</p>
                  </button>
                </li>
              ))}
            </ul>
          </section>
          <ArtifactDetail artifact={detailQuery.data} pending={detailQuery.isPending} error={detailQuery.error} />
        </div>
      )}
    </div>
  );
}

function ArtifactDetail({ artifact, pending, error }: { artifact?: Artifact; pending: boolean; error: Error | null }) {
  if (pending) return <aside role="status" className="rounded-2xl border border-white/8 p-6 text-sm text-slate-500">Loading artifact provenance...</aside>;
  if (error) return <aside><CaseError error={error} /></aside>;
  if (!artifact) return <aside className="rounded-2xl border border-dashed border-white/10 p-8 text-sm text-slate-600"><FileSearch className="mb-3" />Select an artifact.</aside>;
  const limitations = Array.isArray(artifact.metadata.limitations) ? artifact.metadata.limitations.map(String) : [];
  return (
    <aside className="min-w-0 rounded-2xl border border-white/8 bg-white/[0.025] p-5">
      <p className="text-[10px] uppercase tracking-[0.16em] text-cyan-300">Normalized metadata</p>
      <h2 className="mt-2 break-words text-xl font-semibold text-white">{artifact.title}</h2>
      <dl className="mt-5 space-y-4 text-xs">
        <Detail label="Source path" value={artifact.source_relative_path} mono />
        <Detail label="SHA-256" value={artifact.primary_sha256} mono />
        <Detail label="Size" value={`${formatBytes(artifact.size_bytes)} (${String(artifact.size_bytes)} bytes)`} />
        <Detail label="Extension-derived MIME" value={artifact.detected_mime} />
        <Detail label="Collected" value={new Date(artifact.collected_at).toLocaleString()} />
        <Detail label="Normalizer" value={`${artifact.parser_id} ${artifact.parser_version}`} />
        <Detail label="Evidence file ID" value={artifact.evidence_file_id} mono />
        <Detail label="Device ID" value={artifact.device_id} mono />
      </dl>
      {limitations.length > 0 && (
        <div className="mt-6 rounded-lg border border-amber-200/12 bg-amber-200/5 p-3 text-[11px] leading-5 text-amber-100/70">
          <p className="font-semibold text-amber-100">Normalization limitations</p>
          <ul className="mt-2 list-disc space-y-1 pl-4">{limitations.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
      )}
    </aside>
  );
}

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div><dt className="text-slate-600">{label}</dt><dd className={`mt-1 break-all text-slate-300 ${mono ? "font-mono text-[10px]" : ""}`}>{value}</dd></div>;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${String(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

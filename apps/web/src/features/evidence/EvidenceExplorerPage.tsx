import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Bookmark, FileSearch, ImageIcon, LoaderCircle, ShieldAlert, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import {
  getArtifact,
  getArtifactAnnotations,
  getArtifactPreview,
  getCase,
  listCases,
  searchArtifacts,
  addAnalystNote,
  addArtifactTag,
  bookmarkArtifact,
  removeArtifactBookmark,
  artifactPreviewContentUrl,
  generateArtifactPreview,
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
      duplicateOnly: parameters.get("duplicates") === "true" ? "true" : "",
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
        ...(filters.duplicateOnly ? { duplicateOnly: true } : {}),
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
          Search normalized metadata, inspect provenance, and request bounded derivatives for supported images.
        </p>
      </header>
      <div className="mt-6 flex gap-3 rounded-xl border border-amber-200/15 bg-amber-200/5 p-4 text-xs leading-5 text-amber-100/75">
        <ShieldAlert size={18} className="mt-0.5 shrink-0" aria-hidden="true" />
        Original evidence is never rendered. Preview requests run in an isolated, resource-bounded worker and the browser receives only a verified PNG derivative.
      </div>
      <div className="mt-6 grid gap-3 md:grid-cols-[1fr_180px_140px_150px]">
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
        <label className="flex min-h-11 items-center gap-2 self-end rounded-lg border border-white/10 bg-black/20 px-3 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={filters.duplicateOnly === "true"}
            onChange={(event) => { updateFilter("duplicates", event.target.checked ? "true" : ""); }}
          />
          Duplicates only
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
                    {artifact.duplicate_count > 1 && <p className="mt-2 text-[10px] font-semibold text-amber-200">{artifact.duplicate_count} files share this SHA-256</p>}
                  </button>
                </li>
              ))}
            </ul>
          </section>
          <ArtifactDetail caseId={caseId} artifact={detailQuery.data} pending={detailQuery.isPending} error={detailQuery.error} />
        </div>
      )}
    </div>
  );
}

function ArtifactDetail({ caseId, artifact, pending, error }: { caseId: string; artifact?: Artifact; pending: boolean; error: Error | null }) {
  if (pending) return <aside role="status" className="rounded-2xl border border-white/8 p-6 text-sm text-slate-500">Loading artifact provenance...</aside>;
  if (error) return <aside><CaseError error={error} /></aside>;
  if (!artifact) return <aside className="rounded-2xl border border-dashed border-white/10 p-8 text-sm text-slate-600"><FileSearch className="mb-3" />Select an artifact.</aside>;
  return <ArtifactDetailContent caseId={caseId} artifact={artifact} />;
}

function ArtifactDetailContent({ caseId, artifact }: { caseId: string; artifact: Artifact }) {
  const queryClient = useQueryClient();
  const [tagName, setTagName] = useState("");
  const [noteBody, setNoteBody] = useState("");
  const annotationKey = ["artifact-annotations", caseId, artifact.id] as const;
  const annotations = useQuery({
    queryKey: annotationKey,
    queryFn: () => getArtifactAnnotations(caseId, artifact.id),
  });
  const previewKey = ["artifact-preview", caseId, artifact.id] as const;
  const preview = useQuery({
    queryKey: previewKey,
    queryFn: () => getArtifactPreview(caseId, artifact.id),
  });
  const generatePreview = useMutation({
    mutationFn: () => generateArtifactPreview(caseId, artifact.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: previewKey }),
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: annotationKey });
  const bookmark = useMutation({
    mutationFn: async () => {
      if (annotations.data?.bookmark) {
        await removeArtifactBookmark(caseId, artifact.id);
      } else {
        await bookmarkArtifact(caseId, artifact.id);
      }
    },
    onSuccess: refresh,
  });
  const addTag = useMutation({
    mutationFn: () => addArtifactTag(caseId, artifact.id, tagName),
    onSuccess: () => {
      setTagName("");
      void refresh();
    },
  });
  const addNote = useMutation({
    mutationFn: () => addAnalystNote(caseId, artifact.id, noteBody),
    onSuccess: () => {
      setNoteBody("");
      void refresh();
    },
  });
  const limitations = Array.isArray(artifact.metadata.limitations) ? artifact.metadata.limitations.map(String) : [];
  const actionError = annotations.error ?? preview.error ?? generatePreview.error ?? bookmark.error ?? addTag.error ?? addNote.error;
  return (
    <aside className="min-w-0 rounded-2xl border border-white/8 bg-white/[0.025] p-5">
      <p className="text-[10px] uppercase tracking-[0.16em] text-cyan-300">Normalized metadata</p>
      <h2 className="mt-2 break-words text-xl font-semibold text-white">{artifact.title}</h2>
      <dl className="mt-5 space-y-4 text-xs">
        <Detail label="Source path" value={artifact.source_relative_path} mono />
        <Detail label="SHA-256" value={artifact.primary_sha256} mono />
        <Detail label="Exact duplicates" value={artifact.duplicate_count > 1 ? `${artifact.duplicate_count} artifacts share this hash` : "No exact duplicate in this case"} />
        <Detail label="Size" value={`${formatBytes(artifact.size_bytes)} (${String(artifact.size_bytes)} bytes)`} />
        <Detail label="Extension-derived MIME" value={artifact.detected_mime} />
        <Detail label="Collected" value={new Date(artifact.collected_at).toLocaleString()} />
        <Detail label="Normalizer" value={`${artifact.parser_id} ${artifact.parser_version}`} />
        <Detail label="Evidence file ID" value={artifact.evidence_file_id} mono />
        <Detail label="Device ID" value={artifact.device_id} mono />
      </dl>
      <section className="mt-6 rounded-xl border border-cyan-200/10 bg-cyan-300/[0.025] p-4" aria-label="Safe evidence preview">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="flex items-center gap-2 text-xs font-semibold text-cyan-100"><ShieldCheck size={14} />Safe derivative preview</p>
            <p className="mt-1 text-[10px] leading-4 text-slate-500">Signature checked, decoded out of process, re-encoded without source metadata.</p>
          </div>
          {preview.data?.status === "not_generated" && (
            <button
              type="button"
              disabled={generatePreview.isPending}
              onClick={() => { generatePreview.mutate(); }}
              className="inline-flex min-h-9 shrink-0 items-center gap-2 rounded border border-cyan-200/15 px-3 text-[11px] text-cyan-100 disabled:opacity-40"
            >
              {generatePreview.isPending ? <LoaderCircle size={13} className="animate-spin" /> : <ImageIcon size={13} />}
              Inspect safely
            </button>
          )}
        </div>
        {preview.isPending && <p role="status" className="mt-4 text-[11px] text-slate-500">Checking preview status...</p>}
        {preview.data?.status === "available" && (
          <div className="mt-4">
            <img
              src={artifactPreviewContentUrl(caseId, artifact.id)}
              alt={`Safe derivative preview of ${artifact.title}`}
              className="max-h-80 w-full rounded-lg border border-white/8 bg-black/30 object-contain"
            />
            <p className="mt-2 break-all font-mono text-[9px] text-slate-600">Derivative SHA-256: {preview.data.output_sha256}</p>
            <div className="mt-3 grid grid-cols-2 gap-2 rounded border border-white/7 bg-black/15 p-3 text-[10px] text-slate-400">
              <Detail label="Source dimensions" value={`${String(preview.data.source_width)} x ${String(preview.data.source_height)}`} />
              <Detail label="Format" value={String(preview.data.media_metadata.format ?? preview.data.detected_mime)} />
              {typeof preview.data.media_metadata.frame_count === "number" && <Detail label="Frames" value={String(preview.data.media_metadata.frame_count)} />}
              {typeof preview.data.media_metadata.gps_present === "boolean" && <Detail label="GPS metadata" value={preview.data.media_metadata.gps_present ? "Present" : "Not present"} />}
            </div>
            {isRecord(preview.data.media_metadata.exif) && (
              <details className="mt-3 rounded border border-white/7 p-3 text-[10px] text-slate-400">
                <summary className="cursor-pointer text-slate-300">Bounded EXIF metadata</summary>
                <dl className="mt-3 grid grid-cols-2 gap-2">
                  {Object.entries(preview.data.media_metadata.exif).map(([key, value]) => <Detail key={key} label={key} value={String(value)} />)}
                </dl>
              </details>
            )}
            {preview.data.extension_mismatch && <p className="mt-2 text-[11px] text-amber-200">The file signature does not match its extension-derived MIME label.</p>}
          </div>
        )}
        {(preview.data?.status === "rejected" || preview.data?.status === "failed") && (
          <div className="mt-4 flex gap-2 rounded border border-amber-200/10 bg-amber-200/5 p-3 text-[11px] leading-5 text-amber-100/75">
            <ShieldAlert size={15} className="mt-0.5 shrink-0" />
            <div><p className="font-semibold">Preview {preview.data.status}</p><p>{preview.data.error_message}</p><p className="mt-1 font-mono text-[9px]">{preview.data.error_code}</p></div>
          </div>
        )}
      </section>
      {limitations.length > 0 && (
        <div className="mt-6 rounded-lg border border-amber-200/12 bg-amber-200/5 p-3 text-[11px] leading-5 text-amber-100/70">
          <p className="font-semibold text-amber-100">Normalization limitations</p>
          <ul className="mt-2 list-disc space-y-1 pl-4">{limitations.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
      )}
      <section className="mt-6 border-t border-white/8 pt-5">
        <div className="flex items-center justify-between gap-3">
          <h3 className="text-sm font-semibold text-white">Analyst annotations</h3>
          <button
            type="button"
            disabled={bookmark.isPending || annotations.isPending}
            onClick={() => {
              bookmark.mutate();
            }}
            className="inline-flex min-h-9 items-center gap-2 rounded border border-cyan-200/15 px-3 text-[11px] text-cyan-100 disabled:opacity-40"
          >
            <Bookmark size={13} fill={annotations.data?.bookmark ? "currentColor" : "none"} />
            {annotations.data?.bookmark ? "Remove bookmark" : "Bookmark"}
          </button>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          {annotations.data?.tags.map((tag) => <span key={tag.id} className="rounded-full bg-cyan-300/8 px-2 py-1 text-[10px] text-cyan-100">{tag.name}</span>)}
        </div>
        <form
          className="mt-3 flex gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (tagName.trim()) addTag.mutate();
          }}
        >
          <input aria-label="New evidence tag" value={tagName} onChange={(event) => { setTagName(event.target.value); }} maxLength={64} className="min-h-9 min-w-0 flex-1 rounded border border-white/10 bg-black/20 px-2 text-xs" placeholder="priority" />
          <button type="submit" disabled={addTag.isPending || !tagName.trim()} className="rounded border border-white/10 px-3 text-[11px] disabled:opacity-40">Add tag</button>
        </form>
        <form
          className="mt-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (noteBody.trim()) addNote.mutate();
          }}
        >
          <label className="text-[11px] text-slate-500">Append analyst note
            <textarea aria-label="Append analyst note" value={noteBody} onChange={(event) => { setNoteBody(event.target.value); }} maxLength={4000} className="mt-2 min-h-20 w-full rounded border border-white/10 bg-black/20 p-2 text-xs text-slate-200" />
          </label>
          <button type="submit" disabled={addNote.isPending || !noteBody.trim()} className="mt-2 min-h-9 rounded border border-white/10 px-3 text-[11px] disabled:opacity-40">Append note</button>
        </form>
        <ol className="mt-4 space-y-2">
          {annotations.data?.notes.map((note) => (
            <li key={note.id} className="rounded border border-white/7 bg-black/10 p-3 text-[11px] leading-5 text-slate-300">
              {note.body}
              <p className="mt-1 text-[9px] text-slate-600">{new Date(note.created_at).toLocaleString()}{note.supersedes_id ? " · amendment" : ""}</p>
            </li>
          ))}
        </ol>
        {actionError && <div className="mt-3"><CaseError error={actionError} /></div>}
      </section>
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

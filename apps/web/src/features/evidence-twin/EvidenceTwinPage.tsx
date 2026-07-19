import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  CopyCheck,
  DatabaseBackup,
  FileUp,
  LoaderCircle,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import {
  createEvidenceWorkingCopy,
  getCase,
  importEvidenceSource,
  listEvidenceSources,
  listEvidenceSourceVerifications,
  listEvidenceWorkingCopies,
  verifyEvidenceSource,
  type EvidenceSource,
} from "../../lib/api";

const twinKeys = {
  sources: (caseId: string) => ["evidence-twin", caseId, "sources"] as const,
  copies: (caseId: string, sourceId: string) =>
    ["evidence-twin", caseId, sourceId, "copies"] as const,
  verifications: (caseId: string, sourceId: string) =>
    ["evidence-twin", caseId, sourceId, "verifications"] as const,
};

export function EvidenceTwinPage() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [displayName, setDisplayName] = useState("");
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const sourcesQuery = useQuery({
    queryKey: twinKeys.sources(caseId),
    queryFn: () => listEvidenceSources(caseId),
    enabled: Boolean(caseId),
  });
  const importSource = useMutation({
    mutationFn: () => {
      if (!selectedFile) throw new Error("Select an evidence source before importing.");
      return importEvidenceSource(caseId, selectedFile, displayName);
    },
    onSuccess: () => {
      setSelectedFile(null);
      setDisplayName("");
      void queryClient.invalidateQueries({ queryKey: twinKeys.sources(caseId) });
    },
  });
  const caseWritable = !new Set(["closed", "archived"]).has(caseQuery.data?.status ?? "closed");

  return (
    <div className="mx-auto max-w-6xl">
      <Link
        to={`/cases/${caseId}`}
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"
      >
        <ArrowLeft size={15} aria-hidden="true" /> Back to case
      </Link>
      <header className="mt-6 border-b border-white/8 pb-8">
        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">
          Offline forensic examination
        </p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight text-white">Evidence Twin</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
          Import an existing image or extraction, seal its master bytes, and examine only a
          separately verified working copy. Import does not prove how the original source was
          acquired.
        </p>
      </header>

      <section className="mt-8 grid gap-6 lg:grid-cols-[1.05fr_0.95fr]">
        <form
          className="rounded-2xl border border-white/8 bg-white/[0.025] p-6"
          onSubmit={(event) => {
            event.preventDefault();
            importSource.mutate();
          }}
        >
          <div className="flex items-start gap-3">
            <FileUp className="mt-1 text-cyan-300" size={21} aria-hidden="true" />
            <div>
              <h2 className="text-xl font-semibold text-white">Import evidence source</h2>
              <p className="mt-2 text-xs leading-5 text-slate-500">
                Supported containers currently include RAW, IMG, DD, TAR, and ZIP. Content
                detection and parsing happen only after a verified working copy exists.
              </p>
            </div>
          </div>
          <label className="mt-6 block text-sm font-medium text-slate-300" htmlFor="twin-source">
            Evidence image or extraction
          </label>
          <input
            id="twin-source"
            type="file"
            accept=".raw,.img,.dd,.tar,.zip,application/octet-stream,application/zip"
            disabled={!caseWritable || importSource.isPending}
            onChange={(event) => {
              setSelectedFile(event.target.files?.[0] ?? null);
            }}
            className="mt-2 block min-h-12 w-full rounded-lg border border-white/10 bg-black/20 p-3 text-xs text-slate-300 file:mr-4 file:rounded file:border-0 file:bg-cyan-300 file:px-3 file:py-2 file:font-semibold file:text-slate-950 disabled:opacity-40"
          />
          <label className="mt-5 block text-sm font-medium text-slate-300" htmlFor="twin-name">
            Examination label
          </label>
          <input
            id="twin-name"
            value={displayName}
            maxLength={255}
            disabled={!caseWritable || importSource.isPending}
            onChange={(event) => {
              setDisplayName(event.target.value);
            }}
            placeholder={selectedFile?.name ?? "Example: Infinix X666 imported filesystem"}
            className="mt-2 min-h-11 w-full rounded-lg border border-white/10 bg-black/20 px-3 text-sm text-slate-200 outline-none focus:border-cyan-300/40 disabled:opacity-40"
          />
          {selectedFile && (
            <p className="mt-3 text-xs text-slate-500">
              {selectedFile.name} · {formatBytes(selectedFile.size)} selected
            </p>
          )}
          <div className="mt-5 flex gap-3 rounded-xl border border-amber-200/15 bg-amber-200/5 p-4 text-xs leading-5 text-amber-100/75">
            <AlertTriangle className="mt-0.5 shrink-0" size={17} aria-hidden="true" />
            <p>
              ForensiX will record this as an imported source at filesystem level. A filename or
              extension alone is never treated as proof of physical acquisition.
            </p>
          </div>
          <button
            type="submit"
            disabled={!selectedFile || !caseWritable || importSource.isPending}
            className="mt-5 inline-flex min-h-11 items-center gap-2 rounded-lg bg-cyan-300 px-4 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {importSource.isPending ? (
              <LoaderCircle className="animate-spin" size={16} aria-hidden="true" />
            ) : (
              <DatabaseBackup size={16} aria-hidden="true" />
            )}
            {importSource.isPending ? "Streaming and sealing…" : "Import and seal master"}
          </button>
          {!caseWritable && (
            <p className="mt-3 text-xs text-rose-200">Closed or archived cases cannot import evidence.</p>
          )}
          {importSource.isError && <div className="mt-4"><CaseError error={importSource.error} /></div>}
        </form>

        <div className="rounded-2xl border border-cyan-200/10 bg-cyan-200/5 p-6">
          <ShieldCheck className="text-cyan-300" size={24} aria-hidden="true" />
          <h2 className="mt-4 text-xl font-semibold text-white">Integrity boundary</h2>
          <ol className="mt-5 space-y-4 text-sm leading-6 text-slate-400">
            <IntegrityStep number="1" text="Stream source bytes into contained evidence storage." />
            <IntegrityStep number="2" text="Calculate fixed 4 MiB chunk hashes and complete SHA-256." />
            <IntegrityStep number="3" text="Seal master, chunk ledger, and canonical manifest separately." />
            <IntegrityStep number="4" text="Create and verify a distinct examination working copy." />
          </ol>
          <p className="mt-6 text-xs leading-5 text-slate-500">
            Read-only permissions reduce accidental modification. Hash verification provides the
            tamper-evident control; local files are not described as tamper-proof.
          </p>
        </div>
      </section>

      <section className="mt-8">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
              Sealed sources
            </p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Case Evidence Twins</h2>
          </div>
          {sourcesQuery.isFetching && <LoaderCircle className="animate-spin text-cyan-300" size={18} />}
        </div>
        {sourcesQuery.isError && <div className="mt-5"><CaseError error={sourcesQuery.error} /></div>}
        {!sourcesQuery.isPending && sourcesQuery.data?.length === 0 && (
          <div className="mt-5 rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-slate-500">
            No Evidence Twin source has been registered for this case.
          </div>
        )}
        <div className="mt-5 space-y-4">
          {sourcesQuery.data?.map((source) => (
            <EvidenceSourceCard key={source.id} caseId={caseId} source={source} />
          ))}
        </div>
      </section>
    </div>
  );
}

function EvidenceSourceCard({ caseId, source }: { caseId: string; source: EvidenceSource }) {
  const queryClient = useQueryClient();
  const copiesQuery = useQuery({
    queryKey: twinKeys.copies(caseId, source.id),
    queryFn: () => listEvidenceWorkingCopies(caseId, source.id),
    enabled: source.status === "sealed",
  });
  const verificationsQuery = useQuery({
    queryKey: twinKeys.verifications(caseId, source.id),
    queryFn: () => listEvidenceSourceVerifications(caseId, source.id),
    enabled: source.status === "sealed",
  });
  const verify = useMutation({
    mutationFn: () => verifyEvidenceSource(caseId, source.id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: twinKeys.verifications(caseId, source.id) });
    },
  });
  const createCopy = useMutation({
    mutationFn: () => createEvidenceWorkingCopy(caseId, source.id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: twinKeys.copies(caseId, source.id) });
      void queryClient.invalidateQueries({ queryKey: twinKeys.verifications(caseId, source.id) });
    },
  });
  const latestVerification = verificationsQuery.data?.[0];

  return (
    <article className="rounded-2xl border border-white/8 bg-white/[0.025] p-5 sm:p-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-lg font-semibold text-white">{source.display_name}</h3>
            <span className="rounded-full border border-emerald-200/15 px-2 py-1 text-[10px] uppercase tracking-wide text-emerald-200">
              {source.status}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-500">
            {source.source_name} · {source.container_format.toUpperCase()} · {formatBytes(source.size_bytes ?? 0)}
          </p>
        </div>
        <span className="text-xs text-slate-600">{source.chunk_count} hashed chunks</span>
      </div>
      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <HashClaim label="Master SHA-256" value={source.sha256} />
        <HashClaim label="Chunk ledger SHA-256" value={source.chunks_sha256} />
        <HashClaim label="Manifest SHA-256" value={source.manifest_sha256} />
      </div>
      <div className="mt-5 flex flex-wrap items-center gap-3">
        <button
          type="button"
          disabled={source.status !== "sealed" || verify.isPending}
          onClick={() => {
            verify.mutate();
          }}
          className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-emerald-200/15 px-3 text-xs font-semibold text-emerald-100 disabled:opacity-40"
        >
          {verify.isPending ? <LoaderCircle className="animate-spin" size={14} /> : <CheckCircle2 size={14} />}
          Verify sealed master
        </button>
        <button
          type="button"
          disabled={source.status !== "sealed" || createCopy.isPending}
          onClick={() => {
            createCopy.mutate();
          }}
          className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-300 px-3 text-xs font-semibold text-slate-950 disabled:opacity-40"
        >
          {createCopy.isPending ? <LoaderCircle className="animate-spin" size={14} /> : <CopyCheck size={14} />}
          Create verified working copy
        </button>
        {latestVerification && (
          <span className={`text-xs font-semibold ${latestVerification.status === "verified" ? "text-emerald-200" : "text-rose-200"}`}>
            Latest {latestVerification.target_type.replace("_", " ")}: {latestVerification.status}
          </span>
        )}
      </div>
      <p className="mt-4 text-xs text-slate-500">
        {copiesQuery.data?.length ?? 0} working copies · {verificationsQuery.data?.length ?? 0} integrity observations · read-only permission {source.read_only_applied ? "applied" : "not confirmed"}
      </p>
      {source.limitations.map((limitation) => (
        <p key={limitation} className="mt-2 text-xs leading-5 text-amber-100/65">• {limitation}</p>
      ))}
      {verify.isError && <div className="mt-4"><CaseError error={verify.error} /></div>}
      {createCopy.isError && <div className="mt-4"><CaseError error={createCopy.error} /></div>}
    </article>
  );
}

function IntegrityStep({ number, text }: { number: string; text: string }) {
  return (
    <li className="flex gap-3">
      <span className="grid size-7 shrink-0 place-items-center rounded-full border border-cyan-200/15 text-xs text-cyan-200">
        {number}
      </span>
      <span>{text}</span>
    </li>
  );
}

function HashClaim({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="min-w-0 rounded-lg border border-white/8 bg-black/10 p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-600">{label}</p>
      <p className="mt-2 truncate font-mono text-[10px] text-slate-400" title={value ?? undefined}>
        {value ?? "Not available"}
      </p>
    </div>
  );
}

function formatBytes(value: number): string {
  if (value < 1024) return `${String(value)} bytes`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

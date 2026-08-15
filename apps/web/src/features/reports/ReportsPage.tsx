import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, FileCheck2, LoaderCircle, ShieldAlert } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useState } from "react";

import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import { FileTypeIcon } from "../../components/FileTypeIcon";
import {
  artifactPreviewContentUrl,
  auditLogDownloadUrl,
  caseAuditLogDownloadUrl,
  generateReport,
  generateArtifactPreview,
  getArtifactPreview,
  getCurrentUser,
  getCase,
  listCustodyEvents,
  listCases,
  listReports,
  reportDownloadUrl,
  reviewReport,
  searchArtifacts,
  type Artifact,
} from "../../lib/api";
import { authKeys } from "../auth/authKeys";
import { formatUtcAsLocal } from "../../lib/time";

export function ReportsCasesPage() {
  const casesQuery = useQuery({ queryKey: caseKeys.all, queryFn: listCases });
  return (
    <div className="mx-auto max-w-5xl">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">Versioned exports</p>
      <h1 className="mt-2 text-3xl font-semibold text-white">Preliminary reports</h1>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
        Choose a case to generate reproducible PDF, JSON, and spreadsheet-safe CSV outputs.
      </p>
      {casesQuery.isPending && <p role="status" className="mt-8 text-sm text-slate-500">Loading accessible cases...</p>}
      {casesQuery.isError && <div className="mt-6"><CaseError error={casesQuery.error} /></div>}
      <ul className="mt-7 grid gap-3 sm:grid-cols-2">
        {casesQuery.data?.items.map((item) => (
          <li key={item.id}>
            <Link to={`/cases/${item.id}/reports`} className="block rounded-md border border-neutral-300 bg-white p-5 transition hover:border-neutral-500 hover:bg-neutral-50">
              <p className="font-mono text-[10px] font-medium text-[#246c44]">{item.case_number}</p>
              <h2 className="mt-2 text-base font-semibold text-neutral-950">{item.title}</h2>
              <p className="mt-2 text-xs font-medium uppercase tracking-wide text-neutral-600">{item.status}</p>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function CaseReportsPage() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const [redactionProfile, setRedactionProfile] = useState<"full" | "mask_sensitive" | "metadata_only">("full");
  const [reviewNotes, setReviewNotes] = useState<Record<string, string>>({});
  const [evidencePage, setEvidencePage] = useState(0);
  const currentUser = useQuery({ queryKey: authKeys.me, queryFn: getCurrentUser });
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const reportsQuery = useQuery({
    queryKey: ["reports", caseId],
    queryFn: () => listReports(caseId),
    enabled: Boolean(caseId),
  });
  const artifactsQuery = useQuery({
    queryKey: ["report-evidence", caseId, evidencePage],
    queryFn: () => searchArtifacts(caseId, { offset: evidencePage * 50, limit: 50 }),
    enabled: Boolean(caseId),
  });
  const custodyQuery = useQuery({
    queryKey: ["report-custody", caseId],
    queryFn: () => listCustodyEvents(caseId),
    enabled: Boolean(caseId),
  });
  const generation = useMutation({
    mutationFn: () => generateReport(caseId, redactionProfile),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["reports", caseId] });
    },
  });
  const review = useMutation({
    mutationFn: ({ reportId, decision }: { reportId: string; decision: "approved" | "rejected" }) =>
      reviewReport(caseId, reportId, decision, reviewNotes[reportId] ?? ""),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ["reports", caseId] }); },
  });
  if (caseQuery.isPending) return <LoaderCircle className="animate-spin text-cyan-300" aria-label="Loading case" />;
  if (caseQuery.isError) return <CaseError error={caseQuery.error} />;
  return (
    <div className="mx-auto max-w-5xl">
      <Link to={`/cases/${caseId}`} className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"><ArrowLeft size={15} /> Back to case</Link>
      <div className="mt-6 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <div>
          <p className="font-mono text-xs text-cyan-300/70">{caseQuery.data.case_number}</p>
          <h1 className="mt-2 text-3xl font-semibold text-white">Reports</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">Each generation freezes a new schema-validated snapshot. Existing outputs are never overwritten.</p>
        </div>
        <div className="flex flex-col gap-2">
          <label className="text-xs text-slate-400">Redaction profile
            <select value={redactionProfile} onChange={(event) => { setRedactionProfile(event.target.value as typeof redactionProfile); }} className="mt-1 min-h-10 w-full rounded border border-white/10 bg-[#0b1820] px-3 text-sm text-white">
              <option value="full">Full case detail</option>
              <option value="mask_sensitive">Mask sensitive narrative</option>
              <option value="metadata_only">Metadata and hashes only</option>
            </select>
          </label>
          <button type="button" disabled={generation.isPending} onClick={() => { generation.mutate(); }} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-cyan-300 px-5 text-sm font-semibold text-slate-950 disabled:cursor-wait disabled:opacity-50">
            {generation.isPending ? <LoaderCircle size={17} className="animate-spin" /> : <FileCheck2 size={17} />} Generate preliminary report
          </button>
          <a href={caseAuditLogDownloadUrl(caseId)} className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg border border-cyan-300/20 px-4 text-xs font-semibold text-cyan-100">
            <Download size={14} /> Download this case audit log
          </a>
          <a href={auditLogDownloadUrl()} className="inline-flex min-h-9 items-center justify-center gap-2 px-4 text-xs font-medium text-slate-400 hover:text-cyan-100">
            <Download size={13} /> Download all workstation audit logs
          </a>
        </div>
      </div>
      <div className="mt-6 flex gap-3 rounded-xl border border-amber-300/20 bg-amber-300/5 p-4 text-sm leading-6 text-amber-100/80">
        <ShieldAlert className="mt-0.5 shrink-0 text-amber-300" size={19} />
        <p>Reports are marked Preliminary by default. ADB is not a hardware write blocker, and unsupported private application data is not claimed.</p>
      </div>
      <section className="mt-6 border-y border-white/10 py-6" aria-labelledby="acquired-evidence-heading">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">Evidence inventory</p>
            <h2 id="acquired-evidence-heading" className="mt-2 text-xl font-semibold text-white">All acquired files</h2>
            <p className="mt-2 text-xs text-slate-500">Evidence keys, integrity hashes, and safe visual identification.</p>
          </div>
          <p className="font-mono text-xs text-slate-500">{artifactsQuery.data?.total ?? 0} files</p>
        </div>
        {artifactsQuery.isPending && <p role="status" className="mt-5 text-sm text-slate-500">Loading acquired evidence...</p>}
        {artifactsQuery.isError && <div className="mt-5"><CaseError error={artifactsQuery.error} /></div>}
        <ul className="mt-5 space-y-2">
          {artifactsQuery.data?.items.map((artifact) => (
            <li key={artifact.id} className="grid gap-4 rounded-md border border-white/8 bg-white/[0.02] p-3 sm:grid-cols-[100px_minmax(0,1fr)]">
              <EvidenceVisual caseId={caseId} artifact={artifact} />
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-white" title={artifact.title}>{artifact.title}</p>
                <p className="mt-1 break-all font-mono text-[10px] text-slate-500">{artifact.source_relative_path}</p>
                <dl className="mt-3 grid gap-2 text-[10px] sm:grid-cols-2">
                  <div><dt className="text-slate-600">Evidence key</dt><dd className="mt-0.5 break-all font-mono text-cyan-100/70">{typeof artifact.provenance.storage_key === "string" ? artifact.provenance.storage_key : "Unavailable"}</dd></div>
                  <div><dt className="text-slate-600">SHA-256</dt><dd className="mt-0.5 break-all font-mono text-emerald-100/70">{artifact.primary_sha256}</dd></div>
                  <div><dt className="text-slate-600">Type / size</dt><dd className="mt-0.5 text-slate-300">{artifact.detected_mime} · {artifact.size_bytes.toLocaleString()} bytes</dd></div>
                  <div><dt className="text-slate-600">Collected</dt><dd className="mt-0.5 text-slate-300">{formatUtcAsLocal(artifact.collected_at)}</dd></div>
                </dl>
              </div>
            </li>
          ))}
        </ul>
        {(artifactsQuery.data?.total ?? 0) > 50 && (
          <div className="mt-4 flex items-center justify-between gap-3 text-xs">
            <button type="button" disabled={evidencePage === 0} onClick={() => { setEvidencePage((page) => Math.max(0, page - 1)); }} className="min-h-9 rounded border border-white/10 px-3 text-slate-300 disabled:opacity-35">Previous</button>
            <span className="text-slate-500">Page {evidencePage + 1} of {Math.ceil((artifactsQuery.data?.total ?? 0) / 50)}</span>
            <button type="button" disabled={(evidencePage + 1) * 50 >= (artifactsQuery.data?.total ?? 0)} onClick={() => { setEvidencePage((page) => page + 1); }} className="min-h-9 rounded border border-white/10 px-3 text-slate-300 disabled:opacity-35">Next</button>
          </div>
        )}
        <div className="mt-7 border-t border-white/8 pt-5">
          <h3 className="text-sm font-semibold text-white">Chain of custody</h3>
          <p className="mt-1 text-xs text-slate-500">{custodyQuery.data?.length ?? 0} hash-linked events</p>
          <ol className="mt-3 max-h-72 space-y-2 overflow-auto pr-1">
            {custodyQuery.data?.map((event) => (
              <li key={event.id} className="grid gap-2 rounded border border-white/7 p-3 text-[10px] sm:grid-cols-[3rem_10rem_minmax(0,1fr)]">
                <span className="font-mono text-cyan-300">#{event.sequence}</span>
                <span className="text-slate-500">{formatUtcAsLocal(event.created_at)}</span>
                <span className="min-w-0"><strong className="block text-slate-200">{event.event_type.replaceAll("_", " ")}</strong><span className="block truncate font-mono text-slate-600" title={event.event_hash}>{event.event_hash}</span></span>
              </li>
            ))}
          </ol>
        </div>
      </section>
      {generation.isError && <div className="mt-5"><CaseError error={generation.error} /></div>}
      {review.isError && <div className="mt-5"><CaseError error={review.error} /></div>}
      {reportsQuery.isError && <div className="mt-5"><CaseError error={reportsQuery.error} /></div>}
      {reportsQuery.isPending && <p role="status" className="mt-8 text-sm text-slate-500">Loading reports...</p>}
      <ol className="mt-6 space-y-4">
        {reportsQuery.data?.map((report) => (
          <li key={report.id} className="rounded-2xl border border-white/8 bg-white/[0.025] p-5 sm:p-6">
            <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
              <div>
                <span className="rounded-full border border-amber-300/25 bg-amber-300/7 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-amber-200">Preliminary</span>
                <span className="ml-2 rounded-full border border-white/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-300">{report.approval_state}</span>
                <h2 className="mt-3 font-semibold text-white">{report.title}</h2>
                <p className="mt-1 text-xs text-slate-500">Generated {formatUtcAsLocal(report.generated_at)}</p>
              </div>
              <div className="flex flex-wrap gap-2">
                {report.outputs.map((output) => (
                  <a key={output.format} href={reportDownloadUrl(caseId, report.id, output.format)} className="inline-flex min-h-9 items-center gap-2 rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-3 text-xs font-semibold uppercase text-cyan-100">
                    <Download size={14} /> {output.format}
                  </a>
                ))}
              </div>
            </div>
            <dl className="mt-5 grid gap-4 border-t border-white/8 pt-4 text-xs sm:grid-cols-2">
              <div><dt className="text-slate-600">Snapshot SHA-256</dt><dd className="mt-1 break-all font-mono text-slate-400">{report.snapshot_sha256}</dd></div>
              <div><dt className="text-slate-600">Contract versions</dt><dd className="mt-1 text-slate-400">Schema {report.schema_version} / template {report.template_version}</dd></div>
              <div><dt className="text-slate-600">Redaction profile</dt><dd className="mt-1 text-slate-400">{report.redaction_profile.replaceAll("_", " ")}</dd></div>
              {report.latest_review && <div><dt className="text-slate-600">Latest supervisory review</dt><dd className="mt-1 text-slate-400">{report.latest_review.decision}: {report.latest_review.note}</dd><dd className="mt-1 break-all font-mono text-[9px] text-slate-600">{report.latest_review.event_hash}</dd></div>}
            </dl>
            {currentUser.data?.permissions.includes("reports:approve") && currentUser.data.user_id !== report.generated_by && (
              <div className="mt-5 rounded-xl border border-cyan-300/10 bg-cyan-300/[0.025] p-4">
                <label className="text-xs text-slate-400">Independent review note
                  <textarea value={reviewNotes[report.id] ?? ""} onChange={(event) => { setReviewNotes((current) => ({ ...current, [report.id]: event.target.value })); }} maxLength={1000} className="mt-2 min-h-20 w-full rounded border border-white/10 bg-black/20 p-2 text-xs text-white" />
                </label>
                <div className="mt-3 flex gap-2">
                  <button type="button" disabled={review.isPending || (reviewNotes[report.id]?.trim().length ?? 0) < 5} onClick={() => { review.mutate({ reportId: report.id, decision: "approved" }); }} className="min-h-9 rounded border border-emerald-300/20 px-3 text-xs text-emerald-200 disabled:opacity-40">Approve</button>
                  <button type="button" disabled={review.isPending || (reviewNotes[report.id]?.trim().length ?? 0) < 5} onClick={() => { review.mutate({ reportId: report.id, decision: "rejected" }); }} className="min-h-9 rounded border border-rose-300/20 px-3 text-xs text-rose-200 disabled:opacity-40">Reject</button>
                </div>
              </div>
            )}
          </li>
        ))}
      </ol>
      {reportsQuery.data?.length === 0 && <p className="mt-8 text-sm text-slate-500">No report snapshots have been generated for this case.</p>}
    </div>
  );
}

function EvidenceVisual({ caseId, artifact }: { caseId: string; artifact: Artifact }) {
  const preview = useQuery({
    queryKey: ["report-artifact-preview", caseId, artifact.id],
    queryFn: async () => {
      const current = await getArtifactPreview(caseId, artifact.id);
      return current.status === "not_generated"
        ? generateArtifactPreview(caseId, artifact.id)
        : current;
    },
    enabled: artifact.category === "image",
    retry: false,
  });
  if (preview.data?.status === "available") {
    return <img src={artifactPreviewContentUrl(caseId, artifact.id)} alt={`Thumbnail of ${artifact.title}`} className="size-[100px] rounded border border-white/10 bg-black object-contain" />;
  }
  return <div className="flex size-[100px] items-center justify-center rounded border border-white/10 bg-black/20"><FileTypeIcon extension={artifact.extension} size={58} /></div>;
}

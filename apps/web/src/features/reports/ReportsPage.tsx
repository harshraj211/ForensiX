import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, FileCheck2, LoaderCircle, ShieldAlert } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useState } from "react";

import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import {
  generateReport,
  getCurrentUser,
  getCase,
  listCases,
  listReports,
  reportDownloadUrl,
  reviewReport,
} from "../../lib/api";
import { authKeys } from "../auth/authKeys";

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
            <Link to={`/cases/${item.id}/reports`} className="block rounded-xl border border-white/8 bg-white/[0.025] p-5 transition hover:border-cyan-300/20 hover:bg-cyan-300/5">
              <p className="font-mono text-[10px] text-cyan-300/65">{item.case_number}</p>
              <h2 className="mt-2 text-base font-semibold text-white">{item.title}</h2>
              <p className="mt-2 text-xs uppercase tracking-wide text-slate-600">{item.status}</p>
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
        </div>
      </div>
      <div className="mt-6 flex gap-3 rounded-xl border border-amber-300/20 bg-amber-300/5 p-4 text-sm leading-6 text-amber-100/80">
        <ShieldAlert className="mt-0.5 shrink-0 text-amber-300" size={19} />
        <p>Reports are marked Preliminary by default. ADB is not a hardware write blocker, and unsupported private application data is not claimed.</p>
      </div>
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
                <p className="mt-1 text-xs text-slate-500">Generated {new Date(report.generated_at).toLocaleString()}</p>
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

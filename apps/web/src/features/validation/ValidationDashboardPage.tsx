import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BadgeCheck, CircleAlert, FlaskConical, LoaderCircle, Play } from "lucide-react";

import {
  getLatestEvidenceTwinValidation,
  runEvidenceTwinValidation,
  type EvidenceTwinValidation,
  type ValidationCheck,
} from "../../lib/api";
import { CaseError } from "../cases/CasesPage";

const validationKey = ["validation", "evidence-twin", "latest"] as const;

export function ValidationDashboardPage() {
  const queryClient = useQueryClient();
  const latest = useQuery({
    queryKey: validationKey,
    queryFn: getLatestEvidenceTwinValidation,
  });
  const run = useMutation({
    mutationFn: runEvidenceTwinValidation,
    onSuccess: (result) => {
      queryClient.setQueryData(validationKey, result);
    },
  });
  const result = run.data ?? latest.data;

  return (
    <div className="mx-auto max-w-6xl">
      <header className="border-b border-white/8 pb-7">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-cyan-300/65">
          Independent software assurance
        </p>
        <div className="mt-3 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
          <div>
            <h1 className="text-3xl font-semibold text-white">Known-answer validation</h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
              Run a synthetic, privacy-preserving Evidence Twin workflow with known contacts,
              messages, calls, timestamps, custody events, and report hashes. No connected phone or
              case evidence is read.
            </p>
          </div>
          <button
            type="button"
            disabled={run.isPending}
            onClick={() => { run.mutate(); }}
            className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg bg-cyan-300 px-5 text-sm font-semibold text-slate-950 disabled:cursor-wait disabled:opacity-60"
          >
            {run.isPending ? <LoaderCircle size={16} className="animate-spin" /> : <Play size={16} />}
            {run.isPending ? "Running full validation…" : "Run validation"}
          </button>
        </div>
      </header>
      {latest.isPending && !run.isPending && (
        <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500">
          <LoaderCircle size={16} className="animate-spin" /> Loading latest sealed result…
        </p>
      )}
      {run.isPending && (
        <div className="mt-7 rounded-2xl border border-cyan-300/15 bg-cyan-300/5 p-6">
          <p role="status" className="flex items-center gap-3 text-sm font-semibold text-cyan-100">
            <LoaderCircle size={18} className="animate-spin" />
            Validating seal → copy → parsers → timeline → custody → reports
          </p>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            This isolated end-to-end run can take a few seconds. Its temporary synthetic workspace
            is removed after the sealed result is persisted.
          </p>
        </div>
      )}
      {latest.isError && <div className="mt-6"><CaseError error={latest.error} /></div>}
      {run.isError && <div className="mt-6"><CaseError error={run.error} /></div>}
      {!latest.isPending && !result && !run.isPending && (
        <div className="mt-7 rounded-2xl border border-white/8 bg-white/[0.025] p-8">
          <FlaskConical size={24} className="text-cyan-300" />
          <h2 className="mt-4 text-lg font-semibold text-white">No validation run recorded</h2>
          <p className="mt-2 text-sm text-slate-500">
            Run the controlled known-answer profile before a demo or release.
          </p>
        </div>
      )}
      {result && <ValidationResult result={result} />}
    </div>
  );
}

function ValidationResult({ result }: { result: EvidenceTwinValidation }) {
  const passed = result.report.outcome === "passed";
  return (
    <>
      <section className={`mt-7 rounded-2xl border p-6 ${
        passed
          ? "border-emerald-300/20 bg-emerald-300/5"
          : "border-rose-300/20 bg-rose-300/5"
      }`}>
        <div className="flex flex-col justify-between gap-4 sm:flex-row">
          <div className="flex gap-3">
            {passed ? (
              <BadgeCheck size={24} className="text-emerald-300" />
            ) : (
              <CircleAlert size={24} className="text-rose-300" />
            )}
            <div>
              <h2 className="text-xl font-semibold text-white">
                {result.report.outcome.replaceAll("_", " ")}
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Completed {new Date(result.report.completed_at).toLocaleString()}
              </p>
            </div>
          </div>
          <div className="text-left sm:text-right">
            <p className="text-[10px] uppercase tracking-wider text-slate-600">Tool version</p>
            <p className="mt-1 font-mono text-xs text-slate-300">{result.report.tool_version}</p>
          </div>
        </div>
        <p className="mt-5 break-all font-mono text-[10px] text-emerald-100/55">
          Canonical report SHA-256 {result.canonical_sha256}
        </p>
      </section>
      <section className="mt-5 grid gap-4 lg:grid-cols-2">
        {result.report.checks.map((check) => <CheckCard key={check.check_id} check={check} />)}
      </section>
      <section className="mt-5 grid gap-5 lg:grid-cols-2">
        <div className="rounded-2xl border border-white/8 bg-white/[0.025] p-6">
          <h2 className="text-lg font-semibold text-white">Integrity chain</h2>
          <Hash label="Fixture" value={result.report.fixture_sha256} />
          <Hash label="Sealed source" value={result.report.evidence_source_sha256} />
          <Hash label="Chunk ledger" value={result.report.chunk_ledger_sha256} />
          <Hash label="Manifest" value={result.report.manifest_sha256} />
          <Hash label="Working copy" value={result.report.working_copy_sha256} />
          {Object.entries(result.report.report_output_sha256).map(([format, value]) => (
            <Hash key={format} label={`${format.toUpperCase()} report`} value={value} />
          ))}
        </div>
        <div className="rounded-2xl border border-white/8 bg-white/[0.025] p-6">
          <h2 className="text-lg font-semibold text-white">Scope and limitations</h2>
          <p className="mt-3 text-xs leading-5 text-slate-500">
            {result.report.environment.operating_system} {result.report.environment.operating_system_release}
            {" · "}Python {result.report.environment.python_version}
          </p>
          <ul className="mt-4 space-y-3">
            {result.report.limitations.map((limitation) => (
              <li key={limitation} className="flex gap-2 text-xs leading-5 text-amber-100/70">
                <CircleAlert size={14} className="mt-0.5 shrink-0 text-amber-300" />
                {limitation}
              </li>
            ))}
          </ul>
        </div>
      </section>
    </>
  );
}

function CheckCard({ check }: { check: ValidationCheck }) {
  const passed = check.status === "pass";
  return (
    <article className="rounded-xl border border-white/8 bg-white/[0.025] p-5">
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-sm font-semibold text-white">{check.check_id.replaceAll("_", " ")}</h3>
        <span className={`rounded-full border px-2 py-0.5 text-[9px] uppercase ${
          passed ? "border-emerald-300/20 text-emerald-200" : "border-rose-300/20 text-rose-200"
        }`}>{check.status}</span>
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-500">{check.summary}</p>
      <p className="mt-3 font-mono text-[10px] text-slate-600">
        {Object.entries(check.observed).map(([key, value]) => `${key}=${String(value)}`).join(" · ")}
      </p>
    </article>
  );
}

function Hash({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="mt-4">
      <p className="text-[10px] uppercase tracking-wider text-slate-600">{label}</p>
      <p className="mt-1 break-all font-mono text-[10px] text-cyan-100/60">{value ?? "not produced"}</p>
    </div>
  );
}

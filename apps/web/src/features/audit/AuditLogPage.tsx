import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, FileClock, LoaderCircle, Search, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";

import { listAuditLogs, verifyAuditChain } from "../../lib/api";
import { CaseError } from "../cases/CasesPage";

const auditKeys = {
  list: ["audit", "list"] as const,
  verification: ["audit", "verification"] as const,
};

export function AuditLogPage() {
  const [query, setQuery] = useState("");
  const logs = useQuery({ queryKey: auditKeys.list, queryFn: listAuditLogs });
  const verification = useQuery({
    queryKey: auditKeys.verification,
    queryFn: verifyAuditChain,
  });
  const filtered = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    if (!needle) return logs.data ?? [];
    return (logs.data ?? []).filter((entry) =>
      [entry.event_type, entry.object_type, entry.object_id, entry.case_id ?? ""]
        .join(" ")
        .toLocaleLowerCase()
        .includes(needle),
    );
  }, [logs.data, query]);

  return (
    <div className="mx-auto max-w-6xl">
      <header className="border-b border-white/8 pb-7">
        <p className="font-mono text-xs uppercase tracking-[0.25em] text-cyan-300/65">
          Tamper-evident operational history
        </p>
        <div className="mt-3 flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-3xl font-semibold text-white">Audit log</h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
              Global append-only event history chained with SHA-256. Local storage is tamper-evident,
              not tamper-proof.
            </p>
          </div>
          {verification.data && (
            <span
              className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold ${
                verification.data.valid
                  ? "border-emerald-300/20 bg-emerald-300/5 text-emerald-200"
                  : "border-rose-300/20 bg-rose-300/5 text-rose-200"
              }`}
            >
              {verification.data.valid ? <CheckCircle2 size={14} /> : <ShieldAlert size={14} />}
              {verification.data.valid
                ? `${String(verification.data.record_count)} records verified`
                : `Chain broken at #${String(verification.data.broken_sequence ?? "unknown")}`}
            </span>
          )}
        </div>
      </header>

      <label className="mt-7 flex max-w-xl items-center gap-3 rounded-xl border border-white/10 bg-white/[0.025] px-4 py-3">
        <Search size={16} className="text-slate-500" aria-hidden="true" />
        <span className="sr-only">Filter audit history</span>
        <input
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
          }}
          placeholder="Filter event, case, object type, or object ID"
          className="min-w-0 flex-1 bg-transparent text-sm text-slate-200 outline-none placeholder:text-slate-600"
        />
      </label>

      {(logs.isPending || verification.isPending) && (
        <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500">
          <LoaderCircle size={16} className="animate-spin" /> Verifying audit history...
        </p>
      )}
      {logs.isError && <div className="mt-6"><CaseError error={logs.error} /></div>}
      {verification.isError && <div className="mt-6"><CaseError error={verification.error} /></div>}
      {!logs.isPending && filtered.length === 0 && (
        <p className="mt-8 text-sm text-slate-500">No audit records match this filter.</p>
      )}

      <ol className="mt-7 space-y-3">
        {filtered.map((entry) => (
          <li key={entry.id} className="rounded-xl border border-white/8 bg-white/[0.025] p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex min-w-0 items-start gap-3">
                <span className="grid size-8 shrink-0 place-items-center rounded-lg border border-cyan-300/15 bg-cyan-300/5 font-mono text-[10px] text-cyan-200">
                  {entry.sequence}
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-white">{entry.event_type.replaceAll("_", " ")}</p>
                  <p className="mt-1 break-all font-mono text-[10px] text-slate-600">
                    {entry.object_type} · {entry.object_id}
                    {entry.case_id ? ` · case ${entry.case_id}` : ""}
                  </p>
                </div>
              </div>
              <time className="text-[11px] text-slate-500">{new Date(entry.created_at).toLocaleString()}</time>
            </div>
            <pre className="mt-4 max-h-48 overflow-auto rounded-lg border border-white/6 bg-black/20 p-3 text-[10px] leading-5 text-slate-400">
              {JSON.stringify(entry.detail, null, 2)}
            </pre>
            <div className="mt-3 grid gap-1 font-mono text-[9px] text-slate-700">
              <p className="truncate" title={entry.previous_hash}>Previous {entry.previous_hash}</p>
              <p className="truncate" title={entry.entry_hash}>Entry SHA-256 {entry.entry_hash}</p>
            </div>
          </li>
        ))}
      </ol>
      {verification.data?.head_hash && (
        <p className="mt-6 break-all rounded-lg border border-white/8 p-3 font-mono text-[10px] text-slate-600">
          Verified chain head: {verification.data.head_hash}
        </p>
      )}
      <FileClock className="sr-only" aria-hidden="true" />
    </div>
  );
}

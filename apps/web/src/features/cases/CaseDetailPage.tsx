import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, LoaderCircle } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { getCase, transitionCase, type CaseStatus } from "../../lib/api";
import { CaseError, StatusBadge } from "./CasesPage";
import { caseKeys } from "./caseKeys";

export function CaseDetailPage() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const transition = useMutation({
    mutationFn: (status: CaseStatus) => {
      if (!caseQuery.data) throw new Error("Case state is unavailable.");
      return transitionCase(caseId, caseQuery.data.version, status);
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(caseKeys.detail(caseId), updated);
      void queryClient.invalidateQueries({ queryKey: caseKeys.all });
    },
  });

  if (caseQuery.isPending) {
    return <div role="status"><LoaderCircle className="animate-spin text-cyan-300" aria-hidden="true" /></div>;
  }
  if (caseQuery.isError) return <CaseError error={caseQuery.error} />;
  const item = caseQuery.data;
  const actions: Array<{ label: string; status: CaseStatus }> =
    item.status === "open"
      ? [
          { label: "Mark active", status: "active" },
          { label: "Close case", status: "closed" },
        ]
      : item.status === "active"
        ? [{ label: "Close case", status: "closed" }]
        : item.status === "closed"
          ? [
              { label: "Reopen case", status: "active" },
              { label: "Archive case", status: "archived" },
            ]
          : [];

  return (
    <div className="mx-auto max-w-5xl">
      <Link to="/cases" className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200">
        <ArrowLeft size={15} aria-hidden="true" /> Back to cases
      </Link>
      <div className="mt-6 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:p-8">
        <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-start">
          <div>
            <p className="font-mono text-xs text-cyan-300/70">{item.case_number}</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white">{item.title}</h1>
          </div>
          <StatusBadge status={item.status} />
        </div>
        <dl className="mt-8 grid gap-6 border-y border-white/8 py-6 sm:grid-cols-2">
          <Detail label="Description" value={item.description ?? "Not recorded"} />
          <Detail label="Legal authority" value={item.legal_authority ?? "Not recorded"} />
          <Detail label="Created" value={new Date(item.created_at).toLocaleString()} />
          <Detail label="Version" value={String(item.version)} />
        </dl>
        {actions.length > 0 && (
          <div className="mt-6 flex flex-wrap gap-3">
            {actions.map((action) => (
              <button
                key={action.status}
                type="button"
                disabled={transition.isPending}
                onClick={() => {
                  transition.mutate(action.status);
                }}
                className="min-h-10 rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100 disabled:opacity-50"
              >
                {action.label}
              </button>
            ))}
          </div>
        )}
        {transition.isError && <CaseError error={transition.error} />}
      </div>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-600">{label}</dt>
      <dd className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-300">{value}</dd>
    </div>
  );
}

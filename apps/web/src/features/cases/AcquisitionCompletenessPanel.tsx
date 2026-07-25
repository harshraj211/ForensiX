import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, AlertTriangle, XCircle, FileQuestion, HelpCircle } from "lucide-react";
import { getCaseCompleteness } from "../../lib/api";
import { caseKeys } from "./caseKeys";
import { CaseError } from "./CasesPage";

export function AcquisitionCompletenessPanel({ caseId }: { caseId: string }) {
  const query = useQuery({
    queryKey: [...caseKeys.detail(caseId), "completeness"],
    queryFn: () => getCaseCompleteness(caseId),
    enabled: Boolean(caseId),
  });

  if (query.isPending) {
    return <p role="status" className="mt-4 text-sm text-slate-500">Loading completeness matrix...</p>;
  }
  if (query.isError) {
    return <div className="mt-4"><CaseError error={query.error} /></div>;
  }

  const items = query.data.items;

  return (
    <div className="mt-4 overflow-hidden rounded-xl border border-white/8 bg-black/10">
      <table className="min-w-full divide-y divide-white/8 text-left text-sm text-slate-300">
        <thead className="bg-white/[0.02] text-xs uppercase tracking-wider text-slate-400">
          <tr>
            <th scope="col" className="px-4 py-3 font-semibold">Artifact</th>
            <th scope="col" className="px-4 py-3 font-semibold">Status</th>
            <th scope="col" className="px-4 py-3 font-semibold">Reason</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/8">
          {items.map((item) => {
            const statusConfig = {
              captured: { icon: CheckCircle2, color: "text-emerald-400", bg: "bg-emerald-400/10", border: "border-emerald-400/20" },
              partial: { icon: AlertTriangle, color: "text-amber-400", bg: "bg-amber-400/10", border: "border-amber-400/20" },
              blocked: { icon: XCircle, color: "text-rose-400", bg: "bg-rose-400/10", border: "border-rose-400/20" },
              failed: { icon: XCircle, color: "text-rose-500", bg: "bg-rose-500/10", border: "border-rose-500/20" },
              not_present: { icon: HelpCircle, color: "text-slate-400", bg: "bg-slate-400/10", border: "border-slate-400/20" },
            }[item.status] || { icon: FileQuestion, color: "text-slate-400", bg: "bg-slate-400/10", border: "border-slate-400/20" };
            
            const Icon = statusConfig.icon;
            
            return (
              <tr key={item.artifact} className="transition-colors hover:bg-white/[0.02]">
                <td className="whitespace-nowrap px-4 py-3 font-medium text-white">{item.artifact}</td>
                <td className="whitespace-nowrap px-4 py-3">
                  <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-semibold ${statusConfig.color} ${statusConfig.bg} ${statusConfig.border}`}>
                    <Icon size={14} aria-hidden="true" />
                    {item.status.replace("_", " ")}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-slate-500">{item.reason || "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

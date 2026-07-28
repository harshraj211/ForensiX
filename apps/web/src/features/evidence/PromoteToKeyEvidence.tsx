import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, Flag, LoaderCircle, X } from "lucide-react";

import {
  promoteKeyEvidence,
  type KeyEvidencePriority,
  type KeyEvidenceTargetType,
} from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";

export function PromoteToKeyEvidence({
  caseId,
  targetType,
  targetId,
}: {
  caseId: string;
  targetType: KeyEvidenceTargetType;
  targetId: string;
}) {
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [priority, setPriority] = useState<KeyEvidencePriority>("high");
  const [reason, setReason] = useState("");
  const promote = useMutation({
    mutationFn: () =>
      promoteKeyEvidence(caseId, {
        targetType,
        targetId,
        priority,
        reason,
      }),
    onSuccess: async () => {
      setExpanded(false);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["cases", caseId, "key-evidence"] }),
        queryClient.invalidateQueries({ queryKey: caseKeys.commandCenter(caseId) }),
      ]);
    },
  });

  if (!expanded) {
    return (
      <div>
        <button
          type="button"
          onClick={() => {
            setExpanded(true);
            promote.reset();
          }}
          className="inline-flex min-h-9 items-center gap-2 rounded-lg border border-amber-300/15 bg-amber-300/[0.035] px-3 text-xs font-medium text-amber-200"
        >
          {promote.isSuccess ? <Check size={14} aria-hidden="true" /> : <Flag size={14} aria-hidden="true" />}
          {promote.isSuccess ? "Added to Key Evidence" : "Add to Key Evidence"}
        </button>
      </div>
    );
  }

  return (
    <section className="rounded-xl border border-amber-300/15 bg-amber-300/[0.025] p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-semibold text-amber-200">Promote as a case finding</p>
        <button
          type="button"
          onClick={() => {
            setExpanded(false);
          }}
          aria-label="Close key evidence form"
          className="text-slate-600 hover:text-slate-300"
        >
          <X size={15} aria-hidden="true" />
        </button>
      </div>
      <label className="mt-4 block text-[11px] text-slate-500">
        Priority
        <select
          value={priority}
          onChange={(event) => {
            setPriority(event.target.value as KeyEvidencePriority);
          }}
          className="mt-2 min-h-9 w-full rounded-lg border border-white/10 bg-[#09151d] px-2 text-xs text-slate-200"
        >
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="normal">Normal</option>
        </select>
      </label>
      <label className="mt-3 block text-[11px] text-slate-500">
        Examiner rationale
        <textarea
          value={reason}
          onChange={(event) => {
            setReason(event.target.value);
          }}
          maxLength={2000}
          placeholder="Why is this material to the investigation?"
          className="mt-2 min-h-20 w-full rounded-lg border border-white/10 bg-black/15 p-2 text-xs leading-5 text-slate-200"
        />
      </label>
      <button
        type="button"
        disabled={promote.isPending}
        onClick={() => {
          promote.mutate();
        }}
        className="mt-3 inline-flex min-h-9 items-center gap-2 rounded-lg bg-amber-300 px-3 text-xs font-semibold text-slate-950 disabled:opacity-50"
      >
        {promote.isPending ? <LoaderCircle size={14} className="animate-spin" aria-hidden="true" /> : <Flag size={14} aria-hidden="true" />}
        Save to Key Evidence
      </button>
      {promote.isError && (
        <div className="mt-3">
          <CaseError error={promote.error} />
        </div>
      )}
    </section>
  );
}

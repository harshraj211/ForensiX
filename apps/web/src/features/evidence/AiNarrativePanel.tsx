/* eslint-disable @typescript-eslint/no-misused-promises */
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Bot, Check, Copy, LoaderCircle, Sparkles, AlertTriangle } from "lucide-react";

import { generateCaseNarrative } from "../../lib/api";

interface AiNarrativePanelProps {
  caseId: string;
}

export function AiNarrativePanel({ caseId }: AiNarrativePanelProps) {
  const [copied, setCopied] = useState(false);

  const narrativeMutation = useMutation({
    mutationFn: () => generateCaseNarrative(caseId),
  });

  const copyNarrative = async () => {
    if (!narrativeMutation.data) return;
    await navigator.clipboard.writeText(narrativeMutation.data.narrative);
    setCopied(true);
    setTimeout(() => {
      setCopied(false);
    }, 2000);
  };

  return (
    <div className="mt-8 rounded-xl border border-slate-200 bg-white p-6 shadow-sm overflow-hidden relative">
      <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none text-slate-900">
        <Bot size={120} />
      </div>

      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-200 pb-4 mb-4">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900">
            <Sparkles size={18} className="text-purple-600" />
            AI Case Narrative
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Factual, objective summary synthesized by Groq LLaMA/Qwen from key evidence and timeline events.
          </p>
        </div>

        {!narrativeMutation.data && !narrativeMutation.isPending && (
          <button
            type="button"
            onClick={() => {
              narrativeMutation.mutate();
            }}
            className="flex items-center gap-2 rounded-lg bg-purple-700 hover:bg-purple-800 px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors"
          >
            <Sparkles size={15} />
            Generate Narrative
          </button>
        )}
      </div>

      {narrativeMutation.isPending && (
        <div className="py-8 text-center">
          <LoaderCircle size={28} className="mx-auto animate-spin text-purple-600" />
          <p className="mt-3 text-sm font-medium text-slate-700">
            Synthesizing evidence via Groq Cloud... This may take a moment.
          </p>
        </div>
      )}

      {narrativeMutation.isError && (
        <div className="rounded-lg bg-red-50 border border-red-200 p-4 flex gap-3">
          <AlertTriangle size={18} className="text-red-600 shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-red-900">Generation Failed</p>
            <p className="text-red-700 mt-1">
              {narrativeMutation.error instanceof Error
                ? narrativeMutation.error.message
                : "An unexpected error occurred. Ensure the Groq API key is configured."}
            </p>
            <button
              type="button"
              onClick={() => {
                narrativeMutation.reset();
              }}
              className="mt-3 text-xs font-semibold text-red-800 hover:underline"
            >
              Try again
            </button>
          </div>
        </div>
      )}

      {narrativeMutation.data && (
        <div className="space-y-4">
          <div className="rounded-lg bg-slate-50 border border-slate-200 p-5 relative group">
            <div className="text-sm text-slate-800 whitespace-pre-wrap leading-relaxed font-sans">
              {narrativeMutation.data.narrative}
            </div>

            <button
              type="button"
              onClick={copyNarrative}
              className="absolute top-4 right-4 rounded-md bg-white border border-slate-200 p-2 text-slate-700 shadow-sm transition hover:bg-slate-100 hover:text-slate-900"
              title="Copy narrative"
            >
              {copied ? <Check size={16} className="text-emerald-600" /> : <Copy size={16} />}
            </button>
          </div>

          <div className="flex items-center justify-between text-xs text-slate-500">
            <div className="flex items-center gap-2">
              <Bot size={13} />
              <span>
                Model: <span className="font-mono font-semibold text-slate-700">{narrativeMutation.data.model}</span>
              </span>
            </div>
            <span>Based on {narrativeMutation.data.evidence_item_count} key evidence items</span>
          </div>
        </div>
      )}
    </div>
  );
}

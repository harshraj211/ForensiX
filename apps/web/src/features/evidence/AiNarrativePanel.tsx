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
    setTimeout(() => { setCopied(false); }, 2000);
  };

  return (
    <div className="mt-8 rounded-xl border border-white/8 bg-white/[0.02] p-6 shadow-sm overflow-hidden relative">
      <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
        <Bot size={120} />
      </div>
      
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-white/8 pb-4 mb-4">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
            <Sparkles size={18} className="text-purple-400" />
            AI Case Narrative
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            Factual summary synthesized from key evidence and timeline events.
          </p>
        </div>
        
        {!narrativeMutation.data && !narrativeMutation.isPending && (
          <button
            onClick={() => { narrativeMutation.mutate(); }}
            className="flex items-center gap-2 rounded-lg bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 px-4 py-2 text-sm font-medium text-purple-300 transition-colors"
          >
            <Sparkles size={15} />
            Generate Summary
          </button>
        )}
      </div>

      {narrativeMutation.isPending && (
        <div className="py-8 text-center">
          <LoaderCircle size={24} className="mx-auto animate-spin text-purple-400" />
          <p className="mt-3 text-sm text-slate-500">
            Synthesizing evidence... This may take a moment.
          </p>
        </div>
      )}

      {narrativeMutation.isError && (
        <div className="rounded-lg bg-red-950/30 border border-red-900/50 p-4 flex gap-3">
          <AlertTriangle size={18} className="text-red-400 shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-red-300">Generation Failed</p>
            <p className="text-red-400/80 mt-1">
              {narrativeMutation.error instanceof Error 
                ? narrativeMutation.error.message 
                : "An unexpected error occurred. Ensure the API key is configured."}
            </p>
            <button 
              onClick={() => { narrativeMutation.reset(); }}
              className="mt-3 text-xs text-red-300 hover:underline"
            >
              Try again
            </button>
          </div>
        </div>
      )}

      {narrativeMutation.data && (
        <div className="space-y-4">
          <div className="rounded-lg bg-black/40 border border-white/5 p-5 relative group">
            <div className="prose prose-invert prose-sm max-w-none text-slate-300 whitespace-pre-wrap leading-relaxed">
              {narrativeMutation.data.narrative}
            </div>
            
            <button
              onClick={copyNarrative}
              className="absolute top-4 right-4 rounded-md bg-white/10 p-2 text-slate-300 opacity-0 transition-all hover:bg-white/20 hover:text-white group-hover:opacity-100"
              title="Copy narrative"
            >
              {copied ? <Check size={16} className="text-emerald-400" /> : <Copy size={16} />}
            </button>
          </div>
          
          <div className="flex items-center justify-between text-xs text-slate-500">
            <div className="flex items-center gap-2">
              <Bot size={13} />
              <span>Model: <span className="font-mono">{narrativeMutation.data.model}</span></span>
            </div>
            <span>Based on {narrativeMutation.data.evidence_item_count} key evidence items</span>
          </div>
        </div>
      )}
    </div>
  );
}

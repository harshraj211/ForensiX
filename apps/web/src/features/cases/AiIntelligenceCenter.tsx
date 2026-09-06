import React, { useEffect, useState } from "react";
import {
  Brain,
  Cpu,
  FileCheck,
  FileText,
  Key,
  Lock,
  MessageSquare,
  Search,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react";
import {
  getAiAuditLogs,
  getAiGatewayStatus,
  queryAiCopilot,
  scanMediaAiIntelligence,
  type AiAuditLogItem,
  type AiCopilotResponse,
  type AiGatewayStatus,
  type AiMediaScanItem,
} from "../../lib/api";

interface AiIntelligenceCenterProps {
  caseId: string;
}

export const AiIntelligenceCenter: React.FC<AiIntelligenceCenterProps> = ({ caseId }) => {
  const [activeTab, setActiveTab] = useState<"media" | "copilot" | "audit">("media");
  const [status, setStatus] = useState<AiGatewayStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = useState<boolean>(true);

  // Media scan state
  const [mediaItems, setMediaItems] = useState<AiMediaScanItem[]>([]);
  const [scanningMedia, setScanningMedia] = useState<boolean>(false);
  const [mediaCategoryFilter, setMediaCategoryFilter] = useState<string>("ALL");

  // Copilot state
  const [queryText, setQueryText] = useState<string>("");
  const [copilotLoading, setCopilotLoading] = useState<boolean>(false);
  const [copilotAnswer, setCopilotAnswer] = useState<AiCopilotResponse | null>(null);

  // Audit log state
  const [auditLogs, setAuditLogs] = useState<AiAuditLogItem[]>([]);
  const [loadingAudit, setLoadingAudit] = useState<boolean>(false);

  useEffect(() => {
    fetchStatus();
  }, [caseId]);

  const fetchStatus = async () => {
    setLoadingStatus(true);
    try {
      const res = await getAiGatewayStatus(caseId);
      setStatus(res);
    } catch {
      // Graceful fallback
    } finally {
      setLoadingStatus(false);
    }
  };

  const handleScanMedia = async () => {
    setScanningMedia(true);
    try {
      const res = await scanMediaAiIntelligence(caseId);
      setMediaItems(res.items);
      fetchStatus();
    } catch (err) {
      console.error("Failed to scan media intelligence", err);
    } finally {
      setScanningMedia(false);
    }
  };

  const handleCopilotQuery = async (promptToRun?: string) => {
    const textToSubmit = promptToRun || queryText;
    if (!textToSubmit.trim()) return;

    setCopilotLoading(true);
    try {
      const res = await queryAiCopilot(caseId, textToSubmit);
      setCopilotAnswer(res);
      fetchStatus();
    } catch (err) {
      console.error("Copilot query failed", err);
    } finally {
      setCopilotLoading(false);
    }
  };

  const handleLoadAuditLogs = async () => {
    setLoadingAudit(true);
    try {
      const res = await getAiAuditLogs(caseId);
      setAuditLogs(res.audit_logs);
    } catch (err) {
      console.error("Failed to fetch AI audit logs", err);
    } finally {
      setLoadingAudit(false);
    }
  };

  useEffect(() => {
    if (activeTab === "audit") {
      handleLoadAuditLogs();
    }
  }, [activeTab]);

  const filteredMediaItems =
    mediaCategoryFilter === "ALL"
      ? mediaItems
      : mediaItems.filter((item) => item.category === mediaCategoryFilter);

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 p-6 text-white border border-indigo-500/30 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-indigo-600/30 rounded-lg border border-indigo-400/40">
              <Sparkles className="w-7 h-7 text-indigo-400 animate-pulse" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                ForensiX Centralized AI Gateway & Multimodal Suite
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  Xkiro AI Vision Integrated
                </span>
              </h2>
              <p className="text-sm text-slate-300">
                Multi-model vision OCR, sensitive doc scanner, disappearing chat parser & court chain-of-custody logging.
              </p>
            </div>
          </div>

          {/* Key & Model Badges */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 flex items-center space-x-2">
              <Key className="w-3.5 h-3.5 text-amber-400" />
              <span className="text-slate-300">XKIRO_API_KEY:</span>
              <span
                className={`font-semibold ${
                  status?.xkiro_api_key_configured ? "text-emerald-400" : "text-amber-400"
                }`}
              >
                {status?.xkiro_api_key_configured ? "Active (.env)" : "Fallback Active"}
              </span>
            </div>

            <div className="px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 flex items-center space-x-2">
              <Cpu className="w-3.5 h-3.5 text-indigo-400" />
              <span className="text-slate-300">Vision Engine:</span>
              <span className="font-semibold text-indigo-300">
                {status?.active_vision_model || "xkiro-vision-v2"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex space-x-2 border-b border-slate-200 dark:border-slate-800 pb-1">
        <button
          onClick={() => setActiveTab("media")}
          className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
            activeTab === "media"
              ? "bg-indigo-600 text-white shadow-sm"
              : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
          }`}
        >
          <Search className="w-4 h-4" />
          <span>Multimodal Media Intelligence</span>
          {mediaItems.length > 0 && (
            <span className="ml-1 text-xs px-2 py-0.5 rounded-full bg-indigo-700 text-white font-bold">
              {mediaItems.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab("copilot")}
          className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
            activeTab === "copilot"
              ? "bg-indigo-600 text-white shadow-sm"
              : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
          }`}
        >
          <Brain className="w-4 h-4" />
          <span>Forensic AI Copilot</span>
        </button>

        <button
          onClick={() => setActiveTab("audit")}
          className={`flex items-center space-x-2 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
            activeTab === "audit"
              ? "bg-indigo-600 text-white shadow-sm"
              : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          <span>Court AI Chain-of-Custody Audit</span>
        </button>
      </div>

      {/* TAB 1: Multimodal Media Intelligence */}
      {activeTab === "media" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-50 dark:bg-slate-900 p-4 rounded-lg border border-slate-200 dark:border-slate-800">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                Automated Visual Media & Sensitive Document Scanner
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Xkiro Vision scans extracted photos for Passports, Crypto Seed Phrases, Banking Screenshots, and Contraband.
              </p>
            </div>
            <button
              onClick={handleScanMedia}
              disabled={scanningMedia}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-lg flex items-center justify-center space-x-2 transition-all shadow disabled:opacity-50"
            >
              {scanningMedia ? (
                <>
                  <Zap className="w-4 h-4 animate-spin" />
                  <span>Xkiro Vision Scanning...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  <span>Scan Case Media Intelligence</span>
                </>
              )}
            </button>
          </div>

          {/* Filter Chips */}
          {mediaItems.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              {[
                { label: "All Items", value: "ALL" },
                { label: "Identity Docs", value: "IDENTITY_DOC" },
                { label: "Crypto & Financial", value: "FINANCIAL_CRYPTO" },
                { label: "Threats & Contraband", value: "THREAT_CONTRABAND" },
                { label: "In-Image Text", value: "IN_IMAGE_TEXT" },
              ].map((chip) => (
                <button
                  key={chip.value}
                  onClick={() => setMediaCategoryFilter(chip.value)}
                  className={`px-3 py-1 text-xs font-medium rounded-full transition-colors ${
                    mediaCategoryFilter === chip.value
                      ? "bg-indigo-600 text-white"
                      : "bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-300"
                  }`}
                >
                  {chip.label}
                </button>
              ))}
            </div>
          )}

          {/* Media Items Grid */}
          {filteredMediaItems.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredMediaItems.map((item) => (
                <div
                  key={item.item_id}
                  className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3"
                >
                  <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
                    <div className="flex items-center space-x-2">
                      <FileText className="w-4 h-4 text-indigo-500" />
                      <span className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100 truncate max-w-[200px]">
                        {item.file_name}
                      </span>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        item.risk_level === "CRITICAL"
                          ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                          : "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                      }`}
                    >
                      {item.risk_level} RISK
                    </span>
                  </div>

                  <div className="flex flex-wrap gap-1.5">
                    {item.detected_labels.map((lbl, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium"
                      >
                        🏷️ {lbl}
                      </span>
                    ))}
                  </div>

                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs font-mono text-slate-800 dark:text-slate-200">
                    <div className="text-[10px] text-indigo-400 font-bold mb-1 flex items-center justify-between">
                      <span>XKIRO VISION OCR EXTRACT:</span>
                      <span>Confidence: {(item.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <p className="line-clamp-3">{item.extracted_text}</p>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono pt-1">
                    <span>SHA-256: {item.sha256_hash.slice(0, 16)}...</span>
                    <span className="text-emerald-400 font-semibold">Verified Sealed</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center p-12 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800">
              <Sparkles className="w-10 h-10 text-indigo-400 mx-auto mb-3 animate-pulse" />
              <h4 className="text-sm font-semibold text-slate-900 dark:text-white">
                No Media Items Scanned Yet
              </h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto mt-1">
                Click "Scan Case Media Intelligence" above to run Xkiro Vision OCR and sensitive artifact classification across all extracted files.
              </p>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Forensic AI Copilot */}
      {activeTab === "copilot" && (
        <div className="space-y-4">
          <div className="bg-slate-50 dark:bg-slate-900 p-4 rounded-lg border border-slate-200 dark:border-slate-800 space-y-3">
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <Brain className="w-4 h-4 text-indigo-400" />
              Investigative Natural Language Copilot
            </h3>

            {/* Quick Prompt Suggestion Buttons */}
            <div className="flex flex-wrap gap-2 text-xs">
              {[
                "Find crypto seed phrase images & USDT payment details",
                "Summarize suspect location timeline near crime scene between 10 PM and 2 AM",
                "List all sensitive identity docs and passport scans extracted",
              ].map((suggestion, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setQueryText(suggestion);
                    handleCopilotQuery(suggestion);
                  }}
                  className="px-3 py-1 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 hover:bg-indigo-100 transition-colors text-left text-xs"
                >
                  💡 {suggestion}
                </button>
              ))}
            </div>

            {/* Query Input Bar */}
            <div className="flex items-center space-x-2">
              <input
                type="text"
                value={queryText}
                onChange={(e) => setQueryText(e.target.value)}
                placeholder="Ask any natural language question about case artifacts, suspect actions, or timeline..."
                className="flex-1 px-4 py-2.5 rounded-lg bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
              <button
                onClick={() => handleCopilotQuery()}
                disabled={copilotLoading || !queryText.trim()}
                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-lg flex items-center space-x-2 transition-all disabled:opacity-50"
              >
                {copilotLoading ? (
                  <Zap className="w-4 h-4 animate-spin" />
                ) : (
                  <>
                    <MessageSquare className="w-4 h-4" />
                    <span>Query Copilot</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Copilot Answer Display */}
          {copilotAnswer && (
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
                <div className="flex items-center space-x-2">
                  <Sparkles className="w-5 h-5 text-indigo-500" />
                  <span className="text-sm font-bold text-slate-900 dark:text-white">
                    Copilot Response
                  </span>
                </div>
                <div className="flex items-center space-x-3 text-xs text-slate-500">
                  <span>Model: <strong className="text-indigo-400">{copilotAnswer.model_used}</strong></span>
                  <span>Confidence: <strong className="text-emerald-400">{(copilotAnswer.confidence_score * 100).toFixed(0)}%</strong></span>
                </div>
              </div>

              <p className="text-sm text-slate-800 dark:text-slate-200 leading-relaxed font-sans">
                {copilotAnswer.answer}
              </p>

              <div>
                <h5 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
                  Referenced Case Artifacts:
                </h5>
                <div className="flex flex-wrap gap-2">
                  {copilotAnswer.referenced_artifacts.map((art, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-mono border border-slate-200 dark:border-slate-700 flex items-center space-x-1"
                    >
                      <FileCheck className="w-3 h-3 text-indigo-400" />
                      <span>{art}</span>
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Court Chain-of-Custody Audit */}
      {activeTab === "audit" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between bg-slate-50 dark:bg-slate-900 p-4 rounded-lg border border-slate-200 dark:border-slate-800">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Cryptographic AI Chain-of-Custody Audit Logs
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Every AI inference, image scan, and copilot query is signed and hashed for court admissibility.
              </p>
            </div>
            <button
              onClick={handleLoadAuditLogs}
              disabled={loadingAudit}
              className="px-3 py-1.5 bg-slate-200 dark:bg-slate-800 text-xs font-semibold text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-300 transition-colors"
            >
              Refresh Logs
            </button>
          </div>

          {auditLogs.length > 0 ? (
            <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 uppercase text-[10px]">
                  <tr>
                    <th className="p-3">Timestamp</th>
                    <th className="p-3">Prompt Summary</th>
                    <th className="p-3">Model / Provider</th>
                    <th className="p-3">Input SHA-256</th>
                    <th className="p-3">Court Signature Seal</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800 bg-white dark:bg-slate-900">
                  {auditLogs.map((log) => (
                    <tr key={log.audit_id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                      <td className="p-3 text-slate-500 whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="p-3 text-slate-900 dark:text-white font-medium max-w-xs truncate">
                        {log.prompt_summary}
                      </td>
                      <td className="p-3 text-indigo-400 font-semibold">{log.model_name}</td>
                      <td className="p-3 text-slate-400">{log.input_sha256.slice(0, 12)}...</td>
                      <td className="p-3">
                        <span className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">
                          🛡️ {log.court_admissible_signature}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center p-12 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800">
              <ShieldCheck className="w-10 h-10 text-slate-400 mx-auto mb-3" />
              <p className="text-xs text-slate-500 dark:text-slate-400">
                No AI audit events recorded yet. Run a media scan or copilot query above to generate court-admissible audit logs.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

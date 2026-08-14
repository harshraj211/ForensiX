import { useState, useRef } from "react";
import { useMutation } from "@tanstack/react-query";
import { PackageOpen, LoaderCircle, Upload, Shield, Activity, Share2, FileCode2 } from "lucide-react";

import { analyzeApk } from "../../lib/api";

interface ApkAnalysisPanelProps {
  caseId: string;
}

export function ApkAnalysisPanel({ caseId }: ApkAnalysisPanelProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const analysisMutation = useMutation({
    mutationFn: (file: File) => analyzeApk(caseId, file),
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleAnalyze = () => {
    if (selectedFile) {
      analysisMutation.mutate(selectedFile);
    }
  };

  return (
    <div className="mt-8 rounded-xl border border-white/8 bg-white/[0.02] p-6 shadow-sm">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-white/8 pb-4 mb-4">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
            <PackageOpen size={18} className="text-emerald-400" />
            Static APK Analysis
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            Upload an Android APK to extract permissions, activities, services, and certificates.
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-4">
        {!analysisMutation.data && !analysisMutation.isPending && (
          <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-white/10 bg-black/20 p-8 text-center hover:border-emerald-500/30 transition-colors">
            <Upload size={32} className="text-slate-500 mb-3" />
            <input 
              type="file" 
              accept=".apk" 
              className="hidden" 
              ref={fileInputRef} 
              onChange={handleFileChange} 
            />
            {selectedFile ? (
              <div className="text-emerald-300 font-medium mb-3">{selectedFile.name}</div>
            ) : (
              <p className="text-sm text-slate-400 mb-4">Select an APK file to analyze</p>
            )}
            
            <div className="flex gap-3">
              <button
                onClick={() => fileInputRef.current?.click()}
                className="rounded-lg bg-white/5 border border-white/10 px-4 py-2 text-sm font-medium text-slate-300 hover:bg-white/10 transition-colors"
              >
                {selectedFile ? "Change File" : "Browse Files"}
              </button>
              
              {selectedFile && (
                <button
                  onClick={handleAnalyze}
                  className="rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 px-4 py-2 text-sm font-medium text-emerald-300 transition-colors"
                >
                  Analyze
                </button>
              )}
            </div>
          </div>
        )}

        {analysisMutation.isPending && (
          <div className="py-12 text-center border rounded-lg border-white/5 bg-black/20">
            <LoaderCircle size={28} className="mx-auto animate-spin text-emerald-400" />
            <p className="mt-4 text-sm font-medium text-emerald-300">
              Decompiling and Analyzing APK...
            </p>
            <p className="mt-1 text-xs text-slate-500">
              This may take a few moments depending on the file size.
            </p>
          </div>
        )}

        {analysisMutation.isError && (
          <div className="rounded-lg bg-red-950/30 border border-red-900/50 p-4">
            <p className="font-semibold text-red-300">Analysis Failed</p>
            <p className="text-sm text-red-400/80 mt-1">
              {analysisMutation.error instanceof Error 
                ? analysisMutation.error.message 
                : "An unexpected error occurred during APK analysis."}
            </p>
            <button 
              onClick={() => analysisMutation.reset()}
              className="mt-3 text-xs text-red-300 hover:underline"
            >
              Try again
            </button>
          </div>
        )}

        {analysisMutation.data && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-2">
            <div className="space-y-6">
              <section className="rounded-lg border border-white/5 bg-black/20 p-4">
                <h3 className="flex items-center gap-2 text-sm font-semibold text-white mb-3">
                  <FileCode2 size={16} className="text-emerald-400" />
                  Application Metadata
                </h3>
                <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-3 text-sm">
                  <div>
                    <dt className="text-slate-500 text-xs">Package Name</dt>
                    <dd className="text-slate-300 font-mono mt-0.5 break-all">{analysisMutation.data.package_name || "N/A"}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 text-xs">Version</dt>
                    <dd className="text-slate-300 mt-0.5">{analysisMutation.data.version_name || "N/A"} ({analysisMutation.data.version_code || "N/A"})</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 text-xs">Min SDK</dt>
                    <dd className="text-slate-300 mt-0.5">{analysisMutation.data.min_sdk_version || "N/A"}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 text-xs">Target SDK</dt>
                    <dd className="text-slate-300 mt-0.5">{analysisMutation.data.target_sdk_version || "N/A"}</dd>
                  </div>
                </dl>
              </section>
              
              <section className="rounded-lg border border-white/5 bg-black/20 p-4">
                <h3 className="flex items-center gap-2 text-sm font-semibold text-white mb-3">
                  <Shield size={16} className="text-orange-400" />
                  Certificates ({analysisMutation.data.certificates?.length || 0})
                </h3>
                {(!analysisMutation.data.certificates || analysisMutation.data.certificates.length === 0) ? (
                  <p className="text-sm text-slate-500">No certificates found or APK is unsigned.</p>
                ) : (
                  <div className="space-y-4">
                    {analysisMutation.data.certificates.map((cert, idx) => (
                      <div key={idx} className="bg-white/5 p-3 rounded border border-white/5 text-xs space-y-2">
                        {cert.error ? (
                          <div className="text-red-400">{cert.error}</div>
                        ) : (
                          <>
                            <div><span className="text-slate-500">Subject:</span> <span className="text-slate-300 font-mono">{cert.subject || "N/A"}</span></div>
                            <div><span className="text-slate-500">Issuer:</span> <span className="text-slate-300 font-mono">{cert.issuer || "N/A"}</span></div>
                            <div><span className="text-slate-500">SHA-1:</span> <span className="text-slate-400 font-mono text-[10px] break-all">{cert.hash_sha1 || "N/A"}</span></div>
                            <div><span className="text-slate-500">SHA-256:</span> <span className="text-slate-400 font-mono text-[10px] break-all">{cert.hash_sha256 || "N/A"}</span></div>
                          </>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </div>
            
            <div className="space-y-6">
              <section className="rounded-lg border border-white/5 bg-black/20 p-4">
                <h3 className="flex items-center gap-2 text-sm font-semibold text-white mb-3">
                  <Share2 size={16} className="text-blue-400" />
                  Permissions ({analysisMutation.data.permissions?.length || 0})
                </h3>
                <div className="max-h-60 overflow-y-auto custom-scrollbar pr-2">
                  <ul className="space-y-1">
                    {(analysisMutation.data.permissions || []).map((perm, idx) => (
                      <li key={idx} className="text-xs font-mono text-slate-400 bg-white/5 rounded px-2 py-1 truncate" title={perm}>
                        {perm}
                      </li>
                    ))}
                    {(!analysisMutation.data.permissions || analysisMutation.data.permissions.length === 0) && (
                      <li className="text-sm text-slate-500">No permissions declared.</li>
                    )}
                  </ul>
                </div>
              </section>
              
              <section className="rounded-lg border border-white/5 bg-black/20 p-4">
                <h3 className="flex items-center gap-2 text-sm font-semibold text-white mb-3">
                  <Activity size={16} className="text-purple-400" />
                  Components
                </h3>
                <div className="space-y-4">
                  <div>
                    <h4 className="text-xs font-medium text-slate-400 mb-2">Activities ({analysisMutation.data.activities?.length || 0})</h4>
                    <div className="max-h-32 overflow-y-auto custom-scrollbar pr-2">
                      <ul className="space-y-1">
                        {(analysisMutation.data.activities || []).map((act, idx) => (
                          <li key={idx} className="text-[11px] font-mono text-slate-500 bg-white/[0.02] border border-white/5 rounded px-2 py-1 truncate">{act}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  <div>
                    <h4 className="text-xs font-medium text-slate-400 mb-2">Services ({analysisMutation.data.services?.length || 0})</h4>
                    <div className="max-h-32 overflow-y-auto custom-scrollbar pr-2">
                      <ul className="space-y-1">
                        {(analysisMutation.data.services || []).map((srv, idx) => (
                          <li key={idx} className="text-[11px] font-mono text-slate-500 bg-white/[0.02] border border-white/5 rounded px-2 py-1 truncate">{srv}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              </section>
            </div>
            
            <div className="col-span-1 lg:col-span-2 flex justify-end mt-4">
              <button
                onClick={() => {
                  setSelectedFile(null);
                  analysisMutation.reset();
                }}
                className="text-xs text-slate-400 hover:text-white"
              >
                Clear Analysis
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

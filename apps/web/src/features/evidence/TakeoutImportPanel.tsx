import { useState, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CloudUpload, LoaderCircle, Upload, CheckCircle } from "lucide-react";

import { importTakeout } from "../../lib/api";
import { caseKeys } from "../cases/caseKeys";

interface TakeoutImportPanelProps {
  caseId: string;
}

export function TakeoutImportPanel({ caseId }: TakeoutImportPanelProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  const importMutation = useMutation({
    mutationFn: (file: File) => importTakeout(caseId, file),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: caseKeys.timeline(caseId) });
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleImport = () => {
    if (selectedFile) {
      importMutation.mutate(selectedFile);
    }
  };

  return (
    <div className="mt-8 rounded-xl border border-white/8 bg-white/[0.02] p-6 shadow-sm">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-white/8 pb-4 mb-4">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
            <CloudUpload size={18} className="text-blue-400" />
            Google Takeout Import
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            Import location history and browser activity from a Google Takeout ZIP archive.
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-4">
        {!importMutation.data && !importMutation.isPending && (
          <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-white/10 bg-black/20 p-8 text-center hover:border-blue-500/30 transition-colors">
            <Upload size={32} className="text-slate-500 mb-3" />
            <input 
              type="file" 
              accept=".zip" 
              className="hidden" 
              ref={fileInputRef} 
              onChange={handleFileChange} 
            />
            {selectedFile ? (
              <div className="text-blue-300 font-medium mb-3">{selectedFile.name}</div>
            ) : (
              <p className="text-sm text-slate-400 mb-4">Select a Takeout ZIP file to import</p>
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
                  onClick={handleImport}
                  className="rounded-lg bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/30 px-4 py-2 text-sm font-medium text-blue-300 transition-colors"
                >
                  Import Takeout
                </button>
              )}
            </div>
          </div>
        )}

        {importMutation.isPending && (
          <div className="py-12 text-center border rounded-lg border-white/5 bg-black/20">
            <LoaderCircle size={28} className="mx-auto animate-spin text-blue-400" />
            <p className="mt-4 text-sm font-medium text-blue-300">
              Extracting and Importing Archive...
            </p>
            <p className="mt-1 text-xs text-slate-500">
              This may take a few moments depending on the file size.
            </p>
          </div>
        )}

        {importMutation.isError && (
          <div className="rounded-lg bg-red-950/30 border border-red-900/50 p-4">
            <p className="font-semibold text-red-300">Import Failed</p>
            <p className="text-sm text-red-400/80 mt-1">
              {importMutation.error instanceof Error 
                ? importMutation.error.message 
                : "An unexpected error occurred during import."}
            </p>
            <button 
              onClick={() => importMutation.reset()}
              className="mt-3 text-xs text-red-300 hover:underline"
            >
              Try again
            </button>
          </div>
        )}

        {importMutation.data && (
          <div className="rounded-lg border border-white/5 bg-black/20 p-8 text-center">
            <CheckCircle size={40} className="mx-auto text-emerald-400 mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">Import Successful</h3>
            <p className="text-slate-300 mb-6">
              Extracted and materialized <span className="font-bold text-emerald-400">{importMutation.data.imported_events}</span> events to the case timeline.
            </p>
            <button
              onClick={() => {
                setSelectedFile(null);
                importMutation.reset();
              }}
              className="rounded-lg bg-white/5 border border-white/10 px-4 py-2 text-sm font-medium text-slate-300 hover:bg-white/10 transition-colors"
            >
              Import Another Archive
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

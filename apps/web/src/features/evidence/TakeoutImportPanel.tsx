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
      void queryClient.invalidateQueries({ queryKey: caseKeys.timeline(caseId) });
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
    <div className="mt-8 rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-200 pb-4 mb-4">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-bold text-slate-900">
            <CloudUpload size={18} className="text-sky-700" />
            Google Takeout Import
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Import location history and browser activity from a Google Takeout ZIP archive.
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-4">
        {!importMutation.data && !importMutation.isPending && (
          <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-slate-300 bg-slate-50 p-8 text-center hover:border-slate-400 transition-colors">
            <Upload size={32} className="text-slate-500 mb-3" />
            <input
              type="file"
              accept=".zip"
              className="hidden"
              ref={fileInputRef}
              onChange={handleFileChange}
            />
            {selectedFile ? (
              <div className="text-slate-900 font-semibold mb-3">{selectedFile.name}</div>
            ) : (
              <p className="text-sm text-slate-600 mb-4">Select a Takeout ZIP file to import</p>
            )}

            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="rounded-lg bg-white border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-100 transition-colors"
              >
                {selectedFile ? "Change File" : "Browse Files"}
              </button>

              {selectedFile && (
                <button
                  type="button"
                  onClick={handleImport}
                  className="rounded-lg bg-slate-900 hover:bg-black px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors"
                >
                  Import Takeout
                </button>
              )}
            </div>
          </div>
        )}

        {importMutation.isPending && (
          <div className="py-12 text-center border rounded-lg border-slate-200 bg-slate-50">
            <LoaderCircle size={28} className="mx-auto animate-spin text-slate-700" />
            <p className="mt-4 text-sm font-semibold text-slate-900">
              Extracting and Importing Archive...
            </p>
            <p className="mt-1 text-xs text-slate-500">
              This may take a few moments depending on the file size.
            </p>
          </div>
        )}

        {importMutation.isError && (
          <div className="rounded-lg bg-red-50 border border-red-200 p-4">
            <p className="font-semibold text-red-900">Import Failed</p>
            <p className="text-sm text-red-700 mt-1">
              {importMutation.error instanceof Error
                ? importMutation.error.message
                : "An unexpected error occurred during import."}
            </p>
            <button
              type="button"
              onClick={() => {
                importMutation.reset();
              }}
              className="mt-3 text-xs font-semibold text-red-800 hover:underline"
            >
              Try again
            </button>
          </div>
        )}

        {importMutation.data && (
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-8 text-center">
            <CheckCircle size={40} className="mx-auto text-emerald-700 mb-4" />
            <h3 className="text-lg font-bold text-slate-900 mb-2">Import Successful</h3>
            <p className="text-slate-700 mb-6 text-sm">
              Extracted and materialized{" "}
              <span className="font-bold text-slate-900">{importMutation.data.imported_events}</span> events to the case timeline.
            </p>
            <button
              type="button"
              onClick={() => {
                setSelectedFile(null);
                importMutation.reset();
              }}
              className="rounded-lg bg-white border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-100 transition-colors"
            >
              Import Another Archive
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

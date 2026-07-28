import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, LoaderCircle, MapPin, ScanSearch, Sparkles } from "lucide-react";

import { analyzeMedia, findSimilarMedia, getMediaAnalysis } from "../../lib/api";

const MEDIA_KEY = (caseId: string, artifactId: string) =>
  ["media-analysis", caseId, artifactId] as const;

function Row({ label, value }: { label: string; value: string | number | null | undefined }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div>
      <dt className="text-[10px] uppercase tracking-wider text-slate-600">{label}</dt>
      <dd className="mt-0.5 break-all text-[11px] text-slate-300">{String(value)}</dd>
    </div>
  );
}

export function MediaAnalysisPanel({
  caseId,
  artifactId,
}: {
  caseId: string;
  artifactId: string;
}) {
  const queryClient = useQueryClient();
  const key = MEDIA_KEY(caseId, artifactId);
  const analysis = useQuery({
    queryKey: key,
    queryFn: () => getMediaAnalysis(caseId, artifactId),
  });
  const run = useMutation({
    mutationFn: () => analyzeMedia(caseId, artifactId),
    onSuccess: (record) => queryClient.setQueryData(key, record),
  });
  const similar = useMutation({ mutationFn: () => findSimilarMedia(caseId, artifactId) });
  const record = analysis.data;

  return (
    <section
      className="mt-6 rounded-xl border border-violet-300/12 bg-violet-300/[0.025] p-4"
      aria-label="Media analysis"
    >
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-xs font-semibold text-violet-100">
            <Sparkles size={14} /> Media analysis
          </p>
          <p className="mt-1 text-[10px] leading-4 text-slate-500">
            Perceptual hash, EXIF/GPS, and OCR are extracted out of process from the
            re-hashed sealed file. Classification is a transparent heuristic baseline, not a
            trained model.
          </p>
        </div>
        {!record && (
          <button
            type="button"
            disabled={run.isPending}
            onClick={() => { run.mutate(); }}
            className="inline-flex min-h-9 shrink-0 items-center gap-2 rounded border border-violet-300/20 px-3 text-[11px] text-violet-100 disabled:opacity-40"
          >
            {run.isPending ? (
              <LoaderCircle size={13} className="animate-spin" />
            ) : (
              <ScanSearch size={13} />
            )}
            Analyze media
          </button>
        )}
      </div>

      {analysis.isPending && (
        <p role="status" className="mt-4 text-[11px] text-slate-500">
          Checking analysis status...
        </p>
      )}
      {run.isError && (
        <p className="mt-3 text-[11px] text-rose-300">
          {run.error instanceof Error ? run.error.message : "Analysis failed."}
        </p>
      )}

      {record && record.status === "analyzed" && (
        <div className="mt-4 space-y-4">
          <dl className="grid grid-cols-2 gap-3 rounded border border-white/7 bg-black/15 p-3">
            <Row
              label="Dimensions"
              value={
                record.width && record.height
                  ? `${String(record.width)} x ${String(record.height)}`
                  : null
              }
            />
            <Row label="Detected MIME" value={record.detected_mime} />
            <Row label="Camera" value={[record.camera_make, record.camera_model].filter(Boolean).join(" ")} />
            <Row label="Captured (raw EXIF)" value={record.captured_at_raw} />
          </dl>

          <div className="flex items-center gap-2 rounded border border-white/7 bg-black/15 p-3 text-[11px]">
            <Fingerprint size={14} className="shrink-0 text-violet-200" />
            <div className="min-w-0">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">Perceptual hash (dHash)</p>
              <p className="break-all font-mono text-[11px] text-slate-200">
                {record.perceptual_hash ?? "unavailable"}
              </p>
            </div>
            {record.perceptual_hash && (
              <button
                type="button"
                disabled={similar.isPending}
                onClick={() => { similar.mutate(); }}
                className="ml-auto inline-flex min-h-8 shrink-0 items-center gap-1 rounded border border-violet-300/20 px-2 text-[10px] text-violet-100 disabled:opacity-40"
              >
                {similar.isPending ? <LoaderCircle size={12} className="animate-spin" /> : null}
                Find similar
              </button>
            )}
          </div>

          {similar.data && (
            <div className="rounded border border-white/7 bg-black/15 p-3 text-[11px]">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">
                Similar images (Hamming distance ≤ {similar.data.max_distance})
              </p>
              {similar.data.matches.length === 0 ? (
                <p className="mt-2 text-slate-500">No near-duplicate images found in this case.</p>
              ) : (
                <ul className="mt-2 space-y-1">
                  {similar.data.matches.map((match) => (
                    <li key={match.analysis.id} className="flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-[10px] text-slate-300">
                        {match.analysis.artifact_id}
                      </span>
                      <span className="shrink-0 rounded-full border border-violet-300/20 px-2 py-0.5 text-[9px] text-violet-100">
                        distance {match.distance}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          <div
            className={`flex items-center gap-2 rounded border p-3 text-[11px] ${
              record.gps_present
                ? "border-emerald-300/15 bg-emerald-300/5 text-emerald-100"
                : "border-white/7 bg-black/15 text-slate-400"
            }`}
          >
            <MapPin size={14} className="shrink-0" />
            {record.gps_present && record.gps_latitude !== null && record.gps_longitude !== null ? (
              <span className="font-mono">
                {record.gps_latitude.toFixed(5)}, {record.gps_longitude.toFixed(5)}
              </span>
            ) : record.gps_present ? (
              <span>GPS EXIF block present without resolvable coordinates.</span>
            ) : (
              <span>No GPS metadata embedded in this image.</span>
            )}
          </div>

          <div className="rounded border border-white/7 bg-black/15 p-3 text-[11px]">
            <p className="text-[10px] uppercase tracking-wider text-slate-600">
              OCR ({record.ocr_status}
              {record.ocr_engine ? ` · ${record.ocr_engine}` : ""})
            </p>
            {record.ocr_status === "completed" && record.ocr_text ? (
              <p className="mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap text-slate-300">
                {record.ocr_text}
              </p>
            ) : record.ocr_status === "unavailable" ? (
              <p className="mt-2 text-slate-500">
                No OCR engine is installed in this environment, so no text was extracted.
              </p>
            ) : (
              <p className="mt-2 text-slate-500">No text detected in this image.</p>
            )}
          </div>

          <div className="rounded border border-white/7 bg-black/15 p-3 text-[11px]">
            <p className="text-[10px] uppercase tracking-wider text-slate-600">
              Classification ({record.detector_maturity})
            </p>
            <ul className="mt-2 space-y-1">
              {record.detections.map((label) => (
                <li key={label.label} className="flex items-center justify-between gap-2">
                  <span className="text-slate-300">
                    {label.label}
                    {label.status ? ` (${label.status})` : ""}
                  </span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-500">
                    {label.basis} · {(label.confidence * 100).toFixed(0)}%
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <p className="break-all font-mono text-[9px] text-slate-600">
            Analysis SHA-256: {record.analysis_hash}
          </p>
        </div>
      )}

      {record && record.status !== "analyzed" && (
        <div className="mt-4 rounded border border-amber-200/10 bg-amber-200/5 p-3 text-[11px] leading-5 text-amber-100/75">
          <p className="font-semibold">Analysis {record.status}</p>
          {record.error_message && <p>{record.error_message}</p>}
          {record.error_code && <p className="mt-1 font-mono text-[9px]">{record.error_code}</p>}
        </div>
      )}
    </section>
  );
}

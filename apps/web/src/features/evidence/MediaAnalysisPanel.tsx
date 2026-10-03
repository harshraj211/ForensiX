import type { ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Box, Fingerprint, LoaderCircle, MapPin, MessageSquareText, ScanSearch, Sparkles, UserRound } from "lucide-react";

import {
  analyzeMedia,
  findSimilarMedia,
  findVisualSimilarMedia,
  getMediaAnalysis,
  type MediaAnalysis,
  type MediaDetectionLabel,
} from "../../lib/api";

const MEDIA_KEY = (caseId: string, artifactId: string) =>
  ["media-analysis", caseId, artifactId] as const;


function prettyLabel(label: string): string {
  return label.replace(/^object_/, "").replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function percent(value: number): string {
  return `${(value * 100).toFixed(0)}%`;
}

function detailNumber(details: Record<string, unknown> | null | undefined, key: string): number | null {
  const value = details?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function completeRegion(region: MediaDetectionLabel["region"]): { x: number; y: number; width: number; height: number } | null {
  if (!region) return null;
  const { x, y, width, height } = region;
  return [x, y, width, height].every((value) => typeof value === "number" && Number.isFinite(value))
    ? { x: x as number, y: y as number, width: width as number, height: height as number }
    : null;
}

interface TranscriptSegment {
  start: number;
  end: number;
  text: string;
}

function transcriptSegments(record: MediaAnalysis): TranscriptSegment[] {
  for (const detection of record.detections) {
    const segments = detection.details?.segments;
    if (!Array.isArray(segments)) continue;
    return segments.flatMap((segment) => {
      if (!segment || typeof segment !== "object") return [];
      const item = segment as Record<string, unknown>;
      const start = item.start;
      const end = item.end;
      const text = item.text;
      if (typeof start !== "number" || typeof end !== "number" || typeof text !== "string") return [];
      return [{ start, end, text }];
    });
  }
  return [];
}

function partitionDetections(detections: MediaDetectionLabel[]) {
  const faces = detections.filter((item) => item.label.startsWith("face_"));
  const objects = detections.filter((item) => item.label.startsWith("object_"));
  const speech = detections.filter((item) => item.label.startsWith("speech_"));
  const other = detections.filter(
    (item) =>
      !item.label.startsWith("face_") &&
      !item.label.startsWith("object_") &&
      !item.label.startsWith("speech_"),
  );
  return { faces, objects, speech, other };
}

function DetectionList({ title, icon, items }: { title: string; icon: ReactNode; items: MediaDetectionLabel[] }) {
  if (items.length === 0) return null;
  return (
    <div className="rounded border border-white/7 bg-black/15 p-3 text-[11px]">
      <p className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-slate-600">
        {icon} {title}
      </p>
      <ul className="mt-2 space-y-2">
        {items.map((label, index) => {
          const faceCount = detailNumber(label.details, "face_count");
          const region = completeRegion(label.region);
          return (
            <li key={`${label.label}-${String(index)}`} className="rounded border border-white/5 bg-white/[0.02] p-2">
              <div className="flex items-start justify-between gap-2">
                <span className="font-medium text-slate-300">
                  {prettyLabel(label.label)}
                  {label.status ? <span className="ml-1 text-slate-500">({label.status})</span> : null}
                </span>
                <span className="shrink-0 font-mono text-[10px] text-slate-500">{percent(label.confidence)}</span>
              </div>
              <p className="mt-1 break-all font-mono text-[10px] text-slate-500">{label.basis}</p>
              {faceCount !== null && <p className="mt-1 text-[10px] text-violet-100">Faces detected: {faceCount}</p>}
              {region && (
                <p className="mt-1 font-mono text-[10px] text-cyan-100">
                  region x={region.x.toFixed(3)} y={region.y.toFixed(3)} w={region.width.toFixed(3)} h={region.height.toFixed(3)}
                </p>
              )}
              {typeof label.details?.class_index === "number" && (
                <p className="mt-1 text-[10px] text-slate-400">Class index {label.details.class_index}</p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function TranscriptPanel({ record }: { record: MediaAnalysis }) {
  const segments = transcriptSegments(record);
  const isSpeech = record.media_kind === "audio" || record.media_kind === "video";
  if (!isSpeech && !(record.ocr_status === "completed" && record.ocr_text)) return null;
  return (
    <div className="rounded border border-white/7 bg-black/15 p-3 text-[11px]">
      <p className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-slate-600">
        <MessageSquareText size={13} /> {isSpeech ? "Speech transcript" : "OCR text"} ({record.ocr_status}
        {record.ocr_engine ? ` · ${record.ocr_engine}` : ""})
      </p>
      {record.ocr_status === "completed" && record.ocr_text ? (
        <p className="mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap text-slate-300">{record.ocr_text}</p>
      ) : record.ocr_status === "unavailable" ? (
        <p className="mt-2 text-slate-500">No local model/runtime is configured for this media text extraction path.</p>
      ) : (
        <p className="mt-2 text-slate-500">No text or speech was detected.</p>
      )}
      {segments.length > 0 && (
        <ol className="mt-3 max-h-48 space-y-1 overflow-y-auto border-t border-white/7 pt-3">
          {segments.map((segment, index) => (
            <li key={`${String(segment.start)}-${String(segment.end)}-${String(index)}`} className="grid gap-2 rounded bg-white/[0.02] p-2 sm:grid-cols-[96px_1fr]">
              <span className="font-mono text-[10px] text-violet-100">
                {segment.start.toFixed(2)}s–{segment.end.toFixed(2)}s
              </span>
              <span className="text-slate-300">{segment.text}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function DetectionSections({ record }: { record: MediaAnalysis }) {
  const groups = partitionDetections(record.detections);
  if (record.detections.length === 0) return null;
  return (
    <div className="space-y-3">
      <p className="text-[10px] uppercase tracking-wider text-slate-600">Detections ({record.detector_maturity})</p>
      <DetectionList title="Face analysis" icon={<UserRound size={13} />} items={groups.faces} />
      <DetectionList title="Object labels" icon={<Box size={13} />} items={groups.objects} />
      <DetectionList title="Speech analysis" icon={<MessageSquareText size={13} />} items={groups.speech} />
      <DetectionList title="Other signals" icon={<Sparkles size={13} />} items={groups.other} />
    </div>
  );
}

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
  const visualSimilar = useMutation({
    mutationFn: () => findVisualSimilarMedia(caseId, artifactId),
  });
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
            Media analysis runs out of process from the re-hashed sealed file and surfaces
            perceptual hashes, EXIF/GPS, OCR, local ML detections, and speech transcripts when configured.
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
              <div className="ml-auto flex shrink-0 flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={similar.isPending}
                  onClick={() => { similar.mutate(); }}
                  className="inline-flex min-h-8 items-center gap-1 rounded border border-violet-300/20 px-2 text-[10px] text-violet-100 disabled:opacity-40"
                >
                  {similar.isPending ? <LoaderCircle size={12} className="animate-spin" /> : null}
                  Find similar
                </button>
                <button
                  type="button"
                  disabled={visualSimilar.isPending}
                  onClick={() => { visualSimilar.mutate(); }}
                  className="inline-flex min-h-8 items-center gap-1 rounded border border-cyan-300/20 px-2 text-[10px] text-cyan-100 disabled:opacity-40"
                >
                  {visualSimilar.isPending ? <LoaderCircle size={12} className="animate-spin" /> : null}
                  Find visual matches
                </button>
              </div>
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

          {visualSimilar.data && (
            <div className="rounded border border-white/7 bg-black/15 p-3 text-[11px]">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">
                Visual matches (cosine distance ≤ {visualSimilar.data.max_distance})
              </p>
              {visualSimilar.data.matches.length === 0 ? (
                <p className="mt-2 text-slate-500">No embedding-level visual matches found in this case.</p>
              ) : (
                <ul className="mt-2 space-y-1">
                  {visualSimilar.data.matches.map((match) => (
                    <li key={match.analysis.id} className="flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-[10px] text-slate-300">
                        {match.analysis.artifact_id}
                      </span>
                      <span className="shrink-0 rounded-full border border-cyan-300/20 px-2 py-0.5 text-[9px] text-cyan-100">
                        {match.distance.toFixed(3)} · {match.embedding_model.split(/[\\/]/).pop()}
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

          <TranscriptPanel record={record} />

          <DetectionSections record={record} />

          <p className="break-all font-mono text-[9px] text-slate-600">
            Analysis SHA-256: {record.analysis_hash}
          </p>
        </div>
      )}

      {record && record.status !== "analyzed" && (
        <div className="mt-4 space-y-3">
          <div className="rounded border border-amber-200/10 bg-amber-200/5 p-3 text-[11px] leading-5 text-amber-100/75">
            <p className="font-semibold">Analysis {record.status}</p>
            {record.error_message && <p>{record.error_message}</p>}
            {record.error_code && <p className="mt-1 font-mono text-[9px]">{record.error_code}</p>}
          </div>
          <TranscriptPanel record={record} />
          <DetectionSections record={record} />
        </div>
      )}
    </section>
  );
}

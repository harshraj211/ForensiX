import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Copy, ExternalLink, LoaderCircle, MapPin } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { getCase, listMediaAnalyses, type MediaAnalysis } from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";

// Self-contained offline plot: no external tile server, so inspecting a coordinate
// never reveals to a third party which location the workstation is examining.
const VIEW_WIDTH = 720;
const VIEW_HEIGHT = 420;
const PADDING = 44;

interface GeoPoint {
  analysis: MediaAnalysis;
  latitude: number;
  longitude: number;
  x: number;
  y: number;
}

function projectPoints(analyses: MediaAnalysis[]): GeoPoint[] {
  const geotagged = analyses.filter(
    (a): a is MediaAnalysis & { gps_latitude: number; gps_longitude: number } =>
      a.gps_latitude !== null && a.gps_longitude !== null,
  );
  if (geotagged.length === 0) return [];
  const lats = geotagged.map((a) => a.gps_latitude);
  const lngs = geotagged.map((a) => a.gps_longitude);
  const minLat = Math.min(...lats);
  const maxLat = Math.max(...lats);
  const minLng = Math.min(...lngs);
  const maxLng = Math.max(...lngs);
  // Guard against a zero-span range (single point or a shared coordinate).
  const latSpan = maxLat - minLat || 1;
  const lngSpan = maxLng - minLng || 1;
  const usableWidth = VIEW_WIDTH - PADDING * 2;
  const usableHeight = VIEW_HEIGHT - PADDING * 2;
  return geotagged.map((analysis) => {
    // Equirectangular projection over the bounded set; latitude inverted for screen space.
    const x = PADDING + ((analysis.gps_longitude - minLng) / lngSpan) * usableWidth;
    const y = PADDING + ((maxLat - analysis.gps_latitude) / latSpan) * usableHeight;
    return {
      analysis,
      latitude: analysis.gps_latitude,
      longitude: analysis.gps_longitude,
      x,
      y,
    };
  });
}

export function MediaMapPage() {
  const { caseId = "" } = useParams();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const mediaQuery = useQuery({
    queryKey: caseKeys.mediaMap(caseId),
    queryFn: () => listMediaAnalyses(caseId, { gpsOnly: true, limit: 200 }),
    enabled: Boolean(caseId),
  });

  const points = useMemo(
    () => projectPoints(mediaQuery.data?.items ?? []),
    [mediaQuery.data?.items],
  );
  const selected = points.find((p) => p.analysis.id === selectedId) ?? null;

  async function copyCoordinates(point: GeoPoint) {
    const text = `${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}`;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(point.analysis.id);
      window.setTimeout(() => { setCopiedId(null); }, 1500);
    } catch {
      setCopiedId(null);
    }
  }

  return (
    <div className="mx-auto max-w-6xl">
      <Link
        to={`/cases/${caseId}`}
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"
      >
        <ArrowLeft size={15} /> Back to case
      </Link>
      <header className="mt-6 border-b border-white/8 pb-7">
        <p className="font-mono text-xs text-cyan-300/65">
          {caseQuery.data?.case_number ?? "Case media locations"}
        </p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Media locations</h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">
          GPS coordinates extracted from geotagged photo EXIF, plotted offline. No map tiles
          are fetched, so inspecting a location never leaves the workstation.
        </p>
      </header>

      {mediaQuery.isPending && (
        <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500">
          <LoaderCircle size={16} className="animate-spin" /> Loading geotagged media...
        </p>
      )}
      {mediaQuery.isError && <div className="mt-6"><CaseError error={mediaQuery.error} /></div>}
      {caseQuery.isError && <div className="mt-6"><CaseError error={caseQuery.error} /></div>}
      {mediaQuery.data && points.length === 0 && (
        <p className="mt-8 text-sm text-slate-500">
          No analyzed media in this case carries GPS coordinates.
        </p>
      )}

      {points.length > 0 && (
        <div className="mt-7 grid gap-6 lg:grid-cols-[1fr_320px]">
          <MediaPlot points={points} selectedId={selectedId} onSelect={setSelectedId} />
          <CoordinateList
            points={points}
            selectedId={selectedId}
            copiedId={copiedId}
            onSelect={setSelectedId}
            onCopy={copyCoordinates}
          />
        </div>
      )}

      {selected && <SelectedCard point={selected} />}
    </div>
  );
}

function MediaPlot({
  points,
  selectedId,
  onSelect,
}: {
  points: GeoPoint[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="rounded-2xl border border-white/8 bg-white/[0.02] p-4">
      <svg
        viewBox={`0 0 ${VIEW_WIDTH} ${VIEW_HEIGHT}`}
        className="h-auto w-full"
        role="img"
        aria-label={`Offline plot of ${points.length} geotagged media locations`}
      >
        <rect
          x={PADDING / 2}
          y={PADDING / 2}
          width={VIEW_WIDTH - PADDING}
          height={VIEW_HEIGHT - PADDING}
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth={1}
        />
        {[0.25, 0.5, 0.75].map((fraction) => (
          <g key={fraction} stroke="rgba(255,255,255,0.05)" strokeWidth={1}>
            <line
              x1={PADDING / 2 + fraction * (VIEW_WIDTH - PADDING)}
              y1={PADDING / 2}
              x2={PADDING / 2 + fraction * (VIEW_WIDTH - PADDING)}
              y2={VIEW_HEIGHT - PADDING / 2}
            />
            <line
              x1={PADDING / 2}
              y1={PADDING / 2 + fraction * (VIEW_HEIGHT - PADDING)}
              x2={VIEW_WIDTH - PADDING / 2}
              y2={PADDING / 2 + fraction * (VIEW_HEIGHT - PADDING)}
            />
          </g>
        ))}
        {points.map((point) => {
          const active = point.analysis.id === selectedId;
          return (
            <g key={point.analysis.id} transform={`translate(${point.x} ${point.y})`}>
              <circle
                r={active ? 9 : 6}
                fill={active ? "rgb(103,232,249)" : "rgba(103,232,249,0.55)"}
                stroke="rgb(8,20,28)"
                strokeWidth={1.5}
                className="cursor-pointer"
                onClick={() => { onSelect(point.analysis.id); }}
              >
                <title>{`${point.latitude.toFixed(5)}, ${point.longitude.toFixed(5)}`}</title>
              </circle>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function CoordinateList({
  points,
  selectedId,
  copiedId,
  onSelect,
  onCopy,
}: {
  points: GeoPoint[];
  selectedId: string | null;
  copiedId: string | null;
  onSelect: (id: string) => void;
  onCopy: (point: GeoPoint) => void;
}) {
  return (
    <ul className="max-h-[420px] space-y-2 overflow-y-auto pr-1">
      {points.map((point) => {
        const active = point.analysis.id === selectedId;
        const coords = `${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}`;
        return (
          <li
            key={point.analysis.id}
            className={`rounded-xl border p-3 ${active ? "border-cyan-300/40 bg-cyan-300/5" : "border-white/8 bg-white/[0.02]"}`}
          >
            <button
              type="button"
              onClick={() => { onSelect(point.analysis.id); }}
              className="flex w-full items-start gap-2 text-left"
            >
              <MapPin size={14} className="mt-0.5 shrink-0 text-cyan-300" />
              <span className="font-mono text-xs text-slate-300">{coords}</span>
            </button>
            <div className="mt-2 flex items-center gap-3 pl-6">
              <button
                type="button"
                onClick={() => { onCopy(point); }}
                className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-200"
              >
                <Copy size={12} /> {copiedId === point.analysis.id ? "Copied" : "Copy"}
              </button>
              <a
                href={`https://www.openstreetmap.org/?mlat=${point.latitude}&mlon=${point.longitude}#map=16/${point.latitude}/${point.longitude}`}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-200"
              >
                <ExternalLink size={12} /> Open externally
              </a>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function SelectedCard({ point }: { point: GeoPoint }) {
  return (
    <div className="mt-6 rounded-2xl border border-cyan-300/20 bg-cyan-300/[0.03] p-5">
      <p className="text-[10px] uppercase tracking-wider text-slate-500">Selected location</p>
      <p className="mt-1 font-mono text-sm text-cyan-100">
        {point.latitude.toFixed(6)}, {point.longitude.toFixed(6)}
      </p>
      <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-2">
        <div>
          <dt className="text-slate-600">Captured (EXIF)</dt>
          <dd className="mt-0.5 text-slate-300">{point.analysis.captured_at_raw ?? "Not recorded"}</dd>
        </div>
        <div>
          <dt className="text-slate-600">Camera</dt>
          <dd className="mt-0.5 text-slate-300">
            {[point.analysis.camera_make, point.analysis.camera_model].filter(Boolean).join(" ") || "Unknown"}
          </dd>
        </div>
      </dl>
      <Link
        to={`../artifacts`}
        className="mt-4 inline-block text-[11px] text-cyan-200 hover:underline"
      >
        Open source artifact
      </Link>
    </div>
  );
}

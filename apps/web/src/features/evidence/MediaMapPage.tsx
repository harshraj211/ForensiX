import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Camera,
  Compass,
  Copy,
  ExternalLink,
  Eye,
  LoaderCircle,
  MapPin,
  Navigation,
  Pause,
  Play,
  RefreshCw,
  RotateCcw,
  SkipBack,
  SkipForward,
  Users,
  Wifi,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

import {
  analyzePendingMedia,
  getCase,
  getCaseGeolocation,
  getMediaFaceClusters,
  listMediaAnalyses,
  rebuildMediaFaceClusters,
  type MediaAnalysis,
  type MediaFaceCluster,
} from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import { CaseSubnav } from "../../components/CaseSubnav";
import { formatUtcAsLocal } from "../../lib/time";

type MapLayerMode = "dark" | "streets" | "satellite" | "offline";
type SourceFilter = "all" | "media" | "android" | "network";

export interface UnifiedGeoPoint {
  id: string;
  sourceType: "media_exif" | "android_location" | "cell_tower" | "wifi_cache" | "map_search";
  title: string;
  subtitle: string;
  latitude: number;
  longitude: number;
  timestamp: string | null;
  accuracy: number | null;
  cameraInfo?: string | null;
  metadata: Record<string, unknown>;
  analysis?: MediaAnalysis;
  x?: number;
  y?: number;
}

const VIEW_WIDTH = 720;
const VIEW_HEIGHT = 420;
const PADDING = 44;
const USABLE_WIDTH = VIEW_WIDTH - PADDING * 2;
const USABLE_HEIGHT = VIEW_HEIGHT - PADDING * 2;

function projectOfflinePoints(points: UnifiedGeoPoint[]): UnifiedGeoPoint[] {
  if (points.length === 0) return [];

  const lats = points.map((p) => p.latitude);
  const lons = points.map((p) => p.longitude);
  const minLat = Math.min(...lats);
  const maxLat = Math.max(...lats);
  const minLon = Math.min(...lons);
  const maxLon = Math.max(...lons);
  const spanLat = maxLat - minLat || 1;
  const spanLon = maxLon - minLon || 1;
  return points.map((p) => {
    const normX = (p.longitude - minLon) / spanLon;
    const normY = (p.latitude - minLat) / spanLat;
    const x = PADDING + normX * USABLE_WIDTH;
    const y = VIEW_HEIGHT - PADDING - normY * USABLE_HEIGHT;
    return { ...p, x, y };
  });
}

function cleanCameraString(make?: string | null, model?: string | null): string {
  const sanitize = (s?: string | null) =>
    s
      ? Array.from(s)
          .filter((char) => {
            const code = char.charCodeAt(0);
            return (code >= 32 && code !== 127) || code === 9 || code === 10 || code === 13;
          })
          .join("")
          .trim()
      : "";
  const cleanMake = sanitize(make);
  const cleanModel = sanitize(model);
  if (cleanMake && cleanModel) {
    if (cleanModel.toLowerCase().startsWith(cleanMake.toLowerCase())) {
      return cleanModel;
    }
    return `${cleanMake} ${cleanModel}`;
  }
  return cleanModel || cleanMake || "Device Camera";
}

export function MediaMapPage() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [mapLayer, setMapLayer] = useState<MapLayerMode>("dark");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [showTrail, setShowTrail] = useState(true);
  const [playbackIndex, setPlaybackIndex] = useState<number | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playSpeed, setPlaySpeed] = useState<1 | 2 | 4>(1);

  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });

  const mediaQuery = useQuery({
    queryKey: caseKeys.mediaMap(caseId),
    queryFn: () => listMediaAnalyses(caseId, { gpsOnly: true, limit: 100 }),
    enabled: Boolean(caseId),
  });
  const faceClustersQuery = useQuery({
    queryKey: caseKeys.mediaFaceClusters(caseId),
    queryFn: () => getMediaFaceClusters(caseId),
    enabled: Boolean(caseId),
  });
  const batchAnalysis = useMutation({
    mutationFn: () => analyzePendingMedia(caseId, 100),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: caseKeys.mediaMap(caseId) });
      void queryClient.invalidateQueries({ queryKey: caseKeys.mediaFaceClusters(caseId) });
    },
  });
  const rebuildFaceClusters = useMutation({
    mutationFn: () => rebuildMediaFaceClusters(caseId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: caseKeys.mediaFaceClusters(caseId) });
    },
  });

  const geoQuery = useQuery({
    queryKey: caseKeys.geolocation(caseId),
    queryFn: () => getCaseGeolocation(caseId),
    enabled: Boolean(caseId),
  });

  // Consolidate media EXIF points with Android SQLite location artifacts
  const mediaItems = mediaQuery.data?.items;
  const geoPoints = geoQuery.data?.points;
  const unifiedPoints: UnifiedGeoPoint[] = useMemo(() => {
    const combined: UnifiedGeoPoint[] = [];
    const seenIds = new Set<string>();

    // 1. From media analyses (Photos/Videos)
    if (mediaItems) {
      for (const m of mediaItems) {
        if (typeof m.gps_latitude === "number" && typeof m.gps_longitude === "number") {
          seenIds.add(`media:${m.id}`);
          combined.push({
            id: `media:${m.id}`,
            sourceType: "media_exif",
            title: m.camera_model || "EXIF Photo Geotag",
            subtitle: cleanCameraString(m.camera_make, m.camera_model),
            latitude: m.gps_latitude,
            longitude: m.gps_longitude,
            timestamp: m.captured_at_raw || null,
            accuracy: null,
            cameraInfo: cleanCameraString(m.camera_make, m.camera_model),
            metadata: { pHash: m.perceptual_hash },
            analysis: m,
          });
        }
      }
    }

    // 2. From case geolocation analytics (SQLite Android Locations, Maps, Wi-Fi)
    if (geoPoints) {
      for (const p of geoPoints) {
        const pointId = p.id.startsWith("media:") ? p.id : `geo:${p.id}`;
        if (seenIds.has(pointId)) continue;
        seenIds.add(pointId);

        let sType: UnifiedGeoPoint["sourceType"] = "android_location";
        if (p.source_type === "wifi_profile" || p.application === "wifi") {
          sType = "wifi_cache";
        } else if (p.source_type === "cell_tower_observation" || p.application === "cell") {
          sType = "cell_tower";
        } else if (p.source_type === "maps_search") {
          sType = "map_search";
        } else if (p.source_type === "media_exif") {
          sType = "media_exif";
        }

        combined.push({
          id: pointId,
          sourceType: sType,
          title: p.title || "Location Observation",
          subtitle: p.summary || `${p.application} coordinate`,
          latitude: p.latitude,
          longitude: p.longitude,
          timestamp: p.timestamp || null,
          accuracy: p.metadata.accuracy ? Number(p.metadata.accuracy) : null,
          metadata: p.metadata,
        });
      }
    }

    // Sort chronologically
    combined.sort((a, b) => {
      if (!a.timestamp) return 1;
      if (!b.timestamp) return -1;
      return a.timestamp.localeCompare(b.timestamp);
    });

    return combined;
  }, [mediaItems, geoPoints]);

  const filteredPoints = useMemo(() => {
    if (sourceFilter === "all") return unifiedPoints;
    if (sourceFilter === "media") {
      return unifiedPoints.filter((p) => p.sourceType === "media_exif");
    }
    if (sourceFilter === "android") {
      return unifiedPoints.filter(
        (p) => p.sourceType === "android_location" || p.sourceType === "map_search",
      );
    }
    return unifiedPoints.filter(
      (p) => p.sourceType === "wifi_cache" || p.sourceType === "cell_tower",
    );
  }, [unifiedPoints, sourceFilter]);

  // Playback timer effect
  useEffect(() => {
    if (!isPlaying || filteredPoints.length <= 1) return;

    const intervalMs = Math.round(1200 / playSpeed);
    const timer = window.setInterval(() => {
      setPlaybackIndex((prev) => {
        const current = prev === null ? 0 : prev;
        if (current >= filteredPoints.length - 1) {
          setIsPlaying(false);
          return current;
        }
        return current + 1;
      });
    }, intervalMs);

    return () => { window.clearInterval(timer); };
  }, [isPlaying, playSpeed, filteredPoints.length]);



  const activePoints = useMemo(() => {
    if (playbackIndex === null) return filteredPoints;
    return filteredPoints.slice(0, playbackIndex + 1);
  }, [filteredPoints, playbackIndex]);

  const selected = useMemo(() => {
    const targetId = playbackIndex !== null && filteredPoints[playbackIndex]
      ? filteredPoints[playbackIndex].id
      : selectedId;
    if (!targetId && filteredPoints.length > 0) return filteredPoints[0];
    return filteredPoints.find((p) => p.id === targetId) || null;
  }, [filteredPoints, playbackIndex, selectedId]);

  const offlinePoints = useMemo(() => projectOfflinePoints(activePoints), [activePoints]);


  async function copyCoordinates(point: UnifiedGeoPoint) {
    const text = `${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}`;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(point.id);
      window.setTimeout(() => {
        setCopiedId(null);
      }, 1500);
    } catch {
      setCopiedId(null);
    }
  }

  const mediaCount = unifiedPoints.filter((p) => p.sourceType === "media_exif").length;
  const androidCount = unifiedPoints.filter(
    (p) => p.sourceType === "android_location" || p.sourceType === "map_search",
  ).length;
  const networkCount = unifiedPoints.filter(
    (p) => p.sourceType === "wifi_cache" || p.sourceType === "cell_tower",
  ).length;

  return (
    <div className="mx-auto max-w-6xl">
      <CaseSubnav caseId={caseId} caseNumber={caseQuery.data?.case_number} />
      <Link
        to={`/cases/${caseId}`}
        className="inline-flex items-center gap-2 text-sm font-medium text-slate-600 hover:text-slate-900 transition"
      >
        <ArrowLeft size={15} /> Back to case
      </Link>

      <header className="mt-6 border-b border-slate-200 pb-7">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-500">
              {caseQuery.data?.case_number ?? "Case geospatial intelligence"}
            </p>
            <h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-900">
              Geospatial Timeline & Map
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              Unified forensic mapping across camera EXIF GPS tags, Android FusedLocationProvider fixes,
              Google Maps searches, and cached Wi-Fi/Cellular locations.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={batchAnalysis.isPending || !caseId}
              onClick={() => {
                batchAnalysis.mutate();
              }}
              className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-violet-200 bg-white px-3 text-xs font-semibold text-violet-700 shadow-sm disabled:opacity-40"
            >
              {batchAnalysis.isPending ? <LoaderCircle size={14} className="animate-spin" /> : <Eye size={14} />}
              Analyze pending media
            </button>
            <div className="flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white p-1.5 shadow-sm">
              {[
                { id: "dark", label: "Dark Map" },
                { id: "streets", label: "Streets" },
                { id: "satellite", label: "Satellite" },
                { id: "offline", label: "Air-Gap Grid" },
              ].map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => { setMapLayer(m.id as MapLayerMode); }}
                  className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                    mapLayer === m.id
                      ? "bg-slate-900 text-white shadow-sm"
                      : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {batchAnalysis.data && (
          <div className="mt-5 rounded-xl border border-violet-200 bg-violet-50 p-4 text-sm text-violet-900">
            Analyzed {batchAnalysis.data.analyzed} image(s), marked {batchAnalysis.data.unsupported} video/audio item(s) model-ready, failed {batchAnalysis.data.failed}, skipped {batchAnalysis.data.skipped_existing} existing record(s).
          </div>
        )}
        {batchAnalysis.isError && (
          <div className="mt-5">
            <CaseError error={batchAnalysis.error} />
          </div>
        )}

        {/* Source Filter Tabs & Movement Trail Toggle */}
        <div className="mt-6 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => { setSourceFilter("all"); }}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                sourceFilter === "all"
                  ? "bg-cyan-600 text-white"
                  : "bg-slate-100 text-slate-700 hover:bg-slate-200"
              }`}
            >
              All Sources ({unifiedPoints.length})
            </button>
            <button
              type="button"
              onClick={() => { setSourceFilter("media"); }}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                sourceFilter === "media"
                  ? "bg-cyan-600 text-white"
                  : "bg-slate-100 text-slate-700 hover:bg-slate-200"
              }`}
            >
              <Camera size={13} /> Photos & EXIF ({mediaCount})
            </button>
            <button
              type="button"
              onClick={() => { setSourceFilter("android"); }}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                sourceFilter === "android"
                  ? "bg-emerald-600 text-white"
                  : "bg-slate-100 text-slate-700 hover:bg-slate-200"
              }`}
            >
              <Navigation size={13} /> Android Fixes ({androidCount})
            </button>
            <button
              type="button"
              onClick={() => { setSourceFilter("network"); }}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                sourceFilter === "network"
                  ? "bg-purple-600 text-white"
                  : "bg-slate-100 text-slate-700 hover:bg-slate-200"
              }`}
            >
              <Wifi size={13} /> Wi-Fi & Cellular ({networkCount})
            </button>
          </div>

          <label className="flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showTrail}
              onChange={(e) => { setShowTrail(e.target.checked); }}
              className="rounded border-slate-300 text-cyan-600 focus:ring-cyan-500"
            />
            <Compass size={14} className="text-cyan-600" /> Connect Movement Trail
          </label>
        </div>
      </header>

      {(caseQuery.isPending || mediaQuery.isPending || geoQuery.isPending) && (
        <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500">
          <LoaderCircle size={16} className="animate-spin" /> Correlating geographic coordinates…
        </p>
      )}

      {caseQuery.isError && <div className="mt-6"><CaseError error={caseQuery.error} /></div>}
      {mediaQuery.isError && <div className="mt-6"><CaseError error={mediaQuery.error} /></div>}

      {filteredPoints.length === 0 && !mediaQuery.isPending && !geoQuery.isPending ? (
        <div className="mt-8 rounded-2xl border border-dashed border-slate-300 bg-white p-12 text-center">
          <MapPin size={32} className="mx-auto text-slate-400" />
          <h2 className="mt-3 text-base font-semibold text-slate-900">No Geotagged Locations Found</h2>
          <p className="mt-1 text-xs text-slate-500">
            None of the ingested media files or Android system databases contained valid GPS coordinates.
          </p>
        </div>
      ) : (
        <div className="mt-6">
          {/* Breadcrumb Timeline Playback & Scrubber Controls */}
          <div className="mb-4 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    if (isPlaying) {
                      setIsPlaying(false);
                    } else {
                      if (playbackIndex === null || playbackIndex >= filteredPoints.length - 1) {
                        setPlaybackIndex(0);
                      }
                      setIsPlaying(true);
                    }
                  }}
                  className={`flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-semibold shadow-sm transition ${
                    isPlaying
                      ? "bg-amber-500 text-white hover:bg-amber-600"
                      : "bg-cyan-600 text-white hover:bg-cyan-700"
                  }`}
                  title={isPlaying ? "Pause timeline playback" : "Play timeline breadcrumb playback"}
                >
                  {isPlaying ? <Pause size={14} /> : <Play size={14} />}
                  {isPlaying ? "Pause Playback" : "Play Trail"}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setIsPlaying(false);
                    setPlaybackIndex((prev) => (prev === null || prev <= 0 ? 0 : prev - 1));
                  }}
                  disabled={playbackIndex === 0 || filteredPoints.length === 0}
                  className="rounded-xl border border-slate-200 bg-slate-50 p-2 text-slate-700 hover:bg-slate-100 disabled:opacity-40 transition"
                  title="Previous breadcrumb observation"
                >
                  <SkipBack size={14} />
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setIsPlaying(false);
                    setPlaybackIndex((prev) => {
                      if (prev === null) return Math.min(1, filteredPoints.length - 1);
                      return Math.min(prev + 1, filteredPoints.length - 1);
                    });
                  }}
                  disabled={
                    playbackIndex !== null &&
                    playbackIndex >= filteredPoints.length - 1
                  }
                  className="rounded-xl border border-slate-200 bg-slate-50 p-2 text-slate-700 hover:bg-slate-100 disabled:opacity-40 transition"
                  title="Next breadcrumb observation"
                >
                  <SkipForward size={14} />
                </button>

                {playbackIndex !== null && (
                  <button
                    type="button"
                    onClick={() => {
                      setIsPlaying(false);
                      setPlaybackIndex(null);
                    }}
                    className="flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-600 hover:bg-slate-100 hover:text-slate-900 transition"
                    title="Reset to view all historical points simultaneously"
                  >
                    <RotateCcw size={13} />
                    <span>Show All Points</span>
                  </button>
                )}
              </div>

              {/* Speed Toggle */}
              <div className="flex items-center gap-1 rounded-xl border border-slate-200 bg-slate-50 p-1">
                {([1, 2, 4] as const).map((spd) => (
                  <button
                    key={spd}
                    type="button"
                    onClick={() => { setPlaySpeed(spd); }}
                    className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                      playSpeed === spd
                        ? "bg-white text-slate-900 shadow-sm"
                        : "text-slate-500 hover:text-slate-900"
                    }`}
                  >
                    {spd}x
                  </button>
                ))}
              </div>
            </div>

            {/* Range slider & Breadcrumb Metadata */}
            <div className="mt-4 space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-500">
                <span className="font-mono text-[11px] font-semibold text-slate-700">
                  {playbackIndex !== null
                    ? `Point ${String(playbackIndex + 1)} of ${String(filteredPoints.length)}`
                    : `Showing all ${String(filteredPoints.length)} points`}
                </span>
                <span className="font-mono text-[11px] text-cyan-700 font-medium">
                  {selected?.timestamp ? formatUtcAsLocal(selected.timestamp) : "No timestamp recorded"}
                </span>
              </div>

              <input
                type="range"
                min={0}
                max={Math.max(filteredPoints.length - 1, 0)}
                value={playbackIndex ?? filteredPoints.length - 1}
                onChange={(e) => {
                  setIsPlaying(false);
                  setPlaybackIndex(Number(e.target.value));
                }}
                className="h-2 w-full cursor-pointer appearance-none rounded-lg bg-slate-200 accent-cyan-600"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm lg:col-span-2">
              {mapLayer === "offline" ? (
                <OfflineMediaPlot
                  points={offlinePoints}
                  selectedId={selected?.id ?? null}
                  showTrail={showTrail}
                  onSelect={(id) => {
                    setSelectedId(id);
                    const idx = filteredPoints.findIndex((p) => p.id === id);
                    if (idx !== -1 && playbackIndex !== null) {
                      setPlaybackIndex(idx);
                    }
                  }}
                />
              ) : (
                <InteractiveLeafletMap
                  points={activePoints}
                  selectedId={selected?.id ?? null}
                  onSelect={(id) => {
                    setSelectedId(id);
                    const idx = filteredPoints.findIndex((p) => p.id === id);
                    if (idx !== -1 && playbackIndex !== null) {
                      setPlaybackIndex(idx);
                    }
                  }}
                  layerMode={mapLayer}
                  showTrail={showTrail}
                />
              )}
            </div>

            <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                Locations Trail ({filteredPoints.length})
              </p>
              <div className="mt-3">
                <CoordinateList
                  points={filteredPoints}
                  selectedId={selected?.id ?? null}
                  copiedId={copiedId}
                  onSelect={(id) => {
                    setSelectedId(id);
                    const idx = filteredPoints.findIndex((p) => p.id === id);
                    if (idx !== -1 && playbackIndex !== null) {
                      setPlaybackIndex(idx);
                    }
                  }}
                  onCopy={(coords) => {
                    void copyCoordinates(coords);
                  }}
                />
              </div>
            </div>
          </div>

          {selected && <SelectedCard point={selected} caseId={caseId} />}
        </div>
      )}
      <FaceClusterPanel
        clusters={faceClustersQuery.data?.clusters ?? []}
        totalClusters={faceClustersQuery.data?.total_clusters ?? 0}
        totalEmbeddings={faceClustersQuery.data?.total_embeddings ?? 0}
        isLoading={faceClustersQuery.isPending}
        error={faceClustersQuery.error}
        rebuildResult={rebuildFaceClusters.data}
        isRebuilding={rebuildFaceClusters.isPending}
        onRebuild={() => {
          rebuildFaceClusters.mutate();
        }}
      />
    </div>
  );
}

interface InteractiveLeafletMapProps {
  points: UnifiedGeoPoint[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  layerMode: "dark" | "streets" | "satellite";
  showTrail: boolean;
}
function FaceClusterPanel({
  clusters,
  totalClusters,
  totalEmbeddings,
  isLoading,
  error,
  rebuildResult,
  isRebuilding,
  onRebuild,
}: {
  clusters: MediaFaceCluster[];
  totalClusters: number;
  totalEmbeddings: number;
  isLoading: boolean;
  error: Error | null;
  rebuildResult?: { embeddings: number; clusters: number };
  isRebuilding: boolean;
  onRebuild: () => void;
}) {
  const topClusters = clusters.slice(0, 6);
  return (
    <section className="mt-7 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Users size={18} className="text-violet-600" />
            <h2 className="text-base font-semibold text-slate-900">Case face groups</h2>
          </div>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
            Groups detected face regions across analyzed case media into deterministic person clusters.
            Records include the source artifact, face index, normalized region, embedding model, and
            cluster hash.
          </p>
        </div>
        <button
          type="button"
          disabled={isRebuilding}
          onClick={onRebuild}
          className="inline-flex min-h-10 items-center gap-2 rounded-xl border border-violet-200 bg-violet-50 px-3 text-xs font-semibold text-violet-800 shadow-sm disabled:opacity-40"
        >
          {isRebuilding ? (
            <LoaderCircle size={14} className="animate-spin" />
          ) : (
            <RefreshCw size={14} />
          )}
          Rebuild face groups
        </button>
      </div>

      {rebuildResult && (
        <div className="mt-4 rounded-xl border border-violet-200 bg-violet-50 p-3 text-sm text-violet-900">
          Rebuilt {rebuildResult.clusters} group(s) from {rebuildResult.embeddings} face embedding(s).
        </div>
      )}
      {error ? (
        <div className="mt-4">
          <CaseError error={error} />
        </div>
      ) : null}

      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <Metric label="Groups" value={totalClusters} />
        <Metric label="Face embeddings" value={totalEmbeddings} />
        <Metric label="Algorithm" value={clusters[0]?.algorithm ?? "detector-region-geometry-v1"} />
      </div>

      {isLoading ? (
        <p role="status" className="mt-5 flex items-center gap-2 text-sm text-slate-500">
          <LoaderCircle size={16} className="animate-spin" /> Loading face groups...
        </p>
      ) : topClusters.length === 0 ? (
        <div className="mt-5 rounded-xl border border-dashed border-slate-300 bg-slate-50 p-4 text-sm text-slate-600">
          No face groups are stored yet. Run media analysis on images, then rebuild face groups.
        </div>
      ) : (
        <div className="mt-5 grid gap-3 md:grid-cols-2">
          {topClusters.map((cluster) => (
            <article key={cluster.id} className="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-slate-900">{cluster.label}</p>
                  <p className="font-mono text-[11px] text-slate-500">{cluster.cluster_key}</p>
                </div>
                <span className="rounded-full bg-violet-100 px-2.5 py-1 text-xs font-semibold text-violet-800">
                  {cluster.member_count} face{cluster.member_count === 1 ? "" : "s"}
                </span>
              </div>
              <div className="mt-3 space-y-2">
                {cluster.members.slice(0, 3).map((member) => (
                  <div
                    key={member.id}
                    className="rounded-lg border border-slate-200 bg-white p-2 text-xs text-slate-600"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono text-slate-700">
                        face #{member.face_index} · {member.artifact_id.slice(0, 8)}
                      </span>
                      <span>{member.embedding_model}</span>
                    </div>
                    <p className="mt-1 font-mono text-[11px] text-slate-500">
                      x {formatRegion(member.region.x)} · y {formatRegion(member.region.y)} · w{" "}
                      {formatRegion(member.region.width)} · h {formatRegion(member.region.height)}
                    </p>
                  </div>
                ))}
                {cluster.member_count > 3 && (
                  <p className="text-xs font-medium text-slate-500">
                    +{cluster.member_count - 3} more face record(s)
                  </p>
                )}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-lg font-semibold text-slate-900">{value}</p>
    </div>
  );
}

function formatRegion(value: number | undefined): string {
  return typeof value === "number" ? value.toFixed(3) : "n/a";
}

function InteractiveLeafletMap({
  points,
  selectedId,
  onSelect,
  layerMode,
  showTrail,
}: InteractiveLeafletMapProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const markersRef = useRef<Map<string, L.Marker>>(new Map());
  const layersGroupRef = useRef<L.LayerGroup | null>(null);
  const trailLayerRef = useRef<L.Polyline | null>(null);
  const circlesGroupRef = useRef<L.LayerGroup | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    if (mapRef.current) return;

    const firstPoint = points[0];
    const initialCenter: [number, number] =
      firstPoint ? [firstPoint.latitude, firstPoint.longitude] : [20.5937, 78.9629];

    const map = L.map(containerRef.current, {
      center: initialCenter,
      zoom: 14,
      zoomControl: false,
    });

    L.control.zoom({ position: "bottomright" }).addTo(map);
    layersGroupRef.current = L.layerGroup().addTo(map);
    circlesGroupRef.current = L.layerGroup().addTo(map);
    mapRef.current = map;

    return () => {
      map.remove();
      mapRef.current = null;
    };
  }, [points]);

  // Update tile layers
  useEffect(() => {
    const map = mapRef.current;
    const group = layersGroupRef.current;
    if (!map || !group) return;

    group.clearLayers();

    if (layerMode === "dark") {
      const base = L.tileLayer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
        { attribution: "Tiles &copy; Esri", maxZoom: 16 },
      );
      const labels = L.tileLayer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
        { attribution: "", maxZoom: 16 },
      );
      group.addLayer(base);
      group.addLayer(labels);
    } else if (layerMode === "streets") {
      const osm = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
        maxZoom: 19,
      });
      group.addLayer(osm);
    } else {
      const sat = L.tileLayer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
        { attribution: "Tiles &copy; Esri", maxZoom: 18 },
      );
      group.addLayer(sat);
    }
  }, [layerMode]);

  // Update markers, accuracy circles, and trail polyline
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;

    markersRef.current.forEach((m) => m.remove());
    markersRef.current.clear();

    if (trailLayerRef.current) {
      trailLayerRef.current.remove();
      trailLayerRef.current = null;
    }

    if (circlesGroupRef.current) {
      circlesGroupRef.current.clearLayers();
    }

    const bounds = L.latLngBounds([]);
    const trailCoordinates: [number, number][] = [];

    points.forEach((point) => {
      const isSelected = point.id === selectedId;
      const color = pointColor(point.sourceType);

      const markerHtml = `
        <div style="position: relative; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center;">
          <div style="position: absolute; width: 30px; height: 30px; border-radius: 9999px; background-color: ${color}; opacity: ${
            isSelected ? "0.45" : "0.2"
          }; animation: pulse 2s infinite;"></div>
          <div style="width: 13px; height: 13px; border-radius: 9999px; background-color: ${color}; border: 2px solid #ffffff; box-shadow: 0 2px 6px rgba(0,0,0,0.4);"></div>
        </div>
      `;

      const icon = L.divIcon({
        className: "custom-forensic-marker",
        html: markerHtml,
        iconSize: [30, 30],
        iconAnchor: [15, 15],
      });

      const marker = L.marker([point.latitude, point.longitude], { icon }).addTo(map);

      // Add accuracy circle if accuracy is known
      if (point.accuracy && point.accuracy > 0 && circlesGroupRef.current) {
        const circle = L.circle([point.latitude, point.longitude], {
          radius: point.accuracy,
          color,
          fillColor: color,
          fillOpacity: 0.12,
          weight: 1,
        });
        circlesGroupRef.current.addLayer(circle);
      }

      const popupHtml = `
        <div style="font-family: system-ui, sans-serif; min-width: 220px; padding: 4px;">
          <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 4px;">
            <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; background-color: ${color}; color: #ffffff; padding: 2px 6px; border-radius: 4px;">${point.sourceType.replace("_", " ")}</span>
            <span style="font-size: 11px; color: #64748b;">${point.subtitle}</span>
          </div>
          <p style="font-size: 13px; font-weight: 600; color: #0f172a; margin: 4px 0;">
            ${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}
          </p>
          <div style="font-size: 11px; color: #475569; margin: 4px 0;">
            <div>Time: <strong>${point.timestamp || "Unrecorded"}</strong></div>
            ${point.accuracy ? `<div>Accuracy: <strong>&plusmn;${point.accuracy.toFixed(1)}m</strong></div>` : ""}
          </div>
          <div style="margin-top: 6px; border-top: 1px solid #e2e8f0; padding-top: 6px;">
            <a href="https://www.google.com/maps?q=${point.latitude.toFixed(6)},${point.longitude.toFixed(6)}" target="_blank" rel="noreferrer" style="font-size: 11px; color: #0284c7; text-decoration: none; font-weight: 600;">Open Google Maps &rarr;</a>
          </div>
        </div>
      `;

      marker.bindPopup(popupHtml);
      marker.on("click", () => { onSelect(point.id); });
      markersRef.current.set(point.id, marker);

      bounds.extend([point.latitude, point.longitude]);
      trailCoordinates.push([point.latitude, point.longitude]);
    });

    // Draw Movement Trail Polyline
    if (showTrail && trailCoordinates.length > 1) {
      trailLayerRef.current = L.polyline(trailCoordinates, {
        color: "#06b6d4",
        weight: 2,
        opacity: 0.65,
        dashArray: "4, 6",
      }).addTo(map);
    }

    if (points.length > 0 && !selectedId) {
      map.fitBounds(bounds, { padding: [50, 50], maxZoom: 16 });
    }
  }, [points, selectedId, onSelect, showTrail]);

  // Pan to selected marker
  useEffect(() => {
    if (!selectedId) return;
    const marker = markersRef.current.get(selectedId);
    const map = mapRef.current;
    if (marker && map) {
      const latLng = marker.getLatLng();
      map.flyTo(latLng, 16, { duration: 1.2 });
      marker.openPopup();
    }
  }, [selectedId]);

  return (
    <div className="relative h-[480px] w-full">
      <div ref={containerRef} className="h-full w-full" />
      <div className="pointer-events-none absolute bottom-3 left-3 z-[1000] flex items-center gap-2 rounded-lg bg-black/80 px-3 py-1.5 text-xs backdrop-blur-md">
        <span className="h-2 w-2 rounded-full bg-cyan-400"></span>
        <span className="font-mono text-[11px] text-cyan-200">
          {points.length} Geotagged Location Observation(s)
        </span>
      </div>
    </div>
  );
}

function haversineDistanceMeters(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371000;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function formatLat(lat: number): string {
  const dir = lat >= 0 ? "N" : "S";
  return `${Math.abs(lat).toFixed(4)}° ${dir}`;
}

function formatLon(lon: number): string {
  const dir = lon >= 0 ? "E" : "W";
  return `${Math.abs(lon).toFixed(4)}° ${dir}`;
}

function OfflineMediaPlot({
  points,
  selectedId,
  showTrail = true,
  onSelect,
}: {
  points: UnifiedGeoPoint[];
  selectedId: string | null;
  showTrail?: boolean;
  onSelect: (id: string) => void;
}) {
  const geoBounds = useMemo(() => {
    if (points.length === 0) return null;
    const lats = points.map((p) => p.latitude);
    const lons = points.map((p) => p.longitude);
    const minLat = Math.min(...lats);
    const maxLat = Math.max(...lats);
    const minLon = Math.min(...lons);
    const maxLon = Math.max(...lons);
    const midLat = (minLat + maxLat) / 2;
    const midLon = (minLon + maxLon) / 2;
    const spanMeters = Math.max(haversineDistanceMeters(midLat, minLon, midLat, maxLon), 10);
    return { minLat, maxLat, minLon, maxLon, midLat, midLon, spanMeters };
  }, [points]);

  // Compute a scale bar distance target
  const scaleInfo = useMemo(() => {
    if (!geoBounds) return null;
    const span = geoBounds.spanMeters;
    const steps = [10, 25, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 25000, 50000, 100000, 500000];
    const target = span / 4;
    let chosen = steps[0] ?? 10;
    for (const s of steps) {
      if (s <= target) chosen = s;
      else break;
    }
    const barWidthPx = Math.max(Math.min((chosen / span) * USABLE_WIDTH, 180), 30);
    const label =
      chosen >= 1000
        ? `${(chosen / 1000).toFixed(chosen % 1000 === 0 ? 0 : 1)} km`
        : `${String(chosen)} m`;
    return { barWidthPx, label };
  }, [geoBounds]);

  return (
    <div className="p-4 bg-slate-950 text-slate-100">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="inline-flex size-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-mono text-[11px] font-semibold text-emerald-300">
            AIR-GAPPED FORENSIC VECTOR GRID
          </span>
          <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-400">
            0 External Network Requests
          </span>
        </div>
        {geoBounds && (
          <span className="font-mono text-[10px] text-slate-400">
            Span: {geoBounds.spanMeters >= 1000 ? `${(geoBounds.spanMeters / 1000).toFixed(2)} km` : `${String(Math.round(geoBounds.spanMeters))} m`} · {String(points.length)} Fixes
          </span>
        )}
      </div>

      <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-slate-900/90 shadow-inner">
        <svg
          viewBox={"0 0 " + String(VIEW_WIDTH) + " " + String(VIEW_HEIGHT)}
          className="h-auto w-full select-none"
          role="img"
          aria-label={"Offline forensic plot of " + String(points.length) + " locations"}
        >
          {/* Base Grid Background */}
          <rect
            x={PADDING}
            y={PADDING}
            width={VIEW_WIDTH - PADDING * 2}
            height={VIEW_HEIGHT - PADDING * 2}
            fill="#090d16"
            stroke="#1e293b"
            strokeWidth={1.5}
            rx={4}
          />

          {/* Forensic Graticule Grid Lines */}
          {[0.25, 0.5, 0.75].map((fraction) => {
            const gx = PADDING + fraction * (VIEW_WIDTH - PADDING * 2);
            const gy = PADDING + fraction * (VIEW_HEIGHT - PADDING * 2);
            return (
              <g key={fraction} stroke="#1e293b" strokeDasharray="2, 4" strokeWidth={1}>
                <line x1={gx} y1={PADDING} x2={gx} y2={VIEW_HEIGHT - PADDING} />
                <line x1={PADDING} y1={gy} x2={VIEW_WIDTH - PADDING} y2={gy} />
              </g>
            );
          })}

          {/* Graticule Latitude Axis Labels */}
          {geoBounds && (
            <>
              <text x={PADDING + 6} y={PADDING + 14} fill="#64748b" fontSize="9" fontFamily="monospace">
                {formatLat(geoBounds.maxLat)}
              </text>
              <text x={PADDING + 6} y={VIEW_HEIGHT / 2 + 3} fill="#475569" fontSize="9" fontFamily="monospace">
                {formatLat(geoBounds.midLat)}
              </text>
              <text x={PADDING + 6} y={VIEW_HEIGHT - PADDING - 6} fill="#64748b" fontSize="9" fontFamily="monospace">
                {formatLat(geoBounds.minLat)}
              </text>

              {/* Longitude Labels */}
              <text x={PADDING} y={VIEW_HEIGHT - PADDING + 15} fill="#64748b" fontSize="9" fontFamily="monospace">
                {formatLon(geoBounds.minLon)}
              </text>
              <text x={VIEW_WIDTH / 2} y={VIEW_HEIGHT - PADDING + 15} textAnchor="middle" fill="#475569" fontSize="9" fontFamily="monospace">
                {formatLon(geoBounds.midLon)}
              </text>
              <text x={VIEW_WIDTH - PADDING} y={VIEW_HEIGHT - PADDING + 15} textAnchor="end" fill="#64748b" fontSize="9" fontFamily="monospace">
                {formatLon(geoBounds.maxLon)}
              </text>
            </>
          )}

          {/* Movement Trail Polyline */}
          {showTrail && points.length > 1 && (
            <polyline
              points={points
                .filter((p) => typeof p.x === "number" && typeof p.y === "number")
                .map((p) => `${String(p.x)},${String(p.y)}`)
                .join(" ")}
              fill="none"
              stroke="#06b6d4"
              strokeWidth={2}
              strokeDasharray="4, 5"
              strokeLinejoin="round"
              strokeLinecap="round"
              opacity={0.8}
            />
          )}

          {/* Accuracy Circles & Fix Markers */}
          {points.map((point) => {
            const active = point.id === selectedId;
            const px = point.x ?? VIEW_WIDTH / 2;
            const py = point.y ?? VIEW_HEIGHT / 2;
            const color = pointColor(point.sourceType);

            // Compute accuracy radius in px if present
            const accuracyPx =
              point.accuracy && geoBounds
                ? Math.min(Math.max((point.accuracy / geoBounds.spanMeters) * USABLE_WIDTH, 8), 90)
                : null;

            return (
              <g key={point.id} transform={"translate(" + String(px) + " " + String(py) + ")"}>
                {accuracyPx && (
                  <circle
                    r={accuracyPx}
                    fill={color}
                    fillOpacity={0.08}
                    stroke={color}
                    strokeWidth={1}
                    strokeDasharray="2, 2"
                    opacity={0.5}
                  />
                )}
                {active && (
                  <circle
                    r={18}
                    fill="none"
                    stroke="#22d3ee"
                    strokeWidth={2}
                    className="animate-pulse"
                    opacity={0.8}
                  />
                )}
                <circle
                  r={active ? 8 : 5}
                  fill={color}
                  stroke="#0f172a"
                  strokeWidth={2}
                  className="cursor-pointer transition-all hover:scale-125"
                  onClick={() => { onSelect(point.id); }}
                >
                  <title>{`${point.title} (${point.latitude.toFixed(5)}, ${point.longitude.toFixed(5)})`}</title>
                </circle>
              </g>
            );
          })}

          {/* Forensic Compass Rose in Top-Right */}
          <g transform={`translate(${String(VIEW_WIDTH - PADDING - 24)}, ${String(PADDING + 24)})`}>
            <circle r={16} fill="#090d16" stroke="#334155" strokeWidth={1} />
            <polygon points="0,-13 -4,-2 0,0" fill="#ef4444" />
            <polygon points="0,-13 4,-2 0,0" fill="#f87171" />
            <polygon points="0,13 -4,2 0,0" fill="#64748b" />
            <polygon points="0,13 4,2 0,0" fill="#94a3b8" />
            <text x={0} y={-15} textAnchor="middle" fill="#ef4444" fontSize="8" fontWeight="bold" fontFamily="sans-serif">
              N
            </text>
          </g>

          {/* Forensic Scale Bar in Bottom-Left */}
          {scaleInfo && (
            <g transform={`translate(${String(PADDING + 12)}, ${String(VIEW_HEIGHT - PADDING - 20)})`}>
              <rect x={-4} y={-14} width={scaleInfo.barWidthPx + 8} height={20} fill="#090d16" fillOpacity={0.85} rx={3} />
              <line x1={0} y1={0} x2={scaleInfo.barWidthPx} y2={0} stroke="#94a3b8" strokeWidth={2} />
              <line x1={0} y1={-4} x2={0} y2={4} stroke="#94a3b8" strokeWidth={2} />
              <line x1={scaleInfo.barWidthPx} y1={-4} x2={scaleInfo.barWidthPx} y2={4} stroke="#94a3b8" strokeWidth={2} />
              <text x={scaleInfo.barWidthPx / 2} y={-5} textAnchor="middle" fill="#cbd5e1" fontSize="9" fontFamily="monospace">
                {scaleInfo.label}
              </text>
            </g>
          )}
        </svg>
      </div>
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
  points: UnifiedGeoPoint[];
  selectedId: string | null;
  copiedId: string | null;
  onSelect: (id: string) => void;
  onCopy: (point: UnifiedGeoPoint) => void;
}) {
  return (
    <ul className="flex max-h-[480px] flex-col gap-2 overflow-y-auto pr-1">
      {points.map((point) => {
        const active = point.id === selectedId;
        const copied = copiedId === point.id;
        const coords = `${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}`;
        const color = pointColor(point.sourceType);

        return (
          <li
            key={point.id}
            className={`rounded-xl border p-3.5 transition-all ${
              active
                ? "border-slate-900 bg-slate-50 shadow-sm ring-1 ring-slate-900"
                : "border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50"
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <button
                type="button"
                onClick={() => { onSelect(point.id); }}
                className="flex items-center gap-2 text-left text-xs font-mono font-semibold text-slate-900 hover:text-cyan-700"
              >
                <span
                  className="size-2 rounded-full shrink-0"
                  style={{ backgroundColor: color }}
                />
                {coords}
              </button>
            </div>

            <p className="mt-1 text-[11px] font-medium text-slate-600 truncate">
              {point.title}
            </p>

            <div className="mt-2.5 flex items-center justify-between border-t border-slate-100 pt-2 text-[11px] text-slate-500">
              <span>{point.timestamp ? point.timestamp.slice(0, 16) : "No timestamp"}</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => { onCopy(point); }}
                  className="inline-flex items-center gap-1 font-medium text-slate-600 hover:text-slate-900"
                >
                  <Copy size={11} /> {copied ? "Copied!" : "Copy"}
                </button>
                <a
                  href={`https://www.google.com/maps?q=${point.latitude.toFixed(6)},${point.longitude.toFixed(6)}`}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1 font-medium text-cyan-700 hover:text-cyan-900"
                >
                  <ExternalLink size={11} /> Maps
                </a>
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function SelectedCard({ point, caseId }: { point: UnifiedGeoPoint; caseId: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(
      `${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}`,
    );
    setCopied(true);
    setTimeout(() => {
      setCopied(false);
    }, 1500);
  };

  return (
    <div className="mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <span
              className="rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-white"
              style={{ backgroundColor: pointColor(point.sourceType) }}
            >
              {point.sourceType.replace("_", " ")}
            </span>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              {point.subtitle}
            </p>
          </div>
          <div className="mt-1 flex items-center gap-3">
            <h3 className="font-mono text-lg font-bold text-slate-900">
              {point.latitude.toFixed(6)}, {point.longitude.toFixed(6)}
            </h3>
            <button
              type="button"
              onClick={() => {
                void copy();
              }}
              className="inline-flex items-center gap-1 rounded border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-100"
            >
              <Copy size={12} /> {copied ? "Copied" : "Copy"}
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <a
            href={`https://www.google.com/maps?q=${point.latitude.toFixed(6)},${point.longitude.toFixed(6)}`}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-black"
          >
            <ExternalLink size={13} /> View on Google Maps
          </a>
          <Link
            to={`/cases/${caseId}/evidence-twin`}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50 hover:text-slate-900"
          >
            <Eye size={13} /> View Evidence Sources
          </Link>
        </div>
      </div>

      <dl className="mt-5 grid gap-4 border-t border-slate-100 pt-4 text-xs sm:grid-cols-4">
        <div>
          <dt className="font-medium text-slate-500">Event Timestamp</dt>
          <dd className="mt-1 font-semibold text-slate-900">
            {point.timestamp ?? "Not recorded"}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Accuracy Radius</dt>
          <dd className="mt-1 font-semibold text-slate-900">
            {point.accuracy ? `±${point.accuracy.toFixed(1)} m` : "Exact / Unknown"}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Device / Provider</dt>
          <dd className="mt-1 font-semibold text-slate-900">
            {point.cameraInfo || (typeof point.metadata.provider === "string" ? point.metadata.provider : "Android Location Provider")}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Source Identifier</dt>
          <dd className="mt-1 font-mono text-[11px] font-semibold text-slate-800 truncate">
            {point.id}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function pointColor(type: UnifiedGeoPoint["sourceType"]): string {
  if (type === "media_exif") return "#06b6d4"; // Cyan
  if (type === "android_location") return "#10b981"; // Emerald
  if (type === "wifi_cache" || type === "cell_tower") return "#a855f7"; // Purple
  return "#f59e0b"; // Amber (map_search or default)
}

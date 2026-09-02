import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft,
  Copy,
  ExternalLink,
  Eye,
  LoaderCircle,
  MapPin,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

import {
  getCase,
  listMediaAnalyses,
  type MediaAnalysis,
} from "../../lib/api";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import { CaseSubnav } from "../../components/CaseSubnav";

type MapLayerMode = "dark" | "streets" | "satellite" | "offline";

interface GeoPoint {
  analysis: MediaAnalysis;
  latitude: number;
  longitude: number;
  x: number;
  y: number;
}

const VIEW_WIDTH = 720;
const VIEW_HEIGHT = 420;
const PADDING = 44;

function projectOfflinePoints(analyses: MediaAnalysis[]): GeoPoint[] {
  const valid = analyses.filter(
    (a): a is MediaAnalysis & { gps_latitude: number; gps_longitude: number } =>
      typeof a.gps_latitude === "number" && typeof a.gps_longitude === "number",
  );

  if (valid.length === 0) return [];

  const lats = valid.map((a) => a.gps_latitude);
  const lons = valid.map((a) => a.gps_longitude);
  const minLat = Math.min(...lats);
  const maxLat = Math.max(...lats);
  const minLon = Math.min(...lons);
  const maxLon = Math.max(...lons);
  const spanLat = maxLat - minLat || 1;
  const spanLon = maxLon - minLon || 1;
  const usableWidth = VIEW_WIDTH - PADDING * 2;
  const usableHeight = VIEW_HEIGHT - PADDING * 2;

  return valid.map((analysis) => {
    const normX = (analysis.gps_longitude - minLon) / spanLon;
    const normY = (analysis.gps_latitude - minLat) / spanLat;
    const x = PADDING + normX * usableWidth;
    const y = VIEW_HEIGHT - PADDING - normY * usableHeight;
    return {
      analysis,
      latitude: analysis.gps_latitude,
      longitude: analysis.gps_longitude,
      x,
      y,
    };
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
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [mapLayer, setMapLayer] = useState<MapLayerMode>("dark");

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

  const points = useMemo(
    () => projectOfflinePoints(mediaQuery.data?.items ?? []),
    [mediaQuery.data?.items],
  );

  const selected = points.find((p) => p.analysis.id === selectedId) ?? points[0] ?? null;

  async function copyCoordinates(point: GeoPoint) {
    const text = `${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}`;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(point.analysis.id);
      window.setTimeout(() => {
        setCopiedId(null);
      }, 1500);
    } catch {
      setCopiedId(null);
    }
  }

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
              {caseQuery.data?.case_number ?? "Case media locations"}
            </p>
            <h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-900">Media Locations Map</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              Interactive geographic investigation map plotted from EXIF GPS metadata embedded in acquired photos.
              Choose between interactive Dark / Street / Satellite map tiles or strict Air-Gapped Offline Grid.
            </p>
          </div>

          {points.length > 0 && (
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
                  onClick={() => {
                    setMapLayer(m.id as MapLayerMode);
                  }}
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
          )}
        </div>
      </header>

      {mediaQuery.isPending && (
        <p role="status" className="mt-8 flex items-center gap-2 text-sm text-slate-500">
          <LoaderCircle size={16} className="animate-spin" /> Loading geotagged media...
        </p>
      )}
      {mediaQuery.isError && (
        <div className="mt-6">
          <CaseError error={mediaQuery.error} />
        </div>
      )}
      {caseQuery.isError && (
        <div className="mt-6">
          <CaseError error={caseQuery.error} />
        </div>
      )}

      {mediaQuery.data && points.length === 0 && (
        <div className="mt-8 rounded-xl border border-white/10 bg-white/[0.02] p-8 text-center">
          <MapPin size={32} className="mx-auto text-slate-500" />
          <p className="mt-3 text-base font-medium text-slate-300">
            No analyzed media in this case carries GPS coordinates.
          </p>
          <p className="mx-auto mt-2 max-w-md text-xs leading-5 text-slate-500">
            Photos acquired from mobile devices must undergo Media Analysis in the Evidence Explorer to extract EXIF metadata and GPS coordinates into the offline map.
          </p>
          <Link
            to={`/cases/${caseId}/evidence`}
            className="mt-5 inline-flex items-center gap-2 rounded-lg bg-cyan-300 px-5 py-2.5 text-xs font-semibold text-slate-950 transition hover:bg-cyan-200"
          >
            Open Evidence Explorer to inspect & analyze photos
          </Link>
        </div>
      )}

      {points.length > 0 && (
        <div className="mt-7 grid gap-6 lg:grid-cols-[1fr_340px]">
          <div className="overflow-hidden rounded-2xl border border-white/10 bg-black/60 shadow-2xl">
            {mapLayer === "offline" ? (
              <OfflineMediaPlot
                points={points}
                selectedId={selected?.analysis.id ?? null}
                onSelect={setSelectedId}
              />
            ) : (
              <InteractiveLeafletMap
                points={points}
                selectedId={selected?.analysis.id ?? null}
                onSelect={setSelectedId}
                layerMode={mapLayer}
              />
            )}
          </div>

          <CoordinateList
            points={points}
            selectedId={selected?.analysis.id ?? null}
            copiedId={copiedId}
            onSelect={setSelectedId}
            onCopy={(point) => {
              void copyCoordinates(point);
            }}
          />
        </div>
      )}

      {selected && <SelectedCard point={selected} caseId={caseId} />}
    </div>
  );
}

interface InteractiveLeafletMapProps {
  points: GeoPoint[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  layerMode: "dark" | "streets" | "satellite";
}

function InteractiveLeafletMap({
  points,
  selectedId,
  onSelect,
  layerMode,
}: InteractiveLeafletMapProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const markersRef = useRef<Map<string, L.Marker>>(new Map());
  const layersGroupRef = useRef<L.LayerGroup | null>(null);

  // Initialize map instance
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
    mapRef.current = map;

    return () => {
      map.remove();
      mapRef.current = null;
    };
  }, [points]);

  // Update tile layer based on layerMode
  useEffect(() => {
    const map = mapRef.current;
    const group = layersGroupRef.current;
    if (!map || !group) return;

    group.clearLayers();

    if (layerMode === "dark") {
      const base = L.tileLayer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}",
        {
          attribution: "Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ",
          maxZoom: 16,
        },
      );
      const labels = L.tileLayer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}",
        {
          attribution: "",
          maxZoom: 16,
        },
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
        {
          attribution: "Tiles &copy; Esri",
          maxZoom: 18,
        },
      );
      const boundaries = L.tileLayer(
        "https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}",
        {
          attribution: "",
          maxZoom: 18,
        },
      );
      group.addLayer(sat);
      group.addLayer(boundaries);
    }
  }, [layerMode]);

  // Update markers
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;

    // Clear old markers
    markersRef.current.forEach((m) => {
      m.remove();
    });
    markersRef.current.clear();

    const bounds = L.latLngBounds([]);

    points.forEach((point) => {
      const isSelected = point.analysis.id === selectedId;
      const markerHtml = `
        <div style="position: relative; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center;">
          <div style="position: absolute; width: 32px; height: 32px; border-radius: 9999px; background-color: rgba(34, 211, 238, ${
            isSelected ? "0.35" : "0.15"
          }); animation: pulse 2s infinite;"></div>
          <div style="width: 14px; height: 14px; border-radius: 9999px; background-color: ${
            isSelected ? "#22d3ee" : "#06b6d4"
          }; border: 2.5px solid #ffffff; box-shadow: 0 2px 8px rgba(0,0,0,0.5);"></div>
        </div>
      `;

      const icon = L.divIcon({
        className: "custom-forensic-marker",
        html: markerHtml,
        iconSize: [32, 32],
        iconAnchor: [16, 16],
      });

      const marker = L.marker([point.latitude, point.longitude], { icon }).addTo(map);

      const popupHtml = `
        <div style="font-family: system-ui, sans-serif; min-width: 220px; padding: 4px;">
          <div style="display: flex; align-items: center; gap: 6px; margin-bottom: 6px;">
            <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; background-color: #0891b2; color: #ffffff; padding: 2px 6px; border-radius: 4px;">GPS Geotag</span>
            <span style="font-size: 11px; color: #64748b;">${
              point.analysis.camera_make || "Device Camera"
            }</span>
          </div>
          <p style="font-size: 13px; font-weight: 600; color: #0f172a; margin: 4px 0;">
            ${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}
          </p>
          <div style="font-size: 11px; color: #475569; margin: 6px 0;">
            <div>Camera: <strong>${cleanCameraString(point.analysis.camera_make, point.analysis.camera_model)}</strong></div>
            <div>EXIF Time: <strong>${point.analysis.captured_at_raw || "Not recorded"}</strong></div>
          </div>
          <div style="margin-top: 8px; border-top: 1px solid #e2e8f0; padding-top: 8px; display: flex; gap: 8px;">
            <a href="https://www.google.com/maps?q=${point.latitude.toFixed(6)},${point.longitude.toFixed(6)}" target="_blank" rel="noreferrer" style="font-size: 11px; color: #0284c7; text-decoration: none; font-weight: 600;">Open Google Maps &rarr;</a>
          </div>
        </div>
      `;

      marker.bindPopup(popupHtml);

      marker.on("click", () => {
        onSelect(point.analysis.id);
      });

      markersRef.current.set(point.analysis.id, marker);
      bounds.extend([point.latitude, point.longitude]);
    });

    if (points.length > 0 && !selectedId) {
      map.fitBounds(bounds, { padding: [50, 50], maxZoom: 16 });
    }
  }, [points, selectedId, onSelect]);

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
        <span className="font-mono text-[11px] text-cyan-200">{points.length} Geotagged Media Location(s)</span>
      </div>
    </div>
  );
}

function OfflineMediaPlot({
  points,
  selectedId,
  onSelect,
}: {
  points: GeoPoint[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="p-4">
      <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
        <span className="font-mono text-[11px] text-cyan-300">Air-Gapped Cartesian Projection</span>
        <span className="text-[11px] text-slate-500">Zero Network Requests</span>
      </div>
      <svg
        viewBox={"0 0 " + String(VIEW_WIDTH) + " " + String(VIEW_HEIGHT)}
        className="h-auto w-full"
        role="img"
        aria-label={"Offline plot of " + String(points.length) + " geotagged media locations"}
      >
        <rect
          x={PADDING / 2}
          y={PADDING / 2}
          width={VIEW_WIDTH - PADDING}
          height={VIEW_HEIGHT - PADDING}
          fill="rgba(15, 23, 42, 0.6)"
          stroke="rgba(34, 211, 238, 0.2)"
          strokeWidth={1}
          rx={8}
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
            <g
              key={point.analysis.id}
              transform={"translate(" + String(point.x) + " " + String(point.y) + ")"}
            >
              {active && (
                <circle r={18} fill="rgba(34, 211, 238, 0.25)" className="animate-ping" />
              )}
              <circle
                r={active ? 10 : 6}
                fill={active ? "rgb(103,232,249)" : "rgba(103,232,249,0.55)"}
                stroke="rgb(8,20,28)"
                strokeWidth={2}
                className="cursor-pointer transition-all"
                onClick={() => {
                  onSelect(point.analysis.id);
                }}
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
    <ul className="flex max-h-[480px] flex-col gap-2 overflow-y-auto pr-1">
      {points.map((point) => {
        const active = point.analysis.id === selectedId;
        const copied = copiedId === point.analysis.id;
        const coords = `${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}`;
        return (
          <li
            key={point.analysis.id}
            className={`rounded-xl border p-3.5 transition-all ${
              active
                ? "border-slate-900 bg-slate-50 shadow-sm ring-1 ring-slate-900"
                : "border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50"
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <button
                type="button"
                onClick={() => {
                  onSelect(point.analysis.id);
                }}
                className="flex items-center gap-2 text-left text-xs font-mono font-semibold text-slate-900 hover:text-cyan-700"
              >
                <MapPin size={13} className={active ? "text-cyan-600" : "text-slate-400"} />
                {coords}
              </button>
            </div>

            <p className="mt-1.5 text-[11px] font-medium text-slate-600">
              {cleanCameraString(point.analysis.camera_make, point.analysis.camera_model)}
            </p>

            <div className="mt-3 flex items-center gap-2 border-t border-slate-100 pt-2">
              <button
                type="button"
                onClick={() => {
                  onCopy(point);
                }}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600 transition hover:text-slate-900"
              >
                <Copy size={12} /> {copied ? "Copied!" : "Copy"}
              </button>
              <span className="text-slate-300">·</span>
              <a
                href={`https://www.google.com/maps?q=${point.latitude.toFixed(6)},${point.longitude.toFixed(6)}`}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-1 text-[11px] font-medium text-cyan-700 transition hover:text-cyan-900"
              >
                <ExternalLink size={12} /> Google Maps
              </a>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function SelectedCard({ point, caseId }: { point: GeoPoint; caseId: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(`${point.latitude.toFixed(6)}, ${point.longitude.toFixed(6)}`);
    setCopied(true);
    setTimeout(() => {
      setCopied(false);
    }, 1500);
  };

  return (
    <div className="mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Selected Forensic Location
          </p>
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
            to={`/cases/${caseId}/evidence`}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50 hover:text-slate-900"
          >
            <Eye size={13} /> View in Evidence Explorer
          </Link>
        </div>
      </div>

      <dl className="mt-5 grid gap-4 border-t border-slate-100 pt-4 text-xs sm:grid-cols-3">
        <div>
          <dt className="font-medium text-slate-500">EXIF Timestamp</dt>
          <dd className="mt-1 font-semibold text-slate-900">
            {point.analysis.captured_at_raw ?? "Not recorded in EXIF"}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Camera Device</dt>
          <dd className="mt-1 font-semibold text-slate-900">
            {cleanCameraString(point.analysis.camera_make, point.analysis.camera_model)}
          </dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Perceptual Hash (pHash)</dt>
          <dd className="mt-1 font-mono text-[11px] font-semibold text-slate-800">
            {point.analysis.perceptual_hash ?? "N/A"}
          </dd>
        </div>
      </dl>
    </div>
  );
}

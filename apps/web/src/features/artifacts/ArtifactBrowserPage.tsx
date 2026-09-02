import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft,
  LoaderCircle,
  MessageSquare,
  Phone,
  User,
  MapPin,
  Settings,
  Wifi,
  Bluetooth,
  Calendar,
  Download,
  Globe,
  Bell,
  FileText,
  PackageOpen,
} from "lucide-react";
import { useState, useMemo } from "react";
import { Link, useParams } from "react-router-dom";

import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import { CaseSubnav } from "../../components/CaseSubnav";
import { ApkAnalysisPanel } from "../evidence/ApkAnalysisPanel";
import {
  getCase,
  listEvidenceSources,
  listEvidenceSourceArtifacts,
  type EvidenceSourceArtifact,
} from "../../lib/api";
import { PromoteToKeyEvidence } from "../evidence/PromoteToKeyEvidence";

const twinKeys = {
  sources: (caseId: string) => ["evidence-twin", caseId, "sources"] as const,
  artifacts: (caseId: string, sourceId: string) =>
    ["evidence-twin", caseId, sourceId, "artifacts"] as const,
};

type Category = {
  id: string;
  label: string;
  icon: React.ElementType;
  match: (a: EvidenceSourceArtifact) => boolean;
};

const CATEGORIES: Category[] = [
  { id: "all", label: "All artifacts", icon: FileText, match: () => true },
  {
    id: "sms",
    label: "SMS / MMS",
    icon: MessageSquare,
    match: (a) => a.subtype === "sms" || a.subtype === "mms",
  },
  {
    id: "calls",
    label: "Call log",
    icon: Phone,
    match: (a) => a.subtype === "call",
  },
  {
    id: "contacts",
    label: "Contacts",
    icon: User,
    match: (a) => a.category === "contact",
  },
  {
    id: "whatsapp",
    label: "WhatsApp",
    icon: MessageSquare,
    match: (a) => a.subtype === "whatsapp_message",
  },
  {
    id: "telegram",
    label: "Telegram",
    icon: MessageSquare,
    match: (a) => a.subtype === "telegram_message",
  },
  {
    id: "messenger",
    label: "Messenger",
    icon: MessageSquare,
    match: (a) => a.subtype === "messenger_message",
  },
  {
    id: "instagram",
    label: "Instagram",
    icon: MessageSquare,
    match: (a) => a.subtype === "instagram_message",
  },
  {
    id: "facebook",
    label: "Facebook",
    icon: MessageSquare,
    match: (a) => a.subtype === "facebook_message",
  },
  {
    id: "location",
    label: "Locations",
    icon: MapPin,
    match: (a) => a.category === "location",
  },
  {
    id: "wifi",
    label: "Wi-Fi networks",
    icon: Wifi,
    match: (a) => a.subtype === "wifi_network",
  },
  {
    id: "bluetooth",
    label: "Bluetooth devices",
    icon: Bluetooth,
    match: (a) => a.subtype === "bluetooth_device",
  },
  {
    id: "calendar",
    label: "Calendar",
    icon: Calendar,
    match: (a) => a.subtype === "calendar_event",
  },
  {
    id: "downloads",
    label: "Downloads",
    icon: Download,
    match: (a) => a.subtype === "download_entry",
  },
  {
    id: "browser",
    label: "Browser history",
    icon: Globe,
    match: (a) => a.subtype === "chrome_history_entry",
  },
  {
    id: "notifications",
    label: "Notifications",
    icon: Bell,
    match: (a) => a.subtype === "notification_entry",
  },
  {
    id: "system",
    label: "System",
    icon: Settings,
    match: (a) => a.category === "system" && !["wifi_network", "bluetooth_device"].includes(a.subtype),
  },
  {
    id: "apk_analysis",
    label: "Static APK Scanner",
    icon: PackageOpen,
    match: () => false,
  },
];

function confidenceBadge(confidence: string) {
  const colors: Record<string, string> = {
    high: "text-emerald-300 border-emerald-300/20 bg-emerald-300/5",
    medium: "text-amber-300 border-amber-300/20 bg-amber-300/5",
    low: "text-slate-400 border-white/10 bg-white/3",
  };
  return colors[confidence] ?? "text-slate-400 border-white/10 bg-white/3";
}

function statusBadge(status: string) {
  if (status === "deleted") return "text-rose-300 border-rose-300/20 bg-rose-300/5";
  if (status === "recovered") return "text-violet-300 border-violet-300/20 bg-violet-300/5";
  return "text-slate-500 border-white/8";
}

function MetaRow({ label, value }: { label: string; value: string | number | boolean | null | undefined }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div>
      <dt className="text-[10px] uppercase tracking-wider text-slate-600">{label}</dt>
      <dd className="mt-0.5 break-all text-xs text-slate-300">{String(value)}</dd>
    </div>
  );
}

function DetailPanel({
  artifact,
  caseId,
}: {
  artifact: EvidenceSourceArtifact;
  caseId: string;
}) {
  const meta = artifact.metadata;
  return (
    <div className="flex h-full flex-col overflow-y-auto p-5">
      <div className="flex flex-wrap items-start gap-2">
        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${confidenceBadge(artifact.confidence)}`}>
          {artifact.confidence} confidence
        </span>
        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${statusBadge(artifact.status)}`}>
          {artifact.status}
        </span>
      </div>
      <h2 className="mt-4 text-base font-semibold leading-snug text-white">{artifact.title}</h2>
      <p className="mt-2 text-sm leading-6 text-slate-400">{artifact.summary}</p>
      {artifact.event_time && (
        <p className="mt-3 font-mono text-[11px] text-cyan-300">
          {new Date(artifact.event_time).toLocaleString()}
        </p>
      )}
      <div className="mt-4">
        <PromoteToKeyEvidence
          caseId={caseId}
          targetType="source_artifact"
          targetId={artifact.id}
        />
      </div>
      <dl className="mt-5 space-y-3 border-t border-white/8 pt-4">
        <MetaRow label="Parser" value={`${artifact.parser_id} v${artifact.parser_version}`} />
        <MetaRow label="Source locator" value={artifact.source_locator} />
        <MetaRow label="Artifact hash" value={artifact.artifact_hash} />
        {Object.entries(meta)
          .filter(([k]) => !["application"].includes(k))
          .slice(0, 20)
          .map(([k, v]) => (
            <MetaRow
              key={k}
              label={k.replaceAll("_", " ")}
              value={
                typeof v === "object" ? JSON.stringify(v) : (v as string | number | boolean | null)
              }
            />
          ))}
      </dl>
    </div>
  );
}

function useAllArtifacts(caseId: string) {
  const sourcesQuery = useQuery({
    queryKey: twinKeys.sources(caseId),
    queryFn: () => listEvidenceSources(caseId),
    enabled: Boolean(caseId),
  });

  const sealedSources = useMemo(
    () => (sourcesQuery.data ?? []).filter((s) => s.status === "sealed"),
    [sourcesQuery.data],
  );

  const artifactQueries = useQuery({
    queryKey: ["artifact-browser", caseId, sealedSources.map((s) => s.id).join(",")],
    queryFn: async () => {
      const results = await Promise.all(
        sealedSources.map((s) => listEvidenceSourceArtifacts(caseId, s.id)),
      );
      return results.flat();
    },
    enabled: sealedSources.length > 0,
  });

  return {
    artifacts: artifactQueries.data ?? [],
    isPending: sourcesQuery.isPending || (sealedSources.length > 0 && artifactQueries.isPending),
    isError: sourcesQuery.isError || artifactQueries.isError,
    error: sourcesQuery.error ?? artifactQueries.error,
  };
}

export function ArtifactBrowserPage() {
  const { caseId = "" } = useParams();
  const [activeCategoryId, setActiveCategoryId] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });

  const { artifacts, isPending, error } = useAllArtifacts(caseId);

  const filtered = useMemo(() => {
    const activeCategory =
      CATEGORIES.find((c) => c.id === activeCategoryId) ??
      CATEGORIES[0] ?? { id: "all", label: "All artifacts", icon: FileText, match: () => true };
    const byCategory = artifacts.filter(activeCategory.match);
    if (!search.trim()) return byCategory;
    const q = search.toLowerCase();
    return byCategory.filter(
      (a) =>
        a.title.toLowerCase().includes(q) ||
        a.summary.toLowerCase().includes(q) ||
        a.subtype.toLowerCase().includes(q),
    );
  }, [artifacts, activeCategoryId, search]);

  const counts = useMemo(
    () =>
      Object.fromEntries(
        CATEGORIES.map((c) => [c.id, c.id === "all" ? artifacts.length : artifacts.filter(c.match).length]),
      ),
    [artifacts],
  );

  const selected = filtered.find((a) => a.id === selectedId) ?? null;

  return (
    <div className="flex h-[calc(100vh-73px)] flex-col">
      <CaseSubnav caseId={caseId} caseNumber={caseQuery.data?.case_number} />
      <div className="border-b border-white/8 px-5 py-4 lg:px-10">
        <Link
          to={`/cases/${caseId}`}
          className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"
        >
          <ArrowLeft size={15} /> Back to case
        </Link>
        <div className="mt-3 flex items-end justify-between gap-4">
          <div>
            <p className="font-mono text-xs text-cyan-300/65">{caseQuery.data?.case_number}</p>
            <h1 className="mt-1 text-2xl font-semibold text-white">
              {activeCategoryId === "apk_analysis" ? "Static APK Analysis" : "Artifact browser"}
            </h1>
          </div>
          {isPending && (
            <p className="flex items-center gap-2 text-sm text-slate-500">
              <LoaderCircle size={15} className="animate-spin" /> Loading artifacts…
            </p>
          )}
        </div>
      </div>

      {error && (
        <div className="p-5">
          <CaseError error={error} />
        </div>
      )}

      <div className="grid min-h-0 flex-1 grid-cols-[200px_1fr] lg:grid-cols-[220px_1fr_380px]">
        {/* Category rail */}
        <aside className="overflow-y-auto border-r border-white/8 py-3">
          {CATEGORIES.map((cat) => {
            const count = counts[cat.id] ?? 0;
            const Icon = cat.icon;
            return (
              <button
                key={cat.id}
                type="button"
                onClick={() => {
                  setActiveCategoryId(cat.id);
                  setSelectedId(null);
                }}
                className={`flex w-full items-center gap-2.5 px-4 py-2 text-left text-sm transition ${
                  activeCategoryId === cat.id
                    ? "bg-cyan-300/8 text-cyan-200"
                    : "text-slate-400 hover:bg-white/4 hover:text-slate-200"
                }`}
              >
                <Icon size={14} className="shrink-0" aria-hidden />
                <span className="flex-1 truncate">{cat.label}</span>
                {count > 0 && (
                  <span className="shrink-0 rounded-full bg-white/8 px-1.5 py-0.5 text-[10px] tabular-nums text-slate-400">
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </aside>

        {activeCategoryId === "apk_analysis" ? (
          <div className="col-span-1 overflow-y-auto p-6 lg:col-span-2">
            <ApkAnalysisPanel caseId={caseId} />
          </div>
        ) : (
          <>
            {/* Artifact list */}
            <div className="flex min-h-0 flex-col overflow-hidden border-r border-white/8">
              <div className="border-b border-white/8 px-4 py-3">
                <input
                  type="search"
                  placeholder="Search artifacts…"
                  value={search}
                  onChange={(e) => { setSearch(e.target.value); }}
                  className="w-full rounded-lg border border-white/10 bg-white/4 px-3 py-2 text-sm text-white placeholder:text-slate-600 focus:border-cyan-300/30 focus:outline-none"
                />
              </div>
              <ol className="flex-1 overflow-y-auto divide-y divide-white/5">
                {filtered.length === 0 && !isPending && (
                  <li className="px-4 py-8 text-center text-sm text-slate-600">
                    No artifacts in this category.
                  </li>
                )}
                {filtered.map((artifact) => (
                  <li key={artifact.id}>
                    <button
                      type="button"
                      onClick={() => { setSelectedId(artifact.id === selectedId ? null : artifact.id); }}
                      className={`w-full px-4 py-3 text-left transition ${
                        selectedId === artifact.id
                          ? "bg-cyan-300/8"
                          : "hover:bg-white/4"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-sm font-medium leading-snug text-white line-clamp-1">
                          {artifact.title}
                        </p>
                        {artifact.status === "deleted" && (
                          <span className="shrink-0 rounded border border-rose-300/20 px-1.5 py-0.5 text-[9px] uppercase text-rose-300">
                            deleted
                          </span>
                        )}
                      </div>
                      <p className="mt-1 text-xs text-slate-500 line-clamp-2">{artifact.summary}</p>
                      {artifact.event_time && (
                        <p className="mt-1.5 font-mono text-[10px] text-cyan-300/60">
                          {new Date(artifact.event_time).toLocaleString()}
                        </p>
                      )}
                    </button>
                  </li>
                ))}
              </ol>
              <div className="border-t border-white/8 px-4 py-2 text-[11px] text-slate-600">
                {filtered.length} artifact{filtered.length !== 1 ? "s" : ""}
              </div>
            </div>

            {/* Detail panel — hidden on small screens */}
            <div className="hidden overflow-hidden lg:block">
              {selected ? (
                <DetailPanel artifact={selected} caseId={caseId} />
              ) : (
                <div className="flex h-full items-center justify-center text-sm text-slate-600">
                  Select an artifact to inspect
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

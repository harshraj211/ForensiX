import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BookOpenText,
  Check,
  CircleDot,
  Clock3,
  Database,
  Flag,
  Fingerprint,
  GitFork,
  HardDrive,
  LoaderCircle,
  MapPin,
  PanelsTopLeft,
  Radar,
  Search,
  ShieldCheck,
  Smartphone,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import {
  getCase,
  getCommandCenter,
  type CommandCenterNextAction,
  type CommandCenterSummary,
} from "../../lib/api";
import { CaseError, StatusBadge } from "./CasesPage";
import { caseKeys } from "./caseKeys";
import { CaseSubnav } from "../../components/CaseSubnav";

const NEXT_ACTIONS: Record<
  CommandCenterNextAction,
  { eyebrow: string; title: string; detail: string; route: (caseId: string) => string }
> = {
  detect_device: {
    eyebrow: "Start collection",
    title: "Detect and assess an Android device",
    detail: "Create a case-bound readiness snapshot before selecting an acquisition scope.",
    route: (caseId) => `/cases/${caseId}/devices`,
  },
  create_acquisition_plan: {
    eyebrow: "Collection ready",
    title: "Freeze an acquisition plan",
    detail: "Select a supported scope and bind it to the latest device assessment.",
    route: (caseId) => `/cases/${caseId}/acquisitions`,
  },
  monitor_acquisition: {
    eyebrow: "Operation in progress",
    title: "Monitor the active acquisition",
    detail: "Review durable checkpoints, current module, and interruption recovery options.",
    route: (caseId) => `/cases/${caseId}/acquisitions`,
  },
  acquire_evidence: {
    eyebrow: "Plan prepared",
    title: "Collect approved evidence",
    detail: "Continue from the frozen plan and preserve the acquisition ledger.",
    route: (caseId) => `/cases/${caseId}/acquisitions`,
  },
  index_evidence: {
    eyebrow: "Evidence available",
    title: "Normalize and index evidence",
    detail: "Run compatible parsers so investigators can search, correlate, and build a timeline.",
    route: (caseId) => `/cases/${caseId}/evidence-twin`,
  },
  review_evidence: {
    eyebrow: "Analysis ready",
    title: "Review and mark key evidence",
    detail: "Open the artifact browser, validate provenance, and bookmark important findings.",
    route: (caseId) => `/cases/${caseId}/artifacts`,
  },
  generate_report: {
    eyebrow: "Findings prepared",
    title: "Generate a preliminary report",
    detail: "Freeze a reproducible report snapshot with hashes, limitations, and custody history.",
    route: (caseId) => `/cases/${caseId}/reports`,
  },
  review_report: {
    eyebrow: "Supervisor checkpoint",
    title: "Review the preliminary report",
    detail: "Record an approval or rejection decision in the append-only review chain.",
    route: (caseId) => `/cases/${caseId}/reports`,
  },
  continue_analysis: {
    eyebrow: "Investigation active",
    title: "Continue cross-evidence analysis",
    detail: "Search all parsed artifacts and pivot into timeline, map, and relationship views.",
    route: (caseId) => `/cases/${caseId}/artifact-search`,
  },
};

const ACTIVITY_ICONS: Record<CommandCenterSummary["recent_activity"][number]["kind"], LucideIcon> = {
  case: CircleDot,
  acquisition: Activity,
  custody: Fingerprint,
  evidence: Database,
  report: BookOpenText,
};

export function CommandCenterPage() {
  const { caseId = "" } = useParams();
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const summaryQuery = useQuery({
    queryKey: caseKeys.commandCenter(caseId),
    queryFn: () => getCommandCenter(caseId),
    enabled: Boolean(caseId),
    refetchInterval: 15_000,
  });

  if (caseQuery.isPending || summaryQuery.isPending) {
    return (
      <div className="grid min-h-[55vh] place-items-center" role="status">
        <div className="text-center">
          <LoaderCircle className="mx-auto animate-spin text-cyan-300" aria-hidden="true" />
          <p className="mt-3 text-sm text-slate-500">Building the investigation picture…</p>
        </div>
      </div>
    );
  }
  if (caseQuery.isError) return <CaseError error={caseQuery.error} />;
  if (summaryQuery.isError) return <CaseError error={summaryQuery.error} />;

  const caseRecord = caseQuery.data;
  const summary = summaryQuery.data;
  const nextAction = NEXT_ACTIONS[summary.next_action];
  const stages = investigationStages(summary);
  const completedStages = stages.filter((stage) => stage.complete).length;

  return (
    <div className="mx-auto max-w-[1240px]">
      <CaseSubnav caseId={caseId} caseNumber={caseRecord.case_number} />
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Link
          to={`/cases/${caseId}`}
          className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"
        >
          <ArrowLeft size={15} aria-hidden="true" /> Back to case
        </Link>
        <p className="font-mono text-[11px] text-slate-600">
          Snapshot {new Date(summary.generated_at).toLocaleTimeString()}
        </p>
      </div>

      <header className="mt-7 overflow-hidden rounded-3xl border border-cyan-300/12 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.12),transparent_35%),linear-gradient(135deg,rgba(15,31,40,0.95),rgba(7,16,22,0.98))] p-6 shadow-[0_28px_90px_rgba(0,0,0,0.24)] sm:p-8">
        <div className="flex flex-col justify-between gap-6 lg:flex-row lg:items-end">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">
                Investigation Command Center
              </p>
              <StatusBadge status={caseRecord.status} />
            </div>
            <h1 className="mt-4 text-3xl font-semibold tracking-tight text-white sm:text-4xl">
              {caseRecord.title}
            </h1>
            <p className="mt-2 font-mono text-xs text-cyan-200/55">{caseRecord.case_number}</p>
          </div>
          <div className="min-w-[230px]">
            <div className="flex items-end justify-between">
              <span className="text-sm text-slate-400">Investigation readiness</span>
              <span className="text-2xl font-semibold text-white">
                {Math.round((completedStages / stages.length) * 100)}%
              </span>
            </div>
            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/7">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-emerald-300"
                style={{ width: String((completedStages / stages.length) * 100) + "%" }}
              />
            </div>
          </div>
        </div>
      </header>

      <section aria-label="Investigation metrics" className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          icon={Database}
          label="Searchable evidence"
          value={formatNumber(summary.evidence.total_artifacts)}
          detail={`${formatNumber(summary.evidence.bookmarked_artifacts)} marked as key evidence`}
          tone="cyan"
        />
        <MetricCard
          icon={HardDrive}
          label="Evidence footprint"
          value={formatBytes(summary.evidence.total_size_bytes)}
          detail={`${formatNumber(summary.evidence.acquired_files)} files / ${formatNumber(
            summary.evidence.sealed_sources,
          )} sealed sources`}
          tone="blue"
        />
        <MetricCard
          icon={Smartphone}
          label="Case devices"
          value={formatNumber(summary.device_count)}
          detail={`${formatNumber(summary.jobs.completed)} completed / ${formatNumber(
            summary.jobs.active,
          )} active jobs`}
          tone="violet"
        />
        <MetricCard
          icon={summary.integrity.verification_exceptions ? AlertTriangle : ShieldCheck}
          label="Integrity posture"
          value={summary.integrity.verification_exceptions ? "Review" : "Verified"}
          detail={`${formatNumber(summary.integrity.verified_observations)} observations / custody ${
            summary.integrity.custody_chain_valid ? "valid" : "invalid"
          }`}
          tone={summary.integrity.verification_exceptions ? "amber" : "emerald"}
        />
      </section>

      <section className="mt-5 grid gap-5 xl:grid-cols-[1.35fr_0.65fr]">
        <div className="rounded-2xl border border-cyan-300/15 bg-cyan-300/[0.035] p-6">
          <div className="flex items-start gap-4">
            <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-cyan-300 text-slate-950">
              <Radar size={21} aria-hidden="true" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-cyan-300">
                {nextAction.eyebrow}
              </p>
              <h2 className="mt-2 text-xl font-semibold text-white">{nextAction.title}</h2>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">{nextAction.detail}</p>
              <Link
                to={nextAction.route(caseId)}
                className="mt-5 inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-300 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200"
              >
                Continue investigation <ArrowRight size={16} aria-hidden="true" />
              </Link>
            </div>
          </div>
        </div>
        <IntegrityPanel summary={summary} />
      </section>

      <section className="mt-5 grid gap-5 xl:grid-cols-[0.8fr_1.2fr]">
        <InvestigationStages stages={stages} />
        <EvidenceComposition facets={summary.evidence.category_facets} />
      </section>

      <section className="mt-5 grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
        <RecentActivity items={summary.recent_activity} />
        <AttentionPanel summary={summary} />
      </section>

      <section className="mt-5 rounded-2xl border border-white/8 bg-white/[0.025] p-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
              Analyst workspaces
            </p>
            <h2 className="mt-2 text-xl font-semibold text-white">Pivot without losing context</h2>
          </div>
          <p className="text-xs text-slate-600">
            {formatNumber(summary.timeline_event_count)} timeline events · {summary.report_count} reports
          </p>
        </div>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <WorkspaceLink icon={Search} label="Global artifact search" to={`/cases/${caseId}/artifact-search`} />
          <WorkspaceLink icon={Flag} label="Key Evidence" to={`/cases/${caseId}/key-evidence`} />
          <WorkspaceLink icon={PanelsTopLeft} label="Investigation Storyboard" to={`/cases/${caseId}/storyboard`} />
          <WorkspaceLink icon={Clock3} label="Evidence timeline" to={`/cases/${caseId}/timeline`} />
          <WorkspaceLink icon={GitFork} label="Relationship graph" to={`/cases/${caseId}/correlations`} />
          <WorkspaceLink icon={MapPin} label="Offline media map" to={`/cases/${caseId}/media-map`} />
          <WorkspaceLink icon={BookOpenText} label="Reports and review" to={`/cases/${caseId}/reports`} />
        </div>
      </section>
    </div>
  );
}

type Tone = "cyan" | "blue" | "violet" | "emerald" | "amber";

function MetricCard({
  icon: Icon,
  label,
  value,
  detail,
  tone,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  detail: string;
  tone: Tone;
}) {
  const tones: Record<Tone, string> = {
    cyan: "border-cyan-300/12 bg-cyan-300/[0.035] text-cyan-300",
    blue: "border-blue-300/12 bg-blue-300/[0.035] text-blue-300",
    violet: "border-violet-300/12 bg-violet-300/[0.035] text-violet-300",
    emerald: "border-emerald-300/12 bg-emerald-300/[0.035] text-emerald-300",
    amber: "border-amber-300/12 bg-amber-300/[0.035] text-amber-300",
  };
  return (
    <article className={`rounded-2xl border p-5 ${tones[tone]}`}>
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-slate-500">{label}</p>
        <Icon size={18} aria-hidden="true" />
      </div>
      <p className="mt-4 text-2xl font-semibold tracking-tight text-white">{value}</p>
      <p className="mt-2 text-xs leading-5 text-slate-600">{detail}</p>
    </article>
  );
}

function IntegrityPanel({ summary }: { summary: CommandCenterSummary }) {
  const healthy =
    summary.integrity.custody_chain_valid && summary.integrity.verification_exceptions === 0;
  return (
    <div className="rounded-2xl border border-white/8 bg-white/[0.025] p-5">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.17em] text-slate-500">
            Evidence integrity
          </p>
          <p className="mt-2 font-semibold text-white">{healthy ? "All checks clear" : "Review required"}</p>
        </div>
        <div
          className={`grid size-10 place-items-center rounded-full ${
            healthy ? "bg-emerald-300/10 text-emerald-300" : "bg-rose-300/10 text-rose-300"
          }`}
        >
          {healthy ? <Check size={19} aria-hidden="true" /> : <AlertTriangle size={19} aria-hidden="true" />}
        </div>
      </div>
      <dl className="mt-5 grid grid-cols-2 gap-3 text-xs">
        <MiniStat label="Custody events" value={summary.integrity.custody_event_count} />
        <MiniStat label="Verified hashes" value={summary.integrity.verified_observations} />
      </dl>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-xl border border-white/7 bg-black/10 p-3">
      <dt className="text-slate-600">{label}</dt>
      <dd className="mt-1 text-lg font-semibold text-slate-200">{formatNumber(value)}</dd>
    </div>
  );
}

function InvestigationStages({ stages }: { stages: ReturnType<typeof investigationStages> }) {
  return (
    <section className="rounded-2xl border border-white/8 bg-white/[0.025] p-6">
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
        Investigation path
      </p>
      <h2 className="mt-2 text-xl font-semibold text-white">From device to defensible finding</h2>
      <ol className="mt-6 space-y-1">
        {stages.map((stage, index) => (
          <li key={stage.label} className="relative flex gap-4 pb-5 last:pb-0">
            {index < stages.length - 1 && (
              <span className="absolute left-[13px] top-7 h-full w-px bg-white/8" aria-hidden="true" />
            )}
            <span
              className={`relative z-10 grid size-7 shrink-0 place-items-center rounded-full border text-xs ${
                stage.complete
                  ? "border-emerald-300/30 bg-emerald-300/10 text-emerald-300"
                  : "border-white/10 bg-[#09151d] text-slate-600"
              }`}
            >
              {stage.complete ? <Check size={14} aria-hidden="true" /> : index + 1}
            </span>
            <div>
              <p className={`text-sm font-medium ${stage.complete ? "text-slate-200" : "text-slate-500"}`}>
                {stage.label}
              </p>
              <p className="mt-1 text-xs text-slate-600">{stage.detail}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function EvidenceComposition({ facets }: { facets: Record<string, number> }) {
  const entries = Object.entries(facets).slice(0, 7);
  const maximum = Math.max(...entries.map(([, value]) => value), 1);
  return (
    <section className="rounded-2xl border border-white/8 bg-white/[0.025] p-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
            Evidence composition
          </p>
          <h2 className="mt-2 text-xl font-semibold text-white">What the case actually contains</h2>
        </div>
        <Database size={20} className="text-slate-600" aria-hidden="true" />
      </div>
      {entries.length ? (
        <div className="mt-7 space-y-4">
          {entries.map(([category, value]) => (
            <div key={category}>
              <div className="flex items-center justify-between text-xs">
                <span className="capitalize text-slate-400">{category}</span>
                <span className="font-mono text-slate-600">{formatNumber(value)}</span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/6">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-cyan-400/75 to-blue-400/75"
                  style={{ width: String(Math.max((value / maximum) * 100, 3)) + "%" }}
                />
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="mt-7 rounded-xl border border-dashed border-white/10 p-8 text-center">
          <Database className="mx-auto text-slate-700" size={25} aria-hidden="true" />
          <p className="mt-3 text-sm text-slate-500">No normalized categories yet.</p>
          <p className="mt-1 text-xs text-slate-700">Parsed evidence will appear here automatically.</p>
        </div>
      )}
    </section>
  );
}

function RecentActivity({ items }: { items: CommandCenterSummary["recent_activity"] }) {
  return (
    <section className="rounded-2xl border border-white/8 bg-white/[0.025] p-6">
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
        Recent activity
      </p>
      <h2 className="mt-2 text-xl font-semibold text-white">Investigation pulse</h2>
      {items.length ? (
        <ol className="mt-6 divide-y divide-white/7">
          {items.map((item, index) => {
            const Icon = ACTIVITY_ICONS[item.kind];
            return (
              <li
                key={`${item.occurred_at}-${item.title}-${String(index)}`}
                className="flex gap-4 py-4 first:pt-0"
              >
                <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-white/4 text-slate-500">
                  <Icon size={16} aria-hidden="true" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap justify-between gap-2">
                    <p className="text-sm font-medium text-slate-200">{item.title}</p>
                    <time className="text-[11px] text-slate-700">
                      {formatRelativeTime(item.occurred_at)}
                    </time>
                  </div>
                  <p className="mt-1 truncate text-xs text-slate-600" title={item.detail}>
                    {item.detail}
                  </p>
                </div>
              </li>
            );
          })}
        </ol>
      ) : (
        <p className="mt-6 text-sm text-slate-600">No case activity has been recorded.</p>
      )}
    </section>
  );
}

function AttentionPanel({ summary }: { summary: CommandCenterSummary }) {
  return (
    <section className="rounded-2xl border border-white/8 bg-white/[0.025] p-6">
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
        Examiner attention
      </p>
      <h2 className="mt-2 text-xl font-semibold text-white">
        {summary.attention.length
          ? `${formatNumber(summary.attention.length)} items to review`
          : "No unresolved signals"}
      </h2>
      <div className="mt-6 space-y-3">
        {summary.attention.length ? (
          summary.attention.map((item) => {
            const tone =
              item.severity === "critical"
                ? "border-rose-300/15 bg-rose-300/[0.035] text-rose-300"
                : item.severity === "warning"
                  ? "border-amber-300/15 bg-amber-300/[0.035] text-amber-300"
                  : "border-blue-300/15 bg-blue-300/[0.035] text-blue-300";
            return (
              <article key={item.code} className={`rounded-xl border p-4 ${tone}`}>
                <div className="flex gap-3">
                  <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
                  <div>
                    <p className="text-sm font-medium text-slate-200">{item.title}</p>
                    <p className="mt-1 text-xs leading-5 text-slate-600">{item.detail}</p>
                  </div>
                </div>
              </article>
            );
          })
        ) : (
          <div className="rounded-xl border border-emerald-300/12 bg-emerald-300/[0.035] p-5 text-center">
            <ShieldCheck className="mx-auto text-emerald-300" size={23} aria-hidden="true" />
            <p className="mt-3 text-sm font-medium text-slate-200">Integrity and workflow checks are clear.</p>
          </div>
        )}
      </div>
    </section>
  );
}

function WorkspaceLink({ icon: Icon, label, to }: { icon: LucideIcon; label: string; to: string }) {
  return (
    <Link
      to={to}
      className="group flex min-h-12 items-center gap-3 rounded-xl border border-white/8 bg-black/10 px-4 text-sm text-slate-400 transition hover:border-cyan-300/15 hover:bg-cyan-300/[0.035] hover:text-cyan-100"
    >
      <Icon size={17} className="text-slate-600 transition group-hover:text-cyan-300" aria-hidden="true" />
      <span>{label}</span>
      <ArrowRight size={14} className="ml-auto text-slate-700" aria-hidden="true" />
    </Link>
  );
}

function investigationStages(summary: CommandCenterSummary) {
  const evidenceAvailable = summary.evidence.acquired_files > 0 || summary.evidence.sealed_sources > 0;
  return [
    {
      label: "Device or source registered",
      detail: `${formatNumber(summary.device_count)} case device(s), ${formatNumber(
        summary.evidence.sealed_sources,
      )} sealed source(s)`,
      complete: summary.device_count > 0 || summary.evidence.sealed_sources > 0,
    },
    {
      label: "Evidence collected and sealed",
      detail: `${formatNumber(summary.evidence.acquired_files)} acquired file(s) retained`,
      complete: evidenceAvailable,
    },
    {
      label: "Artifacts normalized",
      detail: `${formatNumber(summary.evidence.total_artifacts)} searchable artifact(s)`,
      complete: summary.evidence.total_artifacts > 0,
    },
    {
      label: "Key evidence identified",
      detail: `${formatNumber(summary.evidence.bookmarked_artifacts)} bookmark(s) recorded`,
      complete: summary.evidence.bookmarked_artifacts > 0,
    },
    {
      label: "Report prepared",
      detail: `${formatNumber(summary.report_count)} preliminary report(s)`,
      complete: summary.report_count > 0,
    },
  ];
}

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(value);
}

function formatBytes(value: number) {
  if (value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const unit = units[index] ?? "B";
  return `${(value / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${unit}`;
}

function formatRelativeTime(value: string) {
  const difference = Date.now() - new Date(value).getTime();
  const minutes = Math.max(0, Math.floor(difference / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${String(minutes)}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${String(hours)}h ago`;
  const days = Math.floor(hours / 24);
  return `${String(days)}d ago`;
}

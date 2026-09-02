import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  BookOpenText,
  Check,
  Clock3,
  Copy,
  Flag,
  GitFork,
  Hash,
  LoaderCircle,
  Printer,
  ShieldAlert,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import {
  getCase,
  getInvestigationStoryboard,
  type InvestigationStoryboard,
  type StoryboardFinding,
  type StoryboardGap,
} from "../../lib/api";
import { CaseSubnav } from "../../components/CaseSubnav";
import { AiNarrativePanel } from "./AiNarrativePanel";
import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";

export function InvestigationStoryboardPage() {
  const { caseId = "" } = useParams();
  const [copied, setCopied] = useState(false);
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const storyboardQuery = useQuery({
    queryKey: caseKeys.storyboard(caseId),
    queryFn: () => getInvestigationStoryboard(caseId),
    enabled: Boolean(caseId),
  });

  if (caseQuery.isPending || storyboardQuery.isPending) {
    return (
      <div role="status" className="grid min-h-[60vh] place-items-center">
        <div className="text-center">
          <LoaderCircle className="mx-auto animate-spin text-cyan-300" aria-hidden="true" />
          <p className="mt-3 text-sm text-slate-500">Assembling evidence-backed storyboard...</p>
        </div>
      </div>
    );
  }
  if (caseQuery.isError) return <CaseError error={caseQuery.error} />;
  if (storyboardQuery.isError) return <CaseError error={storyboardQuery.error} />;

  const storyboard = storyboardQuery.data;
  const findings = new Map(storyboard.findings.map((item) => [item.id, item]));
  const copyNarrative = async () => {
    await navigator.clipboard.writeText(
      narrativeText(caseQuery.data.case_number, caseQuery.data.title, storyboard),
    );
    setCopied(true);
    window.setTimeout(() => {
      setCopied(false);
    }, 1800);
  };

  return (
    <div className="mx-auto max-w-[1380px] print:max-w-none">
      <CaseSubnav caseId={caseId} caseNumber={caseQuery.data.case_number} />
      <Link
        to={`/cases/${caseId}/command-center`}
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200 print:hidden"
      >
        <ArrowLeft size={15} aria-hidden="true" /> Back to Command Center
      </Link>

      <header className="mt-6 flex flex-col justify-between gap-5 border-b border-white/8 pb-7 lg:flex-row lg:items-end">
        <div>
          <p className="font-mono text-xs text-cyan-300/65">{caseQuery.data.case_number}</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">
            Investigation Storyboard
          </h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
            A deterministic review surface built from examiner-curated findings, explicit
            timestamps, and normalized relationships. It does not generate investigative
            conclusions.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 print:hidden">
          <button
            type="button"
            onClick={() => {
              void copyNarrative();
            }}
            className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-white/10 px-4 text-sm text-slate-300 hover:border-cyan-300/20 hover:text-cyan-100"
          >
            {copied ? <Check size={16} /> : <Copy size={16} />}
            {copied ? "Copied" : "Copy narrative"}
          </button>
          <button
            type="button"
            onClick={() => {
              window.print();
            }}
            className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-300 px-4 text-sm font-semibold text-slate-950"
          >
            <Printer size={16} /> Print review
          </button>
        </div>
      </header>

      <section aria-label="Storyboard metrics" className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          icon={Flag}
          label="Key findings"
          value={storyboard.metrics.key_findings}
          detail={`${String(storyboard.metrics.critical_findings)} critical · ${String(storyboard.metrics.high_findings)} high`}
          tone="cyan"
        />
        <Metric
          icon={Clock3}
          label="Linked moments"
          value={storyboard.metrics.linked_moments}
          detail={`${String(storyboard.metrics.timeline_claims)} total timestamp claims`}
          tone="blue"
        />
        <Metric
          icon={GitFork}
          label="Relationship leads"
          value={storyboard.metrics.relationship_leads}
          detail="Explicit normalized identifiers only"
          tone="violet"
        />
        <Metric
          icon={ShieldAlert}
          label="Review gaps"
          value={storyboard.gaps.length}
          detail="Items to address or disclose"
          tone="amber"
        />
      </section>

      <section className="mt-5 rounded-2xl border border-cyan-300/12 bg-cyan-300/[0.035] p-6">
        <div className="flex gap-4">
          <BookOpenText className="mt-1 shrink-0 text-cyan-300" size={20} aria-hidden="true" />
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
              Evidence-backed overview
            </p>
            <p className="mt-3 max-w-5xl text-base leading-7 text-slate-200">
              {storyboard.overview}
            </p>
          </div>
        </div>
      </section>

      <AiNarrativePanel caseId={caseId} />

      <section className="mt-5 grid gap-5 xl:grid-cols-[1.05fr_0.95fr]">
        <div className="rounded-2xl border border-white/8 bg-white/[0.025] p-5 sm:p-6">
          <SectionHeader
            eyebrow="Narrative structure"
            title="Evidence chapters"
            detail="Grouped from examiner-selected findings"
          />
          {storyboard.sections.length ? (
            <div className="mt-5 space-y-4">
              {storyboard.sections.map((section) => (
                <article key={section.id} className="rounded-xl border border-white/8 bg-black/10 p-5">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h2 className="text-base font-semibold text-white">{section.title}</h2>
                      <p className="mt-1 text-xs leading-5 text-slate-600">{section.summary}</p>
                    </div>
                    {section.latest_event_time && (
                      <time className="font-mono text-[10px] text-slate-600">
                        Latest {new Date(section.latest_event_time).toLocaleString()}
                      </time>
                    )}
                  </div>
                  <div className="mt-4 space-y-3">
                    {section.finding_ids.map((findingId) => {
                      const finding = findings.get(findingId);
                      return finding ? <FindingCard key={finding.id} finding={finding} /> : null;
                    })}
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <Empty
              icon={Flag}
              title="No narrative chapters yet"
              detail="Select Key Evidence to create evidence-backed chapters."
              to={`/cases/${caseId}/key-evidence`}
              action="Open Key Evidence"
            />
          )}
        </div>

        <div className="rounded-2xl border border-white/8 bg-white/[0.025] p-5 sm:p-6">
          <SectionHeader
            eyebrow="Chronology"
            title="Pivotal moments"
            detail="Direct links first, high-confidence context second"
          />
          {storyboard.moments.length ? (
            <ol className="relative mt-6 space-y-0 border-l border-white/10 pl-5">
              {storyboard.moments.map((moment) => (
                <li key={moment.id} className="relative pb-6">
                  <span
                    className={`absolute -left-[25px] top-1 h-2.5 w-2.5 rounded-full border-2 border-[#08131a] ${
                      moment.key_evidence_linked ? "bg-cyan-300" : "bg-slate-600"
                    }`}
                  />
                  <div className="flex flex-wrap items-center gap-2">
                    <time className="font-mono text-[10px] text-cyan-200">
                      {new Date(moment.event_time).toLocaleString()}
                    </time>
                    {moment.key_evidence_linked && (
                      <span className="rounded-full bg-cyan-300/8 px-2 py-0.5 text-[9px] uppercase tracking-wider text-cyan-200">
                        Key evidence
                      </span>
                    )}
                  </div>
                  <p className="mt-2 text-sm leading-6 text-slate-300">{moment.summary}</p>
                  <p className="mt-1 text-[10px] text-slate-700">
                    {moment.timestamp_type.replaceAll("_", " ")} · {moment.confidence} confidence
                  </p>
                </li>
              ))}
            </ol>
          ) : (
            <Empty
              icon={Clock3}
              title="No chronology available"
              detail="Only explicit parser and acquisition timestamp claims can appear here."
              to={`/cases/${caseId}/timeline`}
              action="Open timeline"
            />
          )}
        </div>
      </section>

      <section className="mt-5 grid gap-5 xl:grid-cols-2">
        <div className="rounded-2xl border border-white/8 bg-white/[0.025] p-5 sm:p-6">
          <SectionHeader
            eyebrow="Explicit identifiers"
            title="Relationship leads"
            detail="Leads are not identity conclusions"
          />
          {storyboard.leads.length ? (
            <div className="mt-5 grid gap-3 sm:grid-cols-2">
              {storyboard.leads.map((lead) => (
                <article key={lead.id} className="rounded-xl border border-white/8 bg-black/10 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <span className="rounded-full border border-violet-300/15 bg-violet-300/5 px-2 py-1 text-[9px] uppercase tracking-wider text-violet-200">
                      {lead.entity_type}
                    </span>
                    <span className="text-[10px] text-slate-700">
                      {String(lead.evidence_count)} link(s)
                    </span>
                  </div>
                  <h2 className="mt-3 break-words text-sm font-semibold text-slate-100">
                    {lead.label}
                  </h2>
                  <p className="mt-2 text-[10px] text-slate-600">
                    {lead.confidence} confidence · {String(lead.finding_ids.length)} finding(s)
                  </p>
                </article>
              ))}
            </div>
          ) : (
            <Empty
              icon={GitFork}
              title="No explicit relationship leads"
              detail="Shared identifiers will appear only when parsers record them explicitly."
              to={`/cases/${caseId}/correlations`}
              action="Open relationship graph"
            />
          )}
        </div>

        <div className="rounded-2xl border border-white/8 bg-white/[0.025] p-5 sm:p-6">
          <SectionHeader
            eyebrow="Disclosure checklist"
            title="Investigation gaps"
            detail="Resolve these or state them in the report"
          />
          {storyboard.gaps.length ? (
            <div className="mt-5 space-y-3">
              {storyboard.gaps.map((gap) => (
                <GapCard key={gap.code} gap={gap} />
              ))}
            </div>
          ) : (
            <div className="mt-5 rounded-xl border border-emerald-300/12 bg-emerald-300/[0.035] p-5">
              <div className="flex gap-3">
                <Check className="mt-0.5 shrink-0 text-emerald-300" size={17} />
                <div>
                  <h2 className="text-sm font-semibold text-emerald-100">
                    No automated gaps detected
                  </h2>
                  <p className="mt-1 text-xs leading-5 text-emerald-100/55">
                    Examiner review is still required before report approval.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      <section className="mt-5 rounded-2xl border border-amber-300/12 bg-amber-300/[0.025] p-6">
        <div className="flex gap-4">
          <AlertTriangle className="mt-1 shrink-0 text-amber-300" size={19} />
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-amber-100">Required interpretation limits</h2>
            <ul className="mt-3 space-y-2">
              {storyboard.limitations.map((limitation) => (
                <li key={limitation} className="text-xs leading-5 text-amber-100/65">
                  • {limitation}
                </li>
              ))}
            </ul>
            <div className="mt-5 border-t border-amber-300/10 pt-4">
              <div className="flex items-start gap-2">
                <Hash size={14} className="mt-0.5 shrink-0 text-amber-200/45" />
                <p className="break-all font-mono text-[10px] leading-5 text-amber-100/40">
                  Storyboard SHA-256 {storyboard.snapshot_hash} · builder v
                  {storyboard.builder_version}
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function FindingCard({ finding }: { finding: StoryboardFinding }) {
  const tones = {
    critical: "border-rose-300/20 bg-rose-300/7 text-rose-200",
    high: "border-amber-300/20 bg-amber-300/7 text-amber-200",
    normal: "border-cyan-300/15 bg-cyan-300/5 text-cyan-200",
  };
  return (
    <div className="rounded-lg border border-white/7 bg-white/[0.018] p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded-full border px-2 py-0.5 text-[9px] uppercase tracking-wider ${tones[finding.priority]}`}>
          {finding.priority}
        </span>
        <span className="text-[10px] text-slate-700">{finding.subtype.replaceAll("_", " ")}</span>
        <span className="ml-auto text-[10px] text-slate-700">
          {String(finding.timeline_event_ids.length)} moment(s) · {String(finding.related_entities.length)} lead(s)
        </span>
      </div>
      <h3 className="mt-3 text-sm font-semibold text-slate-100">{finding.title}</h3>
      <p className="mt-2 text-xs leading-5 text-slate-500">
        {finding.rationale || finding.summary}
      </p>
      {finding.related_entities.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {finding.related_entities.slice(0, 4).map((entity) => (
            <span key={entity} className="rounded bg-violet-300/6 px-2 py-1 text-[9px] text-violet-200/75">
              {entity}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function GapCard({ gap }: { gap: StoryboardGap }) {
  const tone = {
    critical: "border-rose-300/14 bg-rose-300/[0.035]",
    warning: "border-amber-300/14 bg-amber-300/[0.035]",
    info: "border-blue-300/14 bg-blue-300/[0.035]",
  }[gap.severity];
  return (
    <article className={`rounded-xl border p-4 ${tone}`}>
      <div className="flex items-start gap-3">
        <ShieldAlert size={16} className="mt-0.5 shrink-0 text-slate-400" />
        <div>
          <h2 className="text-sm font-semibold text-slate-200">{gap.title}</h2>
          <p className="mt-1 text-xs leading-5 text-slate-500">{gap.detail}</p>
          <Link to={gap.action_path} className="mt-3 inline-flex text-[11px] font-semibold text-cyan-200 hover:underline">
            Review source workspace
          </Link>
        </div>
      </div>
    </article>
  );
}

function SectionHeader({
  eyebrow,
  title,
  detail,
}: {
  eyebrow: string;
  title: string;
  detail: string;
}) {
  return (
    <div className="flex items-end justify-between gap-4 border-b border-white/8 pb-4">
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-cyan-300/70">
          {eyebrow}
        </p>
        <h2 className="mt-1 text-lg font-semibold text-white">{title}</h2>
      </div>
      <p className="hidden text-right text-[10px] text-slate-700 sm:block">{detail}</p>
    </div>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
  detail,
  tone,
}: {
  icon: LucideIcon;
  label: string;
  value: number;
  detail: string;
  tone: "cyan" | "blue" | "violet" | "amber";
}) {
  const tones = {
    cyan: "text-cyan-300",
    blue: "text-blue-300",
    violet: "text-violet-300",
    amber: "text-amber-300",
  };
  return (
    <article className="rounded-2xl border border-white/8 bg-white/[0.025] p-5">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">{label}</p>
        <Icon size={17} className={tones[tone]} />
      </div>
      <p className="mt-3 text-2xl font-semibold text-white">{value}</p>
      <p className="mt-2 text-[11px] leading-5 text-slate-700">{detail}</p>
    </article>
  );
}

function Empty({
  icon: Icon,
  title,
  detail,
  to,
  action,
}: {
  icon: LucideIcon;
  title: string;
  detail: string;
  to: string;
  action: string;
}) {
  return (
    <div className="mt-5 rounded-xl border border-dashed border-white/10 p-8 text-center">
      <Icon className="mx-auto text-slate-700" size={24} />
      <h2 className="mt-3 text-sm font-semibold text-slate-300">{title}</h2>
      <p className="mx-auto mt-2 max-w-sm text-xs leading-5 text-slate-600">{detail}</p>
      <Link to={to} className="mt-4 inline-flex text-xs font-semibold text-cyan-200 hover:underline">
        {action}
      </Link>
    </div>
  );
}

function narrativeText(
  caseNumber: string,
  caseTitle: string,
  storyboard: InvestigationStoryboard,
): string {
  const lines = [
    `${caseNumber} — ${caseTitle}`,
    "INVESTIGATION STORYBOARD",
    "",
    storyboard.overview,
    "",
  ];
  for (const section of storyboard.sections) {
    lines.push(section.title.toUpperCase(), section.summary);
    for (const findingId of section.finding_ids) {
      const finding = storyboard.findings.find((item) => item.id === findingId);
      if (!finding) continue;
      lines.push(
        `- [${finding.priority.toUpperCase()}] ${finding.title}`,
        `  ${finding.rationale || finding.summary}`,
        `  SHA-256: ${finding.integrity_hash}`,
      );
    }
    lines.push("");
  }
  if (storyboard.moments.length > 0) {
    lines.push("PIVOTAL MOMENTS");
    for (const moment of storyboard.moments) {
      lines.push(`- ${new Date(moment.event_time).toISOString()} — ${moment.summary}`);
    }
    lines.push("");
  }
  if (storyboard.gaps.length > 0) {
    lines.push("INVESTIGATION GAPS");
    for (const gap of storyboard.gaps) lines.push(`- ${gap.title}: ${gap.detail}`);
    lines.push("");
  }
  lines.push(
    "LIMITATIONS",
    ...storyboard.limitations.map((item) => `- ${item}`),
    "",
    `Storyboard SHA-256: ${storyboard.snapshot_hash}`,
  );
  return lines.join("\n");
}

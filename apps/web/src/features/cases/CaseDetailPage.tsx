import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDownToLine, ArrowLeft, BookOpenText, ClipboardList, Clock3, DatabaseBackup, FileCheck2, Flag, GitFork, LayoutDashboard, Link2, LoaderCircle, MapPin, PanelsTopLeft, Plus, Search, ShieldCheck, Smartphone } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import {
  createCustodyCheckpoint,
  createCustodyCheckpointAnchor,
  custodyCheckpointDownloadUrl,
  getCase,
  getCurrentUser,
  listCustodyCheckpointAnchors,
  listCustodyCheckpointSignatures,
  listCustodyCheckpoints,
  listCustodyEvents,
  listCaseDevices,
  transitionCase,
  verifyCustodyChain,
  verifyCustodyCheckpointSignature,
  type CaseDevice,
  type CaseStatus,
  type CustodyCheckpoint,
  type CustodyCheckpointAnchor,
  type CustodyCheckpointSignature,
} from "../../lib/api";
import { authKeys } from "../auth/authKeys";
import { CaseError, StatusBadge } from "./CasesPage";
import { caseKeys } from "./caseKeys";
import { AcquisitionCompletenessPanel } from "./AcquisitionCompletenessPanel";
import { DownloadLink } from "../../components/DownloadLink";

export function CaseDetailPage() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const devicesQuery = useQuery({
    queryKey: caseKeys.devices(caseId),
    queryFn: () => listCaseDevices(caseId),
    enabled: Boolean(caseId),
  });
  const custodyQuery = useQuery({
    queryKey: caseKeys.custody(caseId),
    queryFn: () => listCustodyEvents(caseId),
    enabled: Boolean(caseId),
  });
  const custodyVerificationQuery = useQuery({
    queryKey: caseKeys.custodyVerification(caseId),
    queryFn: () => verifyCustodyChain(caseId),
    enabled: Boolean(caseId),
  });
  const currentUser = useQuery({ queryKey: authKeys.me, queryFn: getCurrentUser });
  const canExportCheckpoint = Boolean(
    currentUser.data?.permissions.includes("custody:review") &&
      currentUser.data.permissions.includes("audit:view"),
  );
  const checkpointsQuery = useQuery({
    queryKey: caseKeys.custodyCheckpoints(caseId),
    queryFn: () => listCustodyCheckpoints(caseId),
    enabled: Boolean(caseId) && canExportCheckpoint,
  });
  const createCheckpoint = useMutation({
    mutationFn: () => createCustodyCheckpoint(caseId),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: caseKeys.custodyCheckpoints(caseId),
      });
    },
  });
  const transition = useMutation({
    mutationFn: (status: CaseStatus) => {
      if (!caseQuery.data) throw new Error("Case state is unavailable.");
      return transitionCase(caseId, caseQuery.data.version, status);
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(caseKeys.detail(caseId), updated);
      void queryClient.invalidateQueries({ queryKey: caseKeys.all });
    },
  });

  if (caseQuery.isPending) {
    return <div role="status"><LoaderCircle className="animate-spin text-cyan-300" aria-hidden="true" /></div>;
  }
  if (caseQuery.isError) return <CaseError error={caseQuery.error} />;
  const item = caseQuery.data;
  const actions: Array<{ label: string; status: CaseStatus }> =
    item.status === "open"
      ? [
          { label: "Mark active", status: "active" },
          { label: "Close case", status: "closed" },
        ]
      : item.status === "active"
        ? [{ label: "Close case", status: "closed" }]
        : item.status === "closed"
          ? [
              { label: "Reopen case", status: "active" },
              { label: "Archive case", status: "archived" },
            ]
          : [];

  return (
    <div className="mx-auto max-w-5xl">
      <Link to="/cases" className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200">
        <ArrowLeft size={15} aria-hidden="true" /> Back to cases
      </Link>
      <div className="mt-6 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:p-8">
        <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-start">
          <div>
            <p className="font-mono text-xs text-cyan-300/70">{item.case_number}</p>
            <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white">{item.title}</h1>
          </div>
          <StatusBadge status={item.status} />
        </div>
        <dl className="mt-8 grid gap-6 border-y border-white/8 py-6 sm:grid-cols-2">
          <Detail label="Description" value={item.description ?? "Not recorded"} />
          <Detail label="Legal authority" value={item.legal_authority ?? "Not recorded"} />
          <Detail label="Created" value={new Date(item.created_at).toLocaleString()} />
          <Detail label="Version" value={String(item.version)} />
        </dl>
        {actions.length > 0 && (
          <div className="mt-6 flex flex-wrap gap-3">
            {actions.map((action) => (
              <button
                key={action.status}
                type="button"
                disabled={transition.isPending}
                onClick={() => {
                  transition.mutate(action.status);
                }}
                className="min-h-10 rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100 disabled:opacity-50"
              >
                {action.label}
              </button>
            ))}
          </div>
        )}
        {transition.isError && <CaseError error={transition.error} />}
      </div>
      <section className="mt-6 overflow-hidden rounded-2xl border border-cyan-300/15 bg-[radial-gradient(circle_at_top_right,rgba(34,211,238,0.12),transparent_42%),rgba(34,211,238,0.035)] p-6 sm:p-8">
        <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-center">
          <div className="flex gap-4">
            <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-cyan-300 text-slate-950">
              <LayoutDashboard size={21} aria-hidden="true" />
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
                Investigation overview
              </p>
              <h2 className="mt-2 text-xl font-semibold text-white">Command Center</h2>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
                See collection progress, integrity posture, evidence composition, recent activity,
                and the next recommended examiner action in one place.
              </p>
            </div>
          </div>
          <Link
            to={`/cases/${caseId}/command-center`}
            className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg bg-cyan-300 px-5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200"
          >
            Open Command Center
          </Link>
        </div>
      </section>
      <section className="mt-6 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:p-8">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
            Completeness
          </p>
          <h2 className="mt-2 text-xl font-semibold text-white">Acquisition Completeness Matrix</h2>
          <p className="mt-2 text-sm leading-6 text-slate-500">
            Overview of the core forensic artifacts and their acquisition status.
          </p>
        </div>
        <AcquisitionCompletenessPanel caseId={caseId} />
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-amber-300/12 bg-amber-300/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <Flag className="mt-1 shrink-0 text-amber-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Key Evidence</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Curate high-value findings from acquired files and parsed Android artifacts into one
              auditable review board.
            </p>
          </div>
        </div>
        <Link
          to={`/cases/${caseId}/key-evidence`}
          className="inline-flex min-h-10 items-center justify-center rounded-lg border border-amber-300/20 bg-amber-300/7 px-4 text-sm font-semibold text-amber-100"
        >
          Review Key Evidence
        </Link>
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-violet-300/12 bg-violet-300/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <PanelsTopLeft className="mt-1 shrink-0 text-violet-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Investigation Storyboard</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Combine Key Evidence, timestamp claims, and explicit relationships into a
              deterministic report-ready review.
            </p>
          </div>
        </div>
        <Link
          to={`/cases/${caseId}/storyboard`}
          className="inline-flex min-h-10 items-center justify-center rounded-lg border border-violet-300/20 bg-violet-300/7 px-4 text-sm font-semibold text-violet-100"
        >
          Open Storyboard
        </Link>
      </section>
      <section className="mt-6 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:p-8">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-300">
              Device registry
            </p>
            <h2 className="mt-2 text-xl font-semibold text-white">Case-linked Android devices</h2>
          </div>
          {!new Set<CaseStatus>(["closed", "archived"]).has(item.status) && (
            <Link
              to={`/cases/${caseId}/devices`}
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg bg-cyan-300 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200"
            >
              <Plus size={16} aria-hidden="true" /> Detect and assess device
            </Link>
          )}
        </div>
        <CaseDevices devices={devicesQuery.data ?? []} isPending={devicesQuery.isPending} error={devicesQuery.error} />
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <DatabaseBackup className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Evidence Twin</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Import and seal existing images or extractions, then create verified examination copies.
            </p>
          </div>
        </div>
        <Link
          to={`/cases/${caseId}/evidence-twin`}
          className="inline-flex min-h-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100"
        >
          Open Evidence Twin
        </Link>
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <BookOpenText className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Preliminary reports</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">Freeze versioned PDF, JSON, and CSV outputs with recorded SHA-256 values.</p>
          </div>
        </div>
        <Link to={`/cases/${caseId}/reports`} className="inline-flex min-h-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100">Open reports</Link>
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <ClipboardList className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Acquisition plans</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Review or create hash-bound plans. Planning does not collect evidence.
            </p>
          </div>
        </div>
        <Link
          to={`/cases/${caseId}/acquisitions`}
          className="inline-flex min-h-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100"
        >
          Open planning
        </Link>
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <Clock3 className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Evidence timeline</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">Review timestamp claims without inventing unavailable device-side times. No missing device-side timestamps are inferred.</p>
          </div>
        </div>
        <Link to={`/cases/${caseId}/timeline`} className="inline-flex min-h-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100">Open timeline</Link>
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <GitFork className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Investigation correlations</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Trace explainable links between sources, artifacts, apps, accounts, and explicit identifiers.
            </p>
          </div>
        </div>
        <Link to={`/cases/${caseId}/correlations`} className="inline-flex min-h-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100">Open graph</Link>
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <ShieldCheck className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Evidence explorer</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Search normalized metadata and inspect provenance without opening hostile content.
            </p>
          </div>
        </div>
        <Link
          to={`/cases/${caseId}/evidence`}
          className="inline-flex min-h-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100"
        >
          Explore evidence
        </Link>
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <ClipboardList className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Artifact browser</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Browse parsed messages, calls, contacts, and app data by category across all sealed sources.
            </p>
          </div>
        </div>
        <Link
          to={`/cases/${caseId}/artifacts`}
          className="inline-flex min-h-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100"
        >
          Browse artifacts
        </Link>
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <MapPin className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Media locations</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Plot GPS coordinates from geotagged photo EXIF on an offline map. No tiles are fetched, so inspecting a location never leaves the workstation.
            </p>
          </div>
        </div>
        <Link
          to={`/cases/${caseId}/media-map`}
          className="inline-flex min-h-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100"
        >
          Open map
        </Link>
      </section>
      <section className="mt-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:flex-row sm:items-center sm:p-8">
        <div className="flex gap-4">
          <Search className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div>
            <h2 className="text-xl font-semibold text-white">Artifact search</h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Search parsed messages, calls, contacts, and app data across every sealed source in the case at once.
            </p>
          </div>
        </div>
        <Link
          to={`/cases/${caseId}/artifact-search`}
          className="inline-flex min-h-10 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/7 px-4 text-sm font-semibold text-cyan-100"
        >
          Search artifacts
        </Link>
      </section>
      <section className="mt-6 rounded-2xl border border-white/8 bg-white/[0.025] p-6 sm:p-8">
        <div className="flex items-start gap-4">
          <Link2 className="mt-1 shrink-0 text-cyan-300" size={21} aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-xl font-semibold text-white">Chain of custody</h2>
              {custodyVerificationQuery.data && (
                <span
                  className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                    custodyVerificationQuery.data.valid
                      ? "border-emerald-200/20 text-emerald-200"
                      : "border-rose-200/20 text-rose-200"
                  }`}
                >
                  {custodyVerificationQuery.data.valid ? "Chain verified" : "Chain broken"}
                </span>
              )}
            </div>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              Append-only evidence registration, integrity, transfer, and amendment history.
            </p>
            {canExportCheckpoint && (
              <div className="mt-4 rounded-xl border border-cyan-200/10 bg-cyan-200/[0.025] p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold text-cyan-100">
                      External checkpoint package
                    </p>
                    <p className="mt-1 text-[11px] leading-5 text-slate-500">
                      Seal the verified custody head and current audit head. The resulting hash is
                      not externally anchored until your agency preserves, publishes, or signs it.
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={
                      createCheckpoint.isPending ||
                      custodyVerificationQuery.data?.valid !== true
                    }
                    onClick={() => {
                      createCheckpoint.mutate();
                    }}
                    className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-cyan-200/20 px-3 text-xs font-semibold text-cyan-100 disabled:opacity-40"
                  >
                    {createCheckpoint.isPending ? (
                      <LoaderCircle className="animate-spin" size={14} aria-hidden="true" />
                    ) : (
                      <ShieldCheck size={14} aria-hidden="true" />
                    )}
                    Create sealed checkpoint
                  </button>
                </div>
                {checkpointsQuery.data?.map((checkpoint) => (
                  <div
                    key={checkpoint.id}
                    className="mt-3 rounded-lg border border-white/8 bg-black/10 p-3"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-xs font-semibold text-white">
                          {checkpoint.custody_record_count} custody record(s) · audit #{checkpoint.audit_sequence}
                        </p>
                        <p
                          className="mt-1 truncate font-mono text-[10px] text-slate-600"
                          title={checkpoint.sha256}
                        >
                          SHA-256 {checkpoint.sha256}
                        </p>
                        <p className="mt-1 text-[10px] uppercase tracking-wide text-amber-200/70">
                          not externally anchored
                        </p>
                      </div>
                      <DownloadLink
                        href={custodyCheckpointDownloadUrl(caseId, checkpoint.id)}
                        filename={checkpoint.filename}
                        className="inline-flex min-h-9 items-center gap-2 rounded-lg border border-white/10 px-3 text-xs font-semibold text-slate-300"
                      >
                        <ArrowDownToLine size={14} aria-hidden="true" /> Download JSON
                      </DownloadLink>
                    </div>
                    <CheckpointAnchorPanel caseId={caseId} checkpoint={checkpoint} />
                    <CheckpointSignaturePanel caseId={caseId} checkpoint={checkpoint} />
                  </div>
                ))}
              </div>
            )}
            {createCheckpoint.isError && (
              <div className="mt-4"><CaseError error={createCheckpoint.error} /></div>
            )}
            {checkpointsQuery.isError && (
              <div className="mt-4"><CaseError error={checkpointsQuery.error} /></div>
            )}
            {custodyQuery.isPending && <p role="status" className="mt-4 text-sm text-slate-500">Loading custody history...</p>}
            {custodyQuery.isError && <div className="mt-4"><CaseError error={custodyQuery.error} /></div>}
            {custodyQuery.data?.length === 0 && <p className="mt-4 text-sm text-slate-600">No evidence custody events yet.</p>}
            <ol className="mt-4 space-y-3">
              {custodyQuery.data?.map((event) => (
                <li key={event.id} className="rounded-lg border border-white/8 bg-black/10 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs font-semibold text-slate-200">
                      #{event.sequence} {event.event_type.replaceAll("_", " ")}
                    </span>
                    <time className="text-[10px] text-slate-600">
                      {new Date(event.created_at).toLocaleString()}
                    </time>
                  </div>
                  {event.purpose && <p className="mt-2 text-xs text-slate-500">{event.purpose}</p>}
                  {event.notes && <p className="mt-2 text-xs text-amber-100/70">Amendment: {event.notes}</p>}
                  <p className="mt-2 truncate font-mono text-[10px] text-slate-700" title={event.event_hash}>
                    SHA-256 {event.event_hash}
                  </p>
                </li>
              ))}
            </ol>
          </div>
        </div>
      </section>
    </div>
  );
}

function CaseDevices({
  devices,
  isPending,
  error,
}: {
  devices: CaseDevice[];
  isPending: boolean;
  error: Error | null;
}) {
  if (isPending) {
    return <p role="status" className="mt-6 text-sm text-slate-500">Loading case devices…</p>;
  }
  if (error) return <div className="mt-6"><CaseError error={error} /></div>;
  if (devices.length === 0) {
    return (
      <div className="mt-6 rounded-xl border border-dashed border-white/10 p-6 text-center">
        <Smartphone className="mx-auto text-slate-600" size={24} aria-hidden="true" />
        <p className="mt-3 text-sm font-medium text-slate-300">No assessed devices</p>
        <p className="mt-1 text-xs leading-5 text-slate-600">
          Device records appear only after an authorized readiness assessment succeeds.
        </p>
      </div>
    );
  }
  return (
    <div className="mt-6 grid gap-3 sm:grid-cols-2">
      {devices.map((device) => (
        <article key={device.id} className="rounded-xl border border-white/8 bg-black/10 p-5">
          <div className="flex gap-3">
            <Smartphone className="mt-0.5 shrink-0 text-cyan-300" size={19} aria-hidden="true" />
            <div>
              <h3 className="font-semibold text-white">
                {[device.manufacturer, device.model].filter(Boolean).join(" ") || "Android device"}
              </h3>
              <p className="mt-1 font-mono text-xs text-slate-600">Serial ending {device.serial_suffix}</p>
            </div>
          </div>
          <p className="mt-4 text-xs text-slate-500">
            Android {device.android_version ?? "unknown"} · API {device.sdk_level ?? "unknown"}
          </p>
          <p className="mt-2 text-xs text-slate-600">
            Last readiness snapshot {new Date(device.last_seen_at).toLocaleString()}
          </p>
        </article>
      ))}
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-600">{label}</dt>
      <dd className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-300">{value}</dd>
    </div>
  );
}

function CheckpointAnchorPanel({
  caseId,
  checkpoint,
}: {
  caseId: string;
  checkpoint: CustodyCheckpoint;
}) {
  const queryClient = useQueryClient();
  const [anchorType, setAnchorType] =
    useState<CustodyCheckpointAnchor["anchor_type"]>("case_management");
  const [provider, setProvider] = useState("");
  const [reference, setReference] = useState("");
  const [anchoredAt, setAnchoredAt] = useState(() => new Date().toISOString().slice(0, 16));
  const [receiptSha256, setReceiptSha256] = useState("");
  const [notes, setNotes] = useState("");
  const anchorsQuery = useQuery({
    queryKey: caseKeys.custodyCheckpointAnchors(caseId, checkpoint.id),
    queryFn: () => listCustodyCheckpointAnchors(caseId, checkpoint.id),
  });
  const createAnchor = useMutation({
    mutationFn: () =>
      createCustodyCheckpointAnchor(caseId, checkpoint.id, {
        anchor_type: anchorType,
        anchor_provider: provider,
        anchor_reference: reference,
        anchored_at: new Date(anchoredAt).toISOString(),
        checkpoint_sha256: checkpoint.sha256,
        receipt_sha256: receiptSha256.trim() || null,
        notes: notes.trim() || null,
      }),
    onSuccess: () => {
      setProvider("");
      setReference("");
      setReceiptSha256("");
      setNotes("");
      void queryClient.invalidateQueries({
        queryKey: caseKeys.custodyCheckpointAnchors(caseId, checkpoint.id),
      });
    },
  });
  const canSubmit =
    provider.trim().length > 0 &&
    reference.trim().length > 0 &&
    anchoredAt.length > 0 &&
    (receiptSha256.trim().length === 0 || /^[a-fA-F0-9]{64}$/.test(receiptSha256.trim()));

  return (
    <div className="mt-3 border-t border-white/8 pt-3">
      <div className="flex items-center gap-2 text-[11px] font-semibold text-cyan-100">
        <FileCheck2 size={14} aria-hidden="true" /> Anchor receipts
      </div>
      <p className="mt-1 text-[11px] leading-5 text-slate-500">
        Record where this checkpoint hash was preserved outside ForensiX.
      </p>
      <form
        className="mt-3 grid gap-2 sm:grid-cols-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (canSubmit) createAnchor.mutate();
        }}
      >
        <label className="text-[11px] text-slate-400">
          Anchor type
          <select
            value={anchorType}
            onChange={(event) => {
              setAnchorType(
                event.currentTarget.value as CustodyCheckpointAnchor["anchor_type"],
              );
            }}
            className="mt-1 min-h-9 w-full rounded-lg border border-white/10 bg-slate-950 px-3 text-xs text-white"
          >
            <option value="case_management">Case management</option>
            <option value="evidence_vault">Evidence vault</option>
            <option value="digital_signature">Digital signature</option>
            <option value="external_timestamp">External timestamp</option>
            <option value="other">Other</option>
          </select>
        </label>
        <label className="text-[11px] text-slate-400">
          Provider
          <input
            value={provider}
            onChange={(event) => {
              setProvider(event.currentTarget.value);
            }}
            maxLength={255}
            className="mt-1 min-h-9 w-full rounded-lg border border-white/10 bg-slate-950 px-3 text-xs text-white"
          />
        </label>
        <label className="text-[11px] text-slate-400">
          Reference
          <input
            value={reference}
            onChange={(event) => {
              setReference(event.currentTarget.value);
            }}
            maxLength={512}
            className="mt-1 min-h-9 w-full rounded-lg border border-white/10 bg-slate-950 px-3 text-xs text-white"
          />
        </label>
        <label className="text-[11px] text-slate-400">
          Anchored at
          <input
            type="datetime-local"
            value={anchoredAt}
            onChange={(event) => {
              setAnchoredAt(event.currentTarget.value);
            }}
            className="mt-1 min-h-9 w-full rounded-lg border border-white/10 bg-slate-950 px-3 text-xs text-white"
          />
        </label>
        <label className="text-[11px] text-slate-400 sm:col-span-2">
          Receipt SHA-256
          <input
            value={receiptSha256}
            onChange={(event) => {
              setReceiptSha256(event.currentTarget.value);
            }}
            maxLength={64}
            placeholder="Optional receipt hash"
            className="mt-1 min-h-9 w-full rounded-lg border border-white/10 bg-slate-950 px-3 font-mono text-xs text-white"
          />
        </label>
        <label className="text-[11px] text-slate-400 sm:col-span-2">
          Notes
          <textarea
            value={notes}
            onChange={(event) => {
              setNotes(event.currentTarget.value);
            }}
            maxLength={2000}
            rows={2}
            className="mt-1 w-full rounded-lg border border-white/10 bg-slate-950 px-3 py-2 text-xs text-white"
          />
        </label>
        <div className="sm:col-span-2">
          <button
            type="submit"
            disabled={!canSubmit || createAnchor.isPending}
            className="inline-flex min-h-9 items-center gap-2 rounded-lg border border-cyan-200/20 px-3 text-xs font-semibold text-cyan-100 disabled:opacity-40"
          >
            {createAnchor.isPending ? (
              <LoaderCircle className="animate-spin" size={14} aria-hidden="true" />
            ) : (
              <FileCheck2 size={14} aria-hidden="true" />
            )}
            Record external anchor
          </button>
        </div>
      </form>
      {createAnchor.isError && (
        <div className="mt-3"><CaseError error={createAnchor.error} /></div>
      )}
      {anchorsQuery.isError && (
        <div className="mt-3"><CaseError error={anchorsQuery.error} /></div>
      )}
      {anchorsQuery.data && anchorsQuery.data.length > 0 && (
        <ol className="mt-3 space-y-2">
          {anchorsQuery.data.map((anchor) => (
            <li key={anchor.id} className="rounded-lg border border-emerald-200/10 bg-emerald-200/[0.025] p-3">
              <p className="text-xs font-semibold text-emerald-100">
                {anchor.anchor_provider} - {anchor.anchor_reference}
              </p>
              <p className="mt-1 text-[10px] uppercase tracking-wide text-emerald-200/70">
                {anchor.anchor_type.replaceAll("_", " ")} - {new Date(anchor.anchored_at).toLocaleString()}
              </p>
              <p className="mt-1 truncate font-mono text-[10px] text-slate-600" title={anchor.anchor_hash}>
                Anchor SHA-256 {anchor.anchor_hash}
              </p>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function CheckpointSignaturePanel({
  caseId,
  checkpoint,
}: {
  caseId: string;
  checkpoint: CustodyCheckpoint;
}) {
  const queryClient = useQueryClient();
  const [algorithm, setAlgorithm] =
    useState<CustodyCheckpointSignature["signature_algorithm"]>(
      "rsa_pkcs1v15_sha256",
    );
  const [signedAt, setSignedAt] = useState(() => new Date().toISOString().slice(0, 16));
  const [certificatePem, setCertificatePem] = useState("");
  const [certificateName, setCertificateName] = useState("");
  const [signatureBase64, setSignatureBase64] = useState("");
  const [signatureName, setSignatureName] = useState("");
  const [fileError, setFileError] = useState<string | null>(null);
  const signaturesQuery = useQuery({
    queryKey: caseKeys.custodyCheckpointSignatures(caseId, checkpoint.id),
    queryFn: () => listCustodyCheckpointSignatures(caseId, checkpoint.id),
  });
  const verifySignature = useMutation({
    mutationFn: () =>
      verifyCustodyCheckpointSignature(caseId, checkpoint.id, {
        signature_algorithm: algorithm,
        certificate_pem: certificatePem,
        signature_base64: signatureBase64,
        signed_at: new Date(signedAt).toISOString(),
        checkpoint_sha256: checkpoint.sha256,
      }),
    onSuccess: () => {
      setCertificatePem("");
      setCertificateName("");
      setSignatureBase64("");
      setSignatureName("");
      void queryClient.invalidateQueries({
        queryKey: caseKeys.custodyCheckpointSignatures(caseId, checkpoint.id),
      });
    },
  });
  const canSubmit =
    certificatePem.length > 0 &&
    signatureBase64.length > 0 &&
    signedAt.length > 0 &&
    fileError === null;

  async function loadCertificate(file: File | undefined): Promise<void> {
    setFileError(null);
    if (!file) return;
    if (file.size > 16 * 1024) {
      setFileError("The certificate file exceeds the 16 KiB limit.");
      return;
    }
    setCertificatePem(await file.text());
    setCertificateName(file.name);
  }

  async function loadSignature(file: File | undefined): Promise<void> {
    setFileError(null);
    if (!file) return;
    if (file.size > 4 * 1024) {
      setFileError("The detached signature exceeds the 4 KiB limit.");
      return;
    }
    setSignatureBase64(bytesToBase64(new Uint8Array(await file.arrayBuffer())));
    setSignatureName(file.name);
  }

  return (
    <div className="mt-3 border-t border-white/8 pt-3">
      <div className="flex items-center gap-2 text-[11px] font-semibold text-cyan-100">
        <ShieldCheck size={14} aria-hidden="true" /> Verify detached signature
      </div>
      <p className="mt-1 text-[11px] leading-5 text-slate-500">
        Verify a public X.509 certificate and detached signature against this sealed checkpoint.
        Private keys must never be uploaded. This does not validate certificate-chain trust or
        revocation.
      </p>
      <form
        className="mt-3 grid gap-2 sm:grid-cols-2"
        onSubmit={(event) => {
          event.preventDefault();
          if (canSubmit) verifySignature.mutate();
        }}
      >
        <label className="text-[11px] text-slate-400">
          Signature algorithm
          <select
            value={algorithm}
            onChange={(event) => {
              setAlgorithm(
                event.currentTarget.value as CustodyCheckpointSignature["signature_algorithm"],
              );
            }}
            className="mt-1 min-h-9 w-full rounded-lg border border-white/10 bg-slate-950 px-3 text-xs text-white"
          >
            <option value="rsa_pkcs1v15_sha256">RSA PKCS#1 v1.5 / SHA-256</option>
            <option value="rsa_pss_sha256">RSA-PSS / SHA-256</option>
            <option value="ecdsa_sha256">ECDSA / SHA-256</option>
          </select>
        </label>
        <label className="text-[11px] text-slate-400">
          Declared signing time
          <input
            type="datetime-local"
            value={signedAt}
            onChange={(event) => {
              setSignedAt(event.currentTarget.value);
            }}
            className="mt-1 min-h-9 w-full rounded-lg border border-white/10 bg-slate-950 px-3 text-xs text-white"
          />
        </label>
        <label className="text-[11px] text-slate-400">
          Public certificate (PEM)
          <input
            type="file"
            accept=".pem,.crt,.cer,application/x-pem-file"
            onChange={(event) => {
              void loadCertificate(event.currentTarget.files?.[0]);
            }}
            className="mt-1 block min-h-9 w-full rounded-lg border border-white/10 bg-slate-950 px-2 py-1.5 text-xs text-slate-300"
          />
          {certificateName && <span className="mt-1 block text-emerald-300">{certificateName}</span>}
        </label>
        <label className="text-[11px] text-slate-400">
          Detached signature
          <input
            type="file"
            onChange={(event) => {
              void loadSignature(event.currentTarget.files?.[0]);
            }}
            className="mt-1 block min-h-9 w-full rounded-lg border border-white/10 bg-slate-950 px-2 py-1.5 text-xs text-slate-300"
          />
          {signatureName && <span className="mt-1 block text-emerald-300">{signatureName}</span>}
        </label>
        <div className="sm:col-span-2">
          <button
            type="submit"
            disabled={!canSubmit || verifySignature.isPending}
            className="inline-flex min-h-9 items-center gap-2 rounded-lg border border-emerald-200/20 px-3 text-xs font-semibold text-emerald-100 disabled:opacity-40"
          >
            {verifySignature.isPending ? (
              <LoaderCircle className="animate-spin" size={14} aria-hidden="true" />
            ) : (
              <ShieldCheck size={14} aria-hidden="true" />
            )}
            Verify signature
          </button>
        </div>
      </form>
      {fileError && <p className="mt-2 text-xs text-rose-300">{fileError}</p>}
      {verifySignature.isError && (
        <div className="mt-3"><CaseError error={verifySignature.error} /></div>
      )}
      {signaturesQuery.isError && (
        <div className="mt-3"><CaseError error={signaturesQuery.error} /></div>
      )}
      {signaturesQuery.data && signaturesQuery.data.length > 0 && (
        <ol className="mt-3 space-y-2">
          {signaturesQuery.data.map((signature) => (
            <li
              key={signature.id}
              className="rounded-lg border border-emerald-200/15 bg-emerald-200/[0.035] p-3"
            >
              <p className="text-xs font-semibold text-emerald-100">
                Signature verified - {signature.signer_subject}
              </p>
              <p className="mt-1 text-[10px] uppercase tracking-wide text-emerald-200/70">
                {signature.signature_algorithm.replaceAll("_", " ")} - signed {new Date(signature.signed_at).toLocaleString()}
              </p>
              <p className="mt-1 truncate font-mono text-[10px] text-slate-600" title={signature.certificate_sha256}>
                Certificate SHA-256 {signature.certificate_sha256}
              </p>
              <p className="mt-1 truncate font-mono text-[10px] text-slate-600" title={signature.verification_hash}>
                Verification SHA-256 {signature.verification_hash}
              </p>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

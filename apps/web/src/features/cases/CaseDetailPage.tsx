import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ClipboardList, Link2, LoaderCircle, Plus, Smartphone } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import {
  getCase,
  listCustodyEvents,
  listCaseDevices,
  transitionCase,
  verifyCustodyChain,
  type CaseDevice,
  type CaseStatus,
} from "../../lib/api";
import { CaseError, StatusBadge } from "./CasesPage";
import { caseKeys } from "./caseKeys";

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

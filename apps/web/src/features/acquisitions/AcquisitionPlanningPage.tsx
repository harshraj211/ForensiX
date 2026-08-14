import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ClipboardCheck,
  FileCheck2,
  Fingerprint,
  LoaderCircle,
  Play,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { caseKeys } from "../cases/caseKeys";
import { CaseError } from "../cases/CasesPage";
import {
  cancelAcquisitionJob,
  acquireInventoryBatch,
  acquireInventoryFile,
  createAcquisitionPlan,
  getAcquisitionInventory,
  getCase,
  listAcquisitionJobs,
  listAcquiredFiles,
  listAcquisitionPartials,
  listEvidenceVerifications,
  listAcquisitionPlans,
  listCaseDeviceAssessments,
  listCaseDevices,
  prepareAcquisitionJob,
  runAcquisitionInventory,
  resumeEvidenceFile,
  verifyEvidenceFile,
  type AcquisitionJob,
  type AcquisitionModule,
  type AcquisitionPlan,
  type AcquisitionScope,
  type BulkAcquireResult,
  type EvidenceVerification,
} from "../../lib/api";
import {
  itemAllowedByScope,
  matchesInventoryFilter,
  type InventoryFilter,
} from "./inventoryFileTypes";

function isAcquirableStatus(status: string | undefined): boolean {
  return status !== "completed" && status !== "acquiring";
}

/**
 * SQLite returns historical UTC values without an offset. Treat those API values
 * as UTC rather than letting the browser reinterpret them in the investigator's
 * local timezone.
 */
function utcTimestamp(value: string): number {
  const hasTimezone = /(?:Z|[+-]\d{2}:\d{2})$/i.test(value);
  return new Date(hasTimezone ? value : `${value}Z`).getTime();
}

const scopeCopy: Record<AcquisitionScope, { label: string; description: string }> = {
  metadata_only: {
    label: "Metadata only",
    description: "Device properties and installed-package identifiers only.",
  },
  quick_triage: {
    label: "Quick triage",
    description: "Metadata, package inventory, and bounded shared-storage inventory.",
  },
  shared_storage_inventory: {
    label: "Storage inventory",
    description: "Plan a metadata-only inventory of approved readable shared-storage roots.",
  },
  media_files: {
    label: "Media only",
    description: "Inventory shared storage and authorize acquisition of recognized images, video, and audio only.",
  },
  document_files: {
    label: "Documents only",
    description: "Inventory shared storage and authorize acquisition of recognized document formats only.",
  },
  downloads_files: {
    label: "Downloads only",
    description: "Inventory shared storage and authorize acquisition only from Download or Downloads paths.",
  },
  custom: {
    label: "Custom",
    description: "Select individual modules supported by the exact readiness snapshot.",
  },
};

const moduleLabels: Record<AcquisitionModule, string> = {
  device_metadata: "Device metadata",
  package_inventory: "Package inventory",
  shared_storage_inventory: "Shared-storage inventory",
};

export function AcquisitionPlanningPage() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const [deviceId, setDeviceId] = useState("");
  const [scope, setScope] = useState<AcquisitionScope>("quick_triage");
  const [modules, setModules] = useState<AcquisitionModule[]>([]);
  const [acknowledged, setAcknowledged] = useState(false);
  const [pageOpenedAt] = useState(Date.now);
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
  const selectedDeviceId = deviceId || devicesQuery.data?.[0]?.id || "";
  const assessmentsQuery = useQuery({
    queryKey: caseKeys.deviceAssessments(caseId, selectedDeviceId),
    queryFn: () => listCaseDeviceAssessments(caseId, selectedDeviceId),
    enabled: Boolean(caseId && selectedDeviceId),
  });
  const plansQuery = useQuery({
    queryKey: caseKeys.acquisitionPlans(caseId),
    queryFn: () => listAcquisitionPlans(caseId),
    enabled: Boolean(caseId),
  });
  const jobsQuery = useQuery({
    queryKey: caseKeys.acquisitionJobs(caseId),
    queryFn: () => listAcquisitionJobs(caseId),
    enabled: Boolean(caseId),
  });
  const latestAssessment = assessmentsQuery.data?.[0];
  const supportedModules = useMemo(() => {
    if (!latestAssessment) return new Set<AcquisitionModule>();
    const supported = new Set<AcquisitionModule>();
    if (latestAssessment.capabilities.device_metadata?.status === "supported") {
      supported.add("device_metadata");
    }
    if (latestAssessment.capabilities.package_inventory?.status === "supported") {
      supported.add("package_inventory");
    }
    if (
      latestAssessment.capabilities.shared_storage?.status === "supported" &&
      latestAssessment.storage_roots.some((root) => root.readable)
    ) {
      supported.add("shared_storage_inventory");
    }
    return supported;
  }, [latestAssessment]);
  const requiredModules = scopeModules(scope, modules);
  const scopeSupported = requiredModules.every((module) => supportedModules.has(module));
  const readinessFresh = latestAssessment
    ? pageOpenedAt <= utcTimestamp(latestAssessment.assessed_at) + 30 * 60 * 1000
    : false;
  const caseWritable = caseQuery.data
    ? !new Set(["closed", "archived"]).has(caseQuery.data.status)
    : false;
  const latestPlan = plansQuery.data?.items[0];
  const latestJob = latestPlan
    ? jobsQuery.data?.items.find((job) => job.plan_id === latestPlan.id)
    : undefined;
  const createPlan = useMutation({
    mutationFn: () => {
      if (!latestAssessment) throw new Error("A current readiness snapshot is required.");
      return createAcquisitionPlan(caseId, {
        device_id: selectedDeviceId,
        assessment_id: latestAssessment.id,
        scope,
        ...(scope === "custom" ? { modules } : {}),
        limitations_acknowledged: true,
      });
    },
    onSuccess: () => {
      setAcknowledged(false);
      void queryClient.invalidateQueries({ queryKey: caseKeys.acquisitionPlans(caseId) });
    },
  });
  const prepareJob = useMutation({
    mutationFn: (planId: string) => prepareAcquisitionJob(caseId, planId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: caseKeys.acquisitionJobs(caseId) });
    },
  });
  const cancelJob = useMutation({
    mutationFn: (jobId: string) => cancelAcquisitionJob(caseId, jobId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: caseKeys.acquisitionJobs(caseId) });
    },
  });
  const runInventory = useMutation({
    mutationFn: (jobId: string) => runAcquisitionInventory(caseId, jobId),
    onSuccess: (inventory) => {
      queryClient.setQueryData(
        ["acquisition-inventory", caseId, inventory.job_id],
        inventory,
      );
      void queryClient.invalidateQueries({ queryKey: caseKeys.acquisitionJobs(caseId) });
    },
  });

  if (caseQuery.isPending) {
    return <LoaderCircle role="status" aria-label="Loading case" className="animate-spin text-cyan-300" />;
  }
  if (caseQuery.isError) return <CaseError error={caseQuery.error} />;

  return (
    <div className="mx-auto max-w-6xl">
      <Link to={`/cases/${caseId}`} className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200">
        <ArrowLeft size={15} aria-hidden="true" /> Back to case
      </Link>
      <div className="mt-6 border-b border-white/8 pb-7">
        <p className="font-mono text-xs text-cyan-300/65">{caseQuery.data.case_number}</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Acquisition planning</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
          Run a scoped, reviewable collection against one exact readiness snapshot. Every stage keeps
          its own manifest, durable event history, and integrity result.
        </p>
      </div>

      <RunProgress
        readinessReady={Boolean(latestAssessment && readinessFresh && scopeSupported)}
        plan={latestPlan}
        job={latestJob}
      />

      <div className="mt-7 grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
        <section className="rounded-2xl border border-white/8 bg-white/[0.025] p-6">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
            Collection scope
          </p>
          <h2 className="mt-2 text-lg font-semibold text-white">Create an immutable run plan</h2>
          {devicesQuery.data?.length === 0 ? (
            <div className="mt-5 rounded-xl border border-dashed border-white/10 p-6 text-center">
              <p className="text-sm text-slate-400">Assess a case device before planning.</p>
              <Link to={`/cases/${caseId}/devices`} className="mt-3 inline-block text-sm font-semibold text-cyan-300">
                Open device readiness
              </Link>
            </div>
          ) : (
            <form
              className="mt-5 space-y-5"
              onSubmit={(event) => {
                event.preventDefault();
                createPlan.mutate();
              }}
            >
              <label className="block text-sm text-slate-300">
                Case device
                <select
                  value={selectedDeviceId}
                  onChange={(event) => {
                    setDeviceId(event.target.value);
                    setAcknowledged(false);
                  }}
                  className="mt-2 min-h-11 w-full rounded-lg border border-white/10 bg-[#0a151d] px-3"
                >
                  {(devicesQuery.data ?? []).map((device) => (
                    <option key={device.id} value={device.id}>
                      {[device.manufacturer, device.model].filter(Boolean).join(" ") || "Android device"} · {device.serial_suffix}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block text-sm text-slate-300">
                Scope
                <select
                  value={scope}
                  onChange={(event) => {
                    setScope(event.target.value as AcquisitionScope);
                    setModules([]);
                    setAcknowledged(false);
                  }}
                  className="mt-2 min-h-11 w-full rounded-lg border border-white/10 bg-[#0a151d] px-3"
                >
                  {Object.entries(scopeCopy).map(([value, copy]) => (
                    <option key={value} value={value}>{copy.label}</option>
                  ))}
                </select>
                <span className="mt-2 block text-xs leading-5 text-slate-500">{scopeCopy[scope].description}</span>
              </label>
              {scope === "custom" && (
                <fieldset>
                  <legend className="text-sm text-slate-300">Modules</legend>
                  <div className="mt-2 grid gap-2 sm:grid-cols-2">
                    {(Object.keys(moduleLabels) as AcquisitionModule[]).map((module) => (
                      <label key={module} className="flex gap-3 rounded-lg border border-white/8 p-3 text-sm text-slate-400">
                        <input
                          type="checkbox"
                          checked={modules.includes(module)}
                          disabled={!supportedModules.has(module)}
                          onChange={(event) => {
                            setModules((current) =>
                              event.target.checked
                                ? [...current, module]
                                : current.filter((item) => item !== module),
                            );
                          }}
                        />
                        {moduleLabels[module]}
                      </label>
                    ))}
                  </div>
                </fieldset>
              )}
              <ReadinessState
                assessmentPending={assessmentsQuery.isPending}
                hasAssessment={Boolean(latestAssessment)}
                fresh={readinessFresh}
                scopeSupported={scopeSupported}
              />
              <label className="flex gap-3 rounded-xl border border-amber-200/15 bg-amber-200/5 p-4 text-sm leading-6 text-amber-100/75">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={(event) => {
                    setAcknowledged(event.target.checked);
                  }}
                  className="mt-1"
                />
                <span>
                  I acknowledge that Controlled Logical Triage Mode is not hardware write blocking,
                  capability results can become stale, and this plan does not start acquisition.
                </span>
              </label>
              <button
                type="submit"
                disabled={
                  createPlan.isPending ||
                  !caseWritable ||
                  !latestAssessment ||
                  !readinessFresh ||
                  !scopeSupported ||
                  !acknowledged ||
                  requiredModules.length === 0
                }
                className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-cyan-300 px-5 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {createPlan.isPending ? <LoaderCircle size={16} className="animate-spin" /> : <ClipboardCheck size={16} />}
                Create frozen plan
              </button>
              {createPlan.isError && <CaseError error={createPlan.error} />}
              {createPlan.isSuccess && (
                <p role="status" className="flex items-center gap-2 text-sm text-emerald-200">
                  <CheckCircle2 size={16} /> Plan created without starting acquisition.
                </p>
              )}
            </form>
          )}
        </section>
        <RunSafeguards
          caseWritable={caseWritable}
          latestAssessmentAt={latestAssessment?.assessed_at}
          latestPlanHash={latestPlan?.plan_hash}
          latestJob={latestJob}
        />
      </div>

      <PlanHistory
        plans={plansQuery.data?.items ?? []}
        jobs={jobsQuery.data?.items ?? []}
        pending={plansQuery.isPending || jobsQuery.isPending}
        error={plansQuery.error ?? jobsQuery.error}
        caseWritable={caseWritable}
        referenceTime={pageOpenedAt}
        preparingPlanId={prepareJob.isPending ? prepareJob.variables : undefined}
        cancellingJobId={cancelJob.isPending ? cancelJob.variables : undefined}
        runningJobId={runInventory.isPending ? runInventory.variables : undefined}
        onPrepare={(planId) => {
          prepareJob.mutate(planId);
        }}
        onCancel={(jobId) => {
          cancelJob.mutate(jobId);
        }}
        onRun={(jobId) => {
          runInventory.mutate(jobId);
        }}
        mutationError={prepareJob.error ?? cancelJob.error ?? runInventory.error}
      />
    </div>
  );
}

function RunProgress({
  readinessReady,
  plan,
  job,
}: {
  readinessReady: boolean;
  plan?: AcquisitionPlan;
  job?: AcquisitionJob;
}) {
  const steps = [
    { label: "Readiness", complete: readinessReady },
    { label: "Scope frozen", complete: Boolean(plan) },
    { label: "Job prepared", complete: Boolean(job) },
    { label: "Inventory sealed", complete: Boolean(job?.result_reference) },
    { label: "Evidence verified", complete: job?.state === "verified" },
  ];
  const currentIndex = Math.min(
    steps.findIndex((step) => !step.complete),
    steps.length - 1,
  );

  return (
    <nav aria-label="Acquisition run progress" className="mt-7 border-y border-white/8 py-4">
      <ol className="grid gap-3 sm:grid-cols-5">
        {steps.map((step, index) => {
          const current = index === (currentIndex === -1 ? steps.length - 1 : currentIndex);
          return (
            <li key={step.label} className="flex min-w-0 items-center gap-3">
              <span
                className={`grid size-7 shrink-0 place-items-center rounded-full border text-xs font-semibold ${
                  step.complete
                    ? "border-emerald-300/30 bg-emerald-300/10 text-emerald-200"
                    : current
                      ? "border-cyan-300/30 bg-cyan-300/10 text-cyan-200"
                      : "border-white/10 text-slate-500"
                }`}
              >
                {step.complete ? <CheckCircle2 size={14} aria-hidden="true" /> : index + 1}
              </span>
              <span className={`truncate text-xs font-medium ${current ? "text-white" : "text-slate-500"}`}>
                {step.label}
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

function RunSafeguards({
  caseWritable,
  latestAssessmentAt,
  latestPlanHash,
  latestJob,
}: {
  caseWritable: boolean;
  latestAssessmentAt?: string;
  latestPlanHash?: string;
  latestJob?: AcquisitionJob;
}) {
  return (
    <aside className="border-l border-white/8 pl-0 lg:pl-6">
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
        Run safeguards
      </p>
      <h2 className="mt-2 text-lg font-semibold text-white">Defensibility snapshot</h2>
      <dl className="mt-5 divide-y divide-white/8 border-y border-white/8 text-sm">
        <SummaryRow label="Case state" value={caseWritable ? "Writable" : "Read only"} />
        <SummaryRow
          label="Readiness"
          value={latestAssessmentAt ? new Date(latestAssessmentAt).toLocaleString() : "Required"}
        />
        <SummaryRow label="Frozen plan" value={latestPlanHash ? shortHash(latestPlanHash) : "Not created"} mono />
        <SummaryRow label="Durable events" value={String(latestJob?.last_event_sequence ?? 0)} />
        <SummaryRow label="Resume policy" value={latestJob?.resume_supported ? "Supported" : "Not active"} />
      </dl>
      <p className="mt-4 text-xs leading-5 text-slate-500">
        Device-side effects, selected scope, file manifests, hashes, and verification outcomes are
        recorded against the case audit history.
      </p>
    </aside>
  );
}

function SummaryRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-3">
      <dt className="text-slate-500">{label}</dt>
      <dd className={`text-right text-slate-200 ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}

function ReadinessState({
  assessmentPending,
  hasAssessment,
  fresh,
  scopeSupported,
}: {
  assessmentPending: boolean;
  hasAssessment: boolean;
  fresh: boolean;
  scopeSupported: boolean;
}) {
  const message = assessmentPending
    ? "Loading readiness history…"
    : !hasAssessment
      ? "No readiness snapshot is available for this device."
      : !fresh
        ? "The latest readiness snapshot is older than 30 minutes. Reassess the device."
        : !scopeSupported
          ? "The selected scope contains a module blocked by this readiness snapshot."
          : "The latest readiness snapshot supports this scope.";
  const valid = hasAssessment && fresh && scopeSupported;
  return (
    <div className={`rounded-lg border p-4 text-sm ${valid ? "border-emerald-200/15 bg-emerald-200/5 text-emerald-200" : "border-rose-200/15 bg-rose-200/5 text-rose-200"}`}>
      <div className="flex gap-2"><AlertTriangle size={16} className="mt-0.5 shrink-0" />{message}</div>
    </div>
  );
}

function PlanHistory({
  plans,
  jobs,
  pending,
  error,
  caseWritable,
  referenceTime,
  preparingPlanId,
  cancellingJobId,
  runningJobId,
  onPrepare,
  onCancel,
  onRun,
  mutationError,
}: {
  plans: AcquisitionPlan[];
  jobs: AcquisitionJob[];
  pending: boolean;
  error: Error | null;
  caseWritable: boolean;
  referenceTime: number;
  preparingPlanId?: string;
  cancellingJobId?: string;
  runningJobId?: string;
  onPrepare: (planId: string) => void;
  onCancel: (jobId: string) => void;
  onRun: (jobId: string) => void;
  mutationError: Error | null;
}) {
  return (
    <section className="mt-8 border-t border-white/8 pt-7">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
            Active collection
          </p>
          <h2 className="mt-2 text-xl font-semibold text-white">Prepared acquisition runs</h2>
        </div>
        <p className="max-w-xl text-xs leading-5 text-slate-500">
          Each run remains tied to its readiness snapshot and immutable scope. Previous runs stay
          visible for review and cannot be silently replaced.
        </p>
      </div>
      <div className="mt-5 flex gap-3 border-y border-cyan-200/10 bg-cyan-200/5 p-3 text-xs leading-5 text-cyan-100/70">
        <ShieldCheck size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
        Inventory records paths and metadata first. File contents are collected only after explicit
        selection, then hashed and stored with a separate manifest.
      </div>
      {pending && <p role="status" className="mt-5 text-sm text-slate-500">Loading plans…</p>}
      {error && <div className="mt-5"><CaseError error={error} /></div>}
      {mutationError && <div className="mt-5"><CaseError error={mutationError} /></div>}
      {!pending && !error && plans.length === 0 && <p className="mt-5 text-sm leading-6 text-slate-500">No acquisition plan has been created for this case.</p>}
      <div className="mt-5 space-y-3">
        {plans.map((plan) => {
          const job = jobs.find((item) => item.plan_id === plan.id);
          const planFresh = referenceTime <= utcTimestamp(plan.readiness_expires_at);
          const cancellable = job && new Set(["created", "validating", "ready", "paused", "interrupted"]).has(job.state);
          const inventoryAllowed = job?.state === "ready" && plan.modules.includes("shared_storage_inventory");
          return (
          <article key={plan.id} className="rounded-xl border border-white/8 bg-white p-5 sm:p-6">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-white">{scopeCopy[plan.scope].label}</h3>
              <span className="rounded-full border border-emerald-200/15 px-2 py-1 text-[10px] uppercase tracking-wide text-emerald-200">{plan.status}</span>
            </div>
            <p className="mt-3 text-xs text-slate-500">{plan.modules.map((module) => moduleLabels[module]).join(" · ")}</p>
            <p className="mt-3 truncate font-mono text-[10px] text-slate-600" title={plan.plan_hash}>SHA-256 {plan.plan_hash}</p>
            <p className="mt-2 text-[11px] text-slate-600">Created {new Date(plan.created_at).toLocaleString()}</p>
            {job ? (
              <div className="mt-5 border-t border-white/8 pt-4">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-semibold text-slate-300">Durable job</span>
                  <span className="rounded-full border border-cyan-200/15 px-2 py-1 text-[10px] uppercase tracking-wide text-cyan-200">{job.state}</span>
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-500">{job.current_step ?? "Awaiting a safe executor step."}</p>
                <p className="mt-2 text-[11px] text-slate-600">{job.progress_percent}% checkpoint / {job.last_event_sequence} durable events</p>
                {inventoryAllowed && (
                  <button
                    type="button"
                    disabled={runningJobId === job.id}
                    onClick={() => {
                      onRun(job.id);
                    }}
                    className="mt-3 inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-300 px-3 text-xs font-semibold text-slate-950 disabled:opacity-40"
                  >
                    {runningJobId === job.id ? <LoaderCircle size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
                    Run bounded path inventory
                  </button>
                )}
                {cancellable && (
                  <button
                    type="button"
                    disabled={cancellingJobId === job.id}
                    onClick={() => {
                      onCancel(job.id);
                    }}
                    className="mt-3 inline-flex min-h-10 items-center gap-2 rounded-lg border border-rose-200/15 px-3 text-xs font-semibold text-rose-200 disabled:opacity-40"
                  >
                    {cancellingJobId === job.id ? <LoaderCircle size={14} className="animate-spin" /> : <XCircle size={14} />}
                    Cancel prepared job
                  </button>
                )}
                {job.result_reference && (
                  <InventoryResultPanel caseId={plan.case_id} jobId={job.id} scope={plan.scope} />
                )}
              </div>
            ) : (
              <div className="mt-4">
                <button
                  type="button"
                  disabled={!caseWritable || !planFresh || preparingPlanId === plan.id}
                  onClick={() => {
                    onPrepare(plan.id);
                  }}
                  className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-cyan-200/15 px-3 text-xs font-semibold text-cyan-200 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {preparingPlanId === plan.id ? <LoaderCircle size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
                  Prepare durable job
                </button>
                {!planFresh && <p className="mt-2 text-[11px] text-rose-200/75">Readiness expired; reassess and create a new plan.</p>}
              </div>
            )}
          </article>
          );
        })}
      </div>
    </section>
  );
}

function InventoryResultPanel({
  caseId,
  jobId,
  scope,
}: {
  caseId: string;
  jobId: string;
  scope: AcquisitionScope;
}) {
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<InventoryFilter>(() => defaultFilterForScope(scope));
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [lastBatch, setLastBatch] = useState<BulkAcquireResult | null>(null);
  const inventoryQuery = useQuery({
    queryKey: ["acquisition-inventory", caseId, jobId],
    queryFn: () => getAcquisitionInventory(caseId, jobId),
  });
  const filesQuery = useQuery({
    queryKey: ["acquired-files", caseId, jobId],
    queryFn: () => listAcquiredFiles(caseId, jobId),
  });
  const verificationsQuery = useQuery({
    queryKey: ["evidence-verifications", caseId, jobId],
    queryFn: () => listEvidenceVerifications(caseId, jobId),
  });
  const partialsQuery = useQuery({
    queryKey: ["acquisition-partials", caseId, jobId],
    queryFn: () => listAcquisitionPartials(caseId, jobId),
  });
  const acquireFile = useMutation({
    mutationFn: (itemId: string) => acquireInventoryFile(caseId, jobId, itemId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["acquired-files", caseId, jobId] });
    },
  });
  const acquireBatch = useMutation({
    mutationFn: (itemIds: string[]) => acquireInventoryBatch(caseId, jobId, itemIds),
    onSuccess: (result) => {
      setLastBatch(result);
      setSelectedIds(new Set());
      void queryClient.invalidateQueries({ queryKey: ["acquired-files", caseId, jobId] });
      void queryClient.invalidateQueries({ queryKey: ["acquisition-partials", caseId, jobId] });
    },
  });
  const verifyFile = useMutation({
    mutationFn: (evidenceFileId: string) =>
      verifyEvidenceFile(caseId, jobId, evidenceFileId),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["evidence-verifications", caseId, jobId],
      });
    },
  });
  const resumeFile = useMutation({
    mutationFn: ({ evidenceFileId, disposition }: { evidenceFileId: string; disposition: "retain" | "discard" }) =>
      resumeEvidenceFile(caseId, jobId, evidenceFileId, disposition),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["acquired-files", caseId, jobId] });
      void queryClient.invalidateQueries({ queryKey: ["acquisition-partials", caseId, jobId] });
    },
  });
  const verifyAll = useMutation({
    mutationFn: async (evidenceFileIds: string[]) => {
      const concurrency = 4;
      for (let index = 0; index < evidenceFileIds.length; index += concurrency) {
        await Promise.all(
          evidenceFileIds
            .slice(index, index + concurrency)
            .map((evidenceFileId) => verifyEvidenceFile(caseId, jobId, evidenceFileId)),
        );
      }
      return evidenceFileIds.length;
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["evidence-verifications", caseId, jobId],
      });
    },
  });
  if (inventoryQuery.isPending) {
    return <p role="status" className="mt-3 text-xs text-slate-500">Loading inventory manifest...</p>;
  }
  if (inventoryQuery.isError) return <div className="mt-3"><CaseError error={inventoryQuery.error} /></div>;
  const inventory = inventoryQuery.data;
  const acquiredByItem = new Map(
    (filesQuery.data ?? []).map((file) => [file.inventory_item_id, file]),
  );
  const latestVerificationByFile = new Map<string, EvidenceVerification>();
  for (const verification of verificationsQuery.data ?? []) {
    if (!latestVerificationByFile.has(verification.evidence_file_id)) {
      latestVerificationByFile.set(verification.evidence_file_id, verification);
    }
  }
  const retainedPartialByFile = new Map(
    (partialsQuery.data ?? [])
      .filter((partial) => partial.status === "retained")
      .map((partial) => [partial.evidence_file_id, partial]),
  );
  const acquiredFiles = filesQuery.data ?? [];
  const completedFiles = acquiredFiles.filter((file) => file.status === "completed");
  const verifiedFiles = completedFiles.filter(
    (file) => latestVerificationByFile.get(file.id)?.status === "verified",
  );
  const unverifiedFileIds = completedFiles
    .filter((file) => latestVerificationByFile.get(file.id)?.status !== "verified")
    .map((file) => file.id);
  const exceptionCount = acquiredFiles.filter(
    (file) => file.status === "failed" || file.status === "interrupted",
  ).length;
  const acquiredBytes = completedFiles.reduce((total, file) => total + (file.size_bytes ?? 0), 0);
  const inScopeItems = inventory.items.filter((item) => itemAllowedByScope(item, scope));
  const visibleItems = inScopeItems.filter((item) => matchesInventoryFilter(item, filter));
  const selectableVisibleIds = visibleItems
    .filter((item) => {
      const acquired = acquiredByItem.get(item.id);
      if (acquired?.partial_preserved && retainedPartialByFile.has(acquired.id)) return false;
      return isAcquirableStatus(acquired?.status);
    })
    .map((item) => item.id);
  const selectedVisibleCount = selectableVisibleIds.filter((id) => selectedIds.has(id)).length;
  const allVisibleSelected =
    selectableVisibleIds.length > 0 && selectedVisibleCount === selectableVisibleIds.length;
  const busy =
    acquireFile.isPending || acquireBatch.isPending || resumeFile.isPending || verifyAll.isPending;

  const toggleSelected = (itemId: string, enabled: boolean) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (enabled) next.add(itemId);
      else next.delete(itemId);
      return next;
    });
  };

  const selectVisible = () => {
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const id of selectableVisibleIds) next.add(id);
      return next;
    });
  };

  const clearVisible = () => {
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const id of selectableVisibleIds) next.delete(id);
      return next;
    });
  };

  return (
    <div className="mt-5 border-t border-emerald-200/20 pt-5">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-200">
            Sealed inventory
          </p>
          <h4 className="mt-1 text-base font-semibold text-white">Collection and verification</h4>
        </div>
        <button
          type="button"
          disabled={unverifiedFileIds.length === 0 || verifyAll.isPending}
          onClick={() => {
            verifyAll.mutate(unverifiedFileIds);
          }}
          className="inline-flex min-h-10 items-center justify-center gap-2 rounded border border-emerald-200/25 px-4 text-xs font-semibold text-emerald-100 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {verifyAll.isPending ? (
            <LoaderCircle size={14} className="animate-spin" aria-hidden="true" />
          ) : (
            <Fingerprint size={14} aria-hidden="true" />
          )}
          {verifyAll.isPending
            ? `Verifying ${String(unverifiedFileIds.length)} files...`
            : unverifiedFileIds.length > 0
              ? `Verify all acquired (${String(unverifiedFileIds.length)})`
              : "All acquired files verified"}
        </button>
      </div>
      <p className="text-xs font-semibold text-emerald-200">
        {inventory.persisted_count} path records · {inventory.status}
      </p>
      <p className="mt-1 truncate font-mono text-[10px] text-slate-500" title={inventory.manifest_hash}>
        Manifest SHA-256 {inventory.manifest_hash}
      </p>
      <dl className="mt-4 grid gap-px overflow-hidden rounded border border-white/8 bg-[#d4d6d1] sm:grid-cols-4">
        <RunMetric label="Inventoried" value={String(inScopeItems.length)} icon={Play} />
        <RunMetric label="Acquired" value={String(completedFiles.length)} icon={FileCheck2} />
        <RunMetric label="Verified" value={String(verifiedFiles.length)} icon={Fingerprint} />
        <RunMetric
          label={exceptionCount > 0 ? "Exceptions" : "Acquired size"}
          value={exceptionCount > 0 ? String(exceptionCount) : formatBytes(acquiredBytes)}
          icon={exceptionCount > 0 ? AlertTriangle : ShieldCheck}
          warning={exceptionCount > 0}
        />
      </dl>
      <p className="mt-2 text-[10px] leading-4 text-amber-200/80">
        File acquisition is limited to 100 MiB per selected path (max 50 per bulk batch) and is not
        physically validated. Transfers run sequentially; failures do not abort the rest of the batch.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        {(
          [
            ["all", "All in scope"],
            ["media", "Media"],
            ["documents", "Documents"],
            ["downloads", "Downloads"],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            onClick={() => {
              setFilter(value);
            }}
            className={`min-h-8 rounded-full border px-3 text-[10px] font-semibold uppercase tracking-wide ${
              filter === value
                ? "border-cyan-200/30 bg-cyan-300/15 text-cyan-100"
                : "border-white/10 text-slate-500 hover:border-white/20 hover:text-slate-300"
            }`}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={selectableVisibleIds.length === 0 || busy}
          onClick={() => {
            if (allVisibleSelected) clearVisible();
            else selectVisible();
          }}
          className="min-h-9 rounded border border-white/10 px-3 text-[10px] font-semibold text-slate-300 disabled:opacity-40"
        >
          {allVisibleSelected ? "Clear visible selection" : "Select all visible"}
        </button>
        <button
          type="button"
          disabled={selectedIds.size === 0 || busy}
          onClick={() => {
            acquireBatch.mutate([...selectedIds]);
          }}
          className="inline-flex min-h-9 items-center gap-2 rounded bg-cyan-300 px-3 text-[10px] font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {acquireBatch.isPending ? (
            <LoaderCircle size={13} className="animate-spin" aria-hidden="true" />
          ) : (
            <ShieldCheck size={13} aria-hidden="true" />
          )}
          {acquireBatch.isPending
            ? `Acquiring batch of ${String(selectedIds.size)}…`
            : `Acquire selected (${String(selectedIds.size)})`}
        </button>
        <span className="text-[10px] text-slate-500">
          {String(selectedVisibleCount)} of {String(selectableVisibleIds.length)} visible selectable
        </span>
      </div>
      {lastBatch && (
        <div
          role="status"
          className="mt-3 rounded border border-cyan-200/15 bg-cyan-200/5 p-2 text-[10px] leading-4 text-cyan-100/85"
        >
          Batch {lastBatch.batch_id.slice(0, 8)}… finished: {lastBatch.completed_count} completed ·{" "}
          {lastBatch.failed_count} failed · {lastBatch.skipped_count} skipped of{" "}
          {lastBatch.requested_count} requested.
        </div>
      )}
      <ul className="mt-3 max-h-96 space-y-2 overflow-y-auto pr-1 text-[11px] text-slate-400">
        {visibleItems.length === 0 && (
          <li className="rounded border border-white/5 p-2 text-slate-500">
            No inventory paths match this filter.
          </li>
        )}
        {visibleItems.map((item) => {
          const acquired = acquiredByItem.get(item.id);
          const verification = acquired
            ? latestVerificationByFile.get(acquired.id)
            : undefined;
          const retainedPartial = acquired ? retainedPartialByFile.get(acquired.id) : undefined;
          const needsReview = Boolean(acquired?.partial_preserved && retainedPartial);
          const selectable = isAcquirableStatus(acquired?.status) && !needsReview;
          const selected = selectedIds.has(item.id);
          return (
            <li key={item.id} className="rounded border border-white/5 p-2">
              <div className="flex items-start gap-2">
                <input
                  type="checkbox"
                  className="mt-0.5 size-4 shrink-0 rounded border-white/20 bg-transparent accent-cyan-300 disabled:opacity-30"
                  checked={selected}
                  disabled={!selectable || busy}
                  aria-label={`Select ${item.relative_path}`}
                  onChange={(event) => {
                    toggleSelected(item.id, event.target.checked);
                  }}
                />
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono" title={item.relative_path}>
                    {item.relative_path}
                  </p>
                  {item.modified_at && (
                    <p className="mt-1 text-[10px] text-slate-500">
                      Android-reported modified {new Date(item.modified_at).toLocaleString()}
                      {item.size_bytes !== null ? ` · ${String(item.size_bytes)} bytes` : ""}
                      {item.timestamp_confidence ? ` · ${item.timestamp_confidence} confidence` : ""}
                    </p>
                  )}
                  {acquired?.status === "completed" ? (
                    <div className="mt-2 text-[10px] text-emerald-200">
                      <p>{acquired.size_bytes} bytes acquired</p>
                      <p className="truncate font-mono" title={acquired.sha256 ?? undefined}>
                        SHA-256 {acquired.sha256}
                      </p>
                      <button
                        type="button"
                        disabled={verifyFile.isPending || verificationsQuery.isPending}
                        onClick={() => {
                          verifyFile.mutate(acquired.id);
                        }}
                        className="mt-2 min-h-9 rounded border border-emerald-200/20 px-3 text-[10px] font-semibold text-emerald-100 disabled:opacity-40"
                      >
                        {verifyFile.isPending && verifyFile.variables === acquired.id
                          ? "Verifying..."
                          : "Verify integrity"}
                      </button>
                      {verification && (
                        <p
                          className={`mt-2 font-semibold ${
                            verification.status === "verified"
                              ? "text-emerald-200"
                              : "text-rose-200"
                          }`}
                        >
                          {verification.status === "verified"
                            ? "Integrity verified"
                            : `Integrity ${verification.status}`}
                        </p>
                      )}
                    </div>
                  ) : needsReview && acquired && retainedPartial ? (
                    <div className="mt-2 rounded border border-amber-200/15 bg-amber-200/5 p-2 text-[10px] text-amber-100/80">
                      <p className="font-semibold">Interrupted partial requires review</p>
                      <p className="mt-1">{retainedPartial.size_bytes ?? 0} bytes retained</p>
                      <p className="mt-1 truncate font-mono" title={retainedPartial.sha256 ?? undefined}>
                        SHA-256 {retainedPartial.sha256}
                      </p>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <button
                          type="button"
                          disabled={resumeFile.isPending}
                          onClick={() => {
                            resumeFile.mutate({ evidenceFileId: acquired.id, disposition: "retain" });
                          }}
                          className="min-h-9 rounded border border-cyan-200/20 px-3 font-semibold text-cyan-100 disabled:opacity-40"
                        >
                          Restart and retain partial
                        </button>
                        <button
                          type="button"
                          disabled={resumeFile.isPending}
                          onClick={() => {
                            resumeFile.mutate({ evidenceFileId: acquired.id, disposition: "discard" });
                          }}
                          className="min-h-9 rounded border border-rose-200/20 px-3 font-semibold text-rose-100 disabled:opacity-40"
                        >
                          Verify, discard, and restart
                        </button>
                      </div>
                      <p className="mt-2">Restart begins from byte zero; ADB byte-range resume is not claimed.</p>
                    </div>
                  ) : (
                    <button
                      type="button"
                      disabled={busy || filesQuery.isPending}
                      onClick={() => {
                        acquireFile.mutate(item.id);
                      }}
                      className="mt-2 min-h-9 rounded border border-cyan-200/15 px-3 text-[10px] font-semibold text-cyan-200 disabled:opacity-40"
                    >
                      {acquireFile.isPending && acquireFile.variables === item.id
                        ? "Acquiring..."
                        : acquired?.status === "failed" || acquired?.status === "interrupted"
                          ? "Retry selected file"
                          : "Acquire selected file"}
                    </button>
                  )}
                  {acquired && acquired.status !== "completed" && (
                    <p className="mt-1 text-[10px] text-rose-200">
                      {acquired.error_code ?? acquired.status}
                      {acquired.partial_preserved ? " · partial preserved" : ""}
                    </p>
                  )}
                </div>
              </div>
            </li>
          );
        })}
      </ul>
      {filesQuery.isError && <div className="mt-3"><CaseError error={filesQuery.error} /></div>}
      {verificationsQuery.isError && <div className="mt-3"><CaseError error={verificationsQuery.error} /></div>}
      {partialsQuery.isError && <div className="mt-3"><CaseError error={partialsQuery.error} /></div>}
      {acquireFile.isError && <div className="mt-3"><CaseError error={acquireFile.error} /></div>}
      {acquireBatch.isError && <div className="mt-3"><CaseError error={acquireBatch.error} /></div>}
      {resumeFile.isError && <div className="mt-3"><CaseError error={resumeFile.error} /></div>}
      {verifyFile.isError && <div className="mt-3"><CaseError error={verifyFile.error} /></div>}
      {verifyAll.isError && <div className="mt-3"><CaseError error={verifyAll.error} /></div>}
      {inventory.total > inventory.items.length && (
        <p className="mt-2 text-[10px] text-slate-600">
          Showing {inventory.items.length} of {inventory.total} paths.
        </p>
      )}
    </div>
  );
}

function RunMetric({
  label,
  value,
  icon: Icon,
  warning = false,
}: {
  label: string;
  value: string;
  icon: typeof ShieldCheck;
  warning?: boolean;
}) {
  return (
    <div className="flex items-center gap-3 bg-white p-3">
      <Icon
        size={16}
        aria-hidden="true"
        className={warning ? "text-rose-300" : "text-emerald-300"}
      />
      <div>
        <dt className="text-[10px] uppercase tracking-wide text-slate-500">{label}</dt>
        <dd className="mt-0.5 text-sm font-semibold text-white">{value}</dd>
      </div>
    </div>
  );
}

function shortHash(value: string): string {
  return `${value.slice(0, 8)}...${value.slice(-8)}`;
}

function formatBytes(value: number): string {
  if (value < 1024) return `${String(value)} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
}

function scopeModules(scope: AcquisitionScope, custom: AcquisitionModule[]): AcquisitionModule[] {
  if (scope === "custom") return custom;
  if (scope === "metadata_only") return ["device_metadata", "package_inventory"];
  if (
    scope === "shared_storage_inventory" ||
    scope === "media_files" ||
    scope === "document_files" ||
    scope === "downloads_files"
  ) return ["shared_storage_inventory"];
  return ["device_metadata", "package_inventory", "shared_storage_inventory"];
}

function defaultFilterForScope(scope: AcquisitionScope): InventoryFilter {
  if (scope === "media_files") return "media";
  if (scope === "document_files") return "documents";
  if (scope === "downloads_files") return "downloads";
  return "all";
}

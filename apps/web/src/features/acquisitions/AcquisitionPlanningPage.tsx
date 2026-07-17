import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ClipboardCheck,
  LoaderCircle,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { caseKeys } from "../cases/caseKeys";
import { CaseError } from "../cases/CasesPage";
import {
  cancelAcquisitionJob,
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
  type EvidenceVerification,
} from "../../lib/api";

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
    ? pageOpenedAt <= new Date(latestAssessment.assessed_at).getTime() + 30 * 60 * 1000
    : false;
  const caseWritable = caseQuery.data
    ? !new Set(["closed", "archived"]).has(caseQuery.data.status)
    : false;
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
          Freeze a reviewable module plan against one device and one exact readiness snapshot. Creating
          a plan does not run ADB commands or collect evidence.
        </p>
      </div>

      <div className="mt-7 grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
        <section className="rounded-2xl border border-white/8 bg-white/[0.025] p-6">
          <h2 className="text-lg font-semibold text-white">New immutable plan</h2>
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
    <aside className="rounded-2xl border border-white/8 bg-white/[0.025] p-6">
      <h2 className="text-lg font-semibold text-white">Frozen plan history</h2>
      <div className="mt-4 flex gap-3 rounded-xl border border-cyan-200/10 bg-cyan-200/5 p-3 text-xs leading-5 text-cyan-100/70">
        <ShieldCheck size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
        The bounded executor records relative paths and counts only. It does not pull or read Android file contents.
      </div>
      {pending && <p role="status" className="mt-5 text-sm text-slate-500">Loading plans…</p>}
      {error && <div className="mt-5"><CaseError error={error} /></div>}
      {mutationError && <div className="mt-5"><CaseError error={mutationError} /></div>}
      {!pending && !error && plans.length === 0 && <p className="mt-5 text-sm leading-6 text-slate-500">No acquisition plan has been created for this case.</p>}
      <div className="mt-5 space-y-3">
        {plans.map((plan) => {
          const job = jobs.find((item) => item.plan_id === plan.id);
          const planFresh = referenceTime <= new Date(plan.readiness_expires_at).getTime();
          const cancellable = job && new Set(["created", "validating", "ready", "paused", "interrupted"]).has(job.state);
          const inventoryAllowed = job?.state === "ready" && plan.modules.includes("shared_storage_inventory");
          return (
          <article key={plan.id} className="rounded-xl border border-white/8 bg-black/10 p-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-white">{scopeCopy[plan.scope].label}</h3>
              <span className="rounded-full border border-emerald-200/15 px-2 py-1 text-[10px] uppercase tracking-wide text-emerald-200">{plan.status}</span>
            </div>
            <p className="mt-3 text-xs text-slate-500">{plan.modules.map((module) => moduleLabels[module]).join(" · ")}</p>
            <p className="mt-3 truncate font-mono text-[10px] text-slate-600" title={plan.plan_hash}>SHA-256 {plan.plan_hash}</p>
            <p className="mt-2 text-[11px] text-slate-600">Created {new Date(plan.created_at).toLocaleString()}</p>
            {job ? (
              <div className="mt-4 rounded-lg border border-white/8 bg-white/[0.025] p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-semibold text-slate-300">Durable job</span>
                  <span className="rounded-full border border-cyan-200/15 px-2 py-1 text-[10px] uppercase tracking-wide text-cyan-200">{job.state}</span>
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-500">{job.current_step ?? "Awaiting a safe executor step."}</p>
                <p className="mt-2 text-[11px] text-slate-600">{job.progress_percent}% checkpoint / {job.last_event_sequence} durable events / not running</p>
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
                {job.result_reference && <InventoryResultPanel caseId={plan.case_id} jobId={job.id} />}
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
    </aside>
  );
}

function InventoryResultPanel({ caseId, jobId }: { caseId: string; jobId: string }) {
  const queryClient = useQueryClient();
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
  return (
    <div className="mt-3 rounded-lg border border-emerald-200/10 bg-emerald-200/5 p-3">
      <p className="text-xs font-semibold text-emerald-200">
        {inventory.persisted_count} path records · {inventory.status}
      </p>
      <p className="mt-1 truncate font-mono text-[10px] text-slate-500" title={inventory.manifest_hash}>
        Manifest SHA-256 {inventory.manifest_hash}
      </p>
      <p className="mt-2 text-[10px] leading-4 text-amber-200/80">
        File acquisition is limited to 100 MiB per selected path and is not physically validated.
      </p>
      <ul className="mt-3 max-h-96 space-y-2 overflow-y-auto pr-1 text-[11px] text-slate-400">
        {inventory.items.map((item) => {
          const acquired = acquiredByItem.get(item.id);
          const verification = acquired
            ? latestVerificationByFile.get(acquired.id)
            : undefined;
          const retainedPartial = acquired ? retainedPartialByFile.get(acquired.id) : undefined;
          return (
            <li key={item.id} className="rounded border border-white/5 p-2">
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
              ) : acquired?.partial_preserved && retainedPartial ? (
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
                  disabled={acquireFile.isPending || filesQuery.isPending}
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
            </li>
          );
        })}
      </ul>
      {filesQuery.isError && <div className="mt-3"><CaseError error={filesQuery.error} /></div>}
      {verificationsQuery.isError && <div className="mt-3"><CaseError error={verificationsQuery.error} /></div>}
      {partialsQuery.isError && <div className="mt-3"><CaseError error={partialsQuery.error} /></div>}
      {acquireFile.isError && <div className="mt-3"><CaseError error={acquireFile.error} /></div>}
      {resumeFile.isError && <div className="mt-3"><CaseError error={resumeFile.error} /></div>}
      {verifyFile.isError && <div className="mt-3"><CaseError error={verifyFile.error} /></div>}
      {inventory.total > inventory.items.length && (
        <p className="mt-2 text-[10px] text-slate-600">
          Showing {inventory.items.length} of {inventory.total} paths.
        </p>
      )}
    </div>
  );
}

function scopeModules(scope: AcquisitionScope, custom: AcquisitionModule[]): AcquisitionModule[] {
  if (scope === "custom") return custom;
  if (scope === "metadata_only") return ["device_metadata", "package_inventory"];
  if (scope === "shared_storage_inventory") return ["shared_storage_inventory"];
  return ["device_metadata", "package_inventory", "shared_storage_inventory"];
}

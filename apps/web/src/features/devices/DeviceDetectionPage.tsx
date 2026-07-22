import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Cable,
  Camera,
  CheckCircle2,
  CircleOff,
  Clock3,
  FolderCheck,
  FolderX,
  HardDrive,
  Info,
  LoaderCircle,
  MonitorUp,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  Usb,
  XCircle,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { useState } from "react";

import { caseKeys } from "../cases/caseKeys";
import { useLiveScreenPreview } from "./liveScreenContext";
import {
  ApiError,
  assessDevice,
  capturePhysicalBlock,
  captureRootedBundle,
  captureDeviceScreenshot,
  collectProviderRecords,
  detectDevices,
  getCase,
  getAdbDiagnostic,
  getPhysicalAcquisitionDiagnostic,
  getScrcpyDiagnostic,
  listCaseDevices,
  launchLiveScreen,
  probePhysicalBlock,
  probeRootAccess,
  type CaseDevice,
  type CapabilityDecision,
  type CapabilityStatus,
  type DeviceCapabilityAssessment,
  type DeviceState,
  type DeviceTransport,
  type ProviderProfile,
} from "../../lib/api";

const stateCopy: Record<
  DeviceState,
  { label: string; guidance: string; tone: "success" | "warning" | "danger" | "neutral" }
> = {
  authorized: {
    label: "Authorized",
    guidance: "Ready for a capability assessment. No evidence collection has started.",
    tone: "success",
  },
  unauthorized: {
    label: "Authorization required",
    guidance: "Unlock and approve this workstation on the Android device, then detect again.",
    tone: "warning",
  },
  offline: {
    label: "Device offline",
    guidance: "Reconnect the cable or restart the ADB transport before continuing.",
    tone: "danger",
  },
  recovery: {
    label: "Recovery transport",
    guidance: "This transport is not approved for MVP collection. Review the device state.",
    tone: "warning",
  },
  sideload: {
    label: "Sideload transport",
    guidance: "Sideload mode is not an approved evidence acquisition state.",
    tone: "warning",
  },
  bootloader: {
    label: "Bootloader transport",
    guidance: "Bootloader operations are excluded from Controlled Logical Triage Mode.",
    tone: "warning",
  },
  unknown: {
    label: "Unknown state",
    guidance: "ForensiX will not proceed until the transport state is understood.",
    tone: "danger",
  },
};

export function DeviceDetectionPage() {
  const { caseId } = useParams();
  const queryClient = useQueryClient();
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId ?? "global"),
    queryFn: () => getCase(caseId ?? ""),
    enabled: Boolean(caseId),
  });
  const linkedDevices = useQuery({
    queryKey: caseKeys.devices(caseId ?? "global"),
    queryFn: () => listCaseDevices(caseId ?? ""),
    enabled: Boolean(caseId),
  });
  const detection = useMutation({ mutationFn: () => detectDevices(caseId) });
  const adbDiagnostic = useQuery({
    queryKey: ["integrations", "adb"],
    queryFn: getAdbDiagnostic,
    enabled: false,
  });
  const assessment = useMutation({
    mutationFn: (serial: string) => assessDevice(serial, caseId),
    onSuccess: () => {
      if (caseId) {
        void queryClient.invalidateQueries({ queryKey: caseKeys.devices(caseId) });
      }
    },
  });

  return (
    <div className="mx-auto max-w-6xl">
      {caseId && (
        <div className="mb-6 flex flex-wrap items-center justify-between gap-3 text-sm">
          <Link to={`/cases/${caseId}`} className="text-slate-500 transition hover:text-cyan-200">
            ← Back to case
          </Link>
          <span className="font-mono text-xs text-cyan-300/60">
            {caseQuery.data?.case_number ?? "Loading case context…"}
          </span>
        </div>
      )}
      <div className="flex flex-col justify-between gap-6 border-b border-white/8 pb-8 md:flex-row md:items-end">
        <div className="min-w-0">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-300">
            {caseId ? "Case-scoped readiness" : "Phase 0 · Transport validation"}
          </p>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
            Device readiness
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
            {caseId
              ? "Detect and assess an Android device inside this authorized case. Successful assessments become immutable readiness history."
              : "Detect connected Android transports and classify their authorization state before any case-linked acquisition is allowed."}
          </p>
        </div>
        <button
          type="button"
          disabled={detection.isPending}
          onClick={() => {
            assessment.reset();
            detection.mutate();
          }}
          className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg bg-cyan-300 px-5 py-2.5 text-sm font-semibold text-[#061118] shadow-[0_10px_30px_rgba(34,211,238,0.12)] transition hover:bg-cyan-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-200 disabled:cursor-wait disabled:opacity-60"
        >
          {detection.isPending ? (
            <LoaderCircle aria-hidden="true" className="animate-spin" size={17} />
          ) : detection.data ? (
            <RefreshCw aria-hidden="true" size={17} />
          ) : (
            <Usb aria-hidden="true" size={17} />
          )}
          {detection.isPending
            ? "Detecting devices…"
            : detection.data
              ? "Detect again"
              : "Detect Android devices"}
        </button>
      </div>

      <div className="mt-7 grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px]">
        <section className="min-w-0" aria-live="polite" aria-busy={detection.isPending}>
          {detection.isIdle && <InitialState />}
          {detection.isPending && <DetectingState />}
          {detection.isError && <ErrorState error={detection.error} />}
          {detection.data && (
            <DetectionResult
              devices={detection.data.devices}
              adbVersion={detection.data.adb.version}
              assessment={assessment.data}
              assessmentError={assessment.error}
              assessingSerial={assessment.isPending ? assessment.variables : undefined}
              onAssess={(serial) => {
                assessment.mutate(serial);
              }}
            />
          )}
        </section>
        <aside className="space-y-4">
          <div className="rounded-xl border border-white/8 bg-white/[0.025] p-5">
            <div className="flex items-center justify-between gap-3">
              <h2 className="text-sm font-semibold text-slate-200">ADB workstation check</h2>
              {adbDiagnostic.data && <span className={`rounded-full border px-2 py-1 text-[9px] font-semibold uppercase ${adbDiagnostic.data.status === "healthy" ? "border-emerald-300/20 text-emerald-200" : "border-amber-300/20 text-amber-200"}`}>{adbDiagnostic.data.status.replaceAll("_", " ")}</span>}
            </div>
            {!adbDiagnostic.data && !adbDiagnostic.isPending && <button type="button" onClick={() => { void adbDiagnostic.refetch(); }} className="mt-3 min-h-9 rounded border border-cyan-300/15 px-3 text-xs text-cyan-100">Run workstation check</button>}
            {adbDiagnostic.isPending && <p role="status" className="mt-3 text-xs text-slate-500">Checking the local ADB runtime...</p>}
            {adbDiagnostic.data && (
              <div className="mt-3 text-xs leading-5 text-slate-500">
                <p>Mode: <span className="text-slate-300">{adbDiagnostic.data.mode}</span>{adbDiagnostic.data.version ? ` / ${adbDiagnostic.data.version}` : ""}</p>
                {adbDiagnostic.data.executable_path && <p className="mt-1 break-all font-mono text-[9px] text-slate-600">{adbDiagnostic.data.executable_path}</p>}
                <ul className="mt-3 list-disc space-y-1 pl-4">{adbDiagnostic.data.guidance.map((item) => <li key={item}>{item}</li>)}</ul>
              </div>
            )}
            {adbDiagnostic.isError && <p className="mt-3 text-xs text-rose-200">ADB diagnostics could not be loaded.</p>}
          </div>
          <div className="rounded-xl border border-amber-300/16 bg-amber-300/5 p-5">
            <div className="flex gap-3">
              <AlertTriangle aria-hidden="true" className="mt-0.5 shrink-0 text-amber-300" size={18} />
              <div>
                <h2 className="text-sm font-semibold text-amber-100">Forensic limitation</h2>
                <p className="mt-2 text-sm leading-6 text-amber-100/65">
                  ADB is not a hardware write blocker. Detection and later logical operations can
                  create unavoidable device-side effects; ForensiX records and reports them.
                </p>
              </div>
            </div>
          </div>
          <div className="rounded-xl border border-white/8 bg-white/[0.025] p-5">
            <h2 className="text-sm font-semibold text-slate-200">Readiness sequence</h2>
            <ol className="mt-4 space-y-4 text-sm text-slate-400">
              {[
                "Observe the ADB transport",
                "Confirm authorization state",
                "Assess device capabilities",
                "Review scope and limitations",
              ].map((label, index) => (
                <li key={label} className="flex gap-3">
                  <span className="grid size-6 shrink-0 place-items-center rounded-full border border-white/10 text-xs text-slate-500">
                    {index + 1}
                  </span>
                  <span className="pt-0.5">{label}</span>
                </li>
              ))}
            </ol>
          </div>
        </aside>
      </div>
      {caseId && (
        <LinkedDevices
          devices={linkedDevices.data ?? []}
          isPending={linkedDevices.isPending}
          error={linkedDevices.error}
        />
      )}
    </div>
  );
}

function LinkedDevices({
  devices,
  isPending,
  error,
}: {
  devices: CaseDevice[];
  isPending: boolean;
  error: Error | null;
}) {
  return (
    <section className="mt-8 rounded-xl border border-white/8 bg-white/[0.02] p-5 sm:p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
            Case device registry
          </p>
          <h2 className="mt-2 text-lg font-semibold text-white">Assessed Android devices</h2>
        </div>
        <span className="rounded-full border border-white/10 px-3 py-1 text-xs text-slate-500">
          {devices.length} linked
        </span>
      </div>
      {isPending && <p role="status" className="mt-5 text-sm text-slate-500">Loading device history…</p>}
      {error && <div className="mt-5"><ErrorState error={error} /></div>}
      {!isPending && !error && devices.length === 0 && (
        <p className="mt-5 text-sm leading-6 text-slate-500">
          No device has been registered yet. Assess an authorized transport to create the first
          readiness snapshot.
        </p>
      )}
      {devices.length > 0 && (
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          {devices.map((device) => (
            <article key={device.id} className="rounded-lg border border-white/8 bg-black/10 p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="font-semibold text-slate-100">
                    {[device.manufacturer, device.model].filter(Boolean).join(" ") || "Android device"}
                  </h3>
                  <p className="mt-1 font-mono text-xs text-slate-600">
                    Serial ending {device.serial_suffix}
                  </p>
                </div>
                <ShieldCheck aria-hidden="true" size={17} className="text-emerald-300" />
              </div>
              <p className="mt-4 text-xs text-slate-500">
                Android {device.android_version ?? "unknown"} · API {device.sdk_level ?? "unknown"}
              </p>
              <p className="mt-2 text-xs text-slate-600">
                Last assessed {new Date(device.last_seen_at).toLocaleString()}
              </p>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function InitialState() {
  return (
    <div className="grid min-h-[370px] place-items-center rounded-xl border border-dashed border-white/10 bg-white/[0.018] px-6 text-center">
      <div className="max-w-md">
        <div className="mx-auto grid size-14 place-items-center rounded-2xl border border-cyan-300/15 bg-cyan-300/5 text-cyan-300">
          <Cable aria-hidden="true" size={25} />
        </div>
        <h2 className="mt-5 text-lg font-semibold">No detection run yet</h2>
        <p className="mt-2 text-sm leading-6 text-slate-500">
          Connect a controlled test device by USB. ForensiX will only enumerate transports and
          classify their state at this step.
        </p>
      </div>
    </div>
  );
}

function DetectingState() {
  return (
    <div className="grid min-h-[370px] place-items-center rounded-xl border border-white/8 bg-white/[0.018] px-6 text-center">
      <div role="status">
        <LoaderCircle aria-hidden="true" className="mx-auto animate-spin text-cyan-300" size={30} />
        <p className="mt-4 font-medium">Checking the local ADB transport</p>
        <p className="mt-1 text-sm text-slate-500">This normally completes within five seconds.</p>
      </div>
    </div>
  );
}

function ErrorState({ error }: { error: Error }) {
  const apiError = error instanceof ApiError ? error : undefined;
  return (
    <div role="alert" className="rounded-xl border border-rose-300/20 bg-rose-300/6 p-6">
      <div className="flex gap-4">
        <XCircle aria-hidden="true" className="mt-0.5 shrink-0 text-rose-300" size={21} />
        <div>
          <h2 className="font-semibold text-rose-100">Device detection could not complete</h2>
          <p className="mt-2 text-sm leading-6 text-rose-100/70">{error.message}</p>
          {apiError && (
            <p className="mt-4 font-mono text-xs text-rose-200/50">Request {apiError.requestId}</p>
          )}
        </div>
      </div>
    </div>
  );
}

function DetectionResult({
  devices,
  adbVersion,
  assessment,
  assessmentError,
  assessingSerial,
  onAssess,
}: {
  devices: DeviceTransport[];
  adbVersion: string;
  assessment?: DeviceCapabilityAssessment;
  assessmentError: Error | null;
  assessingSerial?: string;
  onAssess: (serial: string) => void;
}) {
  if (devices.length === 0) {
    return (
      <div className="grid min-h-[370px] place-items-center rounded-xl border border-white/8 bg-white/[0.018] px-6 text-center">
        <div className="max-w-md">
          <CircleOff aria-hidden="true" className="mx-auto text-slate-500" size={30} />
          <h2 className="mt-4 text-lg font-semibold">No Android transport found</h2>
          <p className="mt-2 text-sm leading-6 text-slate-500">
            Check the USB cable, host drivers, and USB debugging configuration. An absent transport
            does not prove that USB debugging is disabled.
          </p>
        </div>
      </div>
    );
  }
  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">
            {devices.length} {devices.length === 1 ? "transport" : "transports"} observed
          </h2>
          <p className="mt-1 text-sm text-slate-500">
            Select exactly one authorized device before capability assessment.
          </p>
        </div>
        <span className="rounded-full border border-white/8 bg-white/3 px-3 py-1 font-mono text-xs text-slate-500">
          ADB {adbVersion}
        </span>
      </div>
      <div className="space-y-3">
        {devices.map((device) => (
          <DeviceCard
            key={`${device.serial}-${device.transport_id ?? "transport"}`}
            device={device}
            isAssessing={assessingSerial === device.serial}
            onAssess={onAssess}
          />
        ))}
      </div>
      {assessmentError && (
        <div className="mt-4">
          <ErrorState error={assessmentError} />
        </div>
      )}
      {assessment && <CapabilityPanel assessment={assessment} />}
    </div>
  );
}

function DeviceCard({
  device,
  isAssessing,
  onAssess,
}: {
  device: DeviceTransport;
  isAssessing: boolean;
  onAssess: (serial: string) => void;
}) {
  const copy = stateCopy[device.state];
  const model = humanize(device.model ?? device.product ?? "Unidentified Android device");
  const tone = {
    success: "border-emerald-300/18 bg-emerald-300/[0.045] text-emerald-200",
    warning: "border-amber-300/18 bg-amber-300/[0.045] text-amber-200",
    danger: "border-rose-300/18 bg-rose-300/[0.045] text-rose-200",
    neutral: "border-white/10 bg-white/[0.025] text-slate-300",
  }[copy.tone];
  const StateIcon = copy.tone === "success" ? CheckCircle2 : AlertTriangle;
  return (
    <article className={`rounded-xl border p-5 ${tone}`}>
      <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-start">
        <div className="flex min-w-0 gap-4">
          <div className="grid size-11 shrink-0 place-items-center rounded-xl border border-current/15 bg-black/10">
            <Smartphone aria-hidden="true" size={20} />
          </div>
          <div className="min-w-0">
            <h3 className="font-semibold text-white">{model}</h3>
            <p className="mt-1 font-mono text-xs opacity-60">Serial ending {maskSerial(device.serial)}</p>
          </div>
        </div>
        <span className="inline-flex w-fit items-center gap-2 rounded-full border border-current/15 bg-black/10 px-3 py-1 text-xs font-semibold">
          <StateIcon aria-hidden="true" size={14} />
          {copy.label}
        </span>
      </div>
      <p className="mt-5 border-t border-current/10 pt-4 text-sm leading-6 opacity-75">
        {copy.guidance}
      </p>
      <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-3">
        <Meta icon={Usb} label="USB" value={device.usb ?? "Not reported"} />
        <Meta icon={HardDrive} label="Device" value={device.device ?? "Not reported"} />
        <Meta icon={Clock3} label="Transport" value={device.transport_id ?? "Not reported"} />
      </dl>
      {device.state === "authorized" && (
        <button
          type="button"
          disabled={isAssessing}
          onClick={() => {
            onAssess(device.serial);
          }}
          className="mt-5 inline-flex min-h-10 items-center gap-2 rounded-lg border border-emerald-200/20 bg-emerald-200/8 px-4 py-2 text-xs font-semibold text-emerald-100 transition hover:bg-emerald-200/12 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-200 disabled:cursor-wait disabled:opacity-60"
        >
          {isAssessing ? (
            <LoaderCircle aria-hidden="true" className="animate-spin" size={15} />
          ) : (
            <ShieldCheck aria-hidden="true" size={15} />
          )}
          {isAssessing ? "Assessing capabilities…" : "Assess capabilities"}
        </button>
      )}
    </article>
  );
}

function CapabilityPanel({ assessment }: { assessment: DeviceCapabilityAssessment }) {
  const entries = Object.entries(assessment.capabilities);
  const [rootAcknowledged, setRootAcknowledged] = useState(false);
  const [captureAcknowledged, setCaptureAcknowledged] = useState(false);
  const [systemCaptureAcknowledged, setSystemCaptureAcknowledged] = useState(false);
  const [physicalProbeAcknowledged, setPhysicalProbeAcknowledged] = useState(false);
  const [physicalAcquisitionAcknowledged, setPhysicalAcquisitionAcknowledged] = useState(false);
  const [encryptionAcknowledged, setEncryptionAcknowledged] = useState(false);
  const [nonResumableAcknowledged, setNonResumableAcknowledged] = useState(false);
  const [providerAcknowledged, setProviderAcknowledged] = useState(false);
  const [screenAcknowledged, setScreenAcknowledged] = useState(false);
  const websitePreview = useLiveScreenPreview();
  const scrcpyDiagnostic = useQuery({
    queryKey: ["integrations", "scrcpy"],
    queryFn: getScrcpyDiagnostic,
    enabled: Boolean(assessment.case_id && assessment.case_device_id),
  });
  const screenshot = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked assessment is required for screenshots.");
      }
      return captureDeviceScreenshot(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
      );
    },
  });
  const liveScreen = useMutation({
    mutationFn: (mode: "mirror" | "control") => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked assessment is required for live screen access.");
      }
      return launchLiveScreen(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        mode,
      );
    },
  });
  const websiteLiveScreen = useMutation({
    mutationFn: async () => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked assessment is required for live screen access.");
      }
      await websitePreview.start({
        caseId: assessment.case_id,
        deviceId: assessment.case_device_id,
        serial: assessment.serial,
        label: `${assessment.manufacturer ?? "Android"} ${assessment.model ?? "device"}`,
      });
    },
  });
  const providerCollection = useMutation({
    mutationFn: (profile: ProviderProfile) => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked assessment is required for provider collection.");
      }
      return collectProviderRecords(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        profile,
      );
    },
  });
  const rootProbe = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked device assessment is required for elevated access.");
      }
      return probeRootAccess(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
      );
    },
    onSuccess: () => {
      setCaptureAcknowledged(false);
    },
  });
  const rootedCapture = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id || !rootProbe.data) {
        throw new Error("A current rooted-access proof is required for this collection.");
      }
      return captureRootedBundle(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        rootProbe.data.id,
        "android_providers",
      );
    },
  });
  const rootedSystemCapture = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id || !rootProbe.data) {
        throw new Error("A current rooted-access proof is required for this collection.");
      }
      return captureRootedBundle(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        rootProbe.data.id,
        "android_system",
      );
    },
  });
  const physicalDiagnostic = useQuery({
    queryKey: ["integrations", "physical-acquisition"],
    queryFn: getPhysicalAcquisitionDiagnostic,
    enabled: rootProbe.data?.status === "available",
  });
  const physicalProbe = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id || !rootProbe.data) {
        throw new Error("A current rooted-access proof is required for this probe.");
      }
      return probePhysicalBlock(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        rootProbe.data.id,
      );
    },
    onSuccess: () => {
      setPhysicalAcquisitionAcknowledged(false);
      setEncryptionAcknowledged(false);
      setNonResumableAcknowledged(false);
    },
  });
  const physicalCapture = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id || !physicalProbe.data) {
        throw new Error("A current physical-block probe is required for this acquisition.");
      }
      return capturePhysicalBlock(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        physicalProbe.data.id,
      );
    },
  });
  return (
    <section className="mt-5 rounded-xl border border-cyan-300/16 bg-cyan-300/[0.035] p-5 sm:p-6">
      <div className="flex flex-col justify-between gap-4 border-b border-cyan-200/10 pb-5 sm:flex-row sm:items-start">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-300">
            Readiness snapshot
          </p>
          <h2 className="mt-2 text-xl font-semibold text-white">
            {assessment.manufacturer} {assessment.model}
          </h2>
          <p className="mt-2 text-sm text-slate-400">
            Android {assessment.android_version ?? "unknown"} · API {assessment.sdk_level ?? "unknown"} ·{" "}
            {assessment.package_count} packages observed
          </p>
        </div>
        <span className="w-fit rounded-full border border-cyan-200/15 bg-cyan-200/5 px-3 py-1 font-mono text-xs text-cyan-100/60">
          Assessment {assessment.assessment_id.slice(0, 8)}
        </span>
      </div>
      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        {entries.map(([capability, decision]) => (
          <CapabilityRow key={capability} capability={capability} decision={decision} />
        ))}
      </div>
      {assessment.case_id && assessment.case_device_id && (
        <div className="mt-5 rounded-lg border border-cyan-200/12 bg-cyan-200/[0.025] p-4">
          <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-200">
            Permitted live provider preview
          </h3>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            These buttons appear only for providers that this exact Android transport allowed.
            Results are real live rows, capped at 500, and the operation is recorded in the case
            audit history.
          </p>
          <label className="mt-3 flex items-start gap-2 text-xs leading-5 text-amber-100/80">
            <input
              type="checkbox"
              checked={providerAcknowledged}
              onChange={(event) => {
                setProviderAcknowledged(event.target.checked);
              }}
              className="mt-1"
            />
            I understand this is a logical live preview, not a sealed filesystem acquisition.
          </label>
          <div className="mt-3 flex flex-wrap gap-2">
            {(
              [
                ["contacts", "contacts", "Collect contacts"],
                ["sms_mms", "sms", "Collect SMS"],
                ["call_logs", "call_log", "Collect call logs"],
              ] as const
            ).map(([capability, profile, label]) => {
              const supported = assessment.capabilities[capability]?.status === "supported";
              return (
                <button
                  key={profile}
                  type="button"
                  disabled={!supported || !providerAcknowledged || providerCollection.isPending}
                  onClick={() => {
                    providerCollection.mutate(profile);
                  }}
                  className="rounded-lg border border-cyan-200/15 bg-cyan-200/5 px-3 py-2 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-200/10 disabled:cursor-not-allowed disabled:opacity-35"
                >
                  {providerCollection.isPending && providerCollection.variables === profile
                    ? "Collecting…"
                    : label}
                </button>
              );
            })}
          </div>
          {providerCollection.error && (
            <p className="mt-3 text-xs text-rose-300">
              {providerCollection.error instanceof ApiError
                ? providerCollection.error.message
                : "Provider collection failed."}
            </p>
          )}
          {providerCollection.data && (
            <div className="mt-4 rounded-md border border-emerald-200/12 bg-emerald-200/[0.035] p-3">
              <p className="text-xs font-semibold text-emerald-200">
                {providerCollection.data.records.length} {providerCollection.data.profile} record(s)
                collected
              </p>
              <p className="mt-1 text-[11px] leading-5 text-slate-500">
                {providerCollection.data.limitation}
              </p>
              <div className="mt-3 max-h-56 space-y-2 overflow-auto">
                {providerCollection.data.records.map((record, index) => (
                  <dl
                    key={`${providerCollection.data.profile}-${String(record._id ?? index)}`}
                    className="grid gap-1 rounded border border-white/7 bg-black/15 p-2 text-[11px]"
                  >
                    {Object.entries(record).map(([key, value]) => (
                      <div key={key} className="grid grid-cols-[8rem_1fr] gap-2">
                        <dt className="font-mono text-slate-500">{key}</dt>
                        <dd className="break-all text-slate-300">{value ?? "NULL"}</dd>
                      </div>
                    ))}
                  </dl>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      {assessment.case_id && assessment.case_device_id && (
        <div className="mt-5 rounded-lg border border-violet-200/15 bg-violet-200/[0.025] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-violet-200">
                Live screen and capture
              </h3>
              <p className="mt-2 max-w-2xl text-xs leading-5 text-slate-400">
                Screenshot streams a PNG directly to the workstation and seals it as hashed case
                evidence. Live mirror and control open a dedicated scrcpy window.
              </p>
            </div>
            <span className="rounded-full border border-violet-200/15 px-2 py-1 text-[10px] uppercase tracking-wider text-violet-200/70">
              {scrcpyDiagnostic.data?.available
                ? `scrcpy ${scrcpyDiagnostic.data.version ?? "ready"}`
                : "scrcpy not configured"}
            </span>
          </div>
          <label className="mt-3 flex items-start gap-2 text-xs leading-5 text-amber-100/80">
            <input
              type="checkbox"
              checked={screenAcknowledged}
              onChange={(event) => {
                setScreenAcknowledged(event.target.checked);
              }}
              className="mt-1"
            />
            I understand continuous website preview repeatedly requests temporary screen frames;
            scrcpy control-mode taps and typing change device state. These actions are recorded.
          </label>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              disabled={!screenAcknowledged || websiteLiveScreen.isPending}
              onClick={() => {
                websiteLiveScreen.mutate();
              }}
              className="inline-flex items-center gap-2 rounded-lg bg-violet-300 px-3 py-2 text-xs font-semibold text-slate-950 transition hover:bg-violet-200 disabled:opacity-35"
            >
              <MonitorUp size={14} />
              {websiteLiveScreen.isPending ? "Starting previewâ€¦" : "Show screen in website"}
            </button>
            <button
              type="button"
              disabled={screenshot.isPending}
              onClick={() => {
                screenshot.mutate();
              }}
              className="inline-flex items-center gap-2 rounded-lg border border-emerald-200/15 bg-emerald-200/5 px-3 py-2 text-xs font-semibold text-emerald-100 transition hover:bg-emerald-200/10 disabled:opacity-40"
            >
              <Camera size={14} />
              {screenshot.isPending ? "Capturing…" : "Capture evidence screenshot"}
            </button>
            <button
              type="button"
              disabled={
                !screenAcknowledged || !scrcpyDiagnostic.data?.available || liveScreen.isPending
              }
              onClick={() => {
                liveScreen.mutate("mirror");
              }}
              className="inline-flex items-center gap-2 rounded-lg border border-cyan-200/15 bg-cyan-200/5 px-3 py-2 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-200/10 disabled:opacity-35"
            >
              <MonitorUp size={14} /> Read-only mirror
            </button>
            <button
              type="button"
              disabled={
                !screenAcknowledged || !scrcpyDiagnostic.data?.available || liveScreen.isPending
              }
              onClick={() => {
                liveScreen.mutate("control");
              }}
              className="inline-flex items-center gap-2 rounded-lg border border-amber-200/20 bg-amber-200/5 px-3 py-2 text-xs font-semibold text-amber-100 transition hover:bg-amber-200/10 disabled:opacity-35"
            >
              <MonitorUp size={14} /> Interactive control
            </button>
          </div>
          {!scrcpyDiagnostic.isLoading && !scrcpyDiagnostic.data?.available && (
            <p className="mt-3 text-xs leading-5 text-slate-500">
              Install the official scrcpy release and set FORENSIX_SCRCPY_PATH before using live
              mirror or control. Screenshot capture works through ADB without scrcpy.
            </p>
          )}
          {screenshot.data && (
            <p className="mt-3 text-xs text-emerald-200">
              Screenshot sealed · SHA-256 {screenshot.data.sha256?.slice(0, 16)}… · source {" "}
              {screenshot.data.id.slice(0, 8)}
            </p>
          )}
          {(screenshot.error || liveScreen.error || websiteLiveScreen.error) && (
            <p className="mt-3 text-xs text-rose-300">
              {screenshot.error instanceof ApiError
                ? screenshot.error.message
                : liveScreen.error instanceof ApiError
                  ? liveScreen.error.message
                  : websiteLiveScreen.error instanceof ApiError
                    ? websiteLiveScreen.error.message
                  : "The screen operation could not be completed."}
            </p>
          )}
          {liveScreen.data && (
            <p className="mt-3 text-xs text-violet-200">
              {liveScreen.data.mode === "control" ? "Control" : "Mirror"} window launched · process
              {" "}
              {liveScreen.data.process_id}
            </p>
          )}
        </div>
      )}
      <div className="mt-5 rounded-lg border border-white/8 bg-black/10 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-300">
            Content-free root probe
          </h3>
          <span className="text-[10px] uppercase tracking-[0.12em] text-slate-600">
            No files enumerated
          </span>
        </div>
        {assessment.storage_roots.length === 0 ? (
          <p className="mt-3 text-xs leading-5 text-slate-500">
            This older readiness snapshot did not include fixed-root checks.
          </p>
        ) : (
          <div className="mt-3 grid gap-2 sm:grid-cols-2">
            {assessment.storage_roots.map((root) => {
              const accessible = root.status === "accessible";
              const RootIcon = accessible ? FolderCheck : FolderX;
              return (
                <div
                  key={root.root_id}
                  className={`flex items-center gap-3 rounded-md border px-3 py-2 text-xs ${
                    accessible
                      ? "border-emerald-200/12 bg-emerald-200/5 text-emerald-200"
                      : "border-rose-200/12 bg-rose-200/5 text-rose-200"
                  }`}
                >
                  <RootIcon size={15} aria-hidden="true" className="shrink-0" />
                  <span className="min-w-0">
                    <span className="block truncate font-mono">{root.display_path}</span>
                    <span className="mt-0.5 block text-[10px] uppercase tracking-wide opacity-55">
                      {root.status}
                    </span>
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
      <div className="mt-5 rounded-lg border border-amber-200/12 bg-amber-200/5 p-4">
        <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-amber-200">
          Assessment warnings
        </h3>
        <ul className="mt-3 space-y-2 text-sm leading-6 text-amber-100/65">
          {assessment.warnings.map((warning) => (
            <li key={warning} className="flex gap-2">
              <AlertTriangle aria-hidden="true" className="mt-1 shrink-0" size={14} />
              {warning}
            </li>
          ))}
        </ul>
      </div>
      {assessment.case_id && assessment.case_device_id && (
        <div className="mt-5 rounded-lg border border-fuchsia-300/15 bg-fuchsia-300/[0.035] p-4">
          <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-fuchsia-200">
            Optional rooted mode
          </h3>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            This runs only the fixed, serial-scoped command <code>su -c id</code>. It may create
            device logs or display a root-manager prompt. It does not bypass a lock screen or grant
            root access.
          </p>
          <label className="mt-3 flex items-start gap-3 text-xs leading-5 text-fuchsia-100/70">
            <input
              type="checkbox"
              checked={rootAcknowledged}
              onChange={(event) => {
                setRootAcknowledged(event.target.checked);
              }}
              className="mt-1 accent-fuchsia-300"
            />
            I authorize this elevated-access probe and acknowledge its possible device-side effects.
          </label>
          <button
            type="button"
            disabled={!rootAcknowledged || rootProbe.isPending}
            onClick={() => {
              rootProbe.mutate();
            }}
            className="mt-4 inline-flex min-h-9 items-center gap-2 rounded-lg border border-fuchsia-300/20 bg-fuchsia-300/8 px-4 text-xs font-semibold text-fuchsia-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {rootProbe.isPending ? <LoaderCircle size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
            Probe rooted access
          </button>
          {rootProbe.isError && <div className="mt-3"><ErrorState error={rootProbe.error} /></div>}
          {rootProbe.data && (
            <div className={`mt-4 rounded-md border p-3 text-xs ${
              rootProbe.data.status === "available"
                ? "border-emerald-300/20 bg-emerald-300/5 text-emerald-100"
                : "border-amber-300/20 bg-amber-300/5 text-amber-100"
            }`}>
              <p className="font-semibold">Root access {rootProbe.data.status}</p>
              <p className="mt-1 opacity-70">{rootProbe.data.reason_code.replaceAll("_", " ")}</p>
              <p className="mt-2 font-mono text-[10px] opacity-55">
                Proof {rootProbe.data.probe_hash} · expires {new Date(rootProbe.data.expires_at).toLocaleTimeString()}
              </p>
            </div>
          )}
          {rootProbe.data?.status === "available" && (
            <div className="mt-4 border-t border-fuchsia-200/10 pt-4">
              <p className="text-xs font-semibold text-white">Bounded provider collection</p>
              <p className="mt-2 text-xs leading-5 text-slate-400">
                Streams only fixed contacts, telephony, and calendar provider database directories
                into a TAR, then immediately seals it as Evidence Twin evidence. This is not a
                physical or bit-for-bit device image.
              </p>
              <label className="mt-3 flex items-start gap-3 text-xs leading-5 text-fuchsia-100/70">
                <input
                  type="checkbox"
                  checked={captureAcknowledged}
                  onChange={(event) => {
                    setCaptureAcknowledged(event.target.checked);
                  }}
                  className="mt-1 accent-fuchsia-300"
                />
                I authorize this bounded rooted collection and acknowledge device logs and
                root-manager activity may be created.
              </label>
              <button
                type="button"
                disabled={!captureAcknowledged || rootedCapture.isPending}
                onClick={() => {
                  rootedCapture.mutate();
                }}
                className="mt-4 inline-flex min-h-9 items-center gap-2 rounded-lg bg-fuchsia-200 px-4 text-xs font-semibold text-[#12091a] disabled:cursor-not-allowed disabled:opacity-40"
              >
                {rootedCapture.isPending ? (
                  <LoaderCircle size={14} className="animate-spin" />
                ) : (
                  <HardDrive size={14} />
                )}
                {rootedCapture.isPending ? "Capturing and sealing…" : "Capture provider bundle"}
              </button>
              {rootedCapture.isError && (
                <div className="mt-3">
                  <ErrorState error={rootedCapture.error} />
                </div>
              )}
              {rootedCapture.data && (
                <div className="mt-4 rounded-md border border-emerald-300/20 bg-emerald-300/5 p-3 text-xs text-emerald-100">
                  <p className="font-semibold">Evidence Twin source sealed</p>
                  <p className="mt-1 font-mono text-[10px] opacity-65">
                    SHA-256 {rootedCapture.data.sha256}
                  </p>
                  <Link
                    to={`/cases/${assessment.case_id}/evidence-twin`}
                    className="mt-3 inline-flex font-semibold text-cyan-200 underline decoration-cyan-300/30 underline-offset-4"
                  >
                    Open Evidence Twin workspace
                  </Link>
                </div>
              )}
              <div className="mt-5 border-t border-fuchsia-200/10 pt-4">
                <p className="text-xs font-semibold text-white">Bounded system-artifact collection</p>
                <p className="mt-2 text-xs leading-5 text-slate-400">
                  Streams a fixed allowlist covering Downloads, Chrome History, notification and
                  settings XML, Wi-Fi configuration, Bluetooth state, and location-service paths.
                  OEM and Android-version differences may leave some paths absent. This bundle can
                  contain credentials and other highly sensitive records.
                </p>
                <label className="mt-3 flex items-start gap-3 text-xs leading-5 text-fuchsia-100/70">
                  <input
                    type="checkbox"
                    checked={systemCaptureAcknowledged}
                    onChange={(event) => {
                      setSystemCaptureAcknowledged(event.target.checked);
                    }}
                    className="mt-1 accent-fuchsia-300"
                  />
                  I authorize the fixed system-artifact allowlist and acknowledge sensitive
                  network, browser, location, and device configuration data may be collected.
                </label>
                <button
                  type="button"
                  disabled={!systemCaptureAcknowledged || rootedSystemCapture.isPending}
                  onClick={() => {
                    rootedSystemCapture.mutate();
                  }}
                  className="mt-4 inline-flex min-h-9 items-center gap-2 rounded-lg bg-fuchsia-200 px-4 text-xs font-semibold text-[#12091a] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {rootedSystemCapture.isPending ? (
                    <LoaderCircle size={14} className="animate-spin" />
                  ) : (
                    <HardDrive size={14} />
                  )}
                  {rootedSystemCapture.isPending
                    ? "Capturing system artifacts…"
                    : "Capture system-artifact bundle"}
                </button>
                {rootedSystemCapture.isError && (
                  <div className="mt-3"><ErrorState error={rootedSystemCapture.error} /></div>
                )}
                {rootedSystemCapture.data && (
                  <div className="mt-4 rounded-md border border-emerald-300/20 bg-emerald-300/5 p-3 text-xs text-emerald-100">
                    <p className="font-semibold">System-artifact Evidence Twin source sealed</p>
                    <p className="mt-1 font-mono text-[10px] opacity-65">
                      SHA-256 {rootedSystemCapture.data.sha256}
                    </p>
                    <Link
                      to={`/cases/${assessment.case_id}/evidence-twin`}
                      className="mt-3 inline-flex font-semibold text-cyan-200 underline decoration-cyan-300/30 underline-offset-4"
                    >
                      Examine system-artifact bundle
                    </Link>
                  </div>
                )}
              </div>
              <div className="mt-5 border-t border-rose-200/10 pt-4">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-rose-200">
                  Experimental raw userdata image
                </p>
                {physicalDiagnostic.isPending && (
                  <p role="status" className="mt-2 text-xs text-slate-500">
                    Checking workstation policy…
                  </p>
                )}
                {physicalDiagnostic.isError && (
                  <div className="mt-3"><ErrorState error={physicalDiagnostic.error} /></div>
                )}
                {physicalDiagnostic.data && !physicalDiagnostic.data.enabled && (
                  <p className="mt-2 text-xs leading-5 text-slate-400">
                    Disabled by default. An administrator must explicitly set
                    <code className="mx-1 text-rose-200">FORENSIX_ENABLE_EXPERIMENTAL_PHYSICAL_ACQUISITION=true</code>
                    after validating the test device and storage capacity.
                  </p>
                )}
                {physicalDiagnostic.data?.enabled && (
                  <>
                    <p className="mt-2 text-xs leading-5 text-rose-100/75">
                      {physicalDiagnostic.data.warning} The fixed target is
                      <code className="mx-1">/dev/block/by-name/userdata</code>; no arbitrary block
                      path can be supplied.
                    </p>
                    <label className="mt-3 flex items-start gap-3 text-xs leading-5 text-rose-100/75">
                      <input
                        type="checkbox"
                        checked={physicalProbeAcknowledged}
                        onChange={(event) => {
                          setPhysicalProbeAcknowledged(event.target.checked);
                        }}
                        className="mt-1 accent-rose-300"
                      />
                      I authorize a metadata-only probe of the fixed userdata block and understand
                      that root-manager and device logs may change.
                    </label>
                    <button
                      type="button"
                      disabled={!physicalProbeAcknowledged || physicalProbe.isPending}
                      onClick={() => {
                        physicalProbe.mutate();
                      }}
                      className="mt-3 inline-flex min-h-9 items-center gap-2 rounded-lg border border-rose-300/25 bg-rose-300/8 px-4 text-xs font-semibold text-rose-100 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {physicalProbe.isPending ? <LoaderCircle size={14} className="animate-spin" /> : <HardDrive size={14} />}
                      Probe userdata block
                    </button>
                    {physicalProbe.isError && <div className="mt-3"><ErrorState error={physicalProbe.error} /></div>}
                    {physicalProbe.data && (
                      <div className="mt-3 rounded-md border border-rose-300/15 bg-black/10 p-3 text-xs text-slate-300">
                        <p className="font-semibold text-rose-100">Fixed block located</p>
                        <p className="mt-1 font-mono">{physicalProbe.data.device_path}</p>
                        <p className="mt-1">
                          {formatBytes(physicalProbe.data.size_bytes)} · encryption {physicalProbe.data.encryption_state}
                        </p>
                      </div>
                    )}
                    {physicalProbe.data && (
                      <div className="mt-4 space-y-2 border-t border-rose-200/10 pt-4">
                        {[
                          [physicalAcquisitionAcknowledged, setPhysicalAcquisitionAcknowledged, "I authorize the full raw stream and acknowledge that ADB is not a hardware write blocker."],
                          [encryptionAcknowledged, setEncryptionAcknowledged, "I understand the resulting image may remain encrypted and ForensiX does not bypass the lock screen."],
                          [nonResumableAcknowledged, setNonResumableAcknowledged, "I understand this experimental stream can take hours and cannot currently resume after interruption."],
                        ].map(([checked, setter, label]) => (
                          <label key={String(label)} className="flex items-start gap-3 text-xs leading-5 text-rose-100/75">
                            <input
                              type="checkbox"
                              checked={checked as boolean}
                              onChange={(event) => {
                                (setter as (value: boolean) => void)(event.target.checked);
                              }}
                              className="mt-1 accent-rose-300"
                            />
                            {label as string}
                          </label>
                        ))}
                        <button
                          type="button"
                          disabled={
                            !physicalAcquisitionAcknowledged ||
                            !encryptionAcknowledged ||
                            !nonResumableAcknowledged ||
                            physicalCapture.isPending
                          }
                          onClick={() => {
                            physicalCapture.mutate();
                          }}
                          className="mt-2 inline-flex min-h-9 items-center gap-2 rounded-lg bg-rose-200 px-4 text-xs font-semibold text-[#19080b] disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          {physicalCapture.isPending ? <LoaderCircle size={14} className="animate-spin" /> : <HardDrive size={14} />}
                          {physicalCapture.isPending ? "Streaming and sealing…" : "Acquire experimental raw image"}
                        </button>
                        {physicalCapture.isError && <ErrorState error={physicalCapture.error} />}
                        {physicalCapture.data && (
                          <div className="rounded-md border border-emerald-300/20 bg-emerald-300/5 p-3 text-xs text-emerald-100">
                            <p className="font-semibold">Physical Evidence Twin source sealed</p>
                            <p className="mt-1 font-mono text-[10px] opacity-65">SHA-256 {physicalCapture.data.sha256}</p>
                            <Link
                              to={`/cases/${assessment.case_id}/evidence-twin`}
                              className="mt-3 inline-flex font-semibold text-cyan-200 underline decoration-cyan-300/30 underline-offset-4"
                            >
                              Open physical source in Evidence Twin
                            </Link>
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}
      {assessment.case_device_id && (
        <p className="mt-4 flex items-center gap-2 text-xs font-medium text-emerald-200/75">
          <CheckCircle2 size={14} aria-hidden="true" /> Snapshot saved to this case's device history.
        </p>
      )}
    </section>
  );
}

function CapabilityRow({
  capability,
  decision,
}: {
  capability: string;
  decision: CapabilityDecision;
}) {
  const tone: Record<CapabilityStatus, string> = {
    supported: "border-emerald-200/12 bg-emerald-200/5 text-emerald-200",
    unsupported: "border-rose-200/12 bg-rose-200/5 text-rose-200",
    unknown: "border-amber-200/12 bg-amber-200/5 text-amber-200",
    blocked: "border-slate-200/12 bg-slate-200/5 text-slate-300",
  };
  return (
    <article className={`rounded-lg border p-4 ${tone[decision.status]}`}>
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-white">{humanize(capability)}</h3>
        <span className="text-[10px] font-semibold uppercase tracking-[0.14em]">
          {decision.status}
        </span>
      </div>
      <p className="mt-2 text-xs leading-5 opacity-65">{decision.explanation}</p>
    </article>
  );
}

function Meta({ icon: Icon, label, value }: { icon: typeof Info; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2 opacity-60">
      <Icon aria-hidden="true" size={14} />
      <dt className="sr-only">{label}</dt>
      <dd className="truncate" title={`${label}: ${value}`}>
        {value}
      </dd>
    </div>
  );
}

function maskSerial(serial: string): string {
  return serial.length <= 5 ? serial : serial.slice(-5);
}

function formatBytes(sizeBytes: number): string {
  if (sizeBytes < 1024) return `${String(sizeBytes)} B`;
  if (sizeBytes < 1024 ** 2) return `${(sizeBytes / 1024).toFixed(1)} KiB`;
  if (sizeBytes < 1024 ** 3) return `${(sizeBytes / 1024 ** 2).toFixed(1)} MiB`;
  return `${(sizeBytes / 1024 ** 3).toFixed(1)} GiB`;
}

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

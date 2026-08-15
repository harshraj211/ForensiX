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
  Square,
  Usb,
  Video,
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
  captureWithTemporaryRoot,
  captureDeviceScreenshot,
  collectProviderRecords,
  detectDevices,
  getCase,
  getAdbDiagnostic,
  getPhysicalAcquisitionDiagnostic,
  getScrcpyDiagnostic,
  listCaseDevices,
  listRootAccessProbes,
  listScreenRecordings,
  launchLiveScreen,
  probePhysicalBlock,
  probeRootAccess,
  startScreenRecording,
  stopScreenRecording,
  type CaseDevice,
  type CapabilityDecision,
  type CapabilityStatus,
  type DeviceCapabilityAssessment,
  type DeviceState,
  type DeviceTransport,
  type ProviderProfile,
  type RootedCollectionProfile,
} from "../../lib/api";

const selectiveRootedProfiles: ReadonlyArray<{
  profile: RootedCollectionProfile;
  label: string;
  detail: string;
}> = [
  { profile: "android_contacts", label: "Contacts", detail: "Android contacts database only" },
  { profile: "android_messages", label: "SMS / MMS messages", detail: "Android telephony message databases only" },
  { profile: "android_call_log", label: "Call history", detail: "Android call-log database only" },
  { profile: "whatsapp", label: "WhatsApp", detail: "WhatsApp databases, key file, and settings" },
  { profile: "telegram", label: "Telegram", detail: "Telegram message cache and settings" },
  { profile: "signal", label: "Signal", detail: "Signal databases and settings; encryption may remain" },
  { profile: "messenger", label: "Messenger", detail: "Facebook Messenger databases only" },
  { profile: "instagram", label: "Instagram", detail: "Instagram databases only" },
  { profile: "snapchat", label: "Snapchat", detail: "Snapchat databases only" },
];

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
          <div className="rounded-md border border-[#d8c28d] bg-[#fbf5e6] p-5 text-[#674100]">
            <div className="flex gap-3">
              <AlertTriangle aria-hidden="true" className="mt-0.5 shrink-0 text-[#8a5700]" size={18} />
              <div>
                <h2 className="text-sm font-semibold text-[#674100]">Forensic limitation</h2>
                <p className="mt-2 text-sm leading-6 text-[#76541b]">
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
  const queryClient = useQueryClient();
  const entries = Object.entries(assessment.capabilities).filter(
    ([, decision]) => decision.status === "supported",
  );
  const acquisitionReadiness = assessment.acquisition_readiness ?? {
    encryption_type: "unknown" as const,
    credential_storage_state: "unknown" as const,
    chipset_family: "unknown" as const,
    filesystem_status: "root_and_unlock_verification_required" as const,
    explanation: "This older assessment did not record filesystem acquisition readiness.",
  };
  const temporaryRootReadiness = assessment.temporary_root_readiness ?? {
    eligibility_status: "unknown" as const,
    provider_status: "not_configured" as const,
    reference_android_range: "4.0-10.0",
    reference_max_security_patch: "2019-10-31",
    explanation: "This older assessment did not evaluate temporary-root eligibility.",
  };
  const isTemporaryRootCandidate =
    temporaryRootReadiness.eligibility_status === "candidate_requires_validated_profile";
  const isTemporaryRootAvailable =
    temporaryRootReadiness.provider_status === "exact_profile_match";
  const [temporaryRootAuthorityAcknowledged, setTemporaryRootAuthorityAcknowledged] =
    useState(false);
  const [temporaryRootModificationAcknowledged, setTemporaryRootModificationAcknowledged] =
    useState(false);
  const [temporaryRootCleanupAcknowledged, setTemporaryRootCleanupAcknowledged] = useState(false);
  const [rootAcknowledged, setRootAcknowledged] = useState(false);
  const [captureAcknowledged, setCaptureAcknowledged] = useState(false);
  const [systemCaptureAcknowledged, setSystemCaptureAcknowledged] = useState(false);
  const [appCaptureAcknowledged, setAppCaptureAcknowledged] = useState(false);
  const [selectedRootedProfiles, setSelectedRootedProfiles] = useState<RootedCollectionProfile[]>([]);
  const [selectiveCaptureAcknowledged, setSelectiveCaptureAcknowledged] = useState(false);
  const [userDataCaptureAcknowledged, setUserDataCaptureAcknowledged] = useState(false);
  const [physicalProbeAcknowledged, setPhysicalProbeAcknowledged] = useState(false);
  const [physicalAcquisitionAcknowledged, setPhysicalAcquisitionAcknowledged] = useState(false);
  const [encryptionAcknowledged, setEncryptionAcknowledged] = useState(false);
  const [nonResumableAcknowledged, setNonResumableAcknowledged] = useState(false);
  const [providerAcknowledged, setProviderAcknowledged] = useState(false);
  const [selectedProviderIds, setSelectedProviderIds] = useState<Set<string>>(new Set());
  const [panelOpenedAt] = useState(() => Date.now());
  const [screenAcknowledged, setScreenAcknowledged] = useState(false);
  const [recordingAcknowledged, setRecordingAcknowledged] = useState(false);
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
  const recordingKey = [
    "screen-recordings",
    assessment.case_id,
    assessment.case_device_id,
  ] as const;
  const recordings = useQuery({
    queryKey: recordingKey,
    queryFn: () => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked assessment is required for screen recording.");
      }
      return listScreenRecordings(assessment.case_id, assessment.case_device_id);
    },
    enabled: Boolean(
      assessment.case_id &&
        assessment.case_device_id &&
        scrcpyDiagnostic.data?.available,
    ),
    refetchInterval: 5000,
  });
  const activeRecording = recordings.data?.find((recording) => recording.status === "active");
  const screenRecording = useMutation({
    mutationFn: async () => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked assessment is required for screen recording.");
      }
      if (activeRecording) {
        return stopScreenRecording(
          activeRecording.id,
          assessment.case_id,
          assessment.case_device_id,
          assessment.serial,
        );
      }
      return startScreenRecording(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
      );
    },
    onSuccess: (recording) => {
      queryClient.setQueryData(recordingKey, (current: typeof recordings.data) => {
        const remaining = (current ?? []).filter((item) => item.id !== recording.id);
        return [recording, ...remaining];
      });
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
    mutationFn: ({
      profile,
      selectedRecordIds = [],
      sealSelected = false,
    }: {
      profile: ProviderProfile;
      selectedRecordIds?: string[];
      sealSelected?: boolean;
    }) => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked assessment is required for provider collection.");
      }
      return collectProviderRecords(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        profile,
        selectedRecordIds,
        sealSelected,
      );
    },
    onSuccess: (result, variables) => {
      if (!variables.sealSelected) {
        setSelectedProviderIds(new Set(result.records.map((record) => String(record._id))));
      }
    },
  });
  const rootProbeHistory = useQuery({
    queryKey: ["root-probes", assessment.case_id, assessment.case_device_id],
    queryFn: () => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked device is required for root history.");
      }
      return listRootAccessProbes(assessment.case_id, assessment.case_device_id);
    },
    enabled: Boolean(assessment.case_id && assessment.case_device_id),
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
      setSystemCaptureAcknowledged(false);
      setAppCaptureAcknowledged(false);
      void queryClient.invalidateQueries({
        queryKey: ["root-probes", assessment.case_id, assessment.case_device_id],
      });
    },
  });
  const latestRootProbe = rootProbe.data ?? rootProbeHistory.data?.[0];
  const effectiveRootProbe =
    latestRootProbe && new Date(latestRootProbe.expires_at).getTime() > panelOpenedAt
      ? latestRootProbe
      : undefined;
  const rootedCapture = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id || !effectiveRootProbe) {
        throw new Error("A current rooted-access proof is required for this collection.");
      }
      return captureRootedBundle(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        effectiveRootProbe.id,
        "android_providers",
      );
    },
  });
  const rootedSystemCapture = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id || !effectiveRootProbe) {
        throw new Error("A current rooted-access proof is required for this collection.");
      }
      return captureRootedBundle(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        effectiveRootProbe.id,
        "android_system",
      );
    },
  });
  const rootedAppCapture = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id || !effectiveRootProbe) {
        throw new Error("A current rooted-access proof is required for this collection.");
      }
      return captureRootedBundle(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        effectiveRootProbe.id,
        "android_apps",
      );
    },
  });
  const selectiveRootedCapture = useMutation({
    mutationFn: async () => {
      if (!assessment.case_id || !assessment.case_device_id || !effectiveRootProbe) {
        throw new Error("A current rooted-access proof is required for this collection.");
      }
      const captured = [];
      for (const profile of selectedRootedProfiles) {
        captured.push({
          profile,
          source: await captureRootedBundle(
            assessment.case_id,
            assessment.case_device_id,
            assessment.serial,
            effectiveRootProbe.id,
            profile,
          ),
        });
      }
      return captured;
    },
  });
  const temporaryRootCapture = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id) {
        throw new Error("A case-linked assessment is required for temporary root.");
      }
      return captureWithTemporaryRoot(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        "android_providers",
      );
    },
  });
  const rootedUserDataCapture = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id || !effectiveRootProbe) {
        throw new Error("A current rooted-access proof is required for this collection.");
      }
      return captureRootedBundle(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        effectiveRootProbe.id,
        "android_userdata",
      );
    },
  });
  const physicalDiagnostic = useQuery({
    queryKey: ["integrations", "physical-acquisition"],
    queryFn: getPhysicalAcquisitionDiagnostic,
    enabled: effectiveRootProbe?.status === "available",
  });
  const physicalProbe = useMutation({
    mutationFn: () => {
      if (!assessment.case_id || !assessment.case_device_id || !effectiveRootProbe) {
        throw new Error("A current rooted-access proof is required for this probe.");
      }
      return probePhysicalBlock(
        assessment.case_id,
        assessment.case_device_id,
        assessment.serial,
        effectiveRootProbe.id,
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
      <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
        <span className="rounded-full border border-white/10 px-2 py-1 font-semibold text-slate-300">
          {latestRootProbe?.status === "available"
            ? "Rooted device"
            : latestRootProbe
              ? "Non-rooted device"
              : "Root access not verified"}
        </span>
        <span>
          {latestRootProbe && !effectiveRootProbe
            ? "The previous root proof expired. Run a fresh check before rooted acquisition."
            : "Only supported options are shown."}
        </span>
        {!effectiveRootProbe && assessment.case_id && assessment.case_device_id && (
          <div className="flex w-full flex-wrap items-center gap-2 pt-1">
            <label className="flex items-center gap-2 text-amber-800">
              <input
                type="checkbox"
                checked={rootAcknowledged}
                onChange={(event) => { setRootAcknowledged(event.target.checked); }}
              />
              Authorize the fixed root check; it may trigger a root-manager prompt.
            </label>
            <button
              type="button"
              disabled={!rootAcknowledged || rootProbe.isPending}
              onClick={() => { rootProbe.mutate(); }}
              className="min-h-8 rounded border border-neutral-300 bg-white px-3 font-semibold text-neutral-900 disabled:opacity-40"
            >
              {rootProbe.isPending ? "Checking..." : "Check root status"}
            </button>
          </div>
        )}
      </div>
      {assessment.case_id && assessment.case_device_id && (
        <div className="mt-5 rounded-lg border border-cyan-200/12 bg-cyan-200/[0.025] p-4">
          <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-200">
            Selective logical acquisition
          </h3>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            Non-rooted ADB options only. Preview fixed, permitted records, select exactly what is
            relevant, then seal those rows as hashed case evidence. Unsupported providers are hidden.
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
            I understand preview reads live logical records; only my final selection is sealed.
          </label>
          <div className="mt-3 flex flex-wrap gap-2">
            {(
              [
                ["device_metadata", "device_info", "Preview device info"],
                ["contacts", "contacts", "Preview contacts"],
                ["sms_mms", "sms", "Preview messages"],
                ["call_logs", "call_log", "Preview call logs"],
              ] as const
            ).map(([capability, profile, label]) => {
              const supported =
                profile === "device_info" ||
                assessment.capabilities[capability]?.status === "supported";
              return (
                <button
                  key={profile}
                  type="button"
                  disabled={!supported || !providerAcknowledged || providerCollection.isPending}
                  onClick={() => {
                    setSelectedProviderIds(new Set());
                    providerCollection.mutate({ profile });
                  }}
                  className="rounded-lg border border-cyan-200/15 bg-cyan-200/5 px-3 py-2 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-200/10 disabled:cursor-not-allowed disabled:opacity-35"
                >
                  {providerCollection.isPending && providerCollection.variables.profile === profile
                    ? "Reading..."
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
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-xs font-semibold text-emerald-200">
                  {providerCollection.data.records.length}{" "}
                  {providerCollection.data.profile.replaceAll("_", " ")} record(s) available
                </p>
                <button
                  type="button"
                  disabled={selectedProviderIds.size === 0 || providerCollection.isPending}
                  onClick={() => {
                    providerCollection.mutate({
                      profile: providerCollection.data.profile,
                      selectedRecordIds: [...selectedProviderIds],
                      sealSelected: true,
                    });
                  }}
                  className="min-h-9 rounded bg-emerald-300 px-3 text-[11px] font-semibold text-emerald-950 disabled:opacity-40"
                >
                  Acquire selected ({selectedProviderIds.size})
                </button>
              </div>
              <p className="mt-1 text-[11px] leading-5 text-slate-500">
                {providerCollection.data.limitation}
              </p>
              <div className="mt-3 max-h-56 space-y-2 overflow-auto">
                {providerCollection.data.records.map((record, index) => {
                  const recordId = String(record._id ?? index);
                  return (
                    <label
                      key={`${providerCollection.data.profile}-${recordId}`}
                      className="flex gap-3 rounded border border-white/7 bg-black/15 p-3 text-[11px]"
                    >
                      <input
                        type="checkbox"
                        checked={selectedProviderIds.has(recordId)}
                        onChange={(event) => {
                          setSelectedProviderIds((current) => {
                            const next = new Set(current);
                            if (event.target.checked) next.add(recordId);
                            else next.delete(recordId);
                            return next;
                          });
                        }}
                        className="mt-0.5 size-4 shrink-0 accent-emerald-300"
                      />
                      <dl className="min-w-0 flex-1 space-y-1">
                        {Object.entries(record).map(([key, value]) => (
                          <div key={key} className="grid gap-1 sm:grid-cols-[8rem_1fr] sm:gap-2">
                            <dt className="font-mono text-slate-500">{key}</dt>
                            <dd className="break-all text-slate-300">{value ?? "NULL"}</dd>
                          </div>
                        ))}
                      </dl>
                    </label>
                  );
                })}
              </div>
              {providerCollection.data.evidence_source_id && (
                <div className="mt-3 rounded border border-emerald-200/15 bg-emerald-200/5 p-3 text-[11px] text-emerald-100">
                  <p className="font-semibold">Selection sealed as case evidence</p>
                  <p className="mt-1 break-all font-mono">SHA-256 {providerCollection.data.evidence_sha256}</p>
                  <p className="mt-1 break-all font-mono text-emerald-100/60">
                    Key {providerCollection.data.evidence_storage_key}
                  </p>
                </div>
              )}
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
              {websiteLiveScreen.isPending ? "Starting preview…" : "Show screen in website"}
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
              scrcpy is unavailable. The Windows portable build includes it automatically; source
              checkouts must configure FORENSIX_SCRCPY_PATH. Screenshot capture works through ADB
              without scrcpy.
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
          <div className="mt-4 border-t border-violet-200/10 pt-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h4 className="flex items-center gap-2 text-xs font-semibold text-white">
                  <Video size={14} aria-hidden="true" /> Documented examination
                </h4>
                <p className="mt-1 max-w-2xl text-[11px] leading-5 text-slate-400">
                  Record the interactive scrcpy window, then seal the MP4 into this case with its
                  hash and custody history.
                </p>
              </div>
              {activeRecording && (
                <span className="inline-flex items-center gap-2 rounded-full border border-rose-300/20 bg-rose-300/8 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-rose-200">
                  <span className="h-1.5 w-1.5 rounded-full bg-rose-300" /> Recording
                </span>
              )}
            </div>
            {!activeRecording && (
              <label className="mt-3 flex items-start gap-2 text-xs leading-5 text-amber-100/80">
                <input
                  type="checkbox"
                  checked={recordingAcknowledged}
                  onChange={(event) => {
                    setRecordingAcknowledged(event.target.checked);
                  }}
                  className="mt-1"
                />
                I understand this records displayed pixels and my control actions change device
                state; it is documentation, not a full acquisition.
              </label>
            )}
            <button
              type="button"
              disabled={
                screenRecording.isPending ||
                !scrcpyDiagnostic.data?.available ||
                (!activeRecording && !recordingAcknowledged)
              }
              onClick={() => {
                screenRecording.mutate();
              }}
              className={`mt-3 inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition disabled:cursor-not-allowed disabled:opacity-35 ${
                activeRecording
                  ? "border border-rose-200/20 bg-rose-200/5 text-rose-100 hover:bg-rose-200/10"
                  : "bg-white text-slate-950 hover:bg-slate-200"
              }`}
            >
              {activeRecording ? <Square size={13} /> : <Video size={14} />}
              {screenRecording.isPending
                ? activeRecording
                  ? "Stopping and sealing..."
                  : "Starting recording..."
                : activeRecording
                  ? "Stop and seal recording"
                  : "Start documented session"}
            </button>
            {screenRecording.data?.status === "sealed" && (
              <p className="mt-3 text-xs text-emerald-200">
                Recording and MP4 stored · SHA-256 {screenRecording.data.sha256?.slice(0, 16)}... · source {" "}
                {screenRecording.data.evidence_source_id?.slice(0, 8)}
              </p>
            )}
            {screenRecording.error && (
              <p className="mt-3 text-xs text-rose-300">
                {screenRecording.error instanceof ApiError
                  ? screenRecording.error.message
                  : "The documented examination could not be completed."}
              </p>
            )}
          </div>
        </div>
      )}
      <div className="mt-5 rounded-lg border border-white/8 bg-black/10 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-white/8 pb-4">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-300">
              Filesystem acquisition readiness
            </h3>
            <p className="mt-2 max-w-2xl text-xs leading-5 text-slate-400">
              {acquisitionReadiness.explanation}
            </p>
          </div>
          <span className="rounded-full border border-white/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-300">
            {acquisitionReadiness.filesystem_status.replaceAll("_", " ")}
          </span>
        </div>
        <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-3">
          <div>
            <dt className="text-slate-500">Encryption</dt>
            <dd className="mt-1 font-semibold text-slate-200">
              {acquisitionReadiness.encryption_type.replaceAll("_", " ")}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Credential storage</dt>
            <dd className="mt-1 font-semibold text-slate-200">
              {acquisitionReadiness.credential_storage_state}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Chipset family</dt>
            <dd className="mt-1 font-semibold text-slate-200">
              {acquisitionReadiness.chipset_family.replaceAll("_", " ")}
            </dd>
          </div>
        </dl>
      </div>
      <div className={`mt-5 rounded-lg border p-4 ${
        isTemporaryRootCandidate
          ? "border-amber-200/15 bg-amber-200/5"
          : "border-white/8 bg-black/10"
      }`}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-300">
              Temporary-root eligibility
            </h3>
            <p className="mt-2 max-w-2xl text-xs leading-5 text-slate-400">
              {temporaryRootReadiness.explanation}
            </p>
          </div>
          <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider ${
            isTemporaryRootCandidate
              ? "border-amber-200/20 text-amber-200"
              : "border-white/10 text-slate-300"
          }`}>
            {temporaryRootReadiness.eligibility_status.replaceAll("_", " ")}
          </span>
        </div>
        <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-3">
          <div>
            <dt className="text-slate-500">Reference Android range</dt>
            <dd className="mt-1 font-semibold text-slate-200">
              {temporaryRootReadiness.reference_android_range}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Latest reference patch</dt>
            <dd className="mt-1 font-semibold text-slate-200">
              October 2019
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Validated provider</dt>
            <dd className="mt-1 font-semibold text-slate-200">
              {temporaryRootReadiness.provider_status.replaceAll("_", " ")}
            </dd>
          </div>
        </dl>
        <p className="mt-4 text-[11px] leading-5 text-slate-500">
          Eligibility is not confirmed root access. ForensiX will not execute temporary rooting
          until the exact model, chipset, firmware, and build fingerprint match a separately
          validated provider profile.
        </p>
        {isTemporaryRootAvailable ? (
          <div className="mt-4 border-t border-white/8 pt-4">
            <div className="space-y-2 text-xs leading-5 text-slate-300">
              <label className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={temporaryRootAuthorityAcknowledged}
                  onChange={(event) => {
                    setTemporaryRootAuthorityAcknowledged(event.target.checked);
                  }}
                  className="mt-1 accent-amber-300"
                />
                I confirm explicit legal authority for temporary privilege elevation and collection.
              </label>
              <label className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={temporaryRootModificationAcknowledged}
                  onChange={(event) => {
                    setTemporaryRootModificationAcknowledged(event.target.checked);
                  }}
                  className="mt-1 accent-amber-300"
                />
                I acknowledge the provider may modify volatile device state and create logs.
              </label>
              <label className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={temporaryRootCleanupAcknowledged}
                  onChange={(event) => {
                    setTemporaryRootCleanupAcknowledged(event.target.checked);
                  }}
                  className="mt-1 accent-amber-300"
                />
                I authorize provider cleanup, device reboot, and post-cleanup root verification.
              </label>
            </div>
            <button
              type="button"
              disabled={
                !temporaryRootAuthorityAcknowledged ||
                !temporaryRootModificationAcknowledged ||
                !temporaryRootCleanupAcknowledged ||
                temporaryRootCapture.isPending
              }
              onClick={() => {
                temporaryRootCapture.mutate();
              }}
              className="mt-4 inline-flex min-h-9 items-center gap-2 rounded-lg bg-amber-200 px-4 text-xs font-semibold text-[#171006] disabled:cursor-not-allowed disabled:opacity-40"
            >
              {temporaryRootCapture.isPending ? (
                <LoaderCircle size={14} className="animate-spin" />
              ) : (
                <ShieldCheck size={14} />
              )}
              {temporaryRootCapture.isPending
                ? "Running controlled workflow..."
                : "Temporarily root and capture providers"}
            </button>
            {temporaryRootCapture.isError && (
              <div className="mt-3">
                <ErrorState error={temporaryRootCapture.error} />
              </div>
            )}
            {temporaryRootCapture.data && (
              <div className="mt-3 rounded-md border border-emerald-300/20 bg-emerald-300/5 p-3 text-xs text-emerald-100">
                <p className="font-semibold">Temporary-root capture sealed and cleanup verified</p>
                <p className="mt-1 font-mono text-[10px] opacity-65">
                  SHA-256 {temporaryRootCapture.data.sha256}
                </p>
              </div>
            )}
          </div>
        ) : (
          <p className="mt-3 text-xs text-amber-200/75">
            Execution remains unavailable until this exact device build has a configured,
            hash-pinned provider profile.
          </p>
        )}
      </div>
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
            Detect root status
          </button>
          {rootProbe.isError && <div className="mt-3"><ErrorState error={rootProbe.error} /></div>}
          {latestRootProbe && (
            <div className={`mt-4 rounded-md border p-3 text-xs ${
              latestRootProbe.status === "available"
                ? "border-emerald-300/20 bg-emerald-300/5 text-emerald-100"
                : "border-amber-300/20 bg-amber-300/5 text-amber-100"
            }`}>
              <p className="font-semibold">Root access {latestRootProbe.status}</p>
              <p className="mt-1 opacity-70">{latestRootProbe.reason_code.replaceAll("_", " ")}</p>
              <p className="mt-2 font-mono text-[10px] opacity-55">
                Proof {latestRootProbe.probe_hash} · expires {new Date(latestRootProbe.expires_at).toLocaleTimeString()}
              </p>
            </div>
          )}
          {latestRootProbe && latestRootProbe.status !== "available" && (
            <div className="mt-3 rounded-md border border-cyan-200/15 bg-cyan-200/5 p-3 text-xs leading-5 text-cyan-100/75">
              <p className="font-semibold">Non-rooted acquisition mode</p>
              <p className="mt-1">
                Private WhatsApp, Telegram, Signal, and other app databases are unavailable, so
                those acquisition controls are hidden. Shared photos, videos, audio, documents,
                and any Android providers explicitly permitted by this device remain available.
              </p>
            </div>
          )}
          {effectiveRootProbe?.status === "available" && (
            <div className="mt-4 border-t border-fuchsia-200/10 pt-4">
              <div className="rounded-lg border border-emerald-200/15 bg-emerald-200/[0.035] p-4">
                <p className="text-sm font-semibold text-white">Choose exactly what to acquire</p>
                <p className="mt-2 text-xs leading-5 text-slate-400">
                  This phone is rooted. Each checked item is captured and sealed separately; unchecked
                  data is not included. Application choices are never shown as available for a phone
                  whose root check fails.
                </p>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  {selectiveRootedProfiles.map((item) => (
                    <label key={item.profile} className="flex gap-3 rounded-lg border border-white/8 p-3">
                      <input
                        type="checkbox"
                        checked={selectedRootedProfiles.includes(item.profile)}
                        onChange={(event) => {
                          setSelectedRootedProfiles((current) => event.target.checked
                            ? [...current, item.profile]
                            : current.filter((profile) => profile !== item.profile));
                          setSelectiveCaptureAcknowledged(false);
                        }}
                        className="mt-1 accent-fuchsia-300"
                      />
                      <span>
                        <span className="block text-xs font-semibold text-white">{item.label}</span>
                        <span className="mt-1 block text-[10px] leading-4 text-slate-500">{item.detail}</span>
                      </span>
                    </label>
                  ))}
                </div>
                <label className="mt-3 flex items-start gap-3 text-xs leading-5 text-fuchsia-100/70">
                  <input
                    type="checkbox"
                    checked={selectiveCaptureAcknowledged}
                    onChange={(event) => { setSelectiveCaptureAcknowledged(event.target.checked); }}
                    className="mt-1 accent-fuchsia-300"
                  />
                  I authorize acquisition of only the checked data types and acknowledge that
                  private records and account material may be collected.
                </label>
                <button
                  type="button"
                  disabled={
                    selectedRootedProfiles.length === 0 ||
                    !selectiveCaptureAcknowledged ||
                    selectiveRootedCapture.isPending
                  }
                  onClick={() => { selectiveRootedCapture.mutate(); }}
                  className="mt-4 inline-flex min-h-9 items-center gap-2 rounded-lg bg-fuchsia-200 px-4 text-xs font-semibold text-[#12091a] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {selectiveRootedCapture.isPending
                    ? <LoaderCircle size={14} className="animate-spin" />
                    : <HardDrive size={14} />}
                  {selectiveRootedCapture.isPending
                    ? "Acquiring selected data..."
                    : `Acquire selected (${String(selectedRootedProfiles.length)})`}
                </button>
                {selectiveRootedCapture.isError && <div className="mt-3"><ErrorState error={selectiveRootedCapture.error} /></div>}
                {selectiveRootedCapture.data && (
                  <div className="mt-4 rounded-md border border-emerald-300/20 bg-emerald-300/5 p-3 text-xs text-emerald-100">
                    <p className="font-semibold">{selectiveRootedCapture.data.length} selected evidence source(s) sealed</p>
                    <ul className="mt-2 space-y-1 font-mono text-[10px] opacity-70">
                      {selectiveRootedCapture.data.map(({ profile, source }) => (
                        <li key={profile}>{profile.replaceAll("_", " ")}: SHA-256 {source.sha256}</li>
                      ))}
                    </ul>
                    <Link to={`/cases/${assessment.case_id}/evidence-twin`} className="mt-3 inline-flex font-semibold text-cyan-200 underline">
                      Examine selected data
                    </Link>
                  </div>
                )}
              </div>
              <p className="mt-5 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                Advanced full-profile collections (optional)
              </p>
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
              <div className="mt-5 border-t border-fuchsia-200/10 pt-4">
                <p className="text-xs font-semibold text-white">
                  Bounded private-application collection
                </p>
                <p className="mt-2 text-xs leading-5 text-slate-400">
                  Streams only fixed WhatsApp, Telegram, Signal, Messenger, Facebook, Instagram,
                  and Snapchat database or configuration paths that exist on this rooted test
                  device. Application schemas vary. Telegram records may use binary encoding, and
                  ForensiX does not bypass or decrypt Signal encryption. A live database and its
                  WAL files may not represent an atomic snapshot.
                </p>
                <div className="mt-3 rounded-md border border-amber-300/15 bg-amber-300/5 p-3 text-xs leading-5 text-amber-100/80">
                  This bundle can contain messages, account identifiers, authentication material,
                  and other highly sensitive private data. Capture only under explicit legal
                  authority.
                </div>
                <label className="mt-3 flex items-start gap-3 text-xs leading-5 text-fuchsia-100/70">
                  <input
                    type="checkbox"
                    checked={appCaptureAcknowledged}
                    onChange={(event) => {
                      setAppCaptureAcknowledged(event.target.checked);
                    }}
                    className="mt-1 accent-fuchsia-300"
                  />
                  I authorize the fixed private-application allowlist and acknowledge that
                  sensitive account data may be collected while encrypted records may remain
                  unreadable.
                </label>
                <button
                  type="button"
                  disabled={!appCaptureAcknowledged || rootedAppCapture.isPending}
                  onClick={() => {
                    rootedAppCapture.mutate();
                  }}
                  className="mt-4 inline-flex min-h-9 items-center gap-2 rounded-lg bg-fuchsia-200 px-4 text-xs font-semibold text-[#12091a] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {rootedAppCapture.isPending ? (
                    <LoaderCircle size={14} className="animate-spin" />
                  ) : (
                    <HardDrive size={14} />
                  )}
                  {rootedAppCapture.isPending
                    ? "Capturing private applications…"
                    : "Capture private-app bundle"}
                </button>
                {rootedAppCapture.isError && (
                  <div className="mt-3">
                    <ErrorState error={rootedAppCapture.error} />
                  </div>
                )}
                {rootedAppCapture.data && (
                  <div className="mt-4 rounded-md border border-emerald-300/20 bg-emerald-300/5 p-3 text-xs text-emerald-100">
                    <p className="font-semibold">
                      Private-application Evidence Twin source sealed
                    </p>
                    <p className="mt-1 font-mono text-[10px] opacity-65">
                      SHA-256 {rootedAppCapture.data.sha256}
                    </p>
                    <Link
                      to={`/cases/${assessment.case_id}/evidence-twin`}
                      className="mt-3 inline-flex font-semibold text-cyan-200 underline decoration-cyan-300/30 underline-offset-4"
                    >
                      Examine private-application bundle
                    </Link>
                  </div>
                )}
              </div>
              <div className="mt-5 border-t border-fuchsia-200/10 pt-4">
                <p className="text-xs font-semibold text-white">
                  Rooted user-data filesystem snapshot
                </p>
                <p className="mt-2 text-xs leading-5 text-slate-400">
                  Streams fixed Android user, device-encrypted user, system, service, and internal
                  shared-storage paths into one TAR. The workstation stops the stream at 8 GiB and
                  seals a successful snapshot as Evidence Twin evidence. This is not a bit-for-bit
                  image, does not recover deleted blocks, and may be inconsistent if applications
                  change files during capture.
                </p>
                <div className="mt-3 rounded-md border border-amber-300/15 bg-amber-300/5 p-3 text-xs leading-5 text-amber-100/80">
                  This broad snapshot can contain credentials, messages, account tokens, location
                  history, and private files. Use only on an unlocked device under explicit legal
                  authority with an existing authorized root environment.
                </div>
                <label className="mt-3 flex items-start gap-3 text-xs leading-5 text-fuchsia-100/70">
                  <input
                    type="checkbox"
                    checked={userDataCaptureAcknowledged}
                    onChange={(event) => {
                      setUserDataCaptureAcknowledged(event.target.checked);
                    }}
                    className="mt-1 accent-fuchsia-300"
                  />
                  I authorize collection of the fixed broad user-data profile and acknowledge its
                  sensitive scope, live-filesystem limitations, and 8 GiB stream cap.
                </label>
                <button
                  type="button"
                  disabled={!userDataCaptureAcknowledged || rootedUserDataCapture.isPending}
                  onClick={() => {
                    rootedUserDataCapture.mutate();
                  }}
                  className="mt-4 inline-flex min-h-9 items-center gap-2 rounded-lg bg-fuchsia-200 px-4 text-xs font-semibold text-[#12091a] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {rootedUserDataCapture.isPending ? (
                    <LoaderCircle size={14} className="animate-spin" />
                  ) : (
                    <HardDrive size={14} />
                  )}
                  {rootedUserDataCapture.isPending
                    ? "Capturing user-data snapshot..."
                    : "Capture user-data snapshot"}
                </button>
                {rootedUserDataCapture.isError && (
                  <div className="mt-3">
                    <ErrorState error={rootedUserDataCapture.error} />
                  </div>
                )}
                {rootedUserDataCapture.data && (
                  <div className="mt-4 rounded-md border border-emerald-300/20 bg-emerald-300/5 p-3 text-xs text-emerald-100">
                    <p className="font-semibold">User-data Evidence Twin source sealed</p>
                    <p className="mt-1 font-mono text-[10px] opacity-65">
                      SHA-256 {rootedUserDataCapture.data.sha256}
                    </p>
                    <Link
                      to={`/cases/${assessment.case_id}/evidence-twin`}
                      className="mt-3 inline-flex font-semibold text-cyan-200 underline decoration-cyan-300/30 underline-offset-4"
                    >
                      Examine user-data snapshot
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

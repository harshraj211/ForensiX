import { useMutation } from "@tanstack/react-query";
import {
  AlertTriangle,
  Cable,
  CheckCircle2,
  CircleOff,
  Clock3,
  HardDrive,
  Info,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  Usb,
  XCircle,
} from "lucide-react";

import {
  ApiError,
  assessDevice,
  detectDevices,
  type CapabilityDecision,
  type CapabilityStatus,
  type DeviceCapabilityAssessment,
  type DeviceState,
  type DeviceTransport,
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
  const detection = useMutation({ mutationFn: () => detectDevices() });
  const assessment = useMutation({ mutationFn: (serial: string) => assessDevice(serial) });

  return (
    <div className="mx-auto max-w-6xl">
      <div className="flex flex-col justify-between gap-6 border-b border-white/8 pb-8 md:flex-row md:items-end">
        <div className="min-w-0">
          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-300">
            Phase 0 · Transport validation
          </p>
          <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
            Device readiness
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
            Detect connected Android transports and classify their authorization state before any
            case-linked acquisition is allowed.
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
    </div>
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

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

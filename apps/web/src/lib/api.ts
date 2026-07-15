export type DeviceState =
  | "authorized"
  | "unauthorized"
  | "offline"
  | "recovery"
  | "sideload"
  | "bootloader"
  | "unknown";

export interface DeviceTransport {
  serial: string;
  state: DeviceState;
  raw_state: string;
  product: string | null;
  model: string | null;
  device: string | null;
  transport_id: string | null;
  usb: string | null;
}

export interface DeviceDetection {
  detection_id: string;
  observed_at: string;
  result: "no_devices" | "single_device" | "multiple_devices";
  adb: { version: string; executable_path: string };
  devices: DeviceTransport[];
}

export type CapabilityStatus = "supported" | "unsupported" | "unknown" | "blocked";

export interface CapabilityDecision {
  status: CapabilityStatus;
  reason_code: string;
  explanation: string;
}

export interface DeviceCapabilityAssessment {
  assessment_id: string;
  assessed_at: string;
  serial: string;
  manufacturer: string | null;
  model: string | null;
  android_version: string | null;
  sdk_level: number | null;
  build_fingerprint: string | null;
  security_patch: string | null;
  package_count: number;
  capabilities: Record<string, CapabilityDecision>;
  warnings: string[];
  assessor_version: string;
}

interface ErrorEnvelope {
  error?: {
    code?: string;
    message?: string;
    request_id?: string;
  };
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly requestId: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function detectDevices(signal?: AbortSignal): Promise<DeviceDetection> {
  const response = await fetch("/api/v1/devices/detect", {
    method: "POST",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    signal,
  });
  const body = (await response.json()) as DeviceDetection | ErrorEnvelope;
  if (!response.ok) {
    const envelope = body as ErrorEnvelope;
    throw new ApiError(
      envelope.error?.message ?? "ForensiX could not complete device detection.",
      envelope.error?.code ?? "DEVICE_DETECTION_FAILED",
      envelope.error?.request_id ?? response.headers.get("X-Request-ID") ?? "unknown",
      response.status,
    );
  }
  return body as DeviceDetection;
}

export async function assessDevice(serial: string): Promise<DeviceCapabilityAssessment> {
  const response = await fetch("/api/v1/devices/assess", {
    method: "POST",
    credentials: "same-origin",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ serial }),
  });
  const body = (await response.json()) as DeviceCapabilityAssessment | ErrorEnvelope;
  if (!response.ok) {
    const envelope = body as ErrorEnvelope;
    throw new ApiError(
      envelope.error?.message ?? "ForensiX could not assess this device.",
      envelope.error?.code ?? "DEVICE_ASSESSMENT_FAILED",
      envelope.error?.request_id ?? response.headers.get("X-Request-ID") ?? "unknown",
      response.status,
    );
  }
  return body as DeviceCapabilityAssessment;
}

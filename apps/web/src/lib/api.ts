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

export interface AuthUser {
  user_id: string;
  username: string;
  display_name: string;
  roles: string[];
  permissions: string[];
}

export interface AuthSession {
  user: AuthUser;
  expires_at: string;
  csrf_token: string;
}

export interface BootstrapStatus {
  bootstrap_required: boolean;
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

let inMemoryCsrfToken: string | null = null;

export function rememberCsrfToken(token: string | null) {
  inMemoryCsrfToken = token;
}

export function getBootstrapStatus(): Promise<BootstrapStatus> {
  return apiRequest("/api/v1/auth/bootstrap-status");
}

export function getCurrentUser(): Promise<AuthUser> {
  return apiRequest("/api/v1/auth/me");
}

export async function bootstrapAdministrator(input: {
  username: string;
  display_name: string;
  password: string;
}): Promise<AuthSession> {
  const session = await apiRequest<AuthSession>("/api/v1/auth/bootstrap", {
    method: "POST",
    body: JSON.stringify(input),
  });
  rememberCsrfToken(session.csrf_token);
  return session;
}

export async function login(input: {
  username: string;
  password: string;
}): Promise<AuthSession> {
  const session = await apiRequest<AuthSession>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify(input),
  });
  rememberCsrfToken(session.csrf_token);
  return session;
}

export async function logout(): Promise<void> {
  await apiRequest<undefined>("/api/v1/auth/logout", { method: "POST" });
  rememberCsrfToken(null);
}

export async function detectDevices(signal?: AbortSignal): Promise<DeviceDetection> {
  return apiRequest("/api/v1/devices/detect", {
    method: "POST",
    signal,
  });
}

export async function assessDevice(serial: string): Promise<DeviceCapabilityAssessment> {
  return apiRequest("/api/v1/devices/assess", {
    method: "POST",
    body: JSON.stringify({ serial }),
  });
}

async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = options.method?.toUpperCase() ?? "GET";
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (!new Set(["GET", "HEAD", "OPTIONS"]).has(method)) {
    const csrfToken = inMemoryCsrfToken ?? readCookie("forensix_csrf");
    if (csrfToken) {
      headers.set("X-CSRF-Token", csrfToken);
    }
  }

  const response = await fetch(path, {
    ...options,
    method,
    credentials: "same-origin",
    headers,
  });
  if (response.status === 204) {
    return undefined as T;
  }
  const body = (await response.json()) as T | ErrorEnvelope;
  if (!response.ok) {
    const envelope = body as ErrorEnvelope;
    throw new ApiError(
      envelope.error?.message ?? "ForensiX could not complete the local request.",
      envelope.error?.code ?? "API_REQUEST_FAILED",
      envelope.error?.request_id ?? response.headers.get("X-Request-ID") ?? "unknown",
      response.status,
    );
  }
  return body as T;
}

function readCookie(name: string): string | null {
  const prefix = `${encodeURIComponent(name)}=`;
  const entry = document.cookie.split("; ").find((cookie) => cookie.startsWith(prefix));
  return entry ? decodeURIComponent(entry.slice(prefix.length)) : null;
}

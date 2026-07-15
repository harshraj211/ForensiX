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
  case_id: string | null;
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
  case_id: string | null;
  case_device_id: string | null;
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

export type CaseStatus = "open" | "active" | "closed" | "archived";

export interface CaseRecord {
  id: string;
  case_number: string;
  title: string;
  description: string | null;
  legal_authority: string | null;
  status: CaseStatus;
  created_by: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  version: number;
}

export interface CaseList {
  items: CaseRecord[];
  total: number;
  offset: number;
  limit: number;
}

export interface CaseDevice {
  id: string;
  case_id: string;
  serial_suffix: string;
  manufacturer: string | null;
  model: string | null;
  android_version: string | null;
  sdk_level: number | null;
  build_fingerprint: string | null;
  security_patch: string | null;
  registered_by: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface CaseDeviceAssessment {
  id: string;
  case_id: string;
  device_id: string;
  assessed_by: string;
  assessed_at: string;
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

export function listCases(): Promise<CaseList> {
  return apiRequest("/api/v1/cases?offset=0&limit=50");
}

export function getCase(caseId: string): Promise<CaseRecord> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}`);
}

export function createCase(input: {
  title: string;
  description?: string;
  legal_authority?: string;
}): Promise<CaseRecord> {
  return apiRequest("/api/v1/cases", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function transitionCase(
  caseId: string,
  expectedVersion: number,
  status: CaseStatus,
): Promise<CaseRecord> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/transition`, {
    method: "POST",
    body: JSON.stringify({ expected_version: expectedVersion, status }),
  });
}

export async function detectDevices(
  caseId?: string,
  signal?: AbortSignal,
): Promise<DeviceDetection> {
  const query = caseId ? `?case_id=${encodeURIComponent(caseId)}` : "";
  return apiRequest(`/api/v1/devices/detect${query}`, {
    method: "POST",
    signal,
  });
}

export async function assessDevice(
  serial: string,
  caseId?: string,
): Promise<DeviceCapabilityAssessment> {
  return apiRequest("/api/v1/devices/assess", {
    method: "POST",
    body: JSON.stringify({ serial, ...(caseId ? { case_id: caseId } : {}) }),
  });
}

export function listCaseDevices(caseId: string): Promise<CaseDevice[]> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/devices`);
}

export function listCaseDeviceAssessments(
  caseId: string,
  deviceId: string,
): Promise<CaseDeviceAssessment[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/devices/${encodeURIComponent(deviceId)}/assessments`,
  );
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

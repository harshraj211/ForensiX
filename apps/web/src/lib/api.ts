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

export type StorageProbeStatus = "accessible" | "missing" | "blocked";

export interface SharedStorageRootProbe {
  root_id: string;
  display_path: string;
  status: StorageProbeStatus;
  exists: boolean;
  readable: boolean;
  reason_code: string;
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
  storage_roots: SharedStorageRootProbe[];
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
  storage_roots: SharedStorageRootProbe[];
  capabilities: Record<string, CapabilityDecision>;
  warnings: string[];
  assessor_version: string;
}

export type AcquisitionScope =
  | "metadata_only"
  | "quick_triage"
  | "shared_storage_inventory"
  | "custom";

export type AcquisitionModule =
  | "device_metadata"
  | "package_inventory"
  | "shared_storage_inventory";

export interface AcquisitionPlan {
  id: string;
  case_id: string;
  device_id: string;
  assessment_id: string;
  created_by: string;
  scope: AcquisitionScope;
  status: "ready";
  modules: AcquisitionModule[];
  limitations: string[];
  snapshot_hash: string;
  plan_hash: string;
  schema_version: string;
  readiness_assessed_at: string;
  readiness_expires_at: string;
  created_at: string;
}

export interface AcquisitionPlanList {
  items: AcquisitionPlan[];
  total: number;
  offset: number;
  limit: number;
}

export type AcquisitionJobState =
  | "created"
  | "validating"
  | "ready"
  | "running"
  | "paused"
  | "cancelling"
  | "cancelled"
  | "interrupted"
  | "failed"
  | "completed"
  | "verifying"
  | "verified";

export interface AcquisitionJob {
  id: string;
  case_id: string;
  plan_id: string;
  owner_id: string;
  state: AcquisitionJobState;
  progress_percent: number;
  current_step: string | null;
  current_module: string | null;
  cancellation_requested: boolean;
  resume_supported: boolean;
  checkpoint: Record<string, unknown> | null;
  error_code: string | null;
  error_message: string | null;
  result_reference: string | null;
  last_event_sequence: number;
  version: number;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
  executor_available: false;
}

export interface AcquisitionJobList {
  items: AcquisitionJob[];
  total: number;
  offset: number;
  limit: number;
}

export interface AcquisitionInventoryItem {
  id: string;
  ordinal: number;
  relative_path: string;
  path_hash: string;
  extension: string | null;
}

export interface AcquisitionInventory {
  id: string;
  job_id: string;
  case_id: string;
  plan_id: string;
  device_id: string;
  created_by: string;
  root_id: string;
  display_path: string;
  status: "completed" | "truncated";
  discovered_count: number;
  persisted_count: number;
  skipped_count: number;
  max_items: number;
  max_depth: number;
  manifest_hash: string;
  started_at: string;
  completed_at: string;
  items: AcquisitionInventoryItem[];
  total: number;
  offset: number;
  limit: number;
}

export interface AcquiredEvidenceFile {
  id: string;
  inventory_id: string;
  inventory_item_id: string;
  job_id: string;
  case_id: string;
  plan_id: string;
  device_id: string;
  acquired_by: string;
  status: "acquiring" | "completed" | "failed" | "interrupted";
  source_root_id: string;
  source_path_hash: string;
  storage_key: string;
  manifest_storage_key: string;
  size_bytes: number | null;
  sha256: string | null;
  manifest_hash: string | null;
  transfer_limit_bytes: number;
  tool_version: string;
  validation_state: "not_physically_validated";
  partial_preserved: boolean;
  error_code: string | null;
  error_message: string | null;
  started_at: string;
  completed_at: string | null;
}

export interface AcquisitionJobEvent {
  id: string;
  job_id: string;
  sequence: number;
  event_type: string;
  state: AcquisitionJobState;
  progress_percent: number;
  current_step: string | null;
  current_module: string | null;
  checkpoint: Record<string, unknown> | null;
  safe_detail: string | null;
  created_at: string;
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

export function listAcquisitionPlans(caseId: string): Promise<AcquisitionPlanList> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisition-plans?offset=0&limit=50`,
  );
}

export function createAcquisitionPlan(
  caseId: string,
  input: {
    device_id: string;
    assessment_id: string;
    scope: AcquisitionScope;
    modules?: AcquisitionModule[];
    limitations_acknowledged: true;
  },
): Promise<AcquisitionPlan> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/acquisition-plans`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function listAcquisitionJobs(caseId: string): Promise<AcquisitionJobList> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions?offset=0&limit=50`,
  );
}

export function prepareAcquisitionJob(
  caseId: string,
  planId: string,
): Promise<AcquisitionJob> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions`, {
    method: "POST",
    body: JSON.stringify({ plan_id: planId }),
  });
}

export function cancelAcquisitionJob(
  caseId: string,
  jobId: string,
): Promise<AcquisitionJob> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/cancel`,
    { method: "POST" },
  );
}

export function runAcquisitionInventory(
  caseId: string,
  jobId: string,
): Promise<AcquisitionInventory> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/inventory`,
    { method: "POST" },
  );
}

export async function getAcquisitionInventory(
  caseId: string,
  jobId: string,
): Promise<AcquisitionInventory> {
  const base = `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/inventory`;
  const first = await apiRequest<AcquisitionInventory>(`${base}?offset=0&limit=100`);
  const items = [...first.items];
  while (items.length < first.total) {
    const page = await apiRequest<AcquisitionInventory>(
      `${base}?offset=${String(items.length)}&limit=100`,
    );
    if (page.items.length === 0) break;
    items.push(...page.items);
  }
  return { ...first, items, offset: 0, limit: items.length };
}

export function acquireInventoryFile(
  caseId: string,
  jobId: string,
  itemId: string,
): Promise<AcquiredEvidenceFile> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/inventory/items/${encodeURIComponent(itemId)}/acquire`,
    { method: "POST" },
  );
}

export function listAcquiredFiles(
  caseId: string,
  jobId: string,
): Promise<AcquiredEvidenceFile[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/files`,
  );
}

export function listAcquisitionJobEvents(
  caseId: string,
  jobId: string,
): Promise<AcquisitionJobEvent[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/events`,
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

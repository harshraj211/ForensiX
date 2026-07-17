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

export interface CustodyEvent {
  id: string;
  case_id: string;
  evidence_file_id: string | null;
  report_id: string | null;
  actor_id: string;
  sequence: number;
  event_type: string;
  from_custodian: string | null;
  to_custodian: string | null;
  location: string | null;
  purpose: string | null;
  notes: string | null;
  related_event_id: string | null;
  previous_hash: string;
  event_hash: string;
  created_at: string;
}

export interface ChainVerification {
  valid: boolean;
  record_count: number;
  broken_sequence: number | null;
  head_hash: string | null;
}

export interface ReportOutput {
  format: "pdf" | "json" | "csv";
  media_type: string;
  filename: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
}

export interface PreliminaryReport {
  id: string;
  case_id: string;
  generated_by: string;
  report_type: "preliminary";
  status: "available";
  title: string;
  schema_version: string;
  template_version: string;
  snapshot_size_bytes: number;
  snapshot_sha256: string;
  generated_at: string;
  outputs: ReportOutput[];
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
  size_bytes: number | null;
  modified_time_raw: string | null;
  modified_at: string | null;
  timestamp_source: string | null;
  timestamp_confidence: "medium" | null;
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

export interface AcquisitionPartial {
  id: string;
  evidence_file_id: string;
  case_id: string;
  job_id: string;
  created_by: string;
  storage_key: string;
  status: "active" | "retained" | "discarded" | "sealed" | "missing";
  reason_code: string | null;
  size_bytes: number | null;
  sha256: string | null;
  disposition_by: string | null;
  created_at: string;
  reconciled_at: string | null;
  disposition_at: string | null;
}

export type ArtifactCategory = "image" | "video" | "audio" | "document" | "archive" | "other";
export type ArtifactStatus = "active" | "deleted" | "recovered" | "partial" | "corrupted" | "unverified";

export interface Artifact {
  id: string;
  evidence_file_id: string;
  case_id: string;
  device_id: string;
  job_id: string;
  category: ArtifactCategory;
  subtype: string;
  title: string;
  summary: string;
  source_relative_path: string;
  source_path_hash: string;
  extension: string | null;
  detected_mime: string;
  size_bytes: number;
  status: ArtifactStatus;
  primary_sha256: string;
  parser_id: string;
  parser_version: string;
  timestamp_confidence: string;
  collected_at: string;
  provenance: Record<string, unknown>;
  metadata: Record<string, unknown>;
  schema_version: string;
  created_at: string;
}

export interface ArtifactSearchResult {
  items: Artifact[];
  total: number;
  offset: number;
  limit: number;
  category_facets: Record<string, number>;
}

export interface ArtifactPreview {
  id: string | null;
  artifact_id: string;
  status: "not_generated" | "available" | "rejected" | "failed";
  detected_mime: string | null;
  extension_mismatch: boolean;
  output_mime: string | null;
  output_size_bytes: number | null;
  output_sha256: string | null;
  width: number | null;
  height: number | null;
  worker_version: string | null;
  limits: Record<string, unknown>;
  error_code: string | null;
  error_message: string | null;
  created_at: string | null;
}

export interface TimelineEvent {
  id: string;
  case_id: string;
  artifact_id: string;
  job_id: string;
  category: "device" | "file" | "media" | "communication" | "application" | "location" | "system" | "acquisition" | "custody";
  timestamp_type: string;
  event_time: string;
  original_time: string;
  timezone_basis: string;
  precision: string;
  confidence: string;
  summary: string;
  builder_version: string;
  event_hash: string;
}

export interface TimelineSearchResult {
  items: TimelineEvent[];
  total: number;
  offset: number;
  limit: number;
  category_facets: Record<string, number>;
}

export interface Bookmark {
  id: string;
  artifact_id: string;
  user_id: string;
  reason: string | null;
  created_at: string;
}

export interface ArtifactTag {
  id: string;
  name: string;
  created_by: string;
  created_at: string;
}

export interface AnalystNote {
  id: string;
  artifact_id: string;
  author_id: string;
  body: string;
  supersedes_id: string | null;
  created_at: string;
}

export interface ArtifactAnnotations {
  bookmark: Bookmark | null;
  tags: ArtifactTag[];
  notes: AnalystNote[];
}

export interface EvidenceVerification {
  id: string;
  evidence_file_id: string;
  case_id: string;
  job_id: string;
  verified_by: string;
  status: "verified" | "mismatch" | "missing" | "error";
  expected_file_sha256: string;
  observed_file_sha256: string | null;
  file_size_bytes: number | null;
  file_matches: boolean;
  expected_manifest_sha256: string;
  observed_manifest_sha256: string | null;
  manifest_matches: boolean;
  error_code: string | null;
  verification_hash: string;
  tool_version: string;
  verified_at: string;
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

export function listCustodyEvents(caseId: string): Promise<CustodyEvent[]> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/custody`);
}

export function verifyCustodyChain(caseId: string): Promise<ChainVerification> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/custody/verify`);
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

export function listAcquisitionPartials(
  caseId: string,
  jobId: string,
): Promise<AcquisitionPartial[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/partials`,
  );
}

export function searchArtifacts(
  caseId: string,
  filters: {
    q?: string;
    category?: ArtifactCategory;
    status?: ArtifactStatus;
    extension?: string;
  },
): Promise<ArtifactSearchResult> {
  const parameters = new URLSearchParams({ offset: "0", limit: "100" });
  if (filters.q) parameters.set("q", filters.q);
  if (filters.category) parameters.set("category", filters.category);
  if (filters.status) parameters.set("status", filters.status);
  if (filters.extension) parameters.set("extension", filters.extension);
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts?${parameters.toString()}`,
  );
}

export function getArtifact(caseId: string, artifactId: string): Promise<Artifact> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}`,
  );
}

export function getArtifactPreview(
  caseId: string,
  artifactId: string,
): Promise<ArtifactPreview> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}/preview`,
  );
}

export function generateArtifactPreview(
  caseId: string,
  artifactId: string,
): Promise<ArtifactPreview> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}/preview`,
    { method: "POST" },
  );
}

export function artifactPreviewContentUrl(caseId: string, artifactId: string): string {
  return `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}/preview/content`;
}

export function getArtifactAnnotations(
  caseId: string,
  artifactId: string,
): Promise<ArtifactAnnotations> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}/annotations`,
  );
}

export function bookmarkArtifact(
  caseId: string,
  artifactId: string,
  reason?: string,
): Promise<Bookmark> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}/bookmark`,
    { method: "POST", body: JSON.stringify({ reason: reason || null }) },
  );
}

export function removeArtifactBookmark(caseId: string, artifactId: string): Promise<void> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}/bookmark`,
    { method: "DELETE" },
  );
}

export function addArtifactTag(
  caseId: string,
  artifactId: string,
  name: string,
): Promise<ArtifactTag> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}/tags`,
    { method: "POST", body: JSON.stringify({ name }) },
  );
}

export function addAnalystNote(
  caseId: string,
  artifactId: string,
  body: string,
  supersedesId?: string,
): Promise<AnalystNote> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}/notes`,
    {
      method: "POST",
      body: JSON.stringify({ body, supersedes_id: supersedesId ?? null }),
    },
  );
}

export function getTimeline(caseId: string): Promise<TimelineSearchResult> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/timeline?offset=0&limit=200`,
  );
}

export function listReports(caseId: string): Promise<PreliminaryReport[]> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/reports`);
}

export function generateReport(caseId: string): Promise<PreliminaryReport> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/reports`, {
    method: "POST",
  });
}

export function reportDownloadUrl(
  caseId: string,
  reportId: string,
  format: ReportOutput["format"],
): string {
  return `/api/v1/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportId)}/download/${format}`;
}

export function resumeEvidenceFile(
  caseId: string,
  jobId: string,
  evidenceFileId: string,
  partialDisposition: "retain" | "discard",
): Promise<AcquiredEvidenceFile> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/files/${encodeURIComponent(evidenceFileId)}/resume`,
    {
      method: "POST",
      body: JSON.stringify({ partial_disposition: partialDisposition }),
    },
  );
}

export function verifyEvidenceFile(
  caseId: string,
  jobId: string,
  evidenceFileId: string,
): Promise<EvidenceVerification> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/files/${encodeURIComponent(evidenceFileId)}/verify`,
    { method: "POST" },
  );
}

export function listEvidenceVerifications(
  caseId: string,
  jobId: string,
): Promise<EvidenceVerification[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/verifications`,
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

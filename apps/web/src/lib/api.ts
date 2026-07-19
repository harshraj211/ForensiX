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

export interface RootAccessProbe {
  id: string;
  case_id: string;
  device_id: string;
  probed_by: string;
  status: "available" | "unavailable" | "indeterminate";
  uid: number | null;
  identity: string | null;
  reason_code: string;
  potential_side_effect: string;
  probe_hash: string;
  expires_at: string;
  probed_at: string;
}

export interface PhysicalAcquisitionDiagnostic {
  enabled: boolean;
  max_size_bytes: number;
  maturity: "experimental";
  warning: string;
}

export interface AdbDiagnostic {
  mode: "mock" | "system";
  status: "mock" | "healthy" | "missing" | "execution_failed" | "no_transports" | "authorization_required" | "offline" | "unsupported_transport";
  available: boolean;
  platform: string;
  executable_path: string | null;
  version: string | null;
  transport_counts: Record<string, number>;
  checked_locations: string[];
  guidance: string[];
}

export interface PhysicalBlockProbe {
  id: string;
  case_id: string;
  device_id: string;
  root_probe_id: string;
  probed_by: string;
  profile: "userdata_by_name";
  device_path: string;
  size_bytes: number;
  encryption_state: "unknown" | "suspected" | "not_detected";
  probe_hash: string;
  probed_at: string;
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
  evidence_source_id: string | null;
  parser_run_id: string | null;
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

export interface AuditLogEntry {
  id: string;
  sequence: number;
  case_id: string | null;
  actor_id: string;
  event_type: string;
  object_type: string;
  object_id: string;
  detail: Record<string, unknown>;
  previous_hash: string;
  entry_hash: string;
  created_at: string;
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
  redaction_profile: "full" | "mask_sensitive" | "metadata_only";
  approval_state: "unreviewed" | "approved" | "rejected";
  latest_review: {
    id: string;
    sequence: number;
    decision: "approved" | "rejected";
    reviewed_by: string;
    note: string;
    previous_hash: string;
    event_hash: string;
    created_at: string;
  } | null;
  outputs: ReportOutput[];
}

export interface EvidenceSource {
  id: string;
  case_id: string;
  device_id: string | null;
  created_by: string;
  source_type: "imported_file" | "logical_adb" | "rooted_filesystem" | "physical_block";
  acquisition_level: "logical" | "selective" | "filesystem" | "physical";
  status: "pending" | "sealed" | "failed";
  display_name: string;
  source_name: string;
  container_format: "raw" | "img" | "dd" | "tar" | "zip" | "directory_bundle" | "unknown";
  size_bytes: number | null;
  sha256: string | null;
  chunks_sha256: string | null;
  manifest_sha256: string | null;
  chunk_size_bytes: number;
  chunk_count: number;
  read_only_applied: boolean;
  validation_state: string;
  limitations: string[];
  tool_version: string;
  error_code: string | null;
  error_message: string | null;
  sealed_at: string | null;
  created_at: string;
}

export interface EvidenceWorkingCopy {
  id: string;
  evidence_source_id: string;
  case_id: string;
  created_by: string;
  status: "creating" | "ready" | "verification_failed";
  size_bytes: number | null;
  expected_source_sha256: string;
  observed_sha256: string | null;
  copy_method: string;
  verified_at: string | null;
  created_at: string;
}

export interface EvidenceSourceVerification {
  id: string;
  evidence_source_id: string;
  working_copy_id: string | null;
  case_id: string;
  verified_by: string;
  target_type: "master" | "working_copy";
  status: "verified" | "mismatch" | "missing" | "error";
  expected_sha256: string;
  observed_sha256: string | null;
  size_bytes: number | null;
  error_code: string | null;
  verification_hash: string;
  tool_version: string;
  verified_at: string;
}

export interface EvidenceInspection {
  id: string;
  evidence_source_id: string;
  working_copy_id: string;
  case_id: string;
  inspected_by: string;
  detected_type: "zip" | "tar" | "sqlite" | "android_sparse" | "ext4" | "f2fs" | "opaque" | "unknown";
  confidence: "high" | "medium" | "low";
  encryption_state: "not_detected" | "suspected" | "unknown";
  signature: Record<string, unknown>;
  warnings: string[];
  detector_version: string;
  inspection_hash: string;
  inspected_at: string;
}

export interface RecoveryCandidate {
  source_locator: string;
  source_kind: "sqlite_database" | "sqlite_wal" | "sqlite_rollback_journal" | "unknown";
  status: "candidate_regions_observed" | "no_candidate_regions" | "malformed" | "unsupported";
  confidence: "medium" | "low";
  page_size_bytes: number | null;
  candidate_region_count: number;
  source_size_bytes: number;
  metadata: Record<string, unknown>;
  limitations: string[];
  candidate_hash: string;
}

export interface RecoveryAssessment {
  id: string;
  evidence_source_id: string;
  working_copy_id: string;
  inspection_id: string;
  case_id: string;
  assessed_by: string;
  maturity: "experimental";
  status: "candidate_regions_observed" | "no_candidate_regions" | "unsupported";
  candidate_region_count: number;
  candidates: RecoveryCandidate[];
  limitations: string[];
  assessment_hash: string;
  tool_version: string;
  assessed_at: string;
}

export interface EvidenceParserRun {
  id: string;
  evidence_source_id: string;
  working_copy_id: string;
  inspection_id: string;
  case_id: string;
  executed_by: string;
  parser_id: string;
  parser_version: string;
  status: "completed" | "failed";
  artifact_count: number;
  source_sha256: string;
  input_locator: string;
  input_sha256: string;
  run_hash: string;
  error_code: string | null;
  error_message: string | null;
  started_at: string;
  completed_at: string;
}

export interface EvidenceSourceArtifact {
  id: string;
  parser_run_id: string;
  evidence_source_id: string;
  working_copy_id: string;
  case_id: string;
  category: "contact" | "communication" | "application" | "location" | "system" | "file";
  subtype: string;
  title: string;
  summary: string;
  event_time: string | null;
  source_locator: string;
  status: "active" | "deleted" | "recovered" | "partial" | "corrupted" | "unverified";
  confidence: "high" | "medium" | "low";
  parser_id: string;
  parser_version: string;
  metadata: Record<string, unknown>;
  provenance: Record<string, unknown>;
  artifact_hash: string;
  created_at: string;
}

export interface AleappDiagnostic {
  available: boolean;
  hash_verified: boolean;
  release_label: string;
  program_path: string;
  observed_sha256: string | null;
  message: string;
}

export interface ApplicationArtifactSupport {
  app_id: string;
  display_name: string;
  status: "plaintext_parser" | "interchange_parser" | "detection_only";
  maturity: "experimental" | "validated";
  native_parser_id: string | null;
  acquisition_requirements: string[];
  limitations: string[];
}

export interface EvidenceToolOutput {
  id: string;
  parser_run_id: string;
  evidence_source_id: string;
  working_copy_id: string;
  case_id: string;
  relative_path: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
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
  | "media_files"
  | "document_files"
  | "downloads_files"
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
  duplicate_count: number;
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
  source_width: number | null;
  source_height: number | null;
  media_metadata: Record<string, unknown>;
  worker_version: string | null;
  limits: Record<string, unknown>;
  error_code: string | null;
  error_message: string | null;
  created_at: string | null;
}

export interface TimelineEvent {
  id: string;
  case_id: string;
  artifact_id: string | null;
  source_artifact_id: string | null;
  job_id: string | null;
  parser_run_id: string | null;
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

export function listAuditLogs(): Promise<AuditLogEntry[]> {
  return apiRequest("/api/v1/audit-logs?limit=500");
}

export function verifyAuditChain(): Promise<ChainVerification> {
  return apiRequest("/api/v1/audit-logs/verify");
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

export function probeRootAccess(
  caseId: string,
  deviceId: string,
  serial: string,
): Promise<RootAccessProbe> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/devices/${encodeURIComponent(deviceId)}/root-probes`,
    {
      method: "POST",
      body: JSON.stringify({ serial, side_effects_acknowledged: true }),
    },
  );
}

export function captureRootedBundle(
  caseId: string,
  deviceId: string,
  serial: string,
  rootProbeId: string,
  profile: "android_providers" | "android_system",
): Promise<EvidenceSource> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/devices/${encodeURIComponent(deviceId)}/rooted-captures`,
    {
      method: "POST",
      body: JSON.stringify({
        serial,
        root_probe_id: rootProbeId,
        profile,
        side_effects_acknowledged: true,
      }),
    },
  );
}

export function getPhysicalAcquisitionDiagnostic(): Promise<PhysicalAcquisitionDiagnostic> {
  return apiRequest("/api/v1/integrations/physical-acquisition");
}

export function getAdbDiagnostic(): Promise<AdbDiagnostic> {
  return apiRequest("/api/v1/integrations/adb");
}

export function probePhysicalBlock(
  caseId: string,
  deviceId: string,
  serial: string,
  rootProbeId: string,
): Promise<PhysicalBlockProbe> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/devices/${encodeURIComponent(deviceId)}/physical-block-probes`,
    {
      method: "POST",
      body: JSON.stringify({
        serial,
        root_probe_id: rootProbeId,
        profile: "userdata_by_name",
        risk_acknowledged: true,
      }),
    },
  );
}

export function capturePhysicalBlock(
  caseId: string,
  deviceId: string,
  serial: string,
  physicalProbeId: string,
): Promise<EvidenceSource> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/devices/${encodeURIComponent(deviceId)}/physical-captures`,
    {
      method: "POST",
      body: JSON.stringify({
        serial,
        physical_probe_id: physicalProbeId,
        acquisition_acknowledged: true,
        encryption_acknowledged: true,
        non_resumable_acknowledged: true,
      }),
    },
  );
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

export type BulkAcquireOutcome =
  | "completed"
  | "failed"
  | "skipped_already_completed"
  | "skipped_acquiring"
  | "skipped_needs_review";

export interface BulkAcquireItemResult {
  inventory_item_id: string;
  outcome: BulkAcquireOutcome;
  file: AcquiredEvidenceFile | null;
  error_code: string | null;
  error_message: string | null;
}

export interface BulkAcquireResult {
  batch_id: string;
  case_id: string;
  job_id: string;
  requested_count: number;
  completed_count: number;
  failed_count: number;
  skipped_count: number;
  items: BulkAcquireItemResult[];
}

export function acquireInventoryBatch(
  caseId: string,
  jobId: string,
  itemIds: string[],
): Promise<BulkAcquireResult> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/inventory/acquire-batch`,
    {
      method: "POST",
      body: JSON.stringify({ item_ids: itemIds }),
    },
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
    duplicateOnly?: boolean;
    minSize?: number;
    maxSize?: number;
  },
): Promise<ArtifactSearchResult> {
  const parameters = new URLSearchParams({ offset: "0", limit: "100" });
  if (filters.q) parameters.set("q", filters.q);
  if (filters.category) parameters.set("category", filters.category);
  if (filters.status) parameters.set("status", filters.status);
  if (filters.extension) parameters.set("extension", filters.extension);
  if (filters.duplicateOnly) parameters.set("duplicate_only", "true");
  if (filters.minSize !== undefined) parameters.set("min_size", String(filters.minSize));
  if (filters.maxSize !== undefined) parameters.set("max_size", String(filters.maxSize));
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

export function generateReport(
  caseId: string,
  redactionProfile: "full" | "mask_sensitive" | "metadata_only" = "full",
): Promise<PreliminaryReport> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/reports`, {
    method: "POST",
    body: JSON.stringify({ redaction_profile: redactionProfile }),
  });
}

export function reviewReport(
  caseId: string,
  reportId: string,
  decision: "approved" | "rejected",
  note: string,
): Promise<PreliminaryReport> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/reports/${encodeURIComponent(reportId)}/review`,
    { method: "POST", body: JSON.stringify({ decision, note }) },
  );
}

export function listEvidenceSources(caseId: string): Promise<EvidenceSource[]> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources`);
}

export function importEvidenceSource(
  caseId: string,
  source: File,
  displayName: string,
): Promise<EvidenceSource> {
  const body = new FormData();
  body.set("source", source);
  if (displayName.trim()) body.set("display_name", displayName.trim());
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/import`, {
    method: "POST",
    body,
  });
}

export function verifyEvidenceSource(
  caseId: string,
  sourceId: string,
): Promise<EvidenceSourceVerification> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/verify`,
    { method: "POST" },
  );
}

export function listEvidenceSourceVerifications(
  caseId: string,
  sourceId: string,
): Promise<EvidenceSourceVerification[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/verifications`,
  );
}

export function createEvidenceWorkingCopy(
  caseId: string,
  sourceId: string,
): Promise<EvidenceWorkingCopy> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies`,
    { method: "POST" },
  );
}

export function listEvidenceWorkingCopies(
  caseId: string,
  sourceId: string,
): Promise<EvidenceWorkingCopy[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies`,
  );
}

export function verifyEvidenceWorkingCopy(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
): Promise<EvidenceSourceVerification> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/verify`,
    { method: "POST" },
  );
}

export function inspectEvidenceWorkingCopy(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
): Promise<EvidenceInspection> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/inspection`,
    { method: "POST" },
  );
}

export function getEvidenceWorkingCopyInspection(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
): Promise<EvidenceInspection> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/inspection`,
  );
}

export function assessEvidenceRecoveryCandidates(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
): Promise<RecoveryAssessment> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/recovery-assessment`,
    { method: "POST" },
  );
}

export function getEvidenceRecoveryAssessment(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
): Promise<RecoveryAssessment> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/recovery-assessment`,
  );
}

export function runNativeEvidenceParsers(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
  parserIds?: string[],
): Promise<EvidenceParserRun[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/native-parsers`,
    { method: "POST", body: JSON.stringify({ parser_ids: parserIds ?? null }) },
  );
}

export function listEvidenceParserRuns(
  caseId: string,
  sourceId: string,
): Promise<EvidenceParserRun[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/parser-runs`,
  );
}

export function listEvidenceSourceArtifacts(
  caseId: string,
  sourceId: string,
): Promise<EvidenceSourceArtifact[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/artifacts`,
  );
}

export function getAleappDiagnostic(): Promise<AleappDiagnostic> {
  return apiRequest("/api/v1/integrations/aleapp");
}

export function getApplicationArtifactSupport(): Promise<ApplicationArtifactSupport[]> {
  return apiRequest("/api/v1/integrations/application-artifacts");
}

export function runAleapp(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
): Promise<EvidenceParserRun> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/aleapp`,
    { method: "POST" },
  );
}

export function listEvidenceToolOutputs(
  caseId: string,
  sourceId: string,
): Promise<EvidenceToolOutput[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/tool-outputs`,
  );
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
  if (options.body && !(options.body instanceof FormData)) {
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

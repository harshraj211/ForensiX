/* eslint-disable @typescript-eslint/no-explicit-any */
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
  acquisition_readiness?: {
    encryption_type: "file_based" | "full_disk" | "unencrypted" | "unknown";
    credential_storage_state: "unlocked" | "locked" | "unknown";
    chipset_family: "qualcomm" | "mediatek" | "samsung_exynos" | "google_tensor" | "unknown";
    filesystem_status:
      | "unlock_required"
      | "root_required"
      | "root_required_unvalidated_version"
      | "root_and_unlock_verification_required";
    explanation: string;
  };
  temporary_root_readiness?: {
    eligibility_status:
      | "unknown"
      | "outside_reference_range"
      | "unknown_patch_format"
      | "reference_range_requires_verification"
      | "patch_too_new"
      | "candidate_requires_validated_profile";
    provider_status: "not_configured" | "no_exact_profile_match" | "exact_profile_match";
    reference_android_range: string;
    reference_max_security_patch: string;
    research_profile_id?: string | null;
    explanation: string;
  };
  capabilities: Record<string, CapabilityDecision>;
  warnings: string[];
  assessor_version: string;
}

export type ProviderProfile = "contacts" | "sms" | "call_log" | "device_info";

export interface ProviderCollection {
  case_id: string;
  case_device_id: string;
  profile: ProviderProfile;
  records: Record<string, string | null>[];
  discovered_count: number;
  truncated: boolean;
  max_records: number;
  limitation: string;
  evidence_source_id?: string | null;
  evidence_sha256?: string | null;
  evidence_storage_key?: string | null;
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
  mode: "system";
  status: "healthy" | "missing" | "execution_failed" | "no_transports" | "authorization_required" | "offline" | "unsupported_transport";
  available: boolean;
  platform: string;
  executable_path: string | null;
  version: string | null;
  transport_counts: Record<string, number>;
  checked_locations: string[];
  guidance: string[];
}

export interface ScrcpyDiagnostic {
  available: boolean;
  status: "missing" | "digest_mismatch" | "execution_failed" | "invalid_executable" | "ready";
  executable_path: string | null;
  version: string | null;
  sha256: string | null;
  guidance: string[];
}

export interface ScrcpyLaunch {
  process_id: number;
  mode: "mirror" | "control";
  version: string;
  executable_sha256: string;
  side_effects: string[];
}

export interface WebsiteLivePreviewResult {
  case_id: string;
  case_device_id: string;
  status: "started" | "stopped";
  limitation: string;
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

export interface ScreenRecordingSession {
  id: string;
  case_id: string;
  device_id: string;
  started_by: string;
  stopped_by: string | null;
  evidence_source_id: string | null;
  mp4_storage_key: string | null;
  status: "active" | "sealed" | "failed";
  process_id: number;
  scrcpy_version: string;
  executable_sha256: string;
  size_bytes: number | null;
  sha256: string | null;
  error_code: string | null;
  error_message: string | null;
  started_at: string;
  stopped_at: string | null;
}

export type CommandCenterNextAction =
  | "detect_device"
  | "create_acquisition_plan"
  | "monitor_acquisition"
  | "acquire_evidence"
  | "index_evidence"
  | "review_evidence"
  | "generate_report"
  | "review_report"
  | "continue_analysis";

export interface CommandCenterSummary {
  case_id: string;
  generated_at: string;
  device_count: number;
  jobs: {
    total: number;
    active: number;
    completed: number;
    attention_required: number;
  };
  evidence: {
    acquired_files: number;
    sealed_sources: number;
    normalized_artifacts: number;
    imported_artifacts: number;
    total_artifacts: number;
    total_size_bytes: number;
    bookmarked_artifacts: number;
    category_facets: Record<string, number>;
  };
  integrity: {
    custody_chain_valid: boolean;
    custody_event_count: number;
    verification_exceptions: number;
    verified_observations: number;
  };
  timeline_event_count: number;
  report_count: number;
  reports_pending_review: number;
  next_action: CommandCenterNextAction;
  attention: Array<{
    code: string;
    severity: "critical" | "warning" | "info";
    title: string;
    detail: string;
  }>;
  recent_activity: Array<{
    kind: "case" | "acquisition" | "custody" | "evidence" | "report";
    title: string;
    detail: string;
    occurred_at: string;
  }>;
}

export interface ApkAnalysisResult {
  package_name: string;
  version_name: string;
  version_code: string;
  min_sdk_version: string;
  target_sdk_version: string;
  permissions: string[];
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  certificates: any[];
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

export interface CustodyCheckpoint {
  id: string;
  case_id: string;
  created_by: string;
  custody_record_count: number;
  custody_head_hash: string | null;
  audit_sequence: number;
  audit_head_hash: string | null;
  filename: string;
  size_bytes: number;
  sha256: string;
  schema_version: string;
  anchor_status: "not_externally_anchored";
  created_at: string;
}

export interface CustodyCheckpointAnchor {
  id: string;
  checkpoint_id: string;
  case_id: string;
  recorded_by: string;
  anchor_type:
    | "external_timestamp"
    | "digital_signature"
    | "evidence_vault"
    | "case_management"
    | "other";
  anchor_provider: string;
  anchor_reference: string;
  anchored_at: string;
  checkpoint_sha256: string;
  receipt_sha256: string | null;
  notes: string | null;
  anchor_hash: string;
  created_at: string;
}

export interface CustodyCheckpointSignature {
  id: string;
  checkpoint_id: string;
  case_id: string;
  verified_by: string;
  signature_algorithm:
    | "rsa_pkcs1v15_sha256"
    | "rsa_pss_sha256"
    | "ecdsa_sha256";
  signer_subject: string;
  signer_issuer: string;
  certificate_serial: string;
  certificate_sha256: string;
  signature_sha256: string;
  signed_at: string;
  certificate_not_before: string;
  certificate_not_after: string;
  checkpoint_sha256: string;
  verification_hash: string;
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

export interface RecoveryFragment {
  source_file: string;
  offset_bytes: number;
  length_bytes: number;
  fragment_type: string;
  confidence: "high" | "medium" | "low";
  content_preview: string;
  content_sha256: string;
  metadata: Record<string, unknown>;
  fragment_hash: string;
}

export interface RecoveryCarving {
  id: string;
  evidence_source_id: string;
  working_copy_id: string;
  inspection_id: string;
  case_id: string;
  executed_by: string;
  maturity: "experimental";
  status: "candidate_fragments_observed" | "no_candidate_fragments" | "unsupported";
  fragment_count: number;
  fragments: RecoveryFragment[];
  input_locators: string[];
  skipped_locators: string[];
  source_file_count: number;
  source_total_bytes: number;
  wal_fragments_found: number;
  freelist_fragments_found: number;
  unallocated_fragments_found: number;
  duration_seconds: number;
  limitations: string[];
  run_hash: string;
  tool_version: string;
  executed_at: string;
}

export interface ExternalRecoveryOutputFile {
  relative_path: string;
  size_bytes: number;
  sha256: string;
}

export interface ExternalRecovery {
  id: string;
  evidence_source_id: string;
  working_copy_id: string;
  inspection_id: string;
  case_id: string;
  executed_by: string;
  tool_id: string;
  maturity: "experimental";
  status: "completed" | "completed_with_warnings" | "unsupported";
  recovered_file_count: number;
  output_storage_key: string;
  command: string[];
  console_summary: string;
  executable_sha256: string | null;
  exit_code: number | null;
  output_files: ExternalRecoveryOutputFile[];
  output_total_bytes: number;
  version: string;
  limitations: string[];
  run_hash: string;
  tool_version: string;
  executed_at: string;
}

export interface PhotoRecDiagnostic {
  available: boolean;
  status: string;
  executable_path: string | null;
  version: string | null;
  sha256: string | null;
  guidance: string[];
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
  acquisition_readiness?: DeviceCapabilityAssessment["acquisition_readiness"];
  temporary_root_readiness?: DeviceCapabilityAssessment["temporary_root_readiness"];
  capabilities: Record<string, CapabilityDecision>;
  warnings: string[];
  assessor_version: string;
}

export type AcquisitionScope =
  | "metadata_only"
  | "quick_triage"
  | "shared_storage_inventory"
  | "image_files"
  | "video_files"
  | "audio_files"
  | "media_files"
  | "document_files"
  | "downloads_files"
  | "custom";

export type AcquisitionModule =
  | "device_metadata"
  | "package_inventory"
  | "shared_storage_inventory";

export interface CompletenessItem {
  artifact: string;
  status: "captured" | "partial" | "blocked" | "failed" | "not_present";
  reason: string | null;
}

export interface AcquisitionCompletenessResponse {
  case_id: string;
  items: CompletenessItem[];
}

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
  artifact_id?: string | null;
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

export type KeyEvidenceTargetType = "artifact" | "source_artifact";
export type KeyEvidencePriority = "critical" | "high" | "normal";

export interface KeyEvidenceItem {
  id: string;
  case_id: string;
  target_type: KeyEvidenceTargetType;
  target_id: string;
  category: string;
  subtype: string;
  title: string;
  summary: string;
  source_locator: string;
  status: string;
  confidence: string;
  event_time: string | null;
  integrity_hash: string;
  parser_id: string;
  parser_version: string;
  size_bytes: number | null;
  priority: KeyEvidencePriority;
  reason: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  tags: string[];
  note_count: number;
  latest_note: string | null;
}

export interface KeyEvidenceList {
  items: KeyEvidenceItem[];
  total: number;
  priority_counts: Record<string, number>;
  category_facets: Record<string, number>;
}

export interface InvestigationStoryboard {
  case_id: string;
  findings: StoryboardFinding[];
  gaps: StoryboardGap[];
  priority_counts: Record<string, number>;
  category_facets: Record<string, number>;
}

export interface AiNarrative {
  narrative: string;
  model: string;
  generated_at: string;
  evidence_item_count: number;
}

export interface StoryboardMetrics {
  key_findings: number;
  critical_findings: number;
  high_findings: number;
  evidence_categories: number;
  timeline_claims: number;
  linked_moments: number;
  relationship_leads: number;
}

export interface StoryboardFinding {
  id: string;
  target_type: KeyEvidenceTargetType;
  target_id: string;
  priority: KeyEvidencePriority;
  category: string;
  subtype: string;
  title: string;
  summary: string;
  rationale: string | null;
  confidence: string;
  event_time: string | null;
  source_locator: string;
  integrity_hash: string;
  parser_id: string;
  parser_version: string;
  timeline_event_ids: string[];
  related_entities: string[];
}

export interface StoryboardMoment {
  id: string;
  event_time: string;
  summary: string;
  category: string;
  confidence: string;
  timestamp_type: string;
  timezone_basis: string;
  event_hash: string;
  finding_ids: string[];
  key_evidence_linked: boolean;
}

export interface StoryboardLead {
  id: string;
  entity_type: string;
  label: string;
  confidence: string;
  evidence_count: number;
  finding_ids: string[];
}

export interface StoryboardSection {
  id: string;
  title: string;
  summary: string;
  finding_ids: string[];
  critical_count: number;
  high_count: number;
  latest_event_time: string | null;
}

export interface StoryboardGap {
  code: string;
  severity: "critical" | "warning" | "info";
  title: string;
  detail: string;
  action_path: string;
}

export interface InvestigationStoryboard {
  case_id: string;
  overview: string;
  metrics: StoryboardMetrics;
  sections: StoryboardSection[];
  findings: StoryboardFinding[];
  moments: StoryboardMoment[];
  leads: StoryboardLead[];
  gaps: StoryboardGap[];
  limitations: string[];
  source_hashes: Record<string, string>;
  builder_version: string;
  snapshot_hash: string;
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

export type CorrelationNodeType =
  | "device"
  | "source"
  | "artifact"
  | "identity"
  | "phone"
  | "email"
  | "application"
  | "conversation"
  | "domain"
  | "network"
  | "location";

export interface CorrelationNode {
  id: string;
  node_type: CorrelationNodeType;
  label: string;
  subtitle: string | null;
  confidence: string;
  artifact_id: string | null;
  source_artifact_id: string | null;
  evidence_source_id: string | null;
}

export interface CorrelationEdge {
  id: string;
  source: string;
  target: string;
  relation: "contains" | "derived_from" | "mentions";
  confidence: string;
  evidence_count: number;
}

export interface CorrelationGraph {
  case_id: string;
  nodes: CorrelationNode[];
  edges: CorrelationEdge[];
  graph_hash: string;
  builder_version: string;
  truncated: boolean;
  warnings: string[];
}

export interface ValidationCheck {
  check_id: string;
  status: "pass" | "warning" | "fail" | "skipped";
  summary: string;
  observed: Record<string, string | number | boolean | null>;
}

export interface EvidenceTwinValidation {
  report: {
    schema_version: string;
    run_id: string;
    started_at: string;
    completed_at: string;
    tool_version: string;
    profile: "sqlite_provider_known_answer";
    outcome: "passed" | "passed_with_warnings" | "incomplete" | "failed";
    environment: {
      operating_system: string;
      operating_system_release: string;
      machine: string;
      python_version: string;
    };
    fixture_sha256: string | null;
    evidence_source_sha256: string | null;
    chunk_ledger_sha256: string | null;
    manifest_sha256: string | null;
    working_copy_sha256: string | null;
    report_output_sha256: Record<string, string>;
    checks: ValidationCheck[];
    limitations: string[];
  };
  canonical_sha256: string;
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

export type MediaKind = "image" | "video" | "audio";
export type MediaAnalysisStatus = "analyzed" | "unsupported" | "rejected" | "failed";
export type MediaOcrStatus = "not_attempted" | "completed" | "unavailable" | "empty";

export interface MediaDetectionLabel {
  label: string;
  confidence: number;
  basis: string;
  status?: string | null;
}

export interface MediaAnalysis {
  id: string;
  artifact_id: string;
  case_id: string;
  media_kind: MediaKind;
  status: MediaAnalysisStatus;
  detected_mime: string | null;
  width: number | null;
  height: number | null;
  perceptual_hash: string | null;
  captured_at_raw: string | null;
  camera_make: string | null;
  camera_model: string | null;
  gps_present: boolean;
  gps_latitude: number | null;
  gps_longitude: number | null;
  exif: Record<string, unknown>;
  ocr_status: MediaOcrStatus;
  ocr_engine: string | null;
  ocr_text: string | null;
  detections: MediaDetectionLabel[];
  detector_maturity: string;
  error_code: string | null;
  error_message: string | null;
  analysis_hash: string;
  worker_version: string;
  analyzed_at: string;
}

export interface MediaAnalysisList {
  items: MediaAnalysis[];
  total: number;
  offset: number;
  limit: number;
}

export interface SimilarMediaItem {
  distance: number;
  analysis: MediaAnalysis;
}

export interface SimilarMediaResult {
  base: MediaAnalysis;
  matches: SimilarMediaItem[];
  max_distance: number;
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
  detail?: string | Array<{ msg?: string }>;
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

export function getCommandCenter(caseId: string): Promise<CommandCenterSummary> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/command-center`);
}

export async function getInvestigationStoryboard(caseId: string): Promise<InvestigationStoryboard> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/storyboard`);
}

export type RootedCollectionProfile =
  | "android_contacts"
  | "android_messages"
  | "android_call_log"
  | "whatsapp"
  | "telegram"
  | "signal"
  | "messenger"
  | "instagram"
  | "snapchat"
  | "android_providers"
  | "android_system"
  | "android_apps"
  | "android_userdata"
  | "bfu_credentials";

export async function generateCaseNarrative(caseId: string): Promise<AiNarrative> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/ai/narrative`, { method: "POST" });
}

export async function analyzeApk(caseId: string, file: File): Promise<ApkAnalysisResult> {
  const formData = new FormData();
  formData.append("file", file);
  
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/apk/analyze`, { method: "POST", body: formData });
}

export async function importTakeout(caseId: string, file: File): Promise<{imported_events: number}> {
  const formData = new FormData();
  formData.append("file", file);
  
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/takeout/import`, { method: "POST", body: formData });
}

export function listCustodyEvents(caseId: string): Promise<CustodyEvent[]> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/custody`);
}

export function verifyCustodyChain(caseId: string): Promise<ChainVerification> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/custody/verify`);
}

export function listCustodyCheckpoints(caseId: string): Promise<CustodyCheckpoint[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/custody/checkpoints`,
  );
}

export function createCustodyCheckpoint(caseId: string): Promise<CustodyCheckpoint> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/custody/checkpoints`,
    { method: "POST" },
  );
}

export function custodyCheckpointDownloadUrl(
  caseId: string,
  checkpointId: string,
): string {
  return `/api/v1/cases/${encodeURIComponent(caseId)}/custody/checkpoints/${encodeURIComponent(checkpointId)}/download`;
}

export function listCustodyCheckpointAnchors(
  caseId: string,
  checkpointId: string,
): Promise<CustodyCheckpointAnchor[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/custody/checkpoints/${encodeURIComponent(checkpointId)}/anchors`,
  );
}

export function createCustodyCheckpointAnchor(
  caseId: string,
  checkpointId: string,
  input: {
    anchor_type: CustodyCheckpointAnchor["anchor_type"];
    anchor_provider: string;
    anchor_reference: string;
    anchored_at: string;
    checkpoint_sha256: string;
    receipt_sha256?: string | null;
    notes?: string | null;
  },
): Promise<CustodyCheckpointAnchor> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/custody/checkpoints/${encodeURIComponent(checkpointId)}/anchors`,
    { method: "POST", body: JSON.stringify(input) },
  );
}

export function listCustodyCheckpointSignatures(
  caseId: string,
  checkpointId: string,
): Promise<CustodyCheckpointSignature[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/custody/checkpoints/${encodeURIComponent(checkpointId)}/signatures`,
  );
}

export function verifyCustodyCheckpointSignature(
  caseId: string,
  checkpointId: string,
  input: {
    signature_algorithm: CustodyCheckpointSignature["signature_algorithm"];
    certificate_pem: string;
    signature_base64: string;
    signed_at: string;
    checkpoint_sha256: string;
  },
): Promise<CustodyCheckpointSignature> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/custody/checkpoints/${encodeURIComponent(checkpointId)}/signatures/verify`,
    { method: "POST", body: JSON.stringify(input) },
  );
}

export function listAuditLogs(): Promise<AuditLogEntry[]> {
  return apiRequest("/api/v1/audit-logs?limit=500");
}

export function verifyAuditChain(): Promise<ChainVerification> {
  return apiRequest("/api/v1/audit-logs/verify");
}

export function auditLogDownloadUrl(): string {
  return "/api/v1/audit-logs/download";
}

export function caseAuditLogDownloadUrl(caseId: string): string {
  return `/api/v1/cases/${encodeURIComponent(caseId)}/audit-logs/download`;
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

export function collectProviderRecords(
  caseId: string,
  deviceId: string,
  serial: string,
  profile: ProviderProfile,
  selectedRecordIds: string[] = [],
  sealSelected = false,
): Promise<ProviderCollection> {
  return apiRequest("/api/v1/devices/providers/collect", {
    method: "POST",
    body: JSON.stringify({
      case_id: caseId,
      case_device_id: deviceId,
      serial,
      profile,
      limitations_acknowledged: true,
      selected_record_ids: selectedRecordIds,
      seal_selected: sealSelected,
    }),
  });
}

export function captureDeviceScreenshot(
  caseId: string,
  deviceId: string,
  serial: string,
): Promise<EvidenceSource> {
  return apiRequest(
    `/api/v1/devices/${encodeURIComponent(caseId)}/case-devices/${encodeURIComponent(deviceId)}/screenshots?serial=${encodeURIComponent(serial)}`,
    { method: "POST" },
  );
}

export function launchLiveScreen(
  caseId: string,
  deviceId: string,
  serial: string,
  mode: "mirror" | "control",
): Promise<ScrcpyLaunch> {
  return apiRequest("/api/v1/devices/live-screen/launch", {
    method: "POST",
    body: JSON.stringify({
      case_id: caseId,
      case_device_id: deviceId,
      serial,
      mode,
      interaction_acknowledged: true,
    }),
  });
}

export function startWebsiteLivePreview(
  caseId: string,
  deviceId: string,
  serial: string,
): Promise<WebsiteLivePreviewResult> {
  return websiteLivePreviewTransition("start", caseId, deviceId, serial);
}

export function stopWebsiteLivePreview(
  caseId: string,
  deviceId: string,
  serial: string,
): Promise<WebsiteLivePreviewResult> {
  return websiteLivePreviewTransition("stop", caseId, deviceId, serial);
}

export async function fetchWebsiteLivePreviewFrame(
  caseId: string,
  deviceId: string,
  serial: string,
  signal: AbortSignal,
): Promise<Blob> {
  const parameters = new URLSearchParams({
    case_id: caseId,
    case_device_id: deviceId,
    serial,
  });
  const response = await fetch(`/api/v1/devices/live-screen/preview/frame?${parameters}`, {
    credentials: "same-origin",
    headers: { Accept: "image/png" },
    signal,
  });
  if (!response.ok) {
    let envelope: ErrorEnvelope = {};
    try {
      envelope = (await response.json()) as ErrorEnvelope;
    } catch {
      // A non-JSON transport failure is represented by the fallback below.
    }
    throw new ApiError(
      envelope.error?.message ?? "The live phone preview frame could not be retrieved.",
      envelope.error?.code ?? "LIVE_PREVIEW_FRAME_FAILED",
      envelope.error?.request_id ?? response.headers.get("X-Request-ID") ?? "unknown",
      response.status,
    );
  }
  return response.blob();
}

function websiteLivePreviewTransition(
  action: "start" | "stop",
  caseId: string,
  deviceId: string,
  serial: string,
): Promise<WebsiteLivePreviewResult> {
  return apiRequest(`/api/v1/devices/live-screen/preview/${action}`, {
    method: "POST",
    body: JSON.stringify({
      case_id: caseId,
      case_device_id: deviceId,
      serial,
      limitations_acknowledged: true,
    }),
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
  profile: RootedCollectionProfile,
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

export function getScrcpyDiagnostic(): Promise<ScrcpyDiagnostic> {
  return apiRequest("/api/v1/integrations/scrcpy");
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

export interface ExtractionTimelineEntry {
  timestamp: string;
  level: string;
  message: string;
}

export interface WhatsAppDowngradeResult {
  extraction_id: string;
  package_name: string;
  original_version: string | null;
  downgrade_version: string;
  backup_file_size_bytes: number;
  backup_sha256: string;
  encryption_key_found: boolean;
  encrypted_database_found: boolean;
  decrypted_database_path: string | null;
  key_file_path: string | null;
  database_file_path: string | null;
  timeline: ExtractionTimelineEntry[];
  duration_seconds: number;
  success: boolean;
  error_message: string | null;
}

export interface SignalExtractionResult {
  extraction_id: string;
  package_name: string;
  passphrase_found: boolean;
  passphrase_sha256: string;
  encrypted_database_size_bytes: number;
  encrypted_database_sha256: string;
  decrypted_database_path: string | null;
  timeline: ExtractionTimelineEntry[];
  duration_seconds: number;
  success: boolean;
  error_message: string | null;
}

export interface TelegramExtractionResult {
  extraction_id: string;
  package_name: string;
  package_display_name: string;
  database_files_copied: number;
  database_total_size_bytes: number;
  database_sha256: string;
  database_path: string;
  timeline: ExtractionTimelineEntry[];
  duration_seconds: number;
  success: boolean;
  error_message: string | null;
}

export interface CarvedFragment {
  source_file: string;
  offset_bytes: number;
  length_bytes: number;
  fragment_type: string;
  confidence: string;
  content_preview: string;
  content_sha256: string;
  metadata: Record<string, unknown>;
}

export interface SQLiteCarvingResult {
  carving_id: string;
  source_files: string[];
  source_total_bytes: number;
  fragments_found: number;
  fragments: CarvedFragment[];
  wal_fragments_found: number;
  freelist_fragments_found: number;
  unallocated_fragments_found: number;
  duration_seconds: number;
  limitations: string[];
}

export function extractWhatsAppDowngrade(
  caseId: string,
  serial: string,
  operatorId: string,
): Promise<WhatsAppDowngradeResult> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/extractions/whatsapp-downgrade`,
    {
      method: "POST",
      body: JSON.stringify({
        serial,
        case_id: caseId,
        operator_id: operatorId,
        downgrade_acknowledged: true,
      }),
    },
  );
}

export function extractSignalRooted(
  caseId: string,
  serial: string,
  operatorId: string,
): Promise<SignalExtractionResult> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/extractions/signal-rooted`,
    {
      method: "POST",
      body: JSON.stringify({
        serial,
        case_id: caseId,
        operator_id: operatorId,
        root_acknowledged: true,
      }),
    },
  );
}

export function extractTelegramRooted(
  caseId: string,
  serial: string,
  operatorId: string,
  packageName = "",
): Promise<TelegramExtractionResult> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/extractions/telegram-rooted`,
    {
      method: "POST",
      body: JSON.stringify({
        serial,
        case_id: caseId,
        operator_id: operatorId,
        package_name: packageName,
        root_acknowledged: true,
      }),
    },
  );
}

export function carveSqliteDatabase(
  caseId: string,
  sourcePaths: string[],
  maxFragments = 10000,
): Promise<SQLiteCarvingResult> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/extractions/sqlite-carve`,
    {
      method: "POST",
      body: JSON.stringify({
        source_paths: sourcePaths,
        case_id: caseId,
        max_fragments: maxFragments,
      }),
    },
  );
}

export async function getCaseCompleteness(
  caseId: string,
): Promise<AcquisitionCompletenessResponse> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/completeness`);
}

export async function listCaseDevices(caseId: string): Promise<CaseDevice[]> {
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

export async function runAcquisitionInventory(
  caseId: string,
  jobId: string,
): Promise<AcquisitionInventory> {
  await apiRequest<AcquisitionInventory>(
    `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/inventory`,
    { method: "POST" },
  );
  // The inventory-run response is deliberately capped at the API's default page
  // size. Reload the sealed inventory so scope filters and counters operate on
  // every discovered path, including matches beyond the first page.
  return getAcquisitionInventory(caseId, jobId);
}

export function listRootAccessProbes(
  caseId: string,
  deviceId: string,
): Promise<RootAccessProbe[]> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/devices/${encodeURIComponent(deviceId)}/root-probes`,
  );
}

export async function getAcquisitionInventory(
  caseId: string,
  jobId: string,
): Promise<AcquisitionInventory> {
  const base = `/api/v1/cases/${encodeURIComponent(caseId)}/acquisitions/${encodeURIComponent(jobId)}/inventory`;
  const pageSize = 500;
  const first = await apiRequest<AcquisitionInventory>(`${base}?offset=0&limit=${String(pageSize)}`);
  const items = [...first.items];
  while (items.length < first.total) {
    const page = await apiRequest<AcquisitionInventory>(
      `${base}?offset=${String(items.length)}&limit=${String(pageSize)}`,
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
    offset?: number;
    limit?: number;
  },
): Promise<ArtifactSearchResult> {
  const parameters = new URLSearchParams({
    offset: String(filters.offset ?? 0),
    limit: String(filters.limit ?? 100),
  });
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

export async function searchAllArtifacts(
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
  const pageSize = 100;
  const firstPage = await searchArtifacts(caseId, { ...filters, offset: 0, limit: pageSize });
  const items = [...firstPage.items];
  while (items.length < firstPage.total) {
    const page = await searchArtifacts(caseId, {
      ...filters,
      offset: items.length,
      limit: pageSize,
    });
    if (page.items.length === 0) break;
    items.push(...page.items);
  }
  return { ...firstPage, items, offset: 0, limit: items.length };
}

export function getArtifact(caseId: string, artifactId: string): Promise<Artifact> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}`,
  );
}

export function captureWithTemporaryRoot(
  caseId: string,
  deviceId: string,
  serial: string,
  profile:
    | "android_providers"
    | "android_system"
    | "android_apps"
    | "android_userdata"
    | "bfu_credentials",
): Promise<EvidenceSource> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/devices/${encodeURIComponent(deviceId)}/temporary-root-captures`,
    {
      method: "POST",
      body: JSON.stringify({
        serial,
        profile,
        legal_authority_acknowledged: true,
        device_modification_acknowledged: true,
        cleanup_reboot_acknowledged: true,
      }),
    },
  );
}

export function listScreenRecordings(
  caseId: string,
  deviceId: string,
): Promise<ScreenRecordingSession[]> {
  const parameters = new URLSearchParams({ case_id: caseId, case_device_id: deviceId });
  return apiRequest(`/api/v1/devices/live-screen/recordings?${parameters.toString()}`);
}

export function startScreenRecording(
  caseId: string,
  deviceId: string,
  serial: string,
): Promise<ScreenRecordingSession> {
  return apiRequest("/api/v1/devices/live-screen/recordings", {
    method: "POST",
    body: JSON.stringify({
      case_id: caseId,
      case_device_id: deviceId,
      serial,
      interaction_acknowledged: true,
      recording_acknowledged: true,
    }),
  });
}

export function stopScreenRecording(
  recordingId: string,
  caseId: string,
  deviceId: string,
  serial: string,
): Promise<ScreenRecordingSession> {
  return apiRequest(
    `/api/v1/devices/live-screen/recordings/${encodeURIComponent(recordingId)}/stop`,
    {
      method: "POST",
      body: JSON.stringify({ case_id: caseId, case_device_id: deviceId, serial }),
    },
  );
}

export function listKeyEvidence(
  caseId: string,
  filters: { q?: string; priority?: KeyEvidencePriority; category?: string } = {},
): Promise<KeyEvidenceList> {
  const parameters = new URLSearchParams();
  if (filters.q) parameters.set("q", filters.q);
  if (filters.priority) parameters.set("priority", filters.priority);
  if (filters.category) parameters.set("category", filters.category);
  const query = parameters.toString();
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/key-evidence${query ? `?${query}` : ""}`,
  );
}

export function promoteKeyEvidence(
  caseId: string,
  input: {
    targetType: KeyEvidenceTargetType;
    targetId: string;
    priority: KeyEvidencePriority;
    reason?: string;
  },
): Promise<KeyEvidenceItem> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/key-evidence`, {
    method: "POST",
    body: JSON.stringify({
      target_type: input.targetType,
      target_id: input.targetId,
      priority: input.priority,
      reason: input.reason || null,
    }),
  });
}

export function removeKeyEvidence(caseId: string, findingId: string): Promise<void> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/key-evidence/${encodeURIComponent(findingId)}`,
    { method: "DELETE" },
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

export function artifactContentUrl(
  caseId: string,
  artifactId: string,
  inline = false,
): string {
  const base = `/api/v1/cases/${encodeURIComponent(caseId)}/artifacts/${encodeURIComponent(artifactId)}/content`;
  return inline ? `${base}?inline=true` : base;
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

export function getCorrelationGraph(caseId: string): Promise<CorrelationGraph> {
  return apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/correlations`);
}

export function getLatestEvidenceTwinValidation(): Promise<EvidenceTwinValidation | null> {
  return apiRequest("/api/v1/validation/evidence-twin/latest");
}

export function runEvidenceTwinValidation(): Promise<EvidenceTwinValidation> {
  return apiRequest("/api/v1/validation/evidence-twin/runs", { method: "POST" });
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

export function getEvidenceSourceContentUrl(
  caseId: string,
  sourceId: string,
  download = false,
): string {
  const base = `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/content`;
  return download ? `${base}?download=true` : base;
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

export function carveEvidenceRecoveryCandidates(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
): Promise<RecoveryCarving> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/recovery-carving`,
    { method: "POST" },
  );
}

export function getEvidenceRecoveryCarving(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
): Promise<RecoveryCarving> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/recovery-carving`,
  );
}

export function runExternalRecovery(
  caseId: string,
  sourceId: string,
  workingCopyId: string,
): Promise<ExternalRecovery> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(sourceId)}/working-copies/${encodeURIComponent(workingCopyId)}/external-recovery`,
    { method: "POST" },
  );
}

export function getPhotoRecDiagnostic(): Promise<PhotoRecDiagnostic> {
  return apiRequest("/api/v1/integrations/photorec");
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

export interface SourceArtifactSearchResult {
  items: EvidenceSourceArtifact[];
  total: number;
  offset: number;
  limit: number;
  category_facets: Record<string, number>;
}

export function searchSourceArtifacts(
  caseId: string,
  options: {
    query?: string;
    category?: string;
    status?: string;
    offset?: number;
    limit?: number;
  } = {},
): Promise<SourceArtifactSearchResult> {
  const params = new URLSearchParams();
  if (options.query && options.query.trim()) params.set("q", options.query.trim());
  if (options.category) params.set("category", options.category);
  if (options.status) params.set("status", options.status);
  params.set("offset", String(options.offset ?? 0));
  params.set("limit", String(options.limit ?? 50));
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/artifacts/search?${params.toString()}`,
  );
}

export function getMediaAnalysis(
  caseId: string,
  artifactId: string,
): Promise<MediaAnalysis | null> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/media/artifacts/${encodeURIComponent(artifactId)}`,
  );
}

export function analyzeMedia(caseId: string, artifactId: string): Promise<MediaAnalysis> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/media/artifacts/${encodeURIComponent(artifactId)}`,
    { method: "POST" },
  );
}

export function findSimilarMedia(
  caseId: string,
  artifactId: string,
  maxDistance = 10,
): Promise<SimilarMediaResult> {
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/media/artifacts/${encodeURIComponent(artifactId)}/similar?max_distance=${String(maxDistance)}`,
  );
}

export function listMediaAnalyses(
  caseId: string,
  options: { mediaKind?: MediaKind; gpsOnly?: boolean; offset?: number; limit?: number } = {},
): Promise<MediaAnalysisList> {
  const params = new URLSearchParams();
  if (options.mediaKind) params.set("media_kind", options.mediaKind);
  if (options.gpsOnly) params.set("gps_only", "true");
  params.set("offset", String(options.offset ?? 0));
  params.set("limit", String(options.limit ?? 50));
  return apiRequest(
    `/api/v1/cases/${encodeURIComponent(caseId)}/media/analyses?${params.toString()}`,
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
    const validationDetail = Array.isArray(envelope.detail)
      ? envelope.detail.map((item) => item.msg).filter(Boolean).join("; ")
      : envelope.detail;
    throw new ApiError(
      envelope.error?.message ?? validationDetail ?? "ForensiX could not complete the local request.",
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

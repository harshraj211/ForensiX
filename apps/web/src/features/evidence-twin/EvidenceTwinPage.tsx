import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Cloud,
  CopyCheck,
  DatabaseBackup,
  Download,
  ExternalLink,
  FileUp,
  LoaderCircle,
  PackageCheck,
  ShieldCheck,
  Smartphone,
} from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { CaseError } from "../cases/CasesPage";
import { caseKeys } from "../cases/caseKeys";
import { CaseSubnav } from "../../components/CaseSubnav";
import { DownloadLink } from "../../components/DownloadLink";
import { CloudExportResult, TakeoutImportPanel } from "../evidence/TakeoutImportPanel";
import {
  assessEvidenceRecoveryCandidates,
  carveEvidenceRecoveryCandidates,
  createEvidenceWorkingCopy,
  getAleappDiagnostic,
  getAndroidAgentBundleSummary,
  getCloudExportSummary,
  getApplicationArtifactSupport,
  getCase,
  getCloudServiceCatalog,
  getEvidenceSourceContentUrl,
  getEvidenceWorkingCopyInspection,
  getPhotoRecDiagnostic,
  importAndroidAgentBundle,
  importAndroidDeviceBackup,
  importSmartSwitchFolder,
  importEvidenceSource,
  inspectEvidenceWorkingCopy,
  listEvidenceParserRuns,
  listEvidenceSources,
  listEvidenceSourceArtifacts,
  listEvidenceSourceVerifications,
  listEvidenceToolOutputs,
  listEvidenceWorkingCopies,
  runNativeEvidenceParsers,
  runAleapp,
  runExternalRecovery,
  verifyEvidenceWorkingCopy,
  verifyEvidenceSource,
  type EvidenceSource,
  type EvidenceSourceArtifact,
  type EvidenceToolOutput,
  type EvidenceWorkingCopy,
  type ExternalRecovery,
  type PhotoRecDiagnostic,
  type RecoveryAssessment,
  type RecoveryCarving,
  type AleappDiagnostic,
  type ApplicationArtifactSupport,
  type CloudServiceCapability,
} from "../../lib/api";

const twinKeys = {
  sources: (caseId: string) => ["evidence-twin", caseId, "sources"] as const,
  copies: (caseId: string, sourceId: string) =>
    ["evidence-twin", caseId, sourceId, "copies"] as const,
  verifications: (caseId: string, sourceId: string) =>
    ["evidence-twin", caseId, sourceId, "verifications"] as const,
  inspection: (caseId: string, sourceId: string, copyId: string) =>
    ["evidence-twin", caseId, sourceId, copyId, "inspection"] as const,
  parserRuns: (caseId: string, sourceId: string) =>
    ["evidence-twin", caseId, sourceId, "parser-runs"] as const,
  artifacts: (caseId: string, sourceId: string) =>
    ["evidence-twin", caseId, sourceId, "artifacts"] as const,
  toolOutputs: (caseId: string, sourceId: string) =>
    ["evidence-twin", caseId, sourceId, "tool-outputs"] as const,
  aleapp: ["integrations", "aleapp"] as const,
  photorec: ["integrations", "photorec"] as const,
  applicationArtifacts: ["integrations", "application-artifacts"] as const,
  cloudServices: ["integrations", "cloud-services"] as const,
};

export function EvidenceTwinPage() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [agentBundleFile, setAgentBundleFile] = useState<File | null>(null);
  const [backupFile, setBackupFile] = useState<File | null>(null);
  const [smartSwitchFolderFiles, setSmartSwitchFolderFiles] = useState<File[]>([]);
  const [displayName, setDisplayName] = useState("");
  const caseQuery = useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: Boolean(caseId),
  });
  const sourcesQuery = useQuery({
    queryKey: twinKeys.sources(caseId),
    queryFn: () => listEvidenceSources(caseId),
    enabled: Boolean(caseId),
  });
  const aleappQuery = useQuery({
    queryKey: twinKeys.aleapp,
    queryFn: getAleappDiagnostic,
  });
  const photorecQuery = useQuery({
    queryKey: twinKeys.photorec,
    queryFn: getPhotoRecDiagnostic,
  });
  const applicationSupportQuery = useQuery({
    queryKey: twinKeys.applicationArtifacts,
    queryFn: getApplicationArtifactSupport,
  });
  const cloudServicesQuery = useQuery({
    queryKey: twinKeys.cloudServices,
    queryFn: getCloudServiceCatalog,
  });
  const importSource = useMutation({
    mutationFn: () => {
      if (!selectedFile) throw new Error("Select an evidence source before importing.");
      return importEvidenceSource(caseId, selectedFile, displayName);
    },
    onSuccess: () => {
      setSelectedFile(null);
      setDisplayName("");
      void queryClient.invalidateQueries({ queryKey: twinKeys.sources(caseId) });
    },
  });
  const importAgentBundle = useMutation({
    mutationFn: () => {
      if (!agentBundleFile) throw new Error("Select a ForensiX Android agent .fxz bundle.");
      return importAndroidAgentBundle(caseId, agentBundleFile);
    },
    onSuccess: () => {
      setAgentBundleFile(null);
      void queryClient.invalidateQueries({ queryKey: twinKeys.sources(caseId) });
      void queryClient.invalidateQueries({ queryKey: caseKeys.timeline(caseId) });
    },
  });
  const importBackup = useMutation({
    mutationFn: () => {
      if (!backupFile) throw new Error("Select a legacy Android or Smart Switch backup.");
      return importAndroidDeviceBackup(caseId, backupFile);
    },
    onSuccess: () => {
      setBackupFile(null);
      void queryClient.invalidateQueries({ queryKey: twinKeys.sources(caseId) });
    },
  });
  const importSmartSwitchPc = useMutation({
    mutationFn: () => {
      if (!smartSwitchFolderFiles.length) throw new Error("Select one Smart Switch PC backup folder.");
      return importSmartSwitchFolder(caseId, smartSwitchFolderFiles);
    },
    onSuccess: () => {
      setSmartSwitchFolderFiles([]);
      void queryClient.invalidateQueries({ queryKey: twinKeys.sources(caseId) });
      void queryClient.invalidateQueries({ queryKey: caseKeys.timeline(caseId) });
    },
  });
  const caseWritable = !new Set(["closed", "archived"]).has(caseQuery.data?.status ?? "closed");

  return (
    <div className="mx-auto max-w-6xl">
      <CaseSubnav caseId={caseId} caseNumber={caseQuery.data?.case_number} />
      <Link
        to={`/cases/${caseId}`}
        className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-cyan-200"
      >
        <ArrowLeft size={15} aria-hidden="true" /> Back to case
      </Link>
      <header className="mt-6 border-b border-white/8 pb-8">
        <p className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">
          Offline forensic examination
        </p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tight text-white">Evidence Twin</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">
          Import an existing image or extraction, seal its master bytes, and examine only a
          separately verified working copy. Import does not prove how the original source was
          acquired.
        </p>
      </header>

      <section className="mt-8 grid gap-6 lg:grid-cols-[1.05fr_0.95fr]">
        <form
          className="rounded-2xl border border-white/8 bg-white/[0.025] p-6"
          onSubmit={(event) => {
            event.preventDefault();
            importSource.mutate();
          }}
        >
          <div className="flex items-start gap-3">
            <FileUp className="mt-1 text-cyan-300" size={21} aria-hidden="true" />
            <div>
              <h2 className="text-xl font-semibold text-white">Import evidence source</h2>
              <p className="mt-2 text-xs leading-5 text-slate-500">
                Supported containers currently include RAW, IMG, DD, TAR, and ZIP. Content
                detection and parsing happen only after a verified working copy exists.
              </p>
            </div>
          </div>
          <label className="mt-6 block text-sm font-medium text-slate-300" htmlFor="twin-source">
            Evidence image or extraction
          </label>
          <input
            id="twin-source"
            type="file"
            accept=".raw,.img,.dd,.tar,.zip,.fxz,.db,.sqlite,application/octet-stream,application/zip"
            disabled={!caseWritable || importSource.isPending}
            onChange={(event) => {
              setSelectedFile(event.target.files?.[0] ?? null);
            }}
            className="mt-2 block min-h-12 w-full rounded-lg border border-white/10 bg-black/20 p-3 text-xs text-slate-300 file:mr-4 file:rounded file:border-0 file:bg-cyan-300 file:px-3 file:py-2 file:font-semibold file:text-slate-950 disabled:opacity-40"
          />
          <label className="mt-5 block text-sm font-medium text-slate-300" htmlFor="twin-name">
            Examination label
          </label>
          <input
            id="twin-name"
            value={displayName}
            maxLength={255}
            disabled={!caseWritable || importSource.isPending}
            onChange={(event) => {
              setDisplayName(event.target.value);
            }}
            placeholder={selectedFile?.name ?? "Example: Infinix X666 imported filesystem"}
            className="mt-2 min-h-11 w-full rounded-lg border border-white/10 bg-black/20 px-3 text-sm text-slate-200 outline-none focus:border-cyan-300/40 disabled:opacity-40"
          />
          {selectedFile && (
            <p className="mt-3 text-xs text-slate-500">
              {selectedFile.name} · {formatBytes(selectedFile.size)} selected
            </p>
          )}
          <div className="mt-5 flex gap-3 rounded-xl border border-amber-200/15 bg-amber-200/5 p-4 text-xs leading-5 text-amber-100/75">
            <AlertTriangle className="mt-0.5 shrink-0" size={17} aria-hidden="true" />
            <p>
              ForensiX will record this as an imported source at filesystem level. A filename or
              extension alone is never treated as proof of physical acquisition.
            </p>
          </div>
          <button
            type="submit"
            disabled={!selectedFile || !caseWritable || importSource.isPending}
            className="mt-5 inline-flex min-h-11 items-center gap-2 rounded-lg bg-cyan-300 px-4 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {importSource.isPending ? (
              <LoaderCircle className="animate-spin" size={16} aria-hidden="true" />
            ) : (
              <DatabaseBackup size={16} aria-hidden="true" />
            )}
            {importSource.isPending ? "Streaming and sealing…" : "Import and seal master"}
          </button>
          {!caseWritable && (
            <p className="mt-3 text-xs text-rose-200">Closed or archived cases cannot import evidence.</p>
          )}
          {importSource.isError && <div className="mt-4"><CaseError error={importSource.error} /></div>}
        </form>

        <div className="rounded-2xl border border-cyan-200/10 bg-cyan-200/5 p-6">
          <ShieldCheck className="text-cyan-300" size={24} aria-hidden="true" />
          <h2 className="mt-4 text-xl font-semibold text-white">Integrity boundary</h2>
          <ol className="mt-5 space-y-4 text-sm leading-6 text-slate-400">
            <IntegrityStep number="1" text="Stream source bytes into contained evidence storage." />
            <IntegrityStep number="2" text="Calculate fixed 4 MiB chunk hashes and complete SHA-256." />
            <IntegrityStep number="3" text="Seal master, chunk ledger, and canonical manifest separately." />
            <IntegrityStep number="4" text="Create and verify a distinct examination working copy." />
          </ol>
          <p className="mt-6 text-xs leading-5 text-slate-500">
            Read-only permissions reduce accidental modification. Hash verification provides the
            tamper-evident control; local files are not described as tamper-proof.
          </p>
          <div className="mt-5 rounded-xl border border-white/8 bg-black/10 p-4 text-xs leading-5 text-slate-400">
            <p className="font-semibold text-white">Optional ALEAPP integration</p>
            <p className="mt-1">{aleappQuery.data?.message ?? "Checking local configuration…"}</p>
            {aleappQuery.data?.hash_verified && (
              <p className="mt-2 font-mono text-[10px] text-emerald-200">
                {aleappQuery.data.release_label} · {aleappQuery.data.observed_sha256}
              </p>
            )}
          </div>
        </div>
      </section>

      <section className="mt-8 rounded-2xl border border-emerald-200/10 bg-emerald-200/[0.035] p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <Smartphone className="mt-1 text-emerald-200" size={22} aria-hidden="true" />
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-emerald-200">
                No-ADB Android agent
              </p>
              <h2 className="mt-2 text-xl font-semibold text-white">Import agent collection bundle</h2>
              <p className="mt-2 max-w-3xl text-xs leading-5 text-emerald-100/70">
                Upload a ForensiX `.fxz` bundle exported from the Android agent. The backend
                validates the manifest, seals the original ZIP bytes, and the native parser
                `android.agent_bundle.v1` indexes contacts, SMS, calls, installed apps, device
                metadata, and accessible app artifacts.
              </p>
            </div>
          </div>
          {importAgentBundle.data && (
            <span className={`rounded-full border px-3 py-1 text-[10px] uppercase tracking-wide ${
              importAgentBundle.data.collection_complete
                ? "border-emerald-200/20 text-emerald-100"
                : "border-amber-200/20 text-amber-100"
            }`}>
              {importAgentBundle.data.collection_complete ? "complete" : "partial"} collection
            </span>
          )}
        </div>
        <div className="mt-5 grid gap-4 lg:grid-cols-[1fr_auto] lg:items-end">
          <div>
            <label className="block text-sm font-medium text-slate-300" htmlFor="agent-bundle">
              Agent `.fxz` bundle
            </label>
            <input
              id="agent-bundle"
              type="file"
              accept=".fxz,application/zip"
              disabled={!caseWritable || importAgentBundle.isPending}
              onChange={(event) => {
                setAgentBundleFile(event.target.files?.[0] ?? null);
              }}
              className="mt-2 block min-h-12 w-full rounded-lg border border-emerald-200/15 bg-black/20 p-3 text-xs text-slate-300 file:mr-4 file:rounded file:border-0 file:bg-emerald-300 file:px-3 file:py-2 file:font-semibold file:text-slate-950 disabled:opacity-40"
            />
            {agentBundleFile && (
              <p className="mt-3 text-xs text-emerald-100/65">
                {agentBundleFile.name} · {formatBytes(agentBundleFile.size)} selected
              </p>
            )}
          </div>
          <button
            type="button"
            disabled={!agentBundleFile || !caseWritable || importAgentBundle.isPending}
            onClick={() => {
              importAgentBundle.mutate();
            }}
            className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-emerald-300 px-4 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {importAgentBundle.isPending ? (
              <LoaderCircle className="animate-spin" size={16} aria-hidden="true" />
            ) : (
              <PackageCheck size={16} aria-hidden="true" />
            )}
            {importAgentBundle.isPending ? "Validating bundle…" : "Import agent bundle"}
          </button>
        </div>
        {importAgentBundle.data && (
          <div className="mt-5 grid gap-3 md:grid-cols-2">
            <div className="rounded-xl border border-white/8 bg-black/10 p-4">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-emerald-100/70">
                Collection ID
              </p>
              <p className="mt-2 truncate font-mono text-xs text-slate-300">
                {importAgentBundle.data.collection_id}
              </p>
            </div>
            <div className="rounded-xl border border-white/8 bg-black/10 p-4">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-emerald-100/70">
                Record counts
              </p>
              <p className="mt-2 text-xs text-slate-300">
                {Object.entries(importAgentBundle.data.record_counts)
                  .map(([key, value]) => `${key.replaceAll("_", " ")} ${String(value)}`)
                  .join(" · ")}
              </p>
            </div>
          </div>
        )}
        {importAgentBundle.isError && <div className="mt-4"><CaseError error={importAgentBundle.error} /></div>}
      </section>

      <section className="mt-8 rounded-2xl border border-violet-200/10 bg-violet-200/[0.025] p-6">
        <div className="flex items-start gap-3">
          <DatabaseBackup className="mt-1 text-violet-200" size={22} aria-hidden="true" />
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-violet-200">
              Device backup intake
            </p>
            <h2 className="mt-2 text-xl font-semibold text-white">Import Android backup, Smart Switch archive, or card image</h2>
            <p className="mt-2 max-w-3xl text-xs leading-5 text-slate-400">
              Validate a legacy Android `.ab`, ZIP-compatible Samsung Smart Switch `.zip`/`.sbu`,
              or supplied `.img`/`.dd`/`.raw` card image. The import seals the original bytes and indexes
              readable FAT32 files, directories, and deleted-entry candidates from a verified working copy.
            </p>
          </div>
        </div>
        <div className="mt-5 grid gap-4 lg:grid-cols-[1fr_auto] lg:items-end">
          <div>
            <label className="block text-sm font-medium text-slate-300" htmlFor="device-backup">
              Backup container
            </label>
            <input
              id="device-backup"
              type="file"
              accept=".ab,.zip,.sbu,.img,.dd,.raw,application/zip,application/octet-stream"
              disabled={!caseWritable || importBackup.isPending}
              onChange={(event) => { setBackupFile(event.target.files?.[0] ?? null); }}
              className="mt-2 block min-h-12 w-full rounded-lg border border-violet-200/15 bg-black/20 p-3 text-xs text-slate-300 file:mr-4 file:rounded file:border-0 file:bg-violet-300 file:px-3 file:py-2 file:font-semibold file:text-slate-950 disabled:opacity-40"
            />
            {backupFile && <p className="mt-3 text-xs text-violet-100/65">{backupFile.name} · {formatBytes(backupFile.size)} selected</p>}
          </div>
          <button
            type="button"
            disabled={!backupFile || !caseWritable || importBackup.isPending}
            onClick={() => { importBackup.mutate(); }}
            className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-violet-300 px-4 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {importBackup.isPending ? <LoaderCircle className="animate-spin" size={16} aria-hidden="true" /> : <PackageCheck size={16} aria-hidden="true" />}
            {importBackup.isPending ? "Inspecting and sealing…" : "Import backup"}
          </button>
        </div>
        {importBackup.data && (
          <div className="mt-5 rounded-xl border border-white/8 bg-black/10 p-4 text-xs text-slate-300">
            <p>{importBackup.data.backup_kind.replaceAll("_", " ")} · {importBackup.data.encrypted ? "encrypted" : "not encrypted"} · {importBackup.data.compression ?? "unknown compression"}</p>
            {importBackup.data.filesystem_type && <p className="mt-2">Filesystem: {importBackup.data.filesystem_type} {importBackup.data.filesystem_block_size ? `· ${importBackup.data.filesystem_block_size.toLocaleString()} byte blocks` : ""}</p>}
            {importBackup.data.parser_status === "completed" && importBackup.data.parsed_artifact_count !== null && <p className="mt-2">{importBackup.data.parsed_artifact_count.toLocaleString()} source artifacts indexed for case search</p>}
            {importBackup.data.parser_status === "failed" && <p className="mt-2 text-amber-200">Parser failed: {importBackup.data.parser_error ?? "See parser run for details"}</p>}
            {importBackup.data.member_count !== null && <p className="mt-2">{importBackup.data.member_count.toLocaleString()} archive members · {importBackup.data.package_hints.join(", ") || "no package hints"}</p>}
          </div>
        )}
        {importBackup.isError && <div className="mt-4"><CaseError error={importBackup.error} /></div>}
        <div className="mt-6 border-t border-white/8 pt-5">
          <label className="block text-sm font-medium text-slate-300" htmlFor="smart-switch-pc-folder">
            Smart Switch PC backup folder
          </label>
          <p className="mt-1 text-xs text-slate-400">Select one saved backup folder. Files are packaged with their relative paths and hashes before examination.</p>
          <div className="mt-3 flex flex-wrap items-end gap-4">
            <input
              id="smart-switch-pc-folder"
              type="file"
              multiple
              ref={(element) => { element?.setAttribute("webkitdirectory", ""); }}
              disabled={!caseWritable || importSmartSwitchPc.isPending}
              onChange={(event) => { setSmartSwitchFolderFiles(Array.from(event.target.files ?? [])); }}
              className="min-h-12 flex-1 rounded-lg border border-violet-200/15 bg-black/20 p-3 text-xs text-slate-300 file:mr-4 file:rounded file:border-0 file:bg-violet-300 file:px-3 file:py-2 file:font-semibold file:text-slate-950 disabled:opacity-40"
            />
            <button
              type="button"
              disabled={!smartSwitchFolderFiles.length || !caseWritable || importSmartSwitchPc.isPending}
              onClick={() => { importSmartSwitchPc.mutate(); }}
              className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-violet-300 px-4 text-sm font-semibold text-slate-950 disabled:opacity-40"
            >
              {importSmartSwitchPc.isPending ? "Importing folder…" : "Import PC folder"}
            </button>
          </div>
          {smartSwitchFolderFiles.length > 0 && <p className="mt-2 text-xs text-violet-100/65">{smartSwitchFolderFiles.length.toLocaleString()} files selected</p>}
          {importSmartSwitchPc.data && <p className="mt-3 text-xs text-slate-300">{importSmartSwitchPc.data.member_count?.toLocaleString() ?? "0"} files sealed · {importSmartSwitchPc.data.parsed_artifact_count?.toLocaleString() ?? "0"} artifacts · parser {importSmartSwitchPc.data.parser_status ?? "not run"}</p>}
          {importSmartSwitchPc.isError && <div className="mt-4"><CaseError error={importSmartSwitchPc.error} /></div>}
        </div>
      </section>

      <section className="mt-8 rounded-2xl border border-sky-200/10 bg-sky-200/[0.025] p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <Cloud className="mt-1 text-sky-200" size={22} aria-hidden="true" />
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-sky-200">
                Cloud acquisition roadmap
              </p>
              <h2 className="mt-2 text-xl font-semibold text-white">50-service coverage catalog</h2>
              <p className="mt-2 max-w-4xl text-xs leading-5 text-slate-400">
                The first five services have offline export import flows. The rest are tracked as
                planned connectors or import parsers with explicit auth and blocker classes.
              </p>
            </div>
          </div>
          {cloudServicesQuery.data && (
            <span className="rounded-full border border-sky-200/20 px-3 py-1 text-[10px] uppercase tracking-wide text-sky-100">
              {cloudServicesQuery.data.length} services
            </span>
          )}
        </div>
        {cloudServicesQuery.isPending && (
          <p role="status" className="mt-5 text-xs text-slate-500">Loading cloud catalog…</p>
        )}
        {cloudServicesQuery.isError && (
          <div className="mt-5"><CaseError error={cloudServicesQuery.error} /></div>
        )}
        <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          {cloudServicesQuery.data
            ?.filter((service) => service.depth === "deep_target")
            .map((service) => (
              <CloudServiceCard key={service.service_id} service={service} />
            ))}
        </div>
      </section>

      <TakeoutImportPanel caseId={caseId} writable={caseWritable} />

      <section className="mt-8 rounded-2xl border border-white/8 bg-white/[0.02] p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
              Application database support
            </p>
            <h2 className="mt-2 text-xl font-semibold text-white">Schema-gated, not access-bypassing</h2>
          </div>
          <span className="rounded-full border border-amber-200/15 px-3 py-1 text-[10px] uppercase tracking-wide text-amber-200">
            Experimental adapters
          </span>
        </div>
        <p className="mt-3 max-w-4xl text-xs leading-5 text-slate-400">
          These parsers operate only on lawfully obtained, verified plaintext database copies.
          They do not make private app databases readable through ordinary non-rooted ADB and do
          not decrypt Signal, backups, or encrypted userdata images.
        </p>
        {applicationSupportQuery.isPending && (
          <p role="status" className="mt-5 text-xs text-slate-500">Loading application support matrix…</p>
        )}
        {applicationSupportQuery.isError && (
          <div className="mt-5"><CaseError error={applicationSupportQuery.error} /></div>
        )}
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {applicationSupportQuery.data?.map((app) => (
            <ApplicationSupportCard key={app.app_id} app={app} />
          ))}
        </div>
      </section>

      <section className="mt-8">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">
              Sealed sources
            </p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Case Evidence Twins</h2>
          </div>
          {sourcesQuery.isFetching && <LoaderCircle className="animate-spin text-cyan-300" size={18} />}
        </div>
        {sourcesQuery.isError && <div className="mt-5"><CaseError error={sourcesQuery.error} /></div>}
        {!sourcesQuery.isPending && sourcesQuery.data?.length === 0 && (
          <div className="mt-5 rounded-xl border border-dashed border-white/10 p-8 text-center text-sm text-slate-500">
            No Evidence Twin source has been registered for this case.
          </div>
        )}
        <div className="mt-5 space-y-4">
          {sourcesQuery.data?.map((source) => (
            <EvidenceSourceCard
              key={source.id}
              caseId={caseId}
              source={source}
              aleapp={aleappQuery.data ?? null}
              photorec={photorecQuery.data ?? null}
              isAgentBundle={source.source_name.toLowerCase().endsWith(".fxz")}
            />
          ))}
        </div>
      </section>
    </div>
  );
}

function CloudServiceCard({ service }: { service: CloudServiceCapability }) {
  return (
    <article className="rounded-xl border border-sky-200/10 bg-black/10 p-4">
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-white">{service.display_name}</h3>
        <span className="text-[9px] font-semibold uppercase tracking-wide text-sky-100">
          {service.blocker_class.replaceAll("_", " ")}
        </span>
      </div>
      <p className="mt-3 text-[11px] leading-5 text-slate-400">
        {service.artifact_types.slice(0, 4).join(" · ")}
      </p>
      <p className="mt-3 text-[11px] leading-5 text-slate-500">
        {service.implementation_note}
      </p>
      <p className="mt-3 font-mono text-[9px] text-sky-200/60">
        {service.auth_methods.join(" / ")}
      </p>
    </article>
  );
}

function ApplicationSupportCard({ app }: { app: ApplicationArtifactSupport }) {
  const parserAvailable = app.status !== "detection_only";
  return (
    <article className="rounded-xl border border-white/8 bg-black/10 p-4">
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-white">{app.display_name}</h3>
        <span className={`text-[9px] font-semibold uppercase tracking-wide ${parserAvailable ? "text-emerald-200" : "text-amber-200"}`}>
          {app.status.replaceAll("_", " ")}
        </span>
      </div>
      <p className="mt-3 text-[11px] leading-5 text-slate-500">
        {app.limitations[0]}
      </p>
      <p className="mt-3 font-mono text-[9px] text-cyan-200/60">
        {app.native_parser_id ?? "No native content parser"}
      </p>
    </article>
  );
}

function EvidenceSourceCard({
  caseId,
  source,
  aleapp,
  photorec,
  isAgentBundle,
}: {
  caseId: string;
  source: EvidenceSource;
  aleapp: AleappDiagnostic | null;
  photorec: PhotoRecDiagnostic | null;
  isAgentBundle: boolean;
}) {
  const queryClient = useQueryClient();
  const copiesQuery = useQuery({
    queryKey: twinKeys.copies(caseId, source.id),
    queryFn: () => listEvidenceWorkingCopies(caseId, source.id),
    enabled: source.status === "sealed",
  });
  const verificationsQuery = useQuery({
    queryKey: twinKeys.verifications(caseId, source.id),
    queryFn: () => listEvidenceSourceVerifications(caseId, source.id),
    enabled: source.status === "sealed",
  });
  const parserRunsQuery = useQuery({
    queryKey: twinKeys.parserRuns(caseId, source.id),
    queryFn: () => listEvidenceParserRuns(caseId, source.id),
    enabled: source.status === "sealed",
  });
  const artifactsQuery = useQuery({
    queryKey: twinKeys.artifacts(caseId, source.id),
    queryFn: () => listEvidenceSourceArtifacts(caseId, source.id),
    enabled: source.status === "sealed",
  });
  const toolOutputsQuery = useQuery({
    queryKey: twinKeys.toolOutputs(caseId, source.id),
    queryFn: () => listEvidenceToolOutputs(caseId, source.id),
    enabled: source.status === "sealed",
  });
  const agentSummaryQuery = useQuery({
    queryKey: ["evidence-twin", caseId, source.id, "agent-bundle-summary"] as const,
    queryFn: () => getAndroidAgentBundleSummary(caseId, source.id),
    enabled: source.status === "sealed" && isAgentBundle,
  });
  const cloudSummaryQuery = useQuery({
    queryKey: ["evidence-twin", caseId, source.id, "cloud-export-summary"],
    queryFn: () => getCloudExportSummary(caseId, source.id),
    enabled: source.status === "sealed" && source.display_name.includes(" offline export: "),
  });
  const verify = useMutation({
    mutationFn: () => verifyEvidenceSource(caseId, source.id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: twinKeys.verifications(caseId, source.id) });
    },
  });
  const createCopy = useMutation({
    mutationFn: () => createEvidenceWorkingCopy(caseId, source.id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: twinKeys.copies(caseId, source.id) });
      void queryClient.invalidateQueries({ queryKey: twinKeys.verifications(caseId, source.id) });
    },
  });
  const latestVerification = verificationsQuery.data?.[0];

  return (
    <article className="rounded-2xl border border-white/8 bg-white/[0.025] p-5 sm:p-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-lg font-semibold text-white">{source.display_name}</h3>
            <span className="rounded-full border border-emerald-200/15 px-2 py-1 text-[10px] uppercase tracking-wide text-emerald-200">
              {source.status}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-500">
            {source.source_name} · {source.container_format.toUpperCase()} · {formatBytes(source.size_bytes ?? 0)}
          </p>
        </div>
        <span className="text-xs text-slate-600">{source.chunk_count} hashed chunks</span>
      </div>
      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <HashClaim label="Master SHA-256" value={source.sha256} />
        <HashClaim label="Chunk ledger SHA-256" value={source.chunks_sha256} />
        <HashClaim label="Manifest SHA-256" value={source.manifest_sha256} />
      </div>
      {cloudSummaryQuery.data && <CloudExportResult result={cloudSummaryQuery.data} />}
      {cloudSummaryQuery.isError && <div className="mt-4"><CaseError error={cloudSummaryQuery.error} /></div>}
      <div className="mt-5 flex flex-wrap items-center gap-3">
        {source.source_name.toLowerCase().endsWith(".png") && source.status === "sealed" && (
          <>
            <a
              href={getEvidenceSourceContentUrl(caseId, source.id)}
              target="_blank"
              rel="noreferrer"
              className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-cyan-200/20 px-3 text-xs font-semibold text-cyan-100"
            >
              <ExternalLink size={14} />
              View screenshot
            </a>
            <DownloadLink
              href={getEvidenceSourceContentUrl(caseId, source.id, true)}
              filename={source.source_name}
              className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-300 px-3 text-xs font-semibold text-slate-950"
            >
              <Download size={14} />
              Download PNG
            </DownloadLink>
          </>
        )}
        <button
          type="button"
          disabled={source.status !== "sealed" || verify.isPending}
          onClick={() => {
            verify.mutate();
          }}
          className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-emerald-200/15 px-3 text-xs font-semibold text-emerald-100 disabled:opacity-40"
        >
          {verify.isPending ? <LoaderCircle className="animate-spin" size={14} /> : <CheckCircle2 size={14} />}
          Verify sealed master
        </button>
        <button
          type="button"
          disabled={source.status !== "sealed" || createCopy.isPending}
          onClick={() => {
            createCopy.mutate();
          }}
          className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-300 px-3 text-xs font-semibold text-slate-950 disabled:opacity-40"
        >
          {createCopy.isPending ? <LoaderCircle className="animate-spin" size={14} /> : <CopyCheck size={14} />}
          Create verified working copy
        </button>
        {latestVerification && (
          <span className={`text-xs font-semibold ${latestVerification.status === "verified" ? "text-emerald-200" : "text-rose-200"}`}>
            Latest {latestVerification.target_type.replace("_", " ")}: {latestVerification.status}
          </span>
        )}
      </div>
      <p className="mt-4 text-xs text-slate-500">
        {copiesQuery.data?.length ?? 0} working copies · {verificationsQuery.data?.length ?? 0} integrity observations · read-only permission {source.read_only_applied ? "applied" : "not confirmed"}
      </p>
      {source.limitations.map((limitation) => (
        <p key={limitation} className="mt-2 text-xs leading-5 text-amber-100/65">• {limitation}</p>
      ))}
      {isAgentBundle && agentSummaryQuery.data && (
        <div className="mt-5 rounded-xl border border-emerald-200/10 bg-emerald-200/[0.035] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.14em] text-emerald-100">
                Android agent collection
              </p>
              <p className="mt-2 font-mono text-[10px] text-slate-400">
                {agentSummaryQuery.data.collection_id}
              </p>
            </div>
            <span className={`rounded-full border px-2 py-1 text-[10px] uppercase ${
              agentSummaryQuery.data.collection_complete
                ? "border-emerald-200/20 text-emerald-100"
                : "border-amber-200/20 text-amber-100"
            }`}>
              {agentSummaryQuery.data.collection_complete ? "complete" : "partial"}
            </span>
          </div>
          <div className="mt-3 grid gap-2 sm:grid-cols-5">
            {Object.entries(agentSummaryQuery.data.record_counts).map(([key, value]) => (
              <div key={key} className="rounded-lg border border-white/8 bg-black/10 p-3">
                <p className="text-[10px] uppercase tracking-wide text-slate-500">
                  {key.replaceAll("_", " ")}
                </p>
                <p className="mt-1 text-lg font-semibold text-white">{String(value)}</p>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Run the verified working-copy parser to place these records into artifact search,
            timeline, custody, and reports.
          </p>
        </div>
      )}
      {agentSummaryQuery.isError && <div className="mt-4"><CaseError error={agentSummaryQuery.error} /></div>}
      {verify.isError && <div className="mt-4"><CaseError error={verify.error} /></div>}
      {createCopy.isError && <div className="mt-4"><CaseError error={createCopy.error} /></div>}
      {copiesQuery.data?.map((workingCopy) => (
        <WorkingCopyPanel
          key={workingCopy.id}
          caseId={caseId}
          sourceId={source.id}
          workingCopy={workingCopy}
          isAgentBundle={isAgentBundle}
          artifacts={
            artifactsQuery.data?.filter(
              (artifact) => artifact.working_copy_id === workingCopy.id,
            ) ?? []
          }
          parserRunCount={
            parserRunsQuery.data?.filter((run) => run.working_copy_id === workingCopy.id)
              .length ?? 0
          }
          aleapp={aleapp}
          photorec={photorec}
          toolOutputs={
            toolOutputsQuery.data?.filter(
              (output) => output.working_copy_id === workingCopy.id,
            ) ?? []
          }
        />
      ))}
      {parserRunsQuery.isError && <div className="mt-4"><CaseError error={parserRunsQuery.error} /></div>}
      {artifactsQuery.isError && <div className="mt-4"><CaseError error={artifactsQuery.error} /></div>}
      {toolOutputsQuery.isError && <div className="mt-4"><CaseError error={toolOutputsQuery.error} /></div>}
    </article>
  );
}

function WorkingCopyPanel({
  caseId,
  sourceId,
  workingCopy,
  isAgentBundle,
  artifacts,
  parserRunCount,
  aleapp,
  photorec,
  toolOutputs,
}: {
  caseId: string;
  sourceId: string;
  workingCopy: EvidenceWorkingCopy;
  isAgentBundle: boolean;
  artifacts: EvidenceSourceArtifact[];
  parserRunCount: number;
  aleapp: AleappDiagnostic | null;
  photorec: PhotoRecDiagnostic | null;
  toolOutputs: EvidenceToolOutput[];
}) {
  const queryClient = useQueryClient();
  const [recoveryAssessment, setRecoveryAssessment] = useState<RecoveryAssessment | null>(null);
  const [recoveryCarving, setRecoveryCarving] = useState<RecoveryCarving | null>(null);
  const [externalRecovery, setExternalRecovery] = useState<ExternalRecovery | null>(null);
  const inspectionQuery = useQuery({
    queryKey: twinKeys.inspection(caseId, sourceId, workingCopy.id),
    queryFn: () => getEvidenceWorkingCopyInspection(caseId, sourceId, workingCopy.id),
    enabled: workingCopy.status === "ready",
    retry: false,
  });
  const inspectCopy = useMutation({
    mutationFn: () => inspectEvidenceWorkingCopy(caseId, sourceId, workingCopy.id),
    onSuccess: (inspection) => {
      queryClient.setQueryData(
        twinKeys.inspection(caseId, sourceId, workingCopy.id),
        inspection,
      );
    },
  });
  const verifyCopy = useMutation({
    mutationFn: () => verifyEvidenceWorkingCopy(caseId, sourceId, workingCopy.id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: twinKeys.verifications(caseId, sourceId) });
    },
  });
  const runParsers = useMutation({
    mutationFn: () =>
      runNativeEvidenceParsers(
        caseId,
        sourceId,
        workingCopy.id,
        isAgentBundle ? ["android.agent_bundle.v1"] : undefined,
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: twinKeys.parserRuns(caseId, sourceId) });
      void queryClient.invalidateQueries({ queryKey: twinKeys.artifacts(caseId, sourceId) });
      void queryClient.invalidateQueries({ queryKey: twinKeys.verifications(caseId, sourceId) });
    },
  });
  const runAleappParser = useMutation({
    mutationFn: () => runAleapp(caseId, sourceId, workingCopy.id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: twinKeys.parserRuns(caseId, sourceId) });
      void queryClient.invalidateQueries({ queryKey: twinKeys.toolOutputs(caseId, sourceId) });
      void queryClient.invalidateQueries({ queryKey: twinKeys.verifications(caseId, sourceId) });
    },
  });
  const assessRecovery = useMutation({
    mutationFn: () =>
      assessEvidenceRecoveryCandidates(caseId, sourceId, workingCopy.id),
    onSuccess: (assessment) => {
      setRecoveryAssessment(assessment);
    },
  });
  const runRecoveryCarving = useMutation({
    mutationFn: () => carveEvidenceRecoveryCandidates(caseId, sourceId, workingCopy.id),
    onSuccess: (carving) => {
      setRecoveryCarving(carving);
    },
  });
  const runExternalRecoveryTool = useMutation({
    mutationFn: () => runExternalRecovery(caseId, sourceId, workingCopy.id),
    onSuccess: (run) => {
      setExternalRecovery(run);
    },
  });
  const inspection = inspectionQuery.data;
  const recoverySupported = Boolean(
    inspection && new Set(["sqlite", "zip", "tar"]).has(inspection.detected_type),
  );
  const externalRecoverySupported = Boolean(
    inspection &&
      new Set(["ext4", "f2fs"]).has(inspection.detected_type) &&
      photorec?.available,
  );

  return (
    <section className="mt-5 rounded-xl border border-cyan-200/10 bg-cyan-200/[0.025] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-200">
            Verified examination copy
          </p>
          <p className="mt-1 font-mono text-[10px] text-slate-500">{workingCopy.id}</p>
        </div>
        <span className="rounded-full border border-emerald-200/15 px-2 py-1 text-[10px] uppercase text-emerald-200">
          {workingCopy.status}
        </span>
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          disabled={verifyCopy.isPending || workingCopy.status !== "ready"}
          onClick={() => {
            verifyCopy.mutate();
          }}
          className="min-h-9 rounded-lg border border-white/10 px-3 text-xs font-semibold text-slate-300 disabled:opacity-40"
        >
          {verifyCopy.isPending ? "Verifying…" : "Verify copy"}
        </button>
        <button
          type="button"
          disabled={inspectCopy.isPending || workingCopy.status !== "ready"}
          onClick={() => {
            inspectCopy.mutate();
          }}
          className="min-h-9 rounded-lg border border-cyan-200/20 px-3 text-xs font-semibold text-cyan-100 disabled:opacity-40"
        >
          {inspectCopy.isPending
            ? "Inspecting…"
            : inspection
              ? "Reopen inspection"
              : "Inspect signatures"}
        </button>
        <button
          type="button"
          disabled={
            runParsers.isPending ||
            !inspection ||
            !(isAgentBundle || new Set(["sqlite", "zip", "tar"]).has(inspection.detected_type))
          }
          onClick={() => {
            runParsers.mutate();
          }}
          className="min-h-9 rounded-lg bg-cyan-300 px-3 text-xs font-semibold text-slate-950 disabled:opacity-40"
        >
          {runParsers.isPending
            ? "Parsing…"
            : isAgentBundle
              ? "Index Android agent bundle"
              : inspection && new Set(["zip", "tar"]).has(inspection.detected_type)
              ? "Safely extract and run Android parsers"
              : "Run compatible Android parsers"}
        </button>
        <button
          type="button"
          disabled={
            runAleappParser.isPending ||
            !aleapp?.hash_verified ||
            !inspection ||
            !new Set(["zip", "tar"]).has(inspection.detected_type)
          }
          onClick={() => {
            runAleappParser.mutate();
          }}
          className="min-h-9 rounded-lg border border-violet-200/20 px-3 text-xs font-semibold text-violet-100 disabled:opacity-40"
        >
          {runAleappParser.isPending ? "Running ALEAPP…" : "Run pinned ALEAPP"}
        </button>
        <button
          type="button"
          disabled={assessRecovery.isPending || !recoverySupported}
          onClick={() => {
            assessRecovery.mutate();
          }}
          className="min-h-9 rounded-lg border border-amber-200/20 px-3 text-xs font-semibold text-amber-100 disabled:opacity-40"
        >
          {assessRecovery.isPending
            ? "Assessing recovery metadata…"
            : "Assess recovery candidates (experimental)"}
        </button>
        <button
          type="button"
          disabled={runRecoveryCarving.isPending || !recoverySupported}
          onClick={() => {
            runRecoveryCarving.mutate();
          }}
          className="min-h-9 rounded-lg border border-rose-200/25 px-3 text-xs font-semibold text-rose-100 disabled:opacity-40"
        >
          {runRecoveryCarving.isPending
            ? "Scanning byte fragments..."
            : "Run SQLite fragment scan (experimental)"}
        </button>
        <button
          type="button"
          disabled={runExternalRecoveryTool.isPending || !externalRecoverySupported}
          onClick={() => {
            runExternalRecoveryTool.mutate();
          }}
          className="min-h-9 rounded-lg border border-fuchsia-200/25 px-3 text-xs font-semibold text-fuchsia-100 disabled:opacity-40"
        >
          {runExternalRecoveryTool.isPending
            ? "Running PhotoRec on working copy..."
            : "Run TestDisk/PhotoRec recovery (experimental)"}
        </button>
      </div>
      {inspection && (
        <div className="mt-4 rounded-lg border border-white/8 bg-black/10 p-3 text-xs text-slate-400">
          <p>
            Detected <strong className="text-white">{inspection.detected_type}</strong> with{" "}
            {inspection.confidence} confidence · encryption{" "}
            {inspection.encryption_state.replace("_", " ")}
          </p>
          <p className="mt-2 font-mono text-[10px] text-slate-600">
            Inspection SHA-256 {inspection.inspection_hash}
          </p>
          {inspection.warnings.map((warning) => (
            <p key={warning} className="mt-2 text-amber-100/70">
              • {warning}
            </p>
          ))}
        </div>
      )}
      {recoveryAssessment && (
        <RecoveryAssessmentPanel assessment={recoveryAssessment} />
      )}
      {recoveryCarving && <RecoveryCarvingPanel carving={recoveryCarving} />}
      {externalRecovery && <ExternalRecoveryPanel run={externalRecovery} />}
      {inspection && new Set(["ext4", "f2fs"]).has(inspection.detected_type) && !photorec?.available && (
        <p className="mt-4 rounded-lg border border-fuchsia-200/15 bg-fuchsia-200/[0.035] p-3 text-xs leading-5 text-fuchsia-100/80">
          TestDisk/PhotoRec external recovery is not configured on this workstation. {photorec?.guidance[0] ?? "Configure a hash-pinned PhotoRec executable first."}
        </p>
      )}
      <p className="mt-4 text-xs text-slate-500">
        {parserRunCount} parser run(s) · {artifacts.length} normalized artifact(s)
      </p>
      {artifacts.length > 0 && (
        <div className="mt-3 grid gap-3 lg:grid-cols-2">
          {artifacts.map((artifact) => (
            <ParsedArtifactCard key={artifact.id} artifact={artifact} caseId={caseId} />
          ))}
        </div>
      )}
      {toolOutputs.length > 0 && (
        <div className="mt-4 rounded-lg border border-violet-200/10 bg-violet-200/[0.025] p-3">
          <p className="text-xs font-semibold text-violet-100">Sealed ALEAPP outputs</p>
          {toolOutputs.map((output) => (
            <div key={output.id} className="mt-2 text-[10px] text-slate-500">
              <p className="text-slate-300">
                {output.relative_path} · {formatBytes(output.size_bytes)}
              </p>
              <p className="truncate font-mono" title={output.sha256}>
                SHA-256 {output.sha256}
              </p>
            </div>
          ))}
        </div>
      )}
      {inspectCopy.isError && <div className="mt-4"><CaseError error={inspectCopy.error} /></div>}
      {verifyCopy.isError && <div className="mt-4"><CaseError error={verifyCopy.error} /></div>}
      {runParsers.isError && <div className="mt-4"><CaseError error={runParsers.error} /></div>}
      {runAleappParser.isError && <div className="mt-4"><CaseError error={runAleappParser.error} /></div>}
      {assessRecovery.isError && <div className="mt-4"><CaseError error={assessRecovery.error} /></div>}
      {runRecoveryCarving.isError && <div className="mt-4"><CaseError error={runRecoveryCarving.error} /></div>}
      {runExternalRecoveryTool.isError && <div className="mt-4"><CaseError error={runExternalRecoveryTool.error} /></div>}
    </section>
  );
}

function ExternalRecoveryPanel({ run }: { run: ExternalRecovery }) {
  return (
    <div className="mt-4 rounded-lg border border-fuchsia-200/20 bg-fuchsia-200/[0.04] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-fuchsia-100">
            TestDisk/PhotoRec external recovery
          </p>
          <p className="mt-2 text-sm font-semibold text-white">
            {run.recovered_file_count} carved file candidate(s)
          </p>
        </div>
        <span className="rounded-full border border-fuchsia-200/20 px-2 py-1 text-[10px] uppercase text-fuchsia-100">
          {run.status.replaceAll("_", " ")}
        </span>
      </div>
      <p className="mt-3 text-xs leading-5 text-fuchsia-100/75">
        The TestDisk project’s PhotoRec component was run only on the verified examination copy.
        Output is candidate material: it is not proof of deletion, original ownership, or Android source.
      </p>
      <div className="mt-3 grid gap-2 text-xs text-slate-400 sm:grid-cols-3">
        <p>{formatBytes(run.output_total_bytes)} output</p>
        <p>Exit code {run.exit_code ?? "not run"}</p>
        <p>PhotoRec {run.version}</p>
      </div>
      {run.output_files.length > 0 && (
        <div className="mt-3 max-h-56 overflow-y-auto rounded-lg border border-white/8 bg-black/10 p-3">
          {run.output_files.map((file) => (
            <p key={file.relative_path} className="mt-2 text-xs text-slate-300 first:mt-0">
              {file.relative_path} · {formatBytes(file.size_bytes)}
              <span className="ml-2 font-mono text-[10px] text-slate-600">{file.sha256}</span>
            </p>
          ))}
        </div>
      )}
      {run.limitations.map((limitation) => (
        <p key={limitation} className="mt-2 text-xs leading-5 text-slate-500">• {limitation}</p>
      ))}
      <p className="mt-3 truncate font-mono text-[10px] text-slate-600" title={run.run_hash}>
        Recovery run SHA-256 {run.run_hash}
      </p>
    </div>
  );
}

function RecoveryCarvingPanel({ carving }: { carving: RecoveryCarving }) {
  return (
    <div className="mt-4 rounded-lg border border-rose-200/20 bg-rose-200/[0.04] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-rose-100">
            Experimental SQLite fragment scan
          </p>
          <p className="mt-2 text-sm font-semibold text-white">
            {carving.fragment_count} candidate fragment(s) — not verified recovered records
          </p>
        </div>
        <span className="rounded-full border border-rose-200/20 px-2 py-1 text-[10px] uppercase text-rose-100">
          {carving.status.replaceAll("_", " ")}
        </span>
      </div>
      <p className="mt-3 text-xs leading-5 text-rose-100/75">
        The scan is bounded to a verified working copy and never modifies the Android device or
        sealed master. Its text snippets are investigative leads only and can be current, stale,
        or false-positive bytes.
      </p>
      <div className="mt-3 grid gap-2 text-xs text-slate-400 sm:grid-cols-3">
        <p>{carving.source_file_count} SQLite input(s)</p>
        <p>{carving.wal_fragments_found} WAL candidate(s)</p>
        <p>{carving.freelist_fragments_found} freelist candidate(s)</p>
      </div>
      {carving.fragments.length > 0 && (
        <div className="mt-3 max-h-96 space-y-2 overflow-y-auto pr-1">
          {carving.fragments.map((fragment) => (
            <details
              key={fragment.fragment_hash}
              className="rounded-lg border border-white/8 bg-black/10 p-3"
            >
              <summary className="cursor-pointer text-xs font-semibold text-slate-200">
                {fragment.source_file} · offset {fragment.offset_bytes.toLocaleString()} · {fragment.fragment_type.replaceAll("_", " ")}
              </summary>
              <p className="mt-2 text-[10px] uppercase tracking-wide text-rose-100/75">
                {fragment.confidence} confidence · {fragment.length_bytes} bytes · SHA-256 {fragment.content_sha256}
              </p>
              <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap rounded bg-slate-950/70 p-3 text-xs leading-5 text-slate-200">
                {fragment.content_preview}
              </pre>
            </details>
          ))}
        </div>
      )}
      {carving.skipped_locators.length > 0 && (
        <p className="mt-3 text-xs text-amber-100/80">
          {carving.skipped_locators.length} input(s) exceeded the scan policy and were skipped.
        </p>
      )}
      {carving.limitations.map((limitation) => (
        <p key={limitation} className="mt-2 text-xs leading-5 text-slate-500">
          • {limitation}
        </p>
      ))}
      <p className="mt-3 truncate font-mono text-[10px] text-slate-600" title={carving.run_hash}>
        Scan SHA-256 {carving.run_hash}
      </p>
    </div>
  );
}

function RecoveryAssessmentPanel({ assessment }: { assessment: RecoveryAssessment }) {
  return (
    <div className="mt-4 rounded-lg border border-amber-200/20 bg-amber-200/[0.04] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-100">
            Experimental recovery readiness
          </p>
          <p className="mt-2 text-sm font-semibold text-white">
            Candidate regions are not recovered records
          </p>
        </div>
        <span className="rounded-full border border-amber-200/20 px-2 py-1 text-[10px] uppercase text-amber-100">
          {assessment.status.replaceAll("_", " ")}
        </span>
      </div>
      <p className="mt-3 text-xs leading-5 text-amber-100/75">
        This metadata-only probe observed {assessment.candidate_region_count} candidate region(s)
        across {assessment.candidates.length} supported SQLite source(s). It did not carve rows,
        reconstruct transactions, bypass encryption, or prove that a user deleted data.
      </p>
      {assessment.candidates.length > 0 && (
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {assessment.candidates.map((candidate) => (
            <div
              key={candidate.candidate_hash}
              className="rounded-lg border border-white/8 bg-black/10 p-3"
            >
              <p
                className="truncate font-mono text-[10px] text-slate-300"
                title={candidate.source_locator}
              >
                {candidate.source_locator}
              </p>
              <p className="mt-2 text-[10px] uppercase tracking-wide text-amber-100/75">
                {candidate.source_kind.replaceAll("_", " ")} ·{" "}
                {candidate.status.replaceAll("_", " ")} · {candidate.confidence} confidence
              </p>
              <p className="mt-2 text-xs text-slate-500">
                {candidate.candidate_region_count} candidate region(s) ·{" "}
                {formatBytes(candidate.source_size_bytes)}
              </p>
            </div>
          ))}
        </div>
      )}
      {assessment.limitations.map((limitation) => (
        <p key={limitation} className="mt-2 text-xs leading-5 text-slate-500">
          • {limitation}
        </p>
      ))}
      <p
        className="mt-3 truncate font-mono text-[10px] text-slate-600"
        title={assessment.assessment_hash}
      >
        Assessment SHA-256 {assessment.assessment_hash}
      </p>
    </div>
  );
}

function ParsedArtifactCard({ artifact, caseId }: { artifact: EvidenceSourceArtifact; caseId: string }) {
  const cardCandidate = artifact.subtype === "memory_card_deleted_candidate";
  const imageCandidate = artifact.subtype === "raw_image_media_candidate";
  const extractable = cardCandidate && artifact.metadata.recovery_status === "contiguous_unallocated_candidate";
  const readableCardFile = artifact.subtype === "memory_card_file" && artifact.metadata.hash_status === "complete";
  return (
    <article className="rounded-lg border border-white/8 bg-black/10 p-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-white">{artifact.title}</p>
          <p className="mt-1 text-[10px] uppercase tracking-wide text-cyan-200">
            {artifact.subtype.replace("_", " ")} · {artifact.status}
          </p>
        </div>
        <span className="text-[10px] text-slate-600">{artifact.confidence}</span>
      </div>
      <p className="mt-3 text-xs leading-5 text-slate-400">{artifact.summary}</p>
      {cardCandidate && (
        <p className="mt-2 text-xs text-amber-100/80">
          {extractable
            ? "Deleted entry: contiguous bytes are unallocated and match the recorded SHA-256. Original file identity remains unproven."
            : "Deleted entry found; file content is not safely extractable from this image."}
        </p>
      )}
      {extractable && (
        <a
          className="mt-2 inline-block text-xs font-medium text-cyan-200 underline underline-offset-2"
          href={`/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(artifact.evidence_source_id)}/artifacts/${encodeURIComponent(artifact.id)}/candidate-content`}
        >
          Download verified candidate bytes
        </a>
      )}
      {readableCardFile && (
        <a
          className="mt-2 inline-block text-xs font-medium text-cyan-200 underline underline-offset-2"
          href={`/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(artifact.evidence_source_id)}/artifacts/${encodeURIComponent(artifact.id)}/file-content`}
        >
          Download verified file bytes
        </a>
      )}
      {imageCandidate && (
        <a
          className="mt-2 inline-block text-xs font-medium text-cyan-200 underline underline-offset-2"
          href={`/api/v1/cases/${encodeURIComponent(caseId)}/evidence-sources/${encodeURIComponent(artifact.evidence_source_id)}/artifacts/${encodeURIComponent(artifact.id)}/carved-content`}
        >
          Download hash-verified candidate bytes
        </a>
      )}
      {typeof artifact.metadata.attachment_resolution === "string" && (
        <p className="mt-2 text-xs text-sky-200">Attachment: {artifact.metadata.attachment_resolution}</p>
      )}
      {artifact.parser_id.startsWith("cloud.") && (
        <details className="mt-2 text-xs text-slate-400">
          <summary>Export fields and provenance</summary>
          <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all">{JSON.stringify(artifact.metadata, null, 2)}</pre>
        </details>
      )}
      {artifact.event_time && (
        <p className="mt-2 text-[10px] text-slate-500">
          {new Date(artifact.event_time).toLocaleString()}
        </p>
      )}
      <p
        className="mt-2 truncate font-mono text-[10px] text-slate-600"
        title={artifact.artifact_hash}
      >
        {artifact.source_locator} · {artifact.artifact_hash}
      </p>
    </article>
  );
}

function IntegrityStep({ number, text }: { number: string; text: string }) {
  return (
    <li className="flex gap-3">
      <span className="grid size-7 shrink-0 place-items-center rounded-full border border-cyan-200/15 text-xs text-cyan-200">
        {number}
      </span>
      <span>{text}</span>
    </li>
  );
}

function HashClaim({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="min-w-0 rounded-lg border border-white/8 bg-black/10 p-3">
      <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-600">{label}</p>
      <p className="mt-2 truncate font-mono text-[10px] text-slate-400" title={value ?? undefined}>
        {value ?? "Not available"}
      </p>
    </div>
  );
}

function formatBytes(value: number): string {
  if (value < 1024) return `${String(value)} bytes`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

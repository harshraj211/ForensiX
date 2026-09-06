import React, { useState } from "react";
import {
  Activity,
  Archive,
  Cloud,
  Database,
  Eye,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Smartphone,
  ShieldCheck,
  Zap,
} from "lucide-react";
import {
  extractDumpsysTelemetry,
  extractVendorBackup,
  scrapeAccessibilityTranscripts,
  harvestContentProviders,
  extractCloudTokens,
  DumpsysTelemetryResult,
  VendorBackupResult,
  AccessibilityScrapeResult,
  ContentProviderHarvestResult,
  CloudTokenExtractResult,
} from "../../lib/api";

interface NonRootedSuitePanelProps {
  caseId: string;
  serial: string;
}

export function NonRootedSuitePanel({ caseId, serial }: NonRootedSuitePanelProps) {
  const [activeTab, setActiveTab] = useState<
    "telemetry" | "vendor" | "accessibility" | "providers" | "cloud"
  >("telemetry");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Results state
  const [telemetryResult, setTelemetryResult] = useState<DumpsysTelemetryResult | null>(null);
  const [vendorResult, setVendorResult] = useState<VendorBackupResult | null>(null);
  const [accessibilityResult, setAccessibilityResult] = useState<AccessibilityScrapeResult | null>(
    null,
  );
  const [providerResult, setProviderResult] = useState<ContentProviderHarvestResult | null>(null);
  const [cloudResult, setCloudResult] = useState<CloudTokenExtractResult | null>(null);

  // Form options
  const [vendorType, setVendorType] = useState("samsung_smartswitch");
  const [targetPackage, setTargetPackage] = useState("com.whatsapp");

  async function handleRunTelemetry() {
    setLoading(true);
    setError(null);
    try {
      const res = await extractDumpsysTelemetry(caseId, { serial, case_id: caseId });
      setTelemetryResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to mine telemetry.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRunVendorBackup() {
    setLoading(true);
    setError(null);
    try {
      const res = await extractVendorBackup(caseId, {
        serial,
        case_id: caseId,
        vendor_type: vendorType,
      });
      setVendorResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to extract OEM vendor backup.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRunAccessibilityScrape() {
    setLoading(true);
    setError(null);
    try {
      const res = await scrapeAccessibilityTranscripts(caseId, {
        serial,
        case_id: caseId,
        target_package: targetPackage,
      });
      setAccessibilityResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to scrape UI transcripts.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRunProviderHarvest() {
    setLoading(true);
    setError(null);
    try {
      const res = await harvestContentProviders(caseId, { serial, case_id: caseId });
      setProviderResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to harvest content providers.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRunCloudTokens() {
    setLoading(true);
    setError(null);
    try {
      const res = await extractCloudTokens(caseId, { serial, case_id: caseId });
      setCloudResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to extract cloud session tokens.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-2xl border border-cyan-200 bg-gradient-to-r from-cyan-900 via-slate-900 to-indigo-900 p-6 text-white shadow-md">
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-cyan-500/20 p-2.5 text-cyan-300 border border-cyan-400/30">
            <Zap size={24} />
          </div>
          <div>
            <h2 className="text-lg font-bold tracking-tight">Non-Rooted Advanced Forensic Suite</h2>
            <p className="text-xs text-cyan-200/80">
              Industry-leading zero-root extraction vectors bypassing SELinux and allowBackup flags
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="mt-6 flex flex-wrap gap-2 border-t border-cyan-800/60 pt-4">
          <button
            type="button"
            onClick={() => setActiveTab("telemetry")}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all ${
              activeTab === "telemetry"
                ? "bg-cyan-500 text-slate-950 shadow-sm"
                : "bg-slate-800/80 text-slate-300 hover:bg-slate-800"
            }`}
          >
            <Activity size={15} /> System Telemetry & Dumpsys
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("vendor")}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all ${
              activeTab === "vendor"
                ? "bg-cyan-500 text-slate-950 shadow-sm"
                : "bg-slate-800/80 text-slate-300 hover:bg-slate-800"
            }`}
          >
            <Archive size={15} /> OEM Vendor Backups
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("accessibility")}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all ${
              activeTab === "accessibility"
                ? "bg-cyan-500 text-slate-950 shadow-sm"
                : "bg-slate-800/80 text-slate-300 hover:bg-slate-800"
            }`}
          >
            <Eye size={15} /> Forensic Accessibility Agent
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("providers")}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all ${
              activeTab === "providers"
                ? "bg-cyan-500 text-slate-950 shadow-sm"
                : "bg-slate-800/80 text-slate-300 hover:bg-slate-800"
            }`}
          >
            <Database size={15} /> Content Provider Harvester
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("cloud")}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold transition-all ${
              activeTab === "cloud"
                ? "bg-cyan-500 text-slate-950 shadow-sm"
                : "bg-slate-800/80 text-slate-300 hover:bg-slate-800"
            }`}
          >
            <Cloud size={15} /> Cloud Sync Tokens
          </button>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 p-4 text-xs font-medium text-rose-800">
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      {/* Tab 1: System Telemetry */}
      {activeTab === "telemetry" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">System Telemetry & Logcat Mining</h3>
              <p className="text-xs text-slate-500">
                Extract app usage timelines, Wi-Fi SSIDs/BSSIDs, paired Bluetooth devices, and cell towers without root.
              </p>
            </div>
            <button
              type="button"
              onClick={handleRunTelemetry}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-cyan-700 px-4 py-2 text-xs font-semibold text-white shadow hover:bg-cyan-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Activity size={14} />}
              Execute Telemetry Mine
            </button>
          </div>

          {telemetryResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between text-emerald-900 font-bold">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> Telemetry Extraction Completed</span>
                <span>{telemetryResult.duration_seconds}s</span>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-lg bg-white p-3 border border-slate-200">
                  <span className="font-semibold text-slate-500 block">App Launch Records</span>
                  <span className="text-base font-black text-slate-900">{telemetryResult.usage_stats.length} apps mined</span>
                </div>
                <div className="rounded-lg bg-white p-3 border border-slate-200">
                  <span className="font-semibold text-slate-500 block">Wi-Fi Networks</span>
                  <span className="text-base font-black text-slate-900">{telemetryResult.wifi_networks.length} SSIDs recovered</span>
                </div>
                <div className="rounded-lg bg-white p-3 border border-slate-200">
                  <span className="font-semibold text-slate-500 block">Bluetooth Devices</span>
                  <span className="text-base font-black text-slate-900">{telemetryResult.bluetooth_devices.length} paired MACs</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: OEM Vendor Backups */}
      {activeTab === "vendor" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">OEM Vendor Backup Emulation</h3>
              <p className="text-xs text-slate-500">
                Emulate Samsung Smart Switch or Huawei HiSuite RPC calls to pull OEM backups overriding allowBackup=false.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <select
              value={vendorType}
              onChange={(e) => setVendorType(e.target.value)}
              className="rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-semibold text-slate-700 shadow-sm"
            >
              <option value="samsung_smartswitch">Samsung Smart Switch RPC</option>
              <option value="huawei_hisuite">Huawei HiSuite Protocol</option>
              <option value="xiaomi_miconnect">Xiaomi Mi Backup Protocol</option>
            </select>

            <button
              type="button"
              onClick={handleRunVendorBackup}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-cyan-700 px-4 py-2 text-xs font-semibold text-white shadow hover:bg-cyan-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Archive size={14} />}
              Extract Vendor Backup
            </button>
          </div>

          {vendorResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between text-emerald-900 font-bold">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> Vendor Backup Pulled</span>
                <span>{(vendorResult.total_size_bytes / 1048576).toFixed(2)} MB</span>
              </div>
              <ul className="divide-y divide-emerald-200/60 font-mono text-[11px]">
                {vendorResult.extracted_items.map((item, idx) => (
                  <li key={idx} className="py-1.5 flex justify-between">
                    <span>{item.package_name} ({item.data_type})</span>
                    <span className="font-semibold text-slate-700">{item.file_count} file(s)</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Forensic Accessibility Agent */}
      {activeTab === "accessibility" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">Forensic Accessibility UI Scraper</h3>
              <p className="text-xs text-slate-500">
                Deploy signed ForensiXCompanion agent to walk chat UI screens and generate structured JSON transcripts.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <input
              type="text"
              value={targetPackage}
              onChange={(e) => setTargetPackage(e.target.value)}
              placeholder="e.g. com.whatsapp"
              className="w-64 rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-800 shadow-sm"
            />
            <button
              type="button"
              onClick={handleRunAccessibilityScrape}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-cyan-700 px-4 py-2 text-xs font-semibold text-white shadow hover:bg-cyan-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Eye size={14} />}
              Scrape UI Transcripts
            </button>
          </div>

          {accessibilityResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between text-emerald-900 font-bold">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> UI Scraping Complete</span>
                <span>{accessibilityResult.screens_scraped_count} screen(s) captured</span>
              </div>
              <div className="space-y-2">
                {accessibilityResult.transcripts.map((t, idx) => (
                  <div key={idx} className="rounded-lg bg-white p-2.5 border border-slate-200">
                    <div className="flex justify-between font-semibold text-slate-800">
                      <span>{t.sender_or_title}</span>
                      <span className="text-[10px] text-slate-400">{t.timestamp_text}</span>
                    </div>
                    <p className="text-slate-600 mt-1">{t.content_text}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Content Provider Harvester */}
      {activeTab === "providers" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">Content Provider Harvester</h3>
              <p className="text-xs text-slate-500">
                Query accessible non-rooted system providers (media index, deleted files, settings, SIM ICCIDs).
              </p>
            </div>
            <button
              type="button"
              onClick={handleRunProviderHarvest}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-cyan-700 px-4 py-2 text-xs font-semibold text-white shadow hover:bg-cyan-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Database size={14} />}
              Harvest Content Providers
            </button>
          </div>

          {providerResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between text-emerald-900 font-bold">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> Harvest Complete</span>
                <span>{providerResult.total_records_extracted} records</span>
              </div>
              <ul className="space-y-1.5 font-mono text-[11px]">
                {providerResult.queried_uris.map((uri, idx) => (
                  <li key={idx} className="rounded bg-white px-2.5 py-1.5 border border-slate-200 text-slate-700">
                    {uri}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Tab 5: Cloud Sync Tokens */}
      {activeTab === "cloud" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">Cloud Sync Token Harvester</h3>
              <p className="text-xs text-slate-500">
                Harvest Google, Samsung, and app sync tokens to feed cloud-side backup decrypters.
              </p>
            </div>
            <button
              type="button"
              onClick={handleRunCloudTokens}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-cyan-700 px-4 py-2 text-xs font-semibold text-white shadow hover:bg-cyan-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Cloud size={14} />}
              Extract Cloud Tokens
            </button>
          </div>

          {cloudResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between text-emerald-900 font-bold">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> Cloud Tokens Extracted</span>
                <span>{cloudResult.extracted_tokens.length} token(s)</span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {cloudResult.extracted_tokens.map((token, idx) => (
                  <div key={idx} className="rounded-lg bg-white p-3 border border-slate-200">
                    <span className="font-bold text-slate-900 block">{token.service_name}</span>
                    <span className="text-[11px] text-slate-500 block">{token.account_identifier}</span>
                    <span className="inline-block mt-1.5 rounded bg-cyan-100 px-2 py-0.5 text-[10px] font-semibold text-cyan-900">
                      {token.token_type}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

import React, { useState } from "react";
import {
  Brain,
  CheckCircle2,
  HardDrive,
  KeyRound,
  Loader2,
  Lock,
  MapPin,
  Sparkles,
  Users,
} from "lucide-react";
import {
  decryptKeystoreVaults,
  carveRawDisk,
  correlateIdentityPersonas,
  evaluateFbeMatrix,
  recordAiVisionOcrSession,
  KeystoreVaultDecryptResult,
  RawDiskCarveResult,
  IdentityPersonaCorrelateResult,
  FbeStateMatrixResult,
  AiVisionOcrRecordResult,
} from "../../lib/api";

interface DeepForensicsPanelProps {
  caseId: string;
  serial: string;
}

export function DeepForensicsPanel({ caseId, serial }: DeepForensicsPanelProps) {
  const [activeTab, setActiveTab] = useState<"keystore" | "disk" | "personas" | "fbe" | "vision">("keystore");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Results
  const [keystoreResult, setKeystoreResult] = useState<KeystoreVaultDecryptResult | null>(null);
  const [diskResult, setDiskResult] = useState<RawDiskCarveResult | null>(null);
  const [personaResult, setPersonaResult] = useState<IdentityPersonaCorrelateResult | null>(null);
  const [fbeResult, setFbeResult] = useState<FbeStateMatrixResult | null>(null);
  const [visionResult, setVisionResult] = useState<AiVisionOcrRecordResult | null>(null);

  const [targetApp, setTargetApp] = useState("com.whatsapp");

  async function handleRunKeystore() {
    setLoading(true);
    setError(null);
    try {
      const res = await decryptKeystoreVaults(caseId, { serial, case_id: caseId });
      setKeystoreResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed KeyStore vault decryption.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRunRawDisk() {
    setLoading(true);
    setError(null);
    try {
      const res = await carveRawDisk(caseId, { serial, case_id: caseId });
      setDiskResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed raw disk carving.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRunPersonas() {
    setLoading(true);
    setError(null);
    try {
      const res = await correlateIdentityPersonas(caseId, { serial, case_id: caseId });
      setPersonaResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed identity persona correlation.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRunFbe() {
    setLoading(true);
    setError(null);
    try {
      const res = await evaluateFbeMatrix(caseId, { serial, case_id: caseId });
      setFbeResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed FBE matrix evaluation.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRunVision() {
    setLoading(true);
    setError(null);
    try {
      const res = await recordAiVisionOcrSession(caseId, { serial, case_id: caseId, target_app: targetApp });
      setVisionResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed AI vision session recording.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Tier-1 Banner */}
      <div className="rounded-2xl border border-purple-300 bg-gradient-to-r from-slate-950 via-purple-950 to-indigo-950 p-6 text-white shadow-lg">
        <div className="flex items-center gap-3">
          <div className="rounded-xl bg-purple-500/20 p-3 text-purple-300 border border-purple-400/30">
            <Brain size={26} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="rounded bg-purple-500/30 px-2 py-0.5 text-[10px] font-bold tracking-wider uppercase text-purple-200 border border-purple-400/40">
                Tier-1 Laboratory Suite
              </span>
            </div>
            <h2 className="text-xl font-black tracking-tight mt-1">Deep Forensic Engineering &amp; AI Vision</h2>
            <p className="text-xs text-purple-200/80 mt-0.5">
              KeyStore master decrypters, raw disk sector GPS carvers, cross-app persona correlation, FBE state matrices &amp; xKiro AI Vision
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div className="mt-6 flex flex-wrap gap-2 border-t border-purple-800/60 pt-4">
          <button
            type="button"
            onClick={() => { setActiveTab("keystore"); }}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-bold transition-all ${
              activeTab === "keystore" ? "bg-purple-500 text-slate-950 shadow" : "bg-slate-900/90 text-purple-200 hover:bg-slate-800"
            }`}
          >
            <KeyRound size={15} /> KeyStore &amp; Vault Decrypter
          </button>
          <button
            type="button"
            onClick={() => { setActiveTab("disk"); }}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-bold transition-all ${
              activeTab === "disk" ? "bg-purple-500 text-slate-950 shadow" : "bg-slate-900/90 text-purple-200 hover:bg-slate-800"
            }`}
          >
            <HardDrive size={15} /> Raw Disk GPS Carver
          </button>
          <button
            type="button"
            onClick={() => { setActiveTab("personas"); }}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-bold transition-all ${
              activeTab === "personas" ? "bg-purple-500 text-slate-950 shadow" : "bg-slate-900/90 text-purple-200 hover:bg-slate-800"
            }`}
          >
            <Users size={15} /> Identity Persona Correlator
          </button>
          <button
            type="button"
            onClick={() => { setActiveTab("fbe"); }}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-bold transition-all ${
              activeTab === "fbe" ? "bg-purple-500 text-slate-950 shadow" : "bg-slate-900/90 text-purple-200 hover:bg-slate-800"
            }`}
          >
            <Lock size={15} /> BFU / AFU FBE Matrix
          </button>
          <button
            type="button"
            onClick={() => { setActiveTab("vision"); }}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-bold transition-all ${
              activeTab === "vision" ? "bg-purple-500 text-slate-950 shadow" : "bg-slate-900/90 text-purple-200 hover:bg-slate-800"
            }`}
          >
            <Sparkles size={15} /> AI Vision Session OCR &amp; PDF Cert
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-xs font-medium text-rose-800">
          {error}
        </div>
      )}

      {/* Tab 1: KeyStore Decrypter */}
      {activeTab === "keystore" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">KeyStore &amp; EncryptedSharedPreferences Decrypter</h3>
              <p className="text-xs text-slate-500">
                Derives Master Keys from /data/misc/keystore/ and spblob master seeds to unlock app AES-256-GCM vaults offline.
              </p>
            </div>
            <button
              type="button"
              onClick={() => { void handleRunKeystore(); }}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-purple-700 px-4 py-2 text-xs font-bold text-white shadow hover:bg-purple-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <KeyRound size={14} />}
              Decrypt KeyStore Vaults
            </button>
          </div>

          {keystoreResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between font-bold text-emerald-900">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> KeyStore Master Keys Derived</span>
                <span>{keystoreResult.total_vaults_unlocked} Vault(s) Unlocked</span>
              </div>
              <div className="space-y-2">
                {keystoreResult.decrypted_vaults.map((v, idx) => (
                  <div key={idx} className="rounded-lg bg-white p-3 border border-slate-200 font-mono text-[11px]">
                    <div className="flex justify-between font-bold text-slate-800">
                      <span>{v.package_name}</span>
                      <span className="text-purple-700 font-semibold">{v.key_alias}</span>
                    </div>
                    <pre className="mt-2 rounded bg-slate-50 p-2 text-slate-700 overflow-x-auto">
                      {JSON.stringify(v.sample_content, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Raw Disk GPS Carver */}
      {activeTab === "disk" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">Raw Disk Sector &amp; EXIF GPS Carver</h3>
              <p className="text-xs text-slate-500">
                Scans raw unallocated sector blocks for JPEG/PNG/MP4 magic headers, parses EXIF GPS tags, and plots coordinates.
              </p>
            </div>
            <button
              type="button"
              onClick={() => { void handleRunRawDisk(); }}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-purple-700 px-4 py-2 text-xs font-bold text-white shadow hover:bg-purple-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <HardDrive size={14} />}
              Carve Raw Disk Sectors
            </button>
          </div>

          {diskResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between font-bold text-emerald-900">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> Carving Completed</span>
                <span>{diskResult.gps_locations_plotted_count} EXIF GPS Coordinates Plotted</span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {diskResult.carved_media_items.map((item, idx) => (
                  <div key={idx} className="rounded-lg bg-white p-3 border border-slate-200">
                    <div className="flex justify-between font-bold uppercase text-slate-900">
                      <span>{item.file_type} File</span>
                      <span>{(item.size_bytes / 1048576).toFixed(2)} MB</span>
                    </div>
                    {item.has_gps && (
                      <div className="mt-2 flex items-center gap-1.5 text-emerald-700 font-semibold">
                        <MapPin size={13} /> {item.latitude}, {item.longitude} ({item.camera_model})
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Identity Persona Correlator */}
      {activeTab === "personas" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">Cross-App Identity Persona Correlator</h3>
              <p className="text-xs text-slate-500">
                Crawls messaging databases, contacts, and call logs to link handles, phone numbers, and emails into unified personas.
              </p>
            </div>
            <button
              type="button"
              onClick={() => { void handleRunPersonas(); }}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-purple-700 px-4 py-2 text-xs font-bold text-white shadow hover:bg-purple-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Users size={14} />}
              Correlate Personas
            </button>
          </div>

          {personaResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between font-bold text-emerald-900">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> Persona Correlation Complete</span>
                <span>{personaResult.total_correlated_identities} Persona(s) Identified</span>
              </div>
              <div className="space-y-2">
                {personaResult.personas.map((p, idx) => (
                  <div key={idx} className="rounded-lg bg-white p-3 border border-slate-200">
                    <div className="flex justify-between font-bold text-slate-900">
                      <span>{p.primary_name}</span>
                      <span className="text-purple-700 font-semibold">{p.message_count} messages linked</span>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2 text-[11px]">
                      {p.phone_numbers.map((ph, i) => (
                        <span key={i} className="rounded bg-slate-100 px-2 py-0.5 text-slate-700 font-mono">{ph}</span>
                      ))}
                      {p.email_addresses.map((em, i) => (
                        <span key={i} className="rounded bg-indigo-50 px-2 py-0.5 text-indigo-700 font-mono">{em}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: FBE State Matrix */}
      {activeTab === "fbe" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">BFU / AFU File-Based Encryption Matrix</h3>
              <p className="text-xs text-slate-500">
                Probes File-Based Encryption (FBE) storage partitions to categorize Device-Encrypted (DE) vs. Credential-Encrypted (CE) files.
              </p>
            </div>
            <button
              type="button"
              onClick={() => { void handleRunFbe(); }}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-purple-700 px-4 py-2 text-xs font-bold text-white shadow hover:bg-purple-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Lock size={14} />}
              Evaluate FBE Matrix
            </button>
          </div>

          {fbeResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between font-bold text-emerald-900">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> Device Unlock Posture: {fbeResult.device_unlock_status}</span>
                <span>{fbeResult.bfu_accessible_databases_count} BFU Databases Accessible</span>
              </div>
              <ul className="space-y-1.5 text-[11px]">
                {fbeResult.partitions.map((part, idx) => (
                  <li key={idx} className="rounded-lg bg-white p-2.5 border border-slate-200 flex justify-between items-center">
                    <div>
                      <span className="font-bold text-slate-900 block">{part.path}</span>
                      <span className="text-slate-500 text-[10px]">{part.description}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded font-bold uppercase text-[10px] ${
                      part.bfu_readable ? "bg-emerald-100 text-emerald-800" : "bg-rose-100 text-rose-800"
                    }`}>
                      {part.bfu_readable ? "BFU Accessible" : "CE Locked"}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Tab 5: AI Vision OCR Session */}
      {activeTab === "vision" && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-900">AI Vision Session OCR &amp; Court PDF Certificate Generator</h3>
              <p className="text-xs text-slate-500">
                Auto-scrolls chat UI, runs xKiro AI Vision OCR processing, transcribes text, and outputs a signed PDF session certificate.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <input
              type="text"
              value={targetApp}
              onChange={(e) => { setTargetApp(e.target.value); }}
              placeholder="e.g. com.whatsapp"
              className="w-64 rounded-xl border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-800 shadow-sm"
            />
            <button
              type="button"
              onClick={() => { void handleRunVision(); }}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-purple-700 px-4 py-2 text-xs font-bold text-white shadow hover:bg-purple-800 disabled:opacity-50"
            >
              {loading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
              Start AI Vision Session
            </button>
          </div>

          {visionResult && (
            <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-xs space-y-3">
              <div className="flex items-center justify-between font-bold text-emerald-900">
                <span className="flex items-center gap-1.5"><CheckCircle2 size={16} /> Engine: {visionResult.ai_engine_used}</span>
                <span>{visionResult.scanned_frames_count} frames scanned</span>
              </div>
              <div className="rounded-lg bg-white p-3 border border-slate-200 text-slate-800 font-mono text-[11px]">
                <span className="font-bold text-purple-700 block">Court PDF Certificate Generated:</span>
                <span className="block mt-1">{visionResult.pdf_certificate_path}</span>
                <span className="block text-[10px] text-slate-400 mt-0.5">SHA-256: {visionResult.certificate_sha256}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

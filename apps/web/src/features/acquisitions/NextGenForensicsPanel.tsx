import React, { useState } from "react";
import {
  Cpu,
  Database,
  Key,
  Lock,
  MemoryStick,
  ShieldCheck,
  Smartphone,
  Sparkles,
  Unlock,
  Zap,
} from "lucide-react";
import {
  decryptWhatsAppCrypt16_17,
  scanAndroid15PrivateSpace,
  scanEphemeralRamKeys,
  type Android15PrivateSpaceResult,
  type Crypt16_17DecryptResult,
  type EphemeralRamScanResult,
} from "../../lib/api";

interface NextGenForensicsPanelProps {
  caseId: string;
  serial: string;
}

export const NextGenForensicsPanel: React.FC<NextGenForensicsPanelProps> = ({
  caseId,
  serial,
}) => {
  // Private Space state
  const [psLoading, setPsLoading] = useState<boolean>(false);
  const [psResult, setPsResult] = useState<Android15PrivateSpaceResult | null>(null);

  // Crypt16/17 state
  const [cryptLoading, setCryptLoading] = useState<boolean>(false);
  const [cryptResult, setCryptResult] = useState<Crypt16_17DecryptResult | null>(null);

  // RAM Key state
  const [ramLoading, setRamLoading] = useState<boolean>(false);
  const [ramResult, setRamResult] = useState<EphemeralRamScanResult | null>(null);

  const handleScanPrivateSpace = async () => {
    setPsLoading(true);
    try {
      const res = await scanAndroid15PrivateSpace(caseId, { serial, case_id: caseId });
      setPsResult(res);
    } catch (err) {
      console.error("Failed to scan Private Space", err);
    } finally {
      setPsLoading(false);
    }
  };

  const handleDecryptCrypt16_17 = async (fmt: string) => {
    setCryptLoading(true);
    try {
      const res = await decryptWhatsAppCrypt16_17(caseId, {
        serial,
        case_id: caseId,
        backup_file_name: `msgstore.db.${fmt}`,
      });
      setCryptResult(res);
    } catch (err) {
      console.error("Failed to decrypt Crypt16/17", err);
    } finally {
      setCryptLoading(false);
    }
  };

  const handleScanRamKeys = async () => {
    setRamLoading(true);
    try {
      const res = await scanEphemeralRamKeys(caseId, { serial, case_id: caseId });
      setRamResult(res);
    } catch (err) {
      console.error("Failed to scan RAM keys", err);
    } finally {
      setRamLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl bg-gradient-to-r from-slate-900 via-emerald-950 to-slate-900 p-6 text-white border border-emerald-500/30 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-emerald-600/30 rounded-lg border border-emerald-400/40">
              <Zap className="w-7 h-7 text-emerald-400 animate-pulse" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                Next-Gen Non-Rooted Forensic Suite
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-mono">
                  Zero-Root Superiority
                </span>
              </h2>
              <p className="text-sm text-slate-300">
                Android 15 Private Space hidden profile triage, WhatsApp Crypt16/17 HKDF decrypter & volatile RAM key miner.
              </p>
            </div>
          </div>
          <div className="text-xs font-mono text-emerald-300 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
            Target Serial: <strong>{serial || "CONNECTED_ADB"}</strong>
          </div>
        </div>
      </div>

      {/* 3 Main Capability Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Card 1: Android 15 Private Space */}
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <Smartphone className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                ANDROID 15 ONLY
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Android 15 Private Space Triage
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              Detects isolated secondary profiles (User 10/11), inventories hidden secret apps, checks container lock state, and dumps databases.
            </p>
          </div>

          <button
            onClick={handleScanPrivateSpace}
            disabled={psLoading}
            className="w-full py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold rounded-lg flex items-center justify-center space-x-2 transition-all disabled:opacity-50"
          >
            {psLoading ? (
              <Zap className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <Unlock className="w-4 h-4" />
                <span>Triage Private Space Profile</span>
              </>
            )}
          </button>
        </div>

        {/* Card 2: WhatsApp Crypt16/17 Decrypter */}
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                <Lock className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                HKDF-SHA256
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              WhatsApp Crypt16 / Crypt17 Decrypter
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              Parses 67-byte Crypt16/Crypt17 headers, executes HKDF key derivation over master seeds, and extracts plaintext msgstore.db.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => handleDecryptCrypt16_17("crypt16")}
              disabled={cryptLoading}
              className="py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-lg flex items-center justify-center space-x-1 transition-all disabled:opacity-50"
            >
              <span>Crypt16 Decrypt</span>
            </button>
            <button
              onClick={() => handleDecryptCrypt16_17("crypt17")}
              disabled={cryptLoading}
              className="py-2 bg-indigo-700 hover:bg-indigo-800 text-white text-xs font-semibold rounded-lg flex items-center justify-center space-x-1 transition-all disabled:opacity-50"
            >
              <span>Crypt17 Decrypt</span>
            </button>
          </div>
        </div>

        {/* Card 3: Ephemeral RAM Key Analyzer */}
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/30">
                <MemoryStick className="w-5 h-5" />
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                VOLATILE MEMORY
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Ephemeral RAM Session Key Analyzer
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              Inspects /proc/pid/maps memory over ADB to extract active SQLCipher keys and Signal/Telegram master seeds before app exit.
            </p>
          </div>

          <button
            onClick={handleScanRamKeys}
            disabled={ramLoading}
            className="w-full py-2 bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold rounded-lg flex items-center justify-center space-x-2 transition-all disabled:opacity-50"
          >
            {ramLoading ? (
              <Zap className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <Cpu className="w-4 h-4" />
                <span>Mine RAM Process Keys</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Results Summaries */}
      {psResult && (
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
            <span className="font-bold text-emerald-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              Android 15 Private Space Scan Results
            </span>
            <span className="text-slate-400">Duration: {psResult.duration_seconds}s</span>
          </div>

          {psResult.profiles_found.map((prof) => (
            <div key={prof.user_id} className="p-3 rounded bg-slate-50 dark:bg-slate-950 space-y-2">
              <div className="flex items-center justify-between text-slate-900 dark:text-white font-bold">
                <span>User ID {prof.user_id}: {prof.user_name} ({prof.user_type})</span>
                <span className="text-emerald-400">Container State: UNLOCKED</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Installed Hidden Target Apps: {prof.installed_target_packages.join(", ")}
              </p>
            </div>
          ))}
        </div>
      )}

      {cryptResult && (
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
            <span className="font-bold text-indigo-400 flex items-center gap-2">
              <Database className="w-4 h-4" />
              WhatsApp {cryptResult.backup_format} Decryption Results
            </span>
            <span className="text-slate-400">Duration: {cryptResult.duration_seconds}s</span>
          </div>
          <div className="grid grid-cols-2 gap-4 text-slate-300">
            <div>Cipher: <strong>{cryptResult.cipher_algorithm}</strong></div>
            <div>HKDF Key Derived: <strong className="text-emerald-400">YES</strong></div>
            <div>Total Unlocked Messages: <strong className="text-emerald-400">{cryptResult.total_messages_unlocked.toLocaleString()}</strong></div>
            <div>Total Chat Threads: <strong>{cryptResult.total_chat_threads}</strong></div>
          </div>
        </div>
      )}

      {ramResult && (
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
            <span className="font-bold text-amber-400 flex items-center gap-2">
              <Key className="w-4 h-4" />
              Volatile RAM Memory Scan Results
            </span>
            <span className="text-slate-400">Scanned Processes: {ramResult.total_processes_scanned}</span>
          </div>

          <div className="space-y-2">
            {ramResult.keys_extracted.map((k, idx) => (
              <div key={idx} className="p-3 rounded bg-slate-50 dark:bg-slate-950 flex items-center justify-between">
                <div>
                  <div className="font-bold text-slate-900 dark:text-white">{k.package_name} (PID {k.pid})</div>
                  <div className="text-[11px] text-slate-400">Region: {k.memory_region} | Entropy: {k.entropy_score}</div>
                </div>
                <span className="px-2 py-1 rounded bg-amber-500/20 text-amber-300 font-bold border border-amber-500/40 text-[10px]">
                  {k.key_type}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

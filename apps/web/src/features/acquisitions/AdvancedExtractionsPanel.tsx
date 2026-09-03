import { useState, useMemo } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Database,
  Flame,
  Hash,
  KeyRound,
  LoaderCircle,
  Lock,
  MessageSquare,
  SearchCheck,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Sparkles,
  Unlock,
} from "lucide-react";

import {
  assessScreenLock,
  attemptAuthorisedEntry,
  bypassScreenLock,
  carveSqliteDatabase,
  crackScreenLock,
  detectDevices,
  extractScreenLockHashes,
  extractSignalRooted,
  extractTelegramRooted,
  extractWhatsAppDowngrade,
  getCurrentUser,
  type AuthorisedEntryResult,
  type SQLiteCarvingResult,
  type ScreenLockAssessResult,
  type ScreenLockBypassResult,
  type ScreenLockCrackResult,
  type ScreenLockExtractHashesResult,
  type SignalExtractionResult,
  type TelegramExtractionResult,
  type WhatsAppDowngradeResult,
} from "../../lib/api";
import { authKeys } from "../auth/authKeys";

interface AdvancedExtractionsPanelProps {
  caseId: string;
}

export function AdvancedExtractionsPanel({ caseId }: AdvancedExtractionsPanelProps) {
  const [activeTab, setActiveTab] = useState<"whatsapp" | "signal" | "telegram" | "sqlite" | "screenlock">("whatsapp");
  const [serial, setSerial] = useState("");
  const [operatorId, setOperatorId] = useState("");
  const [sqlitePaths, setSqlitePaths] = useState("");

  // Screen lock & cracking UI state
  const [crackMode, setCrackMode] = useState<number>(13800);
  const [attackType, setAttackType] = useState<"mask" | "pattern_solve" | "wordlist">("mask");
  const [pinMask, setPinMask] = useState<string>("?d?d?d?d");
  const [targetHash, setTargetHash] = useState<string>("");
  const [wordlistPath, setWordlistPath] = useState<string>("");
  const [hashcatPath, setHashcatPath] = useState<string>("");
  const [authorisedCred, setAuthorisedCred] = useState<string>("");
  const [dryRunBypass, setDryRunBypass] = useState<boolean>(true);

  const currentUser = useQuery({ queryKey: authKeys.me, queryFn: getCurrentUser, retry: false });
  const devicesQuery = useQuery({
    queryKey: ["detected-devices"],
    queryFn: () => detectDevices(),
    refetchInterval: 5000,
  });

  const availableDevices = useMemo(() => devicesQuery.data?.devices ?? [], [devicesQuery.data?.devices]);
  const defaultOperator = currentUser.data?.username || "operator";
  const activeOperator = operatorId.trim() || defaultOperator;
  const effectiveSerial = serial || availableDevices[0]?.serial || "";

  const waMutation = useMutation({
    mutationFn: () => extractWhatsAppDowngrade(caseId, effectiveSerial.trim(), activeOperator),
  });

  const signalMutation = useMutation({
    mutationFn: () => extractSignalRooted(caseId, effectiveSerial.trim(), activeOperator),
  });

  const telegramMutation = useMutation({
    mutationFn: () => extractTelegramRooted(caseId, effectiveSerial.trim(), activeOperator),
  });

  const sqliteMutation = useMutation({
    mutationFn: () => {
      const paths = sqlitePaths
        .split("\n")
        .map((p) => p.trim())
        .filter(Boolean);
      return carveSqliteDatabase(caseId, paths);
    },
  });

  const assessLockMutation = useMutation({
    mutationFn: () => assessScreenLock(caseId, effectiveSerial.trim(), activeOperator),
  });

  const extractHashesMutation = useMutation({
    mutationFn: () => extractScreenLockHashes(caseId, effectiveSerial.trim(), activeOperator),
    onSuccess: (data) => {
      if (data.pattern_hash_hex) {
        setTargetHash(data.pattern_hash_hex);
        setAttackType("pattern_solve");
        setCrackMode(10);
      }
    },
  });

  const crackMutation = useMutation({
    mutationFn: () =>
      crackScreenLock(caseId, activeOperator, {
        mode: crackMode,
        attack_type: attackType,
        mask: pinMask,
        raw_hash: targetHash,
        wordlist_path: wordlistPath,
        hashcat_binary_path: hashcatPath,
      }),
  });

  const bypassMutation = useMutation({
    mutationFn: () => bypassScreenLock(caseId, effectiveSerial.trim(), activeOperator, dryRunBypass),
  });

  const authEntryMutation = useMutation({
    mutationFn: () =>
      attemptAuthorisedEntry(caseId, effectiveSerial.trim(), activeOperator, authorisedCred, "pin"),
  });

  return (
    <section className="mt-8 rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 shadow-sm">
      <div className="flex flex-col justify-between gap-4 border-b border-slate-200 pb-5 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles size={18} className="text-cyan-700" />
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Deep Acquisition Engines
            </p>
          </div>
          <h2 className="mt-2 text-2xl font-bold tracking-tight text-slate-900">
            Advanced Extractions & Forensic Carving
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Execute rollback APK downgrade attacks, SQLCipher key derivation, and SQLite WAL slack space carvers.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="mt-6 flex flex-wrap gap-2 border-b border-slate-100 pb-4">
        {[
          { id: "whatsapp", label: "WhatsApp Downgrade (Non-Root)", icon: MessageSquare },
          { id: "screenlock", label: "Lock Screen & PIN Brute-Force", icon: Lock },
          { id: "signal", label: "Signal SQLCipher (Rooted)", icon: KeyRound },
          { id: "telegram", label: "Telegram Caches (Rooted)", icon: Database },
          { id: "sqlite", label: "SQLite WAL / Slack Carver", icon: SearchCheck },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => {
                setActiveTab(tab.id as typeof activeTab);
              }}
              className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all ${
                isActive
                  ? "bg-slate-900 text-white shadow-sm"
                  : "bg-slate-100 text-slate-700 hover:bg-slate-200 hover:text-slate-900"
              }`}
            >
              <Icon size={15} />
              {tab.label}
            </button>
          );
        })}
      </div>

        <div className="mt-5 grid gap-4 sm:grid-cols-2">
          <div>
            <div className="flex items-center justify-between">
              <label className="block text-xs font-semibold text-slate-700" htmlFor="target-serial">
                Target Device ADB Serial
              </label>
              {availableDevices.length > 0 && (
                <span className="flex items-center gap-1 text-[11px] font-medium text-emerald-700">
                  <Smartphone size={12} /> {availableDevices.length} device detected
                </span>
              )}
            </div>
            {availableDevices.length > 0 ? (
              <select
                id="target-serial"
                value={serial}
                onChange={(e) => {
                  setSerial(e.target.value);
                }}
                className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-mono text-slate-900 focus:border-slate-900 focus:outline-none"
              >
                {availableDevices.map((d) => (
                  <option key={d.serial} value={d.serial}>
                    {d.model ? `${d.model} (${d.serial})` : d.serial} — {d.state}
                  </option>
                ))}
              </select>
            ) : (
              <input
                id="target-serial"
                type="text"
                value={serial}
                onChange={(e) => {
                  setSerial(e.target.value);
                }}
                placeholder="Connect USB device or enter ADB serial"
                className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none"
              />
            )}
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-700" htmlFor="operator-id">
              Examiner / Operator Identifier
            </label>
            <input
              id="operator-id"
              type="text"
              value={operatorId}
              onChange={(e) => {
                setOperatorId(e.target.value);
              }}
              placeholder={`Active user: ${defaultOperator}`}
              className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none"
            />
          </div>
        </div>

      {/* Tab: WhatsApp Downgrade */}
      {activeTab === "whatsapp" && (
        <div className="mt-5 space-y-4">
          <div className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-xs leading-5 text-amber-900">
            <div className="flex gap-2">
              <ShieldAlert size={16} className="shrink-0 text-amber-700 mt-0.5" />
              <div>
                <p className="font-semibold text-amber-900">Downgrade Attack Notice &amp; Required Device Action</p>
                <p className="mt-0.5 text-amber-800">
                  Temporarily downgrades WhatsApp to an ADB-backup-capable version (v2.11.431), captures sandbox data, then automatically restores your original APK set.
                </p>
                <div className="mt-2 rounded-lg border border-amber-400/60 bg-amber-100/80 p-2 text-amber-950 font-medium">
                  📱 <strong>Device Screen Action Required:</strong> Keep your device unlocked. When the &quot;Full backup&quot; prompt appears on the phone, <strong>leave the password blank</strong> and tap <strong>&quot;Back up my data&quot;</strong>.
                </div>
              </div>
            </div>
          </div>


          <button
            type="button"
            disabled={!effectiveSerial.trim() || waMutation.isPending}
            onClick={() => {
              waMutation.mutate();
            }}
            className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-slate-900 px-5 text-sm font-semibold text-white shadow-sm transition hover:bg-black disabled:opacity-40"
          >
            {waMutation.isPending ? (
              <LoaderCircle size={16} className="animate-spin" />
            ) : (
              <MessageSquare size={16} />
            )}
            {waMutation.isPending ? "Executing Downgrade Extraction…" : "Launch WhatsApp Downgrade Extraction"}
          </button>

          {waMutation.isError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900">
              {waMutation.error instanceof Error ? waMutation.error.message : "Extraction failed."}
            </div>
          )}

          {waMutation.data && <WhatsAppResultView result={waMutation.data} />}
        </div>
      )}

      {/* Tab: Signal Rooted */}
      {activeTab === "signal" && (
        <div className="mt-5 space-y-4">
          <div className="rounded-xl border border-sky-200 bg-sky-50 p-4 text-xs leading-5 text-sky-950">
            <div className="flex gap-2">
              <KeyRound size={16} className="shrink-0 text-sky-700 mt-0.5" />
              <div>
                <p className="font-semibold text-sky-900">Root Access Required</p>
                <p className="mt-0.5 text-sky-800">
                  Retrieves Signal shared-preferences from `/data/data/org.thoughtcrime.securesms`, extracts the passphrase, and decrypts the SQLCipher database.
                </p>
              </div>
            </div>
          </div>

          <button
            type="button"
            disabled={!effectiveSerial.trim() || signalMutation.isPending}
            onClick={() => {
              signalMutation.mutate();
            }}
            className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-slate-900 px-5 text-sm font-semibold text-white shadow-sm transition hover:bg-black disabled:opacity-40"
          >
            {signalMutation.isPending ? (
              <LoaderCircle size={16} className="animate-spin" />
            ) : (
              <KeyRound size={16} />
            )}
            {signalMutation.isPending ? "Extracting & Decrypting…" : "Extract Signal SQLCipher Database"}
          </button>

          {signalMutation.isError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900">
              {signalMutation.error instanceof Error ? signalMutation.error.message : "Extraction failed."}
            </div>
          )}

          {signalMutation.data && <SignalResultView result={signalMutation.data} />}
        </div>
      )}

      {/* Tab: Telegram Rooted */}
      {activeTab === "telegram" && (
        <div className="mt-5 space-y-4">
          <div className="rounded-xl border border-sky-200 bg-sky-50 p-4 text-xs leading-5 text-sky-950">
            <div className="flex gap-2">
              <Database size={16} className="shrink-0 text-sky-700 mt-0.5" />
              <div>
                <p className="font-semibold text-sky-900">Root Access Required</p>
                <p className="mt-0.5 text-sky-800">
                  Copies Telegram `cache4.db` database and its Write-Ahead Log (WAL) files directly from the sandbox.
                </p>
              </div>
            </div>
          </div>

          <button
            type="button"
            disabled={!effectiveSerial.trim() || telegramMutation.isPending}
            onClick={() => {
              telegramMutation.mutate();
            }}
            className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-slate-900 px-5 text-sm font-semibold text-white shadow-sm transition hover:bg-black disabled:opacity-40"
          >
            {telegramMutation.isPending ? (
              <LoaderCircle size={16} className="animate-spin" />
            ) : (
              <Database size={16} />
            )}
            {telegramMutation.isPending ? "Extracting Telegram Data…" : "Extract Telegram Caches"}
          </button>

          {telegramMutation.isError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900">
              {telegramMutation.error instanceof Error ? telegramMutation.error.message : "Extraction failed."}
            </div>
          )}

          {telegramMutation.data && <TelegramResultView result={telegramMutation.data} />}
        </div>
      )}

      {/* Tab: SQLite Carving */}
      {activeTab === "sqlite" && (
        <div className="mt-5 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700" htmlFor="sqlite-paths">
              Local SQLite Database File Paths (one per line)
            </label>
            <textarea
              id="sqlite-paths"
              rows={3}
              value={sqlitePaths}
              onChange={(e) => {
                setSqlitePaths(e.target.value);
              }}
              placeholder="Enter absolute SQLite database file paths (one per line, e.g. path/to/databases/msgstore.db)"
              className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white p-3 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none"
            />
          </div>

          <button
            type="button"
            disabled={!sqlitePaths.trim() || sqliteMutation.isPending}
            onClick={() => {
              sqliteMutation.mutate();
            }}
            className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-slate-900 px-5 text-sm font-semibold text-white shadow-sm transition hover:bg-black disabled:opacity-40"
          >
            {sqliteMutation.isPending ? (
              <LoaderCircle size={16} className="animate-spin" />
            ) : (
              <SearchCheck size={16} />
            )}
            {sqliteMutation.isPending ? "Carving SQLite Pages…" : "Carve Unallocated Blocks & WAL"}
          </button>

          {sqliteMutation.isError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900">
              {sqliteMutation.error instanceof Error ? sqliteMutation.error.message : "Carving failed."}
            </div>
          )}

          {sqliteMutation.data && <CarvingResultView result={sqliteMutation.data} />}
        </div>
      )}

      {/* Tab: Screen Lock & PIN Brute-Force */}
      {activeTab === "screenlock" && (
        <div className="mt-5 space-y-6">
          {/* Overview / Notice banner */}
          <div className="rounded-xl border border-blue-200 bg-blue-50 p-4 text-xs leading-5 text-blue-900">
            <div className="flex gap-2">
              <Lock size={16} className="shrink-0 text-blue-700 mt-0.5" />
              <div>
                <p className="font-semibold text-blue-900">
                  Android Screen Lock Assessment, Hash Extraction &amp; Cracking Suite
                </p>
                <p className="mt-0.5 text-blue-800">
                  Assess Android 5–14 lock screen mechanisms, measure wipe risk, extract offline Gatekeeper / pattern credential hashes, and crack PINs or patterns using pure Python solvers or Hashcat GPU acceleration.
                </p>
              </div>
            </div>
          </div>

          {/* Section 1: Assessment & Offline Hash Dump */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-5">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <ShieldAlert size={16} className="text-slate-700" />
              Step 1: Assess Mechanism &amp; Extract Credential Hashes
            </h3>
            <p className="mt-1 text-xs text-slate-600">
              Query locksettings database to evaluate wipe thresholds and dump offline hash blobs from /data/system/.
            </p>

            <div className="mt-4 flex flex-wrap gap-3">
              <button
                type="button"
                disabled={!effectiveSerial.trim() || assessLockMutation.isPending}
                onClick={() => assessLockMutation.mutate()}
                className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-slate-900 px-4 text-xs font-semibold text-white shadow-sm transition hover:bg-black disabled:opacity-40"
              >
                {assessLockMutation.isPending ? (
                  <LoaderCircle size={14} className="animate-spin" />
                ) : (
                  <SearchCheck size={14} />
                )}
                {assessLockMutation.isPending ? "Assessing Lock..." : "Assess Device Lock & Wipe Risk"}
              </button>

              <button
                type="button"
                disabled={!effectiveSerial.trim() || extractHashesMutation.isPending}
                onClick={() => extractHashesMutation.mutate()}
                className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-xs font-semibold text-slate-800 shadow-sm transition hover:bg-slate-100 disabled:opacity-40"
              >
                {extractHashesMutation.isPending ? (
                  <LoaderCircle size={14} className="animate-spin" />
                ) : (
                  <Hash size={14} />
                )}
                {extractHashesMutation.isPending ? "Dumping Hashes..." : "Dump Hashes (Requires Root)"}
              </button>
            </div>

            {assessLockMutation.isError && (
              <div className="mt-3 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-900">
                {assessLockMutation.error instanceof Error ? assessLockMutation.error.message : "Lock assessment failed."}
              </div>
            )}

            {assessLockMutation.data && (
              <div className="mt-4">
                <ScreenLockAssessmentView profile={assessLockMutation.data} />
              </div>
            )}

            {extractHashesMutation.isError && (
              <div className="mt-3 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-900">
                {extractHashesMutation.error instanceof Error ? extractHashesMutation.error.message : "Hash extraction failed. Ensure device is rooted or has su binary."}
              </div>
            )}

            {extractHashesMutation.data && (
              <div className="mt-4">
                <ScreenLockDumpView
                  dump={extractHashesMutation.data}
                  onUsePatternHash={(hex) => {
                    setTargetHash(hex);
                    setAttackType("pattern_solve");
                    setCrackMode(10);
                  }}
                />
              </div>
            )}
          </div>

          {/* Section 2: Cracking & Brute Force Engine */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-5">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Flame size={16} className="text-amber-600" />
              Step 2: Password, PIN &amp; Pattern Cracker
            </h3>
            <p className="mt-1 text-xs text-slate-600">
              Recover plaintext credentials against extracted hashes or manual targets. Pattern lock solver explores all 389,112 legal Android 3x3 paths in pure Python without external dependencies.
            </p>

            {/* Mode selection pills */}
            <div className="mt-4">
              <label className="block text-xs font-semibold text-slate-700">Attack Type &amp; Algorithm</label>
              <div className="mt-1.5 flex flex-wrap gap-2">
                {[
                  { id: "pin4", label: "4-Digit PIN Brute-Force", attack: "mask", mask: "?d?d?d?d", mode: 13800 },
                  { id: "pin6", label: "6-Digit PIN Brute-Force", attack: "mask", mask: "?d?d?d?d?d?d", mode: 13800 },
                  { id: "pattern", label: "Pattern Lock (Instant 3x3 Solver)", attack: "pattern_solve", mask: "", mode: 10 },
                  { id: "wordlist", label: "Dictionary / Wordlist (Hashcat)", attack: "wordlist", mask: "", mode: 13800 },
                ].map((item) => {
                  const isSelected =
                    attackType === item.attack &&
                    (item.attack !== "mask" || pinMask === item.mask);
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setAttackType(item.attack as typeof attackType);
                        setCrackMode(item.mode);
                        if (item.mask) setPinMask(item.mask);
                      }}
                      className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                        isSelected
                          ? "bg-slate-900 text-white shadow-sm"
                          : "border border-slate-300 bg-white text-slate-700 hover:bg-slate-100"
                      }`}
                    >
                      {item.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Target Hash */}
            <div className="mt-4">
              <div className="flex items-center justify-between">
                <label className="block text-xs font-semibold text-slate-700" htmlFor="target-hash">
                  Target Credential Hash (Hex)
                </label>
                {extractHashesMutation.data?.pattern_hash_hex && (
                  <button
                    type="button"
                    onClick={() => {
                      setTargetHash(extractHashesMutation.data?.pattern_hash_hex || "");
                      setAttackType("pattern_solve");
                      setCrackMode(10);
                    }}
                    className="text-[11px] font-semibold text-cyan-700 hover:underline"
                  >
                    Load Extracted Pattern Hash
                  </button>
                )}
              </div>
              <input
                id="target-hash"
                type="text"
                value={targetHash}
                onChange={(e) => setTargetHash(e.target.value)}
                placeholder="e.g. SHA-1/MD5 for pattern.key, or Gatekeeper Scrypt hash line"
                className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none"
              />
            </div>

            {/* Extra inputs for Wordlist or Custom Hashcat */}
            {attackType === "wordlist" && (
              <div className="mt-4 grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-xs font-semibold text-slate-700" htmlFor="wordlist-path">
                    Wordlist File Path
                  </label>
                  <input
                    id="wordlist-path"
                    type="text"
                    value={wordlistPath}
                    onChange={(e) => setWordlistPath(e.target.value)}
                    placeholder="e.g. tools/wordlists/rockyou.txt"
                    className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700" htmlFor="hashcat-path">
                    Hashcat Binary Path (Optional)
                  </label>
                  <input
                    id="hashcat-path"
                    type="text"
                    value={hashcatPath}
                    onChange={(e) => setHashcatPath(e.target.value)}
                    placeholder="Auto-detected if on PATH"
                    className="mt-1.5 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-mono text-slate-900 placeholder:text-slate-400 focus:border-slate-900 focus:outline-none"
                  />
                </div>
              </div>
            )}

            <div className="mt-5">
              <button
                type="button"
                disabled={!targetHash.trim() || crackMutation.isPending}
                onClick={() => crackMutation.mutate()}
                className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-amber-600 px-5 text-sm font-semibold text-white shadow-sm transition hover:bg-amber-700 disabled:opacity-40"
              >
                {crackMutation.isPending ? (
                  <LoaderCircle size={16} className="animate-spin" />
                ) : (
                  <Flame size={16} />
                )}
                {crackMutation.isPending ? "Cracking Target..." : "Launch Cracking Job"}
              </button>
            </div>

            {crackMutation.isError && (
              <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900">
                {crackMutation.error instanceof Error ? crackMutation.error.message : "Cracking job failed."}
              </div>
            )}

            {crackMutation.data && (
              <div className="mt-4">
                <ScreenLockCrackView result={crackMutation.data} />
              </div>
            )}
          </div>

          {/* Section 3: Root Bypass & Supervised Authorised Entry */}
          <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-5">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Unlock size={16} className="text-slate-700" />
              Step 3: Root Lockscreen Bypass &amp; Safe Authorised Entry
            </h3>
            <p className="mt-1 text-xs text-slate-600">
              Directly patch locksettings.db to disable lock verification (requires root), or safely input candidate passcodes via ADB with automatic rate-limit and anti-wipe delay enforcement.
            </p>

            <div className="mt-4 grid gap-6 md:grid-cols-2">
              {/* Bypass */}
              <div className="rounded-lg border border-slate-200 bg-white p-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">Root DB Lock Bypass</h4>
                <p className="mt-1 text-xs text-slate-500">
                  Patches lockscreen.password_type to 0 and clears password salts in locksettings.db.
                </p>
                <div className="mt-3 flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="dry-run"
                    checked={dryRunBypass}
                    onChange={(e) => setDryRunBypass(e.target.checked)}
                    className="h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-slate-900"
                  />
                  <label htmlFor="dry-run" className="text-xs font-medium text-slate-700">
                    Dry-Run Mode (Simulation only, non-destructive)
                  </label>
                </div>
                <div className="mt-4">
                  <button
                    type="button"
                    disabled={!effectiveSerial.trim() || bypassMutation.isPending}
                    onClick={() => bypassMutation.mutate()}
                    className="inline-flex min-h-9 items-center gap-2 rounded-lg bg-slate-900 px-4 text-xs font-semibold text-white transition hover:bg-black disabled:opacity-40"
                  >
                    {bypassMutation.isPending ? <LoaderCircle size={14} className="animate-spin" /> : <Unlock size={14} />}
                    {bypassMutation.isPending ? "Executing Bypass..." : "Execute Lock Bypass"}
                  </button>
                </div>
                {bypassMutation.data && (
                  <div className="mt-3">
                    <ScreenLockBypassView result={bypassMutation.data} />
                  </div>
                )}
              </div>

              {/* Supervised Entry */}
              <div className="rounded-lg border border-slate-200 bg-white p-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">Supervised Passcode Entry</h4>
                <p className="mt-1 text-xs text-slate-500">
                  Emulates hardware keyevents with deliberate delays to avoid triggering wipe thresholds.
                </p>
                <div className="mt-3">
                  <label className="block text-xs font-semibold text-slate-700" htmlFor="auth-cred">
                    Candidate Passcode / PIN
                  </label>
                  <input
                    id="auth-cred"
                    type="password"
                    value={authorisedCred}
                    onChange={(e) => setAuthorisedCred(e.target.value)}
                    placeholder="Enter candidate PIN to test"
                    className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-mono text-slate-900 focus:border-slate-900 focus:outline-none"
                  />
                </div>
                <div className="mt-3">
                  <button
                    type="button"
                    disabled={!effectiveSerial.trim() || !authorisedCred.trim() || authEntryMutation.isPending}
                    onClick={() => authEntryMutation.mutate()}
                    className="inline-flex min-h-9 items-center gap-2 rounded-lg border border-slate-300 bg-slate-50 px-4 text-xs font-semibold text-slate-800 transition hover:bg-slate-100 disabled:opacity-40"
                  >
                    {authEntryMutation.isPending ? <LoaderCircle size={14} className="animate-spin" /> : <KeyRound size={14} />}
                    {authEntryMutation.isPending ? "Attempting Entry..." : "Attempt Supervised Entry"}
                  </button>
                </div>
                {authEntryMutation.data && (
                  <div className="mt-3 text-xs">
                    {authEntryMutation.data.unlock_success ? (
                      <span className="font-semibold text-emerald-700">Unlock Successful! Device is unlocked.</span>
                    ) : (
                      <span className="font-semibold text-rose-700">
                        Unlock Failed: {authEntryMutation.data.error_message || "Invalid credential."}
                      </span>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function WhatsAppResultView({ result }: { result: WhatsAppDowngradeResult }) {
  if (!result.success) {
    return (
      <div className="rounded-xl border border-rose-300 bg-rose-50 p-5">
        <div className="flex items-center gap-2 text-rose-800">
          <AlertTriangle size={18} />
          <h3 className="font-semibold text-slate-900">WhatsApp Extraction Incomplete / Action Needed</h3>
        </div>
        <p className="mt-2 text-xs font-medium text-rose-900">
          {result.error_message || "The downgrade extraction workflow could not be completed."}
        </p>

        {result.timeline && result.timeline.length > 0 && (
          <div className="mt-4">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Execution Timeline Log
            </p>
            <div className="mt-1.5 max-h-52 overflow-y-auto rounded-lg border border-rose-200 bg-white p-3 font-mono text-[11px] space-y-1">
              {result.timeline.map((entry, idx) => (
                <div key={idx} className="flex gap-2">
                  <span
                    className={
                      entry.level === "ERROR"
                        ? "font-bold text-rose-600 shrink-0"
                        : entry.level === "WARN"
                          ? "font-bold text-amber-600 shrink-0"
                          : "text-cyan-700 shrink-0"
                    }
                  >
                    [{entry.level}]
                  </span>
                  <span className="text-slate-700 break-words">{entry.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="mt-4 rounded-lg border border-rose-200 bg-white p-3 text-xs text-slate-700 space-y-1.5">
          <p className="font-semibold text-slate-900">Troubleshooting Guidance:</p>
          <ul className="list-disc pl-4 space-y-1 text-slate-600">
            <li>Ensure the device screen stays unlocked and awake during extraction.</li>
            <li>When the Android &quot;Full backup&quot; prompt appears on the phone, leave the password blank and tap <strong>&quot;Back up my data&quot;</strong>.</li>
            <li>If your device brand (e.g. Xiaomi/Infinix/Oppo) restricts ADB installation, enable <strong>&quot;Install via USB&quot;</strong> in Developer Options.</li>
          </ul>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-5">
      <div className="flex items-center gap-2 text-emerald-800">
        <CheckCircle2 size={18} />
        <h3 className="font-semibold text-slate-900">WhatsApp Extraction Complete</h3>
      </div>
      <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2">
        <div>
          <dt className="font-medium text-slate-500">Decrypted Database</dt>
          <dd className="mt-0.5 font-mono text-slate-800">{result.decrypted_database_path ?? "None"}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Backup SHA-256</dt>
          <dd className="mt-0.5 font-mono text-slate-800">{result.backup_sha256}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Duration</dt>
          <dd className="mt-0.5 text-slate-800">{result.duration_seconds.toFixed(2)} seconds</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Key Status</dt>
          <dd className="mt-0.5 text-slate-800">{result.encryption_key_found ? "Key recovered" : "No key found"}</dd>
        </div>
      </dl>

      {result.timeline && result.timeline.length > 0 && (
        <div className="mt-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Timeline Log
          </p>
          <div className="mt-1.5 max-h-40 overflow-y-auto rounded-lg border border-emerald-200 bg-white p-3 font-mono text-[11px] space-y-1">
            {result.timeline.map((entry, idx) => (
              <div key={idx} className="flex gap-2">
                <span className="text-emerald-700 font-bold shrink-0">[{entry.level}]</span>
                <span className="text-slate-700 break-words">{entry.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SignalResultView({ result }: { result: SignalExtractionResult }) {
  if (!result.success) {
    return (
      <div className="rounded-xl border border-rose-300 bg-rose-50 p-5">
        <div className="flex items-center gap-2 text-rose-800">
          <AlertTriangle size={18} />
          <h3 className="font-semibold text-slate-900">Signal Extraction Incomplete</h3>
        </div>
        <p className="mt-2 text-xs font-medium text-rose-900">
          {result.error_message || "Failed to extract Signal database via root access."}
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-5">
      <div className="flex items-center gap-2 text-emerald-800">
        <CheckCircle2 size={18} />
        <h3 className="font-semibold text-slate-900">Signal Extraction Complete</h3>
      </div>
      <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2">
        <div>
          <dt className="font-medium text-slate-500">Decrypted Database</dt>
          <dd className="mt-0.5 font-mono text-slate-800">{result.decrypted_database_path ?? "None"}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Passphrase Found</dt>
          <dd className="mt-0.5 text-slate-800">{result.passphrase_found ? "Yes (SQLCipher 4)" : "No"}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Passphrase Hash</dt>
          <dd className="mt-0.5 font-mono text-slate-800">{result.passphrase_sha256}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Duration</dt>
          <dd className="mt-0.5 text-slate-800">{result.duration_seconds.toFixed(2)} seconds</dd>
        </div>
      </dl>
    </div>
  );
}

function TelegramResultView({ result }: { result: TelegramExtractionResult }) {
  if (!result.success) {
    return (
      <div className="rounded-xl border border-rose-300 bg-rose-50 p-5">
        <div className="flex items-center gap-2 text-rose-800">
          <AlertTriangle size={18} />
          <h3 className="font-semibold text-slate-900">Telegram Extraction Incomplete</h3>
        </div>
        <p className="mt-2 text-xs font-medium text-rose-900">
          {result.error_message || "Failed to extract Telegram database via root access."}
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-5">
      <div className="flex items-center gap-2 text-emerald-800">
        <CheckCircle2 size={18} />
        <h3 className="font-semibold text-slate-900">Telegram Extraction Complete</h3>
      </div>
      <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-2">
        <div>
          <dt className="font-medium text-slate-500">Database Path</dt>
          <dd className="mt-0.5 font-mono text-slate-800">{result.database_path}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Files Copied</dt>
          <dd className="mt-0.5 text-slate-800">{result.database_files_copied} database files</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Database SHA-256</dt>
          <dd className="mt-0.5 font-mono text-slate-800">{result.database_sha256}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Duration</dt>
          <dd className="mt-0.5 text-slate-800">{result.duration_seconds.toFixed(2)} seconds</dd>
        </div>
      </dl>
    </div>
  );
}


function CarvingResultView({ result }: { result: SQLiteCarvingResult }) {
  return (
    <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-5">
      <div className="flex items-center gap-2 text-emerald-800">
        <CheckCircle2 size={18} />
        <h3 className="font-semibold text-slate-900">Carving Finished: {result.fragments_found} Fragments Found</h3>
      </div>
      <dl className="mt-4 grid gap-3 text-xs sm:grid-cols-3">
        <div>
          <dt className="font-medium text-slate-500">WAL Fragments</dt>
          <dd className="mt-0.5 font-semibold text-slate-900">{result.wal_fragments_found}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Freelist Fragments</dt>
          <dd className="mt-0.5 font-semibold text-slate-900">{result.freelist_fragments_found}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Unallocated Fragments</dt>
          <dd className="mt-0.5 font-semibold text-slate-900">{result.unallocated_fragments_found}</dd>
        </div>
      </dl>
      {result.fragments.length > 0 && (
        <div className="mt-4 max-h-60 overflow-y-auto rounded-lg border border-slate-200 bg-white p-3 font-mono text-[11px] text-slate-800">
          {result.fragments.slice(0, 10).map((f, i) => (
            <div key={i} className="border-b border-slate-100 py-1.5 last:border-0">
              <span className="font-semibold text-cyan-700">[{f.fragment_type}]</span> {f.content_preview}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ScreenLockAssessmentView({ profile }: { profile: ScreenLockAssessResult }) {
  const riskColor =
    profile.wipe_risk === "high"
      ? "bg-rose-100 text-rose-800 border-rose-200"
      : profile.wipe_risk === "medium"
        ? "bg-amber-100 text-amber-800 border-amber-200"
        : "bg-emerald-100 text-emerald-800 border-emerald-200";

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <div className="flex items-center justify-between border-b border-slate-100 pb-3">
        <div className="flex items-center gap-2">
          <ShieldCheck size={16} className="text-cyan-700" />
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">Lock Screen Assessment Profile</h4>
        </div>
        <span className={`rounded-full border px-2.5 py-0.5 text-[11px] font-bold uppercase ${riskColor}`}>
          Wipe Risk: {profile.wipe_risk}
        </span>
      </div>
      <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-3">
        <div>
          <dt className="font-medium text-slate-500">Lock Type</dt>
          <dd className="mt-0.5 font-bold uppercase text-slate-900">{profile.lock_type}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">PIN / Passcode Length</dt>
          <dd className="mt-0.5 font-semibold text-slate-800">{profile.pin_length ? `${profile.pin_length} digits` : "Unknown"}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Search Space</dt>
          <dd className="mt-0.5 font-semibold text-slate-800">{profile.search_space_estimate.toLocaleString()} combinations</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Max Failed Attempts</dt>
          <dd className="mt-0.5 font-semibold text-slate-800">{profile.max_failed_attempts ?? "No hard limit configured"}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Gatekeeper Synthetic Password</dt>
          <dd className="mt-0.5 font-semibold text-slate-800">{profile.gatekeeper_present ? "Present (Modern Android)" : "Legacy"}</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Biometrics Enrolled</dt>
          <dd className="mt-0.5 font-semibold text-slate-800">{profile.biometric_enrolled ? "Yes (Fingerprint/Face)" : "No"}</dd>
        </div>
      </dl>
    </div>
  );
}

function ScreenLockDumpView({
  dump,
  onUsePatternHash,
}: {
  dump: ScreenLockExtractHashesResult;
  onUsePatternHash: (hex: string) => void;
}) {
  return (
    <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-4">
      <div className="flex items-center gap-2 text-emerald-800">
        <CheckCircle2 size={16} />
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900">Credential Hashes Dumped</h4>
      </div>
      <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-2">
        <div>
          <dt className="font-medium text-slate-500">Gatekeeper Blobs</dt>
          <dd className="mt-0.5 font-semibold text-slate-900">{dump.gatekeeper_blobs_count} blob(s)</dd>
        </div>
        <div>
          <dt className="font-medium text-slate-500">Synthetic Password Files</dt>
          <dd className="mt-0.5 font-semibold text-slate-900">{dump.spblob_files_count} file(s)</dd>
        </div>
        {dump.pattern_hash_hex && (
          <div className="sm:col-span-2">
            <dt className="font-medium text-slate-500">Pattern Hash (SHA-1 / MD5)</dt>
            <div className="mt-1 flex items-center gap-2">
              <code className="rounded bg-white px-2 py-1 font-mono text-[11px] text-slate-900 border border-slate-200">
                {dump.pattern_hash_hex}
              </code>
              <button
                type="button"
                onClick={() => onUsePatternHash(dump.pattern_hash_hex || "")}
                className="rounded bg-emerald-700 px-2 py-1 text-[11px] font-semibold text-white hover:bg-emerald-800"
              >
                Send to Solver
              </button>
            </div>
          </div>
        )}
      </dl>
    </div>
  );
}

function ScreenLockCrackView({ result }: { result: ScreenLockCrackResult }) {
  const [copied, setCopied] = useState(false);

  if (!result.success) {
    return (
      <div className="rounded-xl border border-rose-300 bg-rose-50 p-4 text-xs">
        <div className="flex items-center gap-2 text-rose-800">
          <AlertTriangle size={16} />
          <h4 className="font-bold text-slate-900">Cracking Job Incomplete</h4>
        </div>
        <p className="mt-2 font-medium text-rose-900">
          {result.error_message || "Search space exhausted without finding a matching credential."}
        </p>
        {result.stdout_tail && (
          <pre className="mt-3 max-h-36 overflow-x-auto rounded border border-rose-200 bg-white p-2 font-mono text-[11px] text-slate-700">
            {result.stdout_tail}
          </pre>
        )}
      </div>
    );
  }

  const credential = result.recovered_credential;

  return (
    <div className="rounded-xl border-2 border-emerald-500 bg-emerald-50 p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-emerald-800">
          <Unlock size={20} className="text-emerald-600" />
          <h3 className="text-base font-bold text-slate-900">Lock Screen Credential Cracked!</h3>
        </div>
        <span className="rounded-full bg-emerald-200 px-3 py-0.5 text-xs font-bold text-emerald-900">
          Solved in {result.duration_seconds.toFixed(3)}s
        </span>
      </div>

      <div className="mt-4 rounded-xl border border-emerald-300 bg-white p-4">
        <p className="text-xs font-bold uppercase tracking-wider text-slate-500">Recovered Plaintext Credential</p>
        <div className="mt-2 flex items-center justify-between">
          <span className="font-mono text-2xl font-black tracking-widest text-emerald-700">
            {credential ?? "Unknown"}
          </span>
          {credential && (
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(credential);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-100"
            >
              {copied ? <CheckCircle2 size={14} className="text-emerald-600" /> : <Copy size={14} />}
              {copied ? "Copied!" : "Copy Credential"}
            </button>
          )}
        </div>
      </div>

      {result.stdout_tail && (
        <div className="mt-3 text-xs text-slate-600">
          <span className="font-medium text-slate-500">Solver Output: </span>
          <span className="font-mono text-[11px] text-slate-700">{result.stdout_tail}</span>
        </div>
      )}
    </div>
  );
}

function ScreenLockBypassView({ result }: { result: ScreenLockBypassResult }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs">
      <div className="flex items-center gap-1.5">
        <CheckCircle2 size={14} className="text-emerald-600" />
        <span className="font-bold text-slate-800">
          Bypass Execution {result.dry_run ? "(Dry-Run Verified)" : "Complete"}
        </span>
      </div>
      <dl className="mt-2 grid grid-cols-2 gap-2 text-[11px]">
        <div>
          <span className="text-slate-500">Original Lock: </span>
          <span className="font-semibold text-slate-800">{result.previous_lock_type}</span>
        </div>
        <div>
          <span className="text-slate-500">DB Patched: </span>
          <span className="font-semibold text-slate-800">{result.db_patched ? "Yes" : "No"}</span>
        </div>
      </dl>
    </div>
  );
}

import { useState, useEffect } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  CheckCircle2,
  Database,
  KeyRound,
  LoaderCircle,
  MessageSquare,
  SearchCheck,
  ShieldAlert,
  Smartphone,
  Sparkles,
} from "lucide-react";

import {
  carveSqliteDatabase,
  detectDevices,
  extractSignalRooted,
  extractTelegramRooted,
  extractWhatsAppDowngrade,
  getCurrentUser,
  type SQLiteCarvingResult,
  type SignalExtractionResult,
  type TelegramExtractionResult,
  type WhatsAppDowngradeResult,
} from "../../lib/api";
import { authKeys } from "../auth/authKeys";

interface AdvancedExtractionsPanelProps {
  caseId: string;
}

export function AdvancedExtractionsPanel({ caseId }: AdvancedExtractionsPanelProps) {
  const [activeTab, setActiveTab] = useState<"whatsapp" | "signal" | "telegram" | "sqlite">("whatsapp");
  const [serial, setSerial] = useState("");
  const [operatorId, setOperatorId] = useState("");
  const [sqlitePaths, setSqlitePaths] = useState("");

  const currentUser = useQuery({ queryKey: authKeys.me, queryFn: getCurrentUser, retry: false });
  const devicesQuery = useQuery({
    queryKey: ["detected-devices"],
    queryFn: () => detectDevices(),
    refetchInterval: 5000,
  });

  const availableDevices = devicesQuery.data?.devices ?? [];
  const defaultOperator = currentUser.data?.username || "operator";
  const activeOperator = operatorId.trim() || defaultOperator;

  // Auto-populate first connected device if available
  useEffect(() => {
    if (!serial && availableDevices.length > 0 && availableDevices[0]?.serial) {
      setSerial(availableDevices[0].serial);
    }
  }, [availableDevices, serial]);

  const waMutation = useMutation({
    mutationFn: () => extractWhatsAppDowngrade(caseId, serial.trim(), activeOperator),
  });

  const signalMutation = useMutation({
    mutationFn: () => extractSignalRooted(caseId, serial.trim(), activeOperator),
  });

  const telegramMutation = useMutation({
    mutationFn: () => extractTelegramRooted(caseId, serial.trim(), activeOperator),
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
                <p className="font-semibold text-amber-900">Downgrade Attack Notice</p>
                <p className="mt-0.5 text-amber-800">
                  Temporarily downgrades WhatsApp to an ADB-backup-capable version, captures sandbox data, then automatically restores the original APK set. Device screen must be unlocked.
                </p>
              </div>
            </div>
          </div>

          <button
            type="button"
            disabled={!serial.trim() || waMutation.isPending}
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
            disabled={!serial.trim() || signalMutation.isPending}
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
            disabled={!serial.trim() || telegramMutation.isPending}
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
    </section>
  );
}

function WhatsAppResultView({ result }: { result: WhatsAppDowngradeResult }) {
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
    </div>
  );
}

function SignalResultView({ result }: { result: SignalExtractionResult }) {
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

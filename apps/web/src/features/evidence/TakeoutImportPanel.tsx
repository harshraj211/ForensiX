import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CloudUpload, LoaderCircle } from "lucide-react";

import { importCloudExport, type CloudExportImport, type CloudExportProvider } from "../../lib/api";
import { caseKeys } from "../cases/caseKeys";

const providers: { id: CloudExportProvider; name: string; formats: string }[] = [
  { id: "google", name: "Google", formats: "Takeout ZIP; history, locations, activity and photo JSON; Gmail MBOX; contacts CSV/VCF; calendars ICS." },
  { id: "whatsapp", name: "WhatsApp", formats: "Android/iOS chat TXT or ZIP with media; plaintext msgstore/wa SQLite databases. Encrypted .crypt backups are preserved inside ZIP and marked unsupported." },
  { id: "microsoft", name: "Microsoft", formats: "Offline Graph JSON: messages, contacts, events and drive items; EML/MBOX mail, contacts CSV/VCF and calendars ICS. PST is not decoded." },
  { id: "telegram", name: "Telegram", formats: "Telegram Desktop JSON: result.json or individual chat JSON; ZIP may include media. HTML chat exports are not decoded." },
  { id: "icloud", name: "iCloud", formats: "Exported contacts VCF, calendars ICS, EML/MBOX mail, supported contact/photo CSV, or ZIP containing these files." },
];

export function CloudExportResult({ result }: { result: CloudExportImport }) {
  const failed = result.parser_run?.status === "failed";
  const completed = result.parser_run?.status === "completed";
  return <div className="mt-4 rounded-xl border border-white/10 p-4 text-sm text-slate-300" role="status">
    <p className={failed ? "text-amber-200" : "text-emerald-200"}>
      {failed ? "Original sealed; parsing failed" : completed ? "Export sealed and parsed" : "Original sealed; parsing not recorded"}
    </p>
    {failed && <p className="mt-2">{result.parser_run?.error_message}</p>}
    {completed && <>
      <p className="mt-2">{result.summary.parsed_count ?? 0} parsed records · {result.summary.member_count ?? 0} files · {result.summary.undated_count ?? 0} undated records</p>
      <p className="mt-2 text-xs">{result.summary.source_timezone} · {result.summary.date_order} · {result.summary.unsupported_count ?? 0} unsupported · {result.summary.malformed_count ?? 0} malformed</p>
      <dl className="mt-3 grid gap-2 sm:grid-cols-2">
        {Object.entries(result.summary.record_counts ?? {}).map(([kind, count]) => <div key={kind} className="flex justify-between gap-4"><dt>{kind.replaceAll("_", " ")}</dt><dd>{count}</dd></div>)}
      </dl>
    </>}
    <p className="mt-3 break-all text-xs">Original SHA-256: {result.evidence_source.sha256}</p>
    <p className="mt-1 break-all text-xs">Parser run hash: {result.parser_run?.run_hash ?? "No parser run"}</p>
    {(result.summary.warnings?.length ?? 0) > 0 && <details className="mt-3"><summary>Import issues ({result.summary.warnings?.length})</summary><ul className="mt-2 space-y-1">{result.summary.warnings?.map((warning, index) => <li key={index}>{warning}</li>)}</ul></details>}
  </div>;
}

// Preserve the existing page integration while replacing the former Google-only flow.
export function TakeoutImportPanel({ caseId, writable = true }: { caseId: string; writable?: boolean }) {
  const [provider, setProvider] = useState<CloudExportProvider>("google");
  const [file, setFile] = useState<File | null>(null);
  const [timezone, setTimezone] = useState(() => Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC");
  const [dateOrder, setDateOrder] = useState<"DMY" | "MDY">("DMY");
  const client = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => {
      if (!file) throw new Error("Choose an export file");
      return importCloudExport(caseId, file, provider, timezone, dateOrder);
    },
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["evidence-twin", caseId] });
      void client.invalidateQueries({ queryKey: ["cases", caseId] });
      void client.invalidateQueries({ queryKey: caseKeys.timeline(caseId) });
      void client.invalidateQueries({ queryKey: ["source-artifacts", caseId] });
    },
  });
  const selected = providers.find((item) => item.id === provider);
  if (!selected) throw new Error("Unknown cloud export provider");
  return <section className="mt-8 rounded-2xl border border-sky-200/10 bg-sky-200/[0.025] p-6">
    <h2 className="flex items-center gap-2 text-xl font-semibold text-white"><CloudUpload size={22} />Cloud export import</h2>
    <p className="mt-2 text-sm text-slate-400">Seal an offline export, parse supported records, and add dated artifacts to the timeline. Original archives retain media and unsupported content.</p>
    <fieldset disabled={mutation.isPending || !writable} className="mt-5 grid gap-4 sm:grid-cols-2">
      <label className="text-sm text-slate-300">Provider<select aria-label="Cloud export provider" value={provider} onChange={(event) => { setProvider(event.target.value as CloudExportProvider); mutation.reset(); }} className="mt-2 block w-full rounded-lg bg-slate-900 p-3">{providers.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label className="text-sm text-slate-300">Export file<input aria-label="Cloud export file" type="file" accept=".zip,.json,.txt,.csv,.vcf,.ics,.eml,.mbox,.db,.sqlite,.sqlite3" onChange={(event) => { setFile(event.target.files?.[0] ?? null); mutation.reset(); }} className="mt-2 block w-full rounded-lg bg-slate-900 p-3" /></label>
      <label className="text-sm text-slate-300">Source timezone (IANA)<input aria-label="Source timezone" value={timezone} onChange={(event) => { setTimezone(event.target.value); mutation.reset(); }} className="mt-2 block w-full rounded-lg bg-slate-900 p-3" /></label>
      <label className="text-sm text-slate-300">WhatsApp date order<select aria-label="WhatsApp date order" value={dateOrder} onChange={(event) => { setDateOrder(event.target.value as "DMY" | "MDY"); mutation.reset(); }} className="mt-2 block w-full rounded-lg bg-slate-900 p-3"><option value="DMY">Day / month / year</option><option value="MDY">Month / day / year</option></select></label>
    </fieldset>
    <p className="mt-3 text-xs leading-5 text-slate-400">{selected.formats}</p>
    <p className="mt-2 text-xs text-slate-400">The selected timezone applies to timestamps without an offset. Date-only, invalid and ambiguous DST timestamps remain undated. Maximum upload: 2 GiB; text/JSON member: 64 MiB.</p>
    <button type="button" disabled={!writable || !file || !timezone || mutation.isPending} onClick={() => { mutation.mutate(); }} className="mt-4 inline-flex items-center gap-2 rounded-lg bg-cyan-300 px-4 py-3 text-sm font-semibold text-slate-950 disabled:opacity-40">{mutation.isPending && <LoaderCircle size={16} className="animate-spin" />} {mutation.isPending ? "Sealing and parsing…" : `Import ${selected.name} export`}</button>
    {!writable && <p className="mt-3 text-xs text-amber-200">Cloud export imports are unavailable in this case state.</p>}
    {mutation.isError && <p role="alert" className="mt-4 text-sm text-red-300">{mutation.error.message}</p>}
    {mutation.data && <CloudExportResult result={mutation.data} />}
  </section>;
}

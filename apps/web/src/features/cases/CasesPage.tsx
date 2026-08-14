import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BriefcaseBusiness, LoaderCircle, Plus, ShieldAlert } from "lucide-react";
import { type SyntheticEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { ApiError, createCase, listCases, type CaseRecord } from "../../lib/api";
import { caseKeys } from "./caseKeys";

export function CasesPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [legalAuthority, setLegalAuthority] = useState("");
  const cases = useQuery({ queryKey: caseKeys.all, queryFn: listCases });
  const createMutation = useMutation({
    mutationFn: createCase,
    onSuccess: async (created) => {
      queryClient.setQueryData(caseKeys.detail(created.id), created);
      await queryClient.invalidateQueries({ queryKey: caseKeys.all });
      void navigate(`/cases/${created.id}`);
    },
  });

  function submit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    createMutation.mutate({
      title,
      description: description || undefined,
      legal_authority: legalAuthority || undefined,
    });
  }

  return (
    <div className="mx-auto max-w-6xl">
      <div className="flex flex-col justify-between gap-5 border-b border-white/8 pb-8 sm:flex-row sm:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-cyan-300">
            Case workspace
          </p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight text-white sm:text-4xl">
            Cases
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400">
            Every device assessment and future acquisition must belong to an authorized case.
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setShowCreate((visible) => !visible);
          }}
          className="inline-flex min-h-11 items-center justify-center gap-2 rounded-lg bg-cyan-300 px-5 text-sm font-semibold text-slate-950"
        >
          <Plus size={17} aria-hidden="true" />
          New case
        </button>
      </div>

      {showCreate && (
        <form onSubmit={submit} className="mt-6 rounded-xl border border-cyan-300/15 bg-cyan-300/[0.035] p-5 sm:p-6">
          <h2 className="text-lg font-semibold">Create case</h2>
          <div className="mt-5 grid gap-4 sm:grid-cols-2">
            <CaseField label="Case title" value={title} onChange={setTitle} required />
            <CaseField label="Legal authority" value={legalAuthority} onChange={setLegalAuthority} />
          </div>
          <label htmlFor="case-description" className="mt-4 block text-sm font-medium text-slate-300">
            Description
            <textarea
              id="case-description"
              value={description}
              onChange={(event) => {
                setDescription(event.target.value);
              }}
              rows={3}
              className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-slate-100 outline-none focus:border-cyan-300/50"
            />
          </label>
          {createMutation.isError && <CaseError error={createMutation.error} />}
          <div className="mt-5 flex gap-3">
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-300 px-4 text-sm font-semibold text-slate-950 disabled:opacity-60"
            >
              {createMutation.isPending && <LoaderCircle className="animate-spin" size={15} aria-hidden="true" />}
              Create case
            </button>
            <button
              type="button"
              onClick={() => {
                setShowCreate(false);
              }}
              className="px-4 text-sm text-slate-400"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <section className="mt-7" aria-live="polite" aria-busy={cases.isPending}>
        {cases.isPending && (
          <div role="status" className="grid min-h-64 place-items-center rounded-xl border border-white/8">
            <LoaderCircle className="animate-spin text-cyan-300" aria-hidden="true" />
          </div>
        )}
        {cases.isError && <CaseError error={cases.error} />}
        {cases.data?.items.length === 0 && <EmptyCases />}
        {cases.data && cases.data.items.length > 0 && (
          <div className="grid gap-4 md:grid-cols-2">
            {cases.data.items.map((item) => <CaseCard key={item.id} item={item} />)}
          </div>
        )}
      </section>
    </div>
  );
}

function CaseCard({ item }: { item: CaseRecord }) {
  return (
    <Link
      to={`/cases/${item.id}`}
      className="rounded-md border border-neutral-300 bg-white p-5 transition hover:border-neutral-500 hover:bg-neutral-50"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-xs font-medium text-[#246c44]">{item.case_number}</p>
          <h2 className="mt-2 text-lg font-semibold text-neutral-950">{item.title}</h2>
        </div>
        <StatusBadge status={item.status} />
      </div>
      <p className="mt-4 line-clamp-2 text-sm leading-6 text-neutral-700">
        {item.description ?? "No case description has been recorded."}
      </p>
      <p className="mt-4 text-xs text-neutral-600">
        Updated {new Date(item.updated_at).toLocaleString()}
      </p>
    </Link>
  );
}

function EmptyCases() {
  return (
    <div className="grid min-h-72 place-items-center rounded-xl border border-dashed border-white/10 bg-white/[0.018] px-6 text-center">
      <div className="max-w-md">
        <BriefcaseBusiness className="mx-auto text-slate-600" aria-hidden="true" />
        <h2 className="mt-4 text-lg font-semibold">No accessible cases</h2>
        <p className="mt-2 text-sm leading-6 text-slate-500">
          Create the first case before connecting evidence or starting an acquisition.
        </p>
      </div>
    </div>
  );
}

export function StatusBadge({ status }: { status: CaseRecord["status"] }) {
  const tone = {
    open: "border-cyan-300/20 bg-cyan-300/7 text-cyan-200",
    active: "border-emerald-300/20 bg-emerald-300/7 text-emerald-200",
    closed: "border-amber-300/20 bg-amber-300/7 text-amber-200",
    archived: "border-slate-300/15 bg-slate-300/5 text-slate-400",
  }[status];
  return <span className={`rounded-full border px-3 py-1 text-xs font-semibold capitalize ${tone}`}>{status}</span>;
}

export function CaseError({ error }: { error: Error }) {
  return (
    <div role="alert" className="mt-4 flex gap-3 rounded-xl border border-rose-300/20 bg-rose-300/6 p-4 text-sm text-rose-100">
      <ShieldAlert className="shrink-0 text-rose-300" size={18} aria-hidden="true" />
      <div>
        <p>{error.message}</p>
        {error instanceof ApiError && <p className="mt-2 font-mono text-xs opacity-50">Request {error.requestId}</p>}
      </div>
    </div>
  );
}

function CaseField({
  label,
  value,
  onChange,
  required = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
}) {
  const id = label.toLowerCase().replaceAll(" ", "-");
  return (
    <label htmlFor={id} className="block text-sm font-medium text-slate-300">
      {label}
      <input
        id={id}
        value={value}
        required={required}
        onChange={(event) => {
          onChange(event.target.value);
        }}
        className="mt-2 min-h-11 w-full rounded-lg border border-white/10 bg-black/20 px-3 text-slate-100 outline-none focus:border-cyan-300/50"
      />
    </label>
  );
}

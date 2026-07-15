import { useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound, LoaderCircle, LockKeyhole, ShieldCheck } from "lucide-react";
import { type SyntheticEvent, useState } from "react";

import {
  ApiError,
  bootstrapAdministrator,
  login,
  type AuthSession,
} from "../../lib/api";
import { authKeys } from "./authKeys";

export function AuthPage({ mode }: { mode: "bootstrap" | "login" }) {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: () =>
      mode === "bootstrap"
        ? bootstrapAdministrator({ username, display_name: displayName, password })
        : login({ username, password }),
    onSuccess: (session: AuthSession) => {
      queryClient.setQueryData(authKeys.bootstrap, { bootstrap_required: false });
      queryClient.setQueryData(authKeys.me, session.user);
    },
  });

  function submit(event: SyntheticEvent<HTMLFormElement>) {
    event.preventDefault();
    setLocalError(null);
    if (mode === "bootstrap" && password !== confirmPassword) {
      setLocalError("The password confirmation does not match.");
      return;
    }
    mutation.mutate();
  }

  const error = localError ?? (mutation.error instanceof ApiError ? mutation.error.message : null);
  return (
    <div className="min-h-screen bg-[#071016] px-5 py-10 text-slate-100">
      <div className="mx-auto grid min-h-[calc(100vh-5rem)] max-w-5xl items-center gap-10 lg:grid-cols-[1fr_440px]">
        <section>
          <div className="grid size-12 place-items-center rounded-xl border border-cyan-300/25 bg-cyan-300/8 text-cyan-300">
            <ShieldCheck aria-hidden="true" />
          </div>
          <p className="mt-6 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-300">
            Local forensic workstation
          </p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight sm:text-5xl">ForensiX</h1>
          <p className="mt-5 max-w-xl text-base leading-7 text-slate-400">
            Authentication remains on this workstation. Passwords use Argon2id and session tokens
            are stored only as hashes in the local database.
          </p>
          <div className="mt-8 flex items-start gap-3 rounded-xl border border-amber-300/15 bg-amber-300/5 p-4 text-sm leading-6 text-amber-100/70">
            <LockKeyhole className="mt-0.5 shrink-0 text-amber-300" size={18} aria-hidden="true" />
            Keep this API bound to the loopback interface. ForensiX does not use cloud identity in
            offline mode.
          </div>
        </section>
        <section className="rounded-2xl border border-white/10 bg-[#0b1720] p-6 shadow-2xl sm:p-8">
          <KeyRound className="text-cyan-300" aria-hidden="true" />
          <h2 className="mt-5 text-2xl font-semibold">
            {mode === "bootstrap" ? "Create the first administrator" : "Sign in"}
          </h2>
          <p className="mt-2 text-sm leading-6 text-slate-500">
            {mode === "bootstrap"
              ? "This one-time step establishes local administrative control."
              : "Use your local ForensiX account to continue."}
          </p>
          <form className="mt-7 space-y-5" onSubmit={submit}>
            {mode === "bootstrap" && (
              <Field label="Display name" value={displayName} onChange={setDisplayName} autoComplete="name" />
            )}
            <Field label="Username" value={username} onChange={setUsername} autoComplete="username" />
            <Field
              label="Password"
              value={password}
              onChange={setPassword}
              type="password"
              autoComplete={mode === "bootstrap" ? "new-password" : "current-password"}
              description={
                mode === "bootstrap"
                  ? "12-128 characters using at least three character classes."
                  : undefined
              }
            />
            {mode === "bootstrap" && (
              <Field
                label="Confirm password"
                value={confirmPassword}
                onChange={setConfirmPassword}
                type="password"
                autoComplete="new-password"
              />
            )}
            {error && (
              <p role="alert" className="rounded-lg border border-rose-300/20 bg-rose-300/6 p-3 text-sm text-rose-100">
                {error}
              </p>
            )}
            <button
              type="submit"
              disabled={mutation.isPending}
              className="flex min-h-11 w-full items-center justify-center gap-2 rounded-lg bg-cyan-300 px-5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-wait disabled:opacity-60"
            >
              {mutation.isPending && <LoaderCircle className="animate-spin" size={17} aria-hidden="true" />}
              {mutation.isPending
                ? "Securing local session…"
                : mode === "bootstrap"
                  ? "Create administrator"
                  : "Sign in"}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  type = "text",
  autoComplete,
  description,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: "text" | "password";
  autoComplete: string;
  description?: string;
}) {
  const id = label.toLowerCase().replaceAll(" ", "-");
  return (
    <label htmlFor={id} className="block text-sm font-medium text-slate-300">
      {label}
      <input
        id={id}
        type={type}
        value={value}
        required
        autoComplete={autoComplete}
        onChange={(event) => {
          onChange(event.target.value);
        }}
        className="mt-2 min-h-11 w-full rounded-lg border border-white/10 bg-black/20 px-3 text-slate-100 outline-none transition focus:border-cyan-300/50 focus:ring-2 focus:ring-cyan-300/15"
      />
      {description && <span className="mt-2 block text-xs font-normal leading-5 text-slate-600">{description}</span>}
    </label>
  );
}

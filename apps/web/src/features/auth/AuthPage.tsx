import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, KeyRound, LoaderCircle, LockKeyhole, ShieldCheck } from "lucide-react";
import { type SyntheticEvent, useState } from "react";
import { Link } from "react-router-dom";

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
    <div className="auth-layout min-h-screen bg-[#f4f4f1] text-[#151615]">
      <header className="flex h-[68px] items-center justify-between bg-black px-5 text-white sm:px-8">
        <Link to="/" className="flex items-center gap-3" aria-label="ForensiX home">
          <span className="grid size-9 place-items-center border border-white/30">
            <ShieldCheck aria-hidden="true" size={20} />
          </span>
          <span className="text-base font-semibold uppercase tracking-[0.2em]">ForensiX</span>
          <span className="hidden text-[10px] uppercase tracking-[0.14em] text-neutral-500 sm:inline">
            Android forensics workstation
          </span>
        </Link>
        <Link to="/" className="inline-flex items-center gap-2 text-xs text-neutral-400 transition hover:text-white">
          <ArrowLeft size={14} aria-hidden="true" /> Return to platform
        </Link>
      </header>

      <main className="grid min-h-[calc(100vh-68px)] lg:grid-cols-[minmax(320px,0.8fr)_minmax(520px,1.2fr)]">
        <section className="flex flex-col justify-between bg-[#0b0b0b] px-7 py-10 text-white sm:px-12 lg:px-16 lg:py-16">
          <div className="max-w-xl">
            <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-neutral-500">
              Local evidence environment
            </p>
            <h1 className="mt-7 text-4xl font-semibold leading-tight tracking-tight sm:text-5xl">
              Controlled access to forensic evidence.
            </h1>
            <p className="mt-6 max-w-lg text-base leading-7 text-neutral-400">
              Authenticate to review devices, preserve evidence integrity, and maintain a defensible chain of custody.
            </p>
          </div>

          <div className="mt-12 max-w-lg border-t border-white/12 pt-7">
            <div className="flex items-start gap-3 text-sm leading-6 text-neutral-400">
              <LockKeyhole className="mt-0.5 shrink-0 text-neutral-200" size={18} aria-hidden="true" />
              <p>
                Credentials and session records remain on this workstation. The API must stay bound to the loopback interface.
              </p>
            </div>
            <p className="mt-8 text-[10px] uppercase tracking-[0.14em] text-neutral-600">
              ForensiX v0.1.0 / Local-only session
            </p>
          </div>
        </section>

        <section className="flex items-center px-6 py-12 sm:px-12 lg:px-20">
          <div className="w-full max-w-md">
            <KeyRound className="text-[#1d1e1d]" size={24} aria-hidden="true" />
            <p className="mt-7 text-[11px] font-semibold uppercase tracking-[0.16em] text-neutral-500">
              Secure workstation
            </p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight text-black">
              {mode === "bootstrap" ? "Create the first administrator" : "Sign in"}
            </h2>
            <p className="mt-3 text-sm leading-6 text-neutral-600">
              {mode === "bootstrap"
                ? "Establish the first local administrator for this evidence environment."
                : "Use your local ForensiX credentials to continue."}
            </p>

            <form className="mt-9 space-y-5" onSubmit={submit}>
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
                description={mode === "bootstrap" ? "12-128 characters using at least three character classes." : undefined}
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
                <p role="alert" className="border-l-2 border-red-600 bg-red-50 p-3 text-sm text-red-900">
                  {error}
                </p>
              )}
              <button
                type="submit"
                disabled={mutation.isPending}
                className="flex min-h-12 w-full items-center justify-center gap-2 bg-black px-5 text-sm font-semibold text-white transition hover:bg-neutral-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:cursor-wait disabled:opacity-55"
              >
                {mutation.isPending && <LoaderCircle className="animate-spin" size={17} aria-hidden="true" />}
                {mutation.isPending
                  ? "Securing local session..."
                  : mode === "bootstrap"
                    ? "Create administrator"
                    : "Sign in"}
              </button>
            </form>
          </div>
        </section>
      </main>
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
    <label htmlFor={id} className="block text-sm font-medium text-neutral-800">
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
        className="mt-2 min-h-12 w-full border border-neutral-300 bg-white px-3 text-neutral-950 outline-none transition focus:border-neutral-950 focus:ring-1 focus:ring-neutral-950"
      />
      {description && <span className="mt-2 block text-xs font-normal leading-5 text-neutral-500">{description}</span>}
    </label>
  );
}

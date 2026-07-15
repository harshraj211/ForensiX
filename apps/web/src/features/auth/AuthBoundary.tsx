import { useQuery } from "@tanstack/react-query";
import { LoaderCircle, ShieldAlert } from "lucide-react";
import { Outlet } from "react-router-dom";

import { ApiError, getBootstrapStatus, getCurrentUser } from "../../lib/api";
import { AuthPage } from "./AuthPage";
import { authKeys } from "./authKeys";

export function AuthBoundary() {
  const bootstrap = useQuery({ queryKey: authKeys.bootstrap, queryFn: getBootstrapStatus });
  const currentUser = useQuery({
    queryKey: authKeys.me,
    queryFn: getCurrentUser,
    enabled: bootstrap.data?.bootstrap_required === false,
    retry: false,
  });

  if (bootstrap.isPending || (bootstrap.data?.bootstrap_required === false && currentUser.isPending)) {
    return <AuthLoading />;
  }
  if (bootstrap.isError) {
    return <AuthUnavailable error={bootstrap.error} retry={() => void bootstrap.refetch()} />;
  }
  if (bootstrap.data.bootstrap_required) {
    return <AuthPage mode="bootstrap" />;
  }
  if (currentUser.isError) {
    if (currentUser.error instanceof ApiError && currentUser.error.status === 401) {
      return <AuthPage mode="login" />;
    }
    return <AuthUnavailable error={currentUser.error} retry={() => void currentUser.refetch()} />;
  }
  return <Outlet />;
}

function AuthLoading() {
  return (
    <div className="grid min-h-screen place-items-center bg-[#071016] text-slate-100">
      <div role="status" className="text-center">
        <LoaderCircle className="mx-auto animate-spin text-cyan-300" aria-hidden="true" />
        <p className="mt-4 text-sm text-slate-400">Checking the local security boundary…</p>
      </div>
    </div>
  );
}

function AuthUnavailable({ error, retry }: { error: Error; retry: () => void }) {
  return (
    <div className="grid min-h-screen place-items-center bg-[#071016] px-5 text-slate-100">
      <div role="alert" className="max-w-md rounded-xl border border-rose-300/20 bg-rose-300/6 p-6">
        <ShieldAlert className="text-rose-300" aria-hidden="true" />
        <h1 className="mt-4 text-xl font-semibold">Local authentication is unavailable</h1>
        <p className="mt-2 text-sm leading-6 text-rose-100/70">{error.message}</p>
        <button
          type="button"
          onClick={retry}
          className="mt-5 rounded-lg bg-rose-200 px-4 py-2 text-sm font-semibold text-rose-950"
        >
          Retry
        </button>
      </div>
    </div>
  );
}

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
    <div className="grid min-h-screen place-items-center bg-black text-white">
      <div role="status" className="text-center">
        <LoaderCircle className="mx-auto animate-spin text-neutral-300" aria-hidden="true" />
        <p className="mt-4 text-sm text-slate-400">Checking the local security boundary…</p>
      </div>
    </div>
  );
}

function AuthUnavailable({ error, retry }: { error: Error; retry: () => void }) {
  return (
    <div className="grid min-h-screen place-items-center bg-[#f4f4f1] px-5 text-neutral-950">
      <div role="alert" className="max-w-md border-l-2 border-red-600 bg-white p-6">
        <ShieldAlert className="text-red-700" aria-hidden="true" />
        <h1 className="mt-4 text-xl font-semibold">Local authentication is unavailable</h1>
        <p className="mt-2 text-sm leading-6 text-neutral-600">{error.message}</p>
        <button
          type="button"
          onClick={retry}
          className="mt-5 bg-black px-4 py-2 text-sm font-semibold text-white"
        >
          Retry
        </button>
      </div>
    </div>
  );
}

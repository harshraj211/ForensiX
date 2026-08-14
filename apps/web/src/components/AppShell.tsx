import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BookOpenText,
  Boxes,
  FileClock,
  FlaskConical,
  HelpCircle,
  LogOut,
  Menu,
  ShieldCheck,
  X,
} from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";

import { authKeys } from "../features/auth/authKeys";
import { LiveScreenPreviewProvider } from "../features/devices/LiveScreenPreview";
import { getCurrentUser, logout } from "../lib/api";

const workflowNavigation = [
  { label: "Device readiness", to: "/devices", icon: Activity },
  { label: "Cases", to: "/cases", icon: Boxes },
  { label: "Evidence", to: "/evidence", icon: ShieldCheck },
  { label: "Reports", to: "/reports", icon: BookOpenText },
];

const systemNavigation = [
  { label: "Audit log", to: "/audit", icon: FileClock, permission: "audit:view" },
  { label: "Validation", to: "/validation", icon: FlaskConical, permission: "settings:manage" },
];

export function AppShell() {
  const queryClient = useQueryClient();
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);
  const currentUser = useQuery({ queryKey: authKeys.me, queryFn: getCurrentUser, retry: false });
  const logoutMutation = useMutation({
    mutationFn: logout,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: authKeys.me });
    },
  });

  const permissions = currentUser.data?.permissions ?? [];

  return (
    <LiveScreenPreviewProvider>
      <div className="workstation-shell min-h-screen bg-[#f4f4f1] text-[#151615]">
        <a
          href="#main-content"
          className="sr-only z-50 bg-white px-4 py-2 font-semibold text-black focus:not-sr-only focus:fixed focus:left-4 focus:top-4"
        >
          Skip to content
        </a>

        <header className="workstation-header sticky top-0 z-40 flex h-[68px] items-center justify-between border-b border-white/10 bg-black px-4 text-white lg:px-6">
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="grid size-10 place-items-center border border-white/15 lg:hidden"
              aria-label={mobileNavigationOpen ? "Close navigation" : "Open navigation"}
              aria-expanded={mobileNavigationOpen}
              onClick={() => {
                setMobileNavigationOpen((open) => !open);
              }}
            >
              {mobileNavigationOpen ? <X size={19} aria-hidden="true" /> : <Menu size={19} aria-hidden="true" />}
            </button>
            <div className="grid size-9 place-items-center border border-white/30">
              <ShieldCheck aria-hidden="true" size={20} strokeWidth={1.8} />
            </div>
            <div className="flex items-baseline gap-3">
              <p className="text-base font-semibold uppercase tracking-[0.2em]">ForensiX</p>
              <span className="hidden text-[11px] uppercase tracking-[0.12em] text-neutral-400 md:inline">
                Android forensics workstation
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden items-center gap-5 text-sm text-neutral-300 md:flex">
              <NavLink to="/audit" className="inline-flex items-center gap-2 transition hover:text-white">
                <FileClock size={16} aria-hidden="true" /> Activity log
              </NavLink>
              <span className="inline-flex items-center gap-2">
                <HelpCircle size={16} aria-hidden="true" /> Help
              </span>
            </div>
            <div className="h-8 w-px bg-white/15" aria-hidden="true" />
            <div className="hidden text-right sm:block">
              <p className="text-xs font-semibold text-white">
                {currentUser.data?.display_name ?? "Local investigator"}
              </p>
              <p className="mt-0.5 flex items-center justify-end gap-1.5 text-[10px] text-neutral-400">
                Local workstation <span className="size-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
              </p>
            </div>
          </div>
        </header>

        <div className="grid min-h-[calc(100vh-68px)] lg:grid-cols-[236px_minmax(0,1fr)]">
          {mobileNavigationOpen && (
            <button
              type="button"
              className="fixed inset-0 top-[68px] z-20 bg-black/45 lg:hidden"
              aria-label="Close navigation overlay"
              onClick={() => {
                setMobileNavigationOpen(false);
              }}
            />
          )}

          <aside
            className={`workstation-sidebar fixed inset-y-[68px] left-0 z-30 flex w-[236px] flex-col border-r border-white/10 bg-[#0b0b0b] px-3 py-5 text-white transition-transform lg:sticky lg:top-[68px] lg:h-[calc(100vh-68px)] lg:translate-x-0 ${
              mobileNavigationOpen ? "translate-x-0" : "-translate-x-full"
            }`}
          >
            <NavigationGroup
              label="Evidence workflow"
              items={workflowNavigation}
              permissions={permissions}
              onNavigate={() => {
                setMobileNavigationOpen(false);
              }}
            />
            <div className="mt-auto border-t border-white/10 pt-5">
              <NavigationGroup
                label="System"
                items={systemNavigation}
                permissions={permissions}
                onNavigate={() => {
                  setMobileNavigationOpen(false);
                }}
              />
              <button
                type="button"
                disabled={logoutMutation.isPending}
                onClick={() => {
                  logoutMutation.mutate();
                }}
                className="mt-2 flex min-h-10 w-full items-center gap-3 px-3 text-left text-sm text-neutral-400 transition hover:bg-white/8 hover:text-white disabled:cursor-wait disabled:opacity-50"
              >
                <LogOut aria-hidden="true" size={17} />
                {logoutMutation.isPending ? "Signing out..." : "Sign out"}
              </button>
            </div>
            <div className="mt-5 px-3 text-[10px] leading-5 text-neutral-500">
              <p>ForensiX v0.1.0</p>
              <p>Local evidence environment</p>
            </div>
          </aside>

          <main id="main-content" className="workstation-content min-w-0 bg-[#f4f4f1] px-5 py-7 sm:px-7 lg:px-8 lg:py-8 xl:px-10">
            <Outlet />
          </main>
        </div>
      </div>
    </LiveScreenPreviewProvider>
  );
}

type NavigationItem = {
  label: string;
  to: string;
  icon: typeof Activity;
  permission?: string;
};

function NavigationGroup({
  label,
  items,
  permissions,
  onNavigate,
}: {
  label: string;
  items: NavigationItem[];
  permissions: string[];
  onNavigate: () => void;
}) {
  return (
    <nav aria-label={label}>
      <p className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-neutral-500">
        {label}
      </p>
      <div className="space-y-1">
        {items
          .filter(({ permission }) => !permission || permissions.includes(permission))
          .map(({ label: itemLabel, to, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              onClick={onNavigate}
              className={({ isActive }) =>
                `flex min-h-10 items-center gap-3 px-3 text-sm transition ${
                  isActive
                    ? "bg-white/10 font-medium text-white"
                    : "text-neutral-400 hover:bg-white/6 hover:text-white"
                }`
              }
            >
              <Icon aria-hidden="true" size={17} strokeWidth={1.8} />
              {itemLabel}
            </NavLink>
          ))}
      </div>
    </nav>
  );
}

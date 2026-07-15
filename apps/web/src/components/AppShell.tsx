import { Activity, BookOpenText, Boxes, ShieldCheck } from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";

const navigation = [
  { label: "Device readiness", to: "/devices", icon: Activity },
  { label: "Cases", to: "/cases", icon: Boxes, disabled: true },
  { label: "Evidence", to: "/evidence", icon: ShieldCheck, disabled: true },
  { label: "Reports", to: "/reports", icon: BookOpenText, disabled: true },
];

export function AppShell() {
  return (
    <div className="min-h-screen bg-[#071016] text-slate-100">
      <a
        href="#main-content"
        className="sr-only z-50 rounded-md bg-cyan-300 px-4 py-2 font-semibold text-slate-950 focus:not-sr-only focus:fixed focus:left-4 focus:top-4"
      >
        Skip to content
      </a>
      <header className="border-b border-white/8 bg-[#09151d]/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1480px] items-center justify-between px-5 py-4 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="grid size-10 place-items-center rounded-xl border border-cyan-300/30 bg-cyan-300/8 text-cyan-300 shadow-[0_0_30px_rgba(34,211,238,0.08)]">
              <ShieldCheck aria-hidden="true" size={21} />
            </div>
            <div>
              <p className="text-lg font-semibold tracking-tight">ForensiX</p>
              <p className="text-xs text-slate-500">Android forensic triage workstation</p>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-full border border-emerald-300/15 bg-emerald-300/6 px-3 py-1.5 text-xs font-medium text-emerald-300">
            <span className="size-1.5 rounded-full bg-emerald-300" aria-hidden="true" />
            Local-only mode
          </div>
        </div>
      </header>
      <div className="mx-auto grid max-w-[1480px] grid-cols-1 lg:grid-cols-[250px_1fr]">
        <aside className="border-b border-white/8 px-4 py-4 lg:min-h-[calc(100vh-73px)] lg:border-b-0 lg:border-r lg:px-5 lg:py-7">
          <nav aria-label="Primary navigation" className="flex gap-2 overflow-x-auto lg:flex-col">
            {navigation.map(({ label, to, icon: Icon, disabled }) =>
              disabled ? (
                <span
                  key={to}
                  aria-disabled="true"
                  className="flex shrink-0 items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-slate-600"
                >
                  <Icon aria-hidden="true" size={17} />
                  {label}
                  <span className="ml-auto hidden text-[10px] uppercase tracking-wider text-slate-700 lg:inline">
                    Soon
                  </span>
                </span>
              ) : (
                <NavLink
                  key={to}
                  to={to}
                  className={({ isActive }) =>
                    `flex shrink-0 items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition ${
                      isActive
                        ? "bg-cyan-300/9 text-cyan-200 ring-1 ring-inset ring-cyan-300/15"
                        : "text-slate-400 hover:bg-white/4 hover:text-slate-200"
                    }`
                  }
                >
                  <Icon aria-hidden="true" size={17} />
                  {label}
                </NavLink>
              ),
            )}
          </nav>
        </aside>
        <main id="main-content" className="min-w-0 px-5 py-8 lg:px-10 lg:py-10">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

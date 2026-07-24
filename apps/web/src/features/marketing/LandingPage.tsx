import { ArrowRight, BadgeCheck, Blocks, CheckCircle2, ChartNoAxesCombined, Cpu, FileCheck2, Fingerprint, Lock, MonitorSmartphone, ScanSearch, Shield, Sparkles } from "lucide-react";
import { Link } from "react-router-dom";

const STYLE = `
@keyframes scan { 0%{transform:translateY(-100%)} 100%{transform:translateY(100vh)} }
@keyframes pulse-ring { 0%,100%{opacity:.18;transform:scale(1)} 50%{opacity:.38;transform:scale(1.06)} }
@keyframes float-y { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-10px)} }
@keyframes float-y2 { 0%,100%{transform:translateY(0) rotate(-8deg)} 50%{transform:translateY(-8px) rotate(-8deg)} }
@keyframes float-y3 { 0%,100%{transform:translateY(0) rotate(7deg)} 50%{transform:translateY(-12px) rotate(7deg)} }
@keyframes glow-pulse { 0%,100%{box-shadow:0 0 24px rgba(34,211,238,.18)} 50%{box-shadow:0 0 48px rgba(34,211,238,.38)} }
@keyframes progress-fill { from{width:0} to{width:72%} }
@keyframes fade-up { from{opacity:0;transform:translateY(24px)} to{opacity:1;transform:translateY(0)} }
@keyframes spin-slow { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
@keyframes data-flow { 0%{stroke-dashoffset:200} 100%{stroke-dashoffset:0} }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.3} }
.scan-line{animation:scan 4s linear infinite;pointer-events:none}
.float-a{animation:float-y 5s ease-in-out infinite}
.float-b{animation:float-y2 6s ease-in-out infinite}
.float-c{animation:float-y3 7s ease-in-out infinite}
.glow-card{animation:glow-pulse 3s ease-in-out infinite}
.progress-bar{animation:progress-fill 2s ease-out forwards}
.fade-up{animation:fade-up .7s ease-out forwards}
.spin-slow{animation:spin-slow 12s linear infinite}
.blink{animation:blink 1.4s ease-in-out infinite}
.card-hover{transition:transform .25s,box-shadow .25s}
.card-hover:hover{transform:translateY(-4px);box-shadow:0 24px 60px rgba(34,211,238,.14)}
`;

const features = [
  { title: "Capability-Gated Acquisition", copy: "Bind every plan to verified device readiness, allowed scope, and recorded limitations.", icon: Shield },
  { title: "Evidence Twin Validation", copy: "Compare sealed source evidence against validated working copies and known-answer workflows.", icon: Blocks },
  { title: "Chain of Custody", copy: "Track collection, validation, examination, and reporting with append-only checkpoints.", icon: Fingerprint },
  { title: "Audit-Ready Reporting", copy: "Generate reviewable outputs backed by traceable hashes, snapshots, and verification history.", icon: FileCheck2 },
];

const workflow = [
  { label: "Connect & Assess", detail: "Android device detected via ADB secure channel" },
  { label: "Approve Acquisition Plan", detail: "Capability-gated scope with explicit limitations" },
  { label: "Collect Bounded Evidence", detail: "Controlled extraction through verified pipelines" },
  { label: "Validate with Evidence Twin", detail: "SHA-256 integrity verification across both copies" },
  { label: "Review & Export Report", detail: "Audit-ready output with full chain of custody" },
];

const arch = ["Android Device","ADB Layer","Acquisition Engine","Evidence Store","Evidence Twin","Validation","Reporting","Export"];

export function LandingPage() {
  return (
    <div className="relative min-h-screen overflow-x-hidden bg-[#02070d] text-slate-100">
      <style>{STYLE}</style>

      {/* Background layers */}
      <div className="pointer-events-none fixed inset-0 z-0">
        {/* Grid */}
        <div className="absolute inset-0 opacity-[0.07] [background-image:linear-gradient(rgba(34,211,238,0.5)_1px,transparent_1px),linear-gradient(90deg,rgba(34,211,238,0.5)_1px,transparent_1px)] [background-size:80px_80px]" />
        {/* Radial glows */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_40%_at_50%_0%,rgba(14,116,144,0.22),transparent),radial-gradient(ellipse_40%_60%_at_80%_50%,rgba(34,211,238,0.06),transparent),radial-gradient(ellipse_40%_60%_at_20%_70%,rgba(12,74,110,0.14),transparent)]" />
        {/* Scan line */}
        <div className="scan-line absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400/40 to-transparent" />
      </div>

      {/* Nav */}
      <header className="relative z-20 border-b border-white/[0.04] bg-[#02070d]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-[1480px] items-center justify-between px-5 py-4 lg:px-8">
          <Link to="/" className="flex items-center gap-3">
            <div className="relative grid size-10 place-items-center rounded-xl border border-cyan-400/40 bg-cyan-400/10 glow-card">
              <span className="text-lg font-black tracking-[-0.14em] text-cyan-300">FX</span>
            </div>
            <div>
              <p className="font-['Space_Grotesk',sans-serif] text-xl font-bold uppercase tracking-[0.2em] text-white">ForensiX</p>
              <p className="text-[10px] uppercase tracking-[0.28em] text-cyan-300/50">Android Forensics Platform</p>
            </div>
          </Link>
          <nav className="hidden items-center gap-8 text-sm text-slate-400 lg:flex">
            {["Platform","Workflow","Architecture"].map(n => (
              <a key={n} href={`#${n.toLowerCase()}`} className="transition-colors hover:text-cyan-300">{n}</a>
            ))}
          </nav>
          <div className="flex items-center gap-3">
            <Link to="/devices" className="hidden rounded-lg border border-white/10 bg-white/[0.03] px-4 py-2 text-sm text-slate-300 transition hover:border-cyan-400/30 hover:text-white sm:block">
              Open Workstation
            </Link>
            <Link to="/devices" className="rounded-lg border border-cyan-400/50 bg-cyan-400/10 px-4 py-2 text-sm font-semibold text-cyan-200 shadow-[0_0_20px_rgba(34,211,238,0.15)] transition hover:bg-cyan-400/20">
              Request Demo
            </Link>
          </div>
        </div>
      </header>

      <main className="relative z-10">
        {/* ── HERO ── */}
        <section className="mx-auto grid max-w-[1480px] gap-10 px-5 pb-16 pt-14 lg:grid-cols-[minmax(0,520px)_1fr] lg:gap-16 lg:px-8 lg:pt-20">
          <div className="flex flex-col justify-center fade-up">
            <div className="mb-6 inline-flex w-fit items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/8 px-4 py-1.5 text-[11px] uppercase tracking-[0.28em] text-cyan-300/80">
              <Sparkles size={12} />
              Defensible Android Evidence Triage
            </div>
            <h1 className="font-['Space_Grotesk',sans-serif] text-5xl font-bold leading-[0.92] tracking-tight text-white sm:text-6xl lg:text-[4.5rem]">
              Android<br />
              <span className="bg-gradient-to-r from-cyan-300 to-sky-400 bg-clip-text text-transparent">Forensics</span><br />
              Built for<br />Scrutiny.
            </h1>
            <p className="mt-6 max-w-md text-lg leading-relaxed text-slate-400">
              Defensible evidence collection. Proven integrity. Complete chain of custody — from device to courtroom.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link to="/devices" className="inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-6 py-3.5 text-sm font-bold text-slate-950 shadow-[0_8px_32px_rgba(34,211,238,0.3)] transition hover:bg-cyan-300 hover:shadow-[0_8px_40px_rgba(34,211,238,0.45)]">
                Request Demo <ArrowRight size={16} />
              </Link>
              <a href="#platform" className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3.5 text-sm font-medium text-slate-200 transition hover:border-cyan-400/30 hover:bg-cyan-400/5">
                Explore Platform
              </a>
            </div>
            <div className="mt-8 flex flex-wrap gap-2">
              {["Defensible","Transparent","Auditable","Secure"].map(t => (
                <span key={t} className="inline-flex items-center gap-1.5 rounded-lg border border-white/8 bg-white/[0.03] px-3 py-2 text-xs text-slate-400">
                  <CheckCircle2 size={13} className="text-cyan-400" />{t}
                </span>
              ))}
            </div>
          </div>

          {/* Hero dashboard */}
          <div className="relative min-h-[600px]">
            {/* Main card */}
            <div className="float-a absolute inset-x-0 top-0 rounded-2xl border border-cyan-400/18 bg-[linear-gradient(135deg,rgba(7,20,34,0.97),rgba(3,10,20,0.95))] p-5 shadow-[0_0_0_1px_rgba(34,211,238,0.05),0_32px_80px_rgba(0,0,0,0.5)]">
              {/* Top bar */}
              <div className="mb-4 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="size-2.5 rounded-full bg-red-500/70" />
                  <div className="size-2.5 rounded-full bg-amber-400/70" />
                  <div className="size-2.5 rounded-full bg-emerald-400/70" />
                  <span className="ml-2 text-xs text-slate-500 tracking-widest uppercase">ForensiX Workstation</span>
                </div>
                <span className="text-[10px] text-cyan-400/60 tracking-widest blink">● LIVE</span>
              </div>

              <div className="grid gap-4 lg:grid-cols-[1.3fr_1fr]">
                {/* Left panel */}
                <div className="rounded-xl border border-cyan-400/12 bg-[#060f1a]/80 p-4">
                  <div className="mb-4 flex items-center justify-between">
                    <div>
                      <p className="text-[10px] uppercase tracking-[0.22em] text-cyan-300/60">Case Overview</p>
                      <p className="mt-0.5 text-[10px] text-slate-600">CASE-2024-0715</p>
                    </div>
                    <div className="relative grid size-20 place-items-center">
                      <svg className="spin-slow absolute inset-0" viewBox="0 0 80 80">
                        <circle cx="40" cy="40" r="36" fill="none" stroke="rgba(34,211,238,0.12)" strokeWidth="2" />
                        <circle cx="40" cy="40" r="36" fill="none" stroke="rgba(34,211,238,0.7)" strokeWidth="2" strokeDasharray="160" strokeDashoffset="45" strokeLinecap="round" />
                      </svg>
                      <span className="text-lg font-bold text-cyan-300">72%</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    {[["Devices","1","Connected"],["Status","Active","In Progress"],["Evidence","18,456","Indexed"],["Integrity","Verified","All hashes match"]].map(([l,v,d]) => (
                      <div key={l} className="rounded-lg border border-white/5 bg-black/20 p-3">
                        <p className="text-[10px] uppercase tracking-widest text-slate-600">{l}</p>
                        <p className="mt-1.5 text-base font-semibold text-white">{v}</p>
                        <p className="text-[10px] text-cyan-300/60">{d}</p>
                      </div>
                    ))}
                  </div>
                  {/* Sparkline */}
                  <div className="mt-4 rounded-lg border border-white/5 bg-black/20 p-3">
                    <div className="mb-2 flex justify-between text-[10px] uppercase tracking-widest text-slate-600">
                      <span>Timeline Activity</span><span>00:00–09:00</span>
                    </div>
                    <svg viewBox="0 0 260 48" className="h-12 w-full">
                      <defs>
                        <linearGradient id="lg1" x1="0" x2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity=".4"/><stop offset="100%" stopColor="#38bdf8" stopOpacity="1"/></linearGradient>
                        <linearGradient id="lg2" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity=".18"/><stop offset="100%" stopColor="#22d3ee" stopOpacity="0"/></linearGradient>
                      </defs>
                      <path d="M0 38 C18 40,22 16,42 20 S67 36,84 28 S112 12,132 18 S168 36,188 22 S220 8,260 16" fill="none" stroke="url(#lg1)" strokeWidth="2" strokeLinecap="round"/>
                      <path d="M0 38 C18 40,22 16,42 20 S67 36,84 28 S112 12,132 18 S168 36,188 22 S220 8,260 16 L260 48 L0 48Z" fill="url(#lg2)"/>
                    </svg>
                  </div>
                </div>

                {/* Right panels */}
                <div className="flex flex-col gap-4">
                  {/* Evidence Twin */}
                  <div className="rounded-xl border border-cyan-400/12 bg-[#060f1a]/80 p-4">
                    <p className="text-[10px] uppercase tracking-[0.22em] text-cyan-300/60">Evidence Twin</p>
                    <div className="mt-4 grid grid-cols-[1fr_auto_1fr] items-center gap-3">
                      <TwinCube accent="orange" />
                      <div className="flex flex-col items-center gap-1">
                        <div className="h-px w-8 bg-gradient-to-r from-orange-300/30 via-cyan-300 to-cyan-300/30" />
                        <span className="text-[9px] text-cyan-400/60 tracking-widest">SYNC</span>
                        <div className="h-px w-8 bg-gradient-to-r from-cyan-300/30 via-cyan-300 to-orange-300/30" />
                      </div>
                      <TwinCube accent="cyan" />
                    </div>
                    <div className="mt-4 grid grid-cols-2 gap-3 text-[11px]">
                      {[["Original","a8f3c2e7d6..."],["Twin","a8f3c2e7d6..."]].map(([l,h]) => (
                        <div key={l}>
                          <p className="text-slate-400">{l}</p>
                          <p className="mt-1 text-[9px] text-slate-600">SHA256</p>
                          <p className="truncate text-cyan-300/80">{h}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Chain of Custody */}
                  <div className="rounded-xl border border-cyan-400/12 bg-[#060f1a]/80 p-4">
                    <p className="text-[10px] uppercase tracking-[0.22em] text-cyan-300/60">Chain of Custody</p>
                    <div className="mt-4 flex items-center justify-between gap-1">
                      {[Shield,BadgeCheck,Blocks,ScanSearch,ChartNoAxesCombined].map((Icon, i) => (
                        <div key={i} className="flex flex-1 items-center gap-1">
                          <div className="grid size-9 shrink-0 place-items-center rounded-full border border-cyan-300/25 bg-cyan-400/8 text-cyan-300">
                            <Icon size={14} />
                          </div>
                          {i < 4 && <div className="h-px flex-1 bg-gradient-to-r from-cyan-300/40 to-cyan-300/10" />}
                        </div>
                      ))}
                    </div>
                    <div className="mt-2 grid grid-cols-5 gap-1 text-center text-[9px] text-slate-600">
                      {["Collect","Validate","Twin","Analyze","Report"].map(l => <span key={l}>{l}</span>)}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Floating device card */}
            <div className="float-b absolute -bottom-4 -left-4 z-10 hidden w-[200px] rounded-2xl border border-cyan-400/14 bg-[rgba(4,12,22,0.97)] p-4 shadow-[0_20px_60px_rgba(0,0,0,0.6)] xl:block">
              <div className="mx-auto mb-3 grid size-10 place-items-center rounded-full border border-cyan-300/25 bg-cyan-400/8 text-cyan-300">
                <MonitorSmartphone size={18} />
              </div>
              <p className="text-center text-[11px] uppercase tracking-[0.18em] text-slate-300">Device Connected</p>
              <div className="mt-3 space-y-1.5 text-[11px] text-slate-500">
                <p>Android 13 · Pixel 6 Pro</p>
                <p>ADB secure channel ✓</p>
              </div>
              <div className="mt-3 flex items-center justify-center gap-1.5 rounded-lg border border-cyan-400/12 bg-cyan-400/6 py-2">
                <Lock size={12} className="text-cyan-400" />
                <span className="text-[11px] text-cyan-200">Capability Verified</span>
              </div>
            </div>

            {/* Floating artifacts card */}
            <div className="float-c absolute -bottom-4 -right-4 z-10 hidden w-[200px] rounded-2xl border border-cyan-400/14 bg-[rgba(4,12,22,0.97)] p-4 shadow-[0_20px_60px_rgba(0,0,0,0.6)] xl:block">
              <p className="text-[10px] uppercase tracking-[0.22em] text-slate-500">Artifact Categories</p>
              <div className="mt-3 space-y-2 text-[11px]">
                {[["Messages","2,451"],["Photos","4,212"],["Calls","1,037"],["Documents","2,304"],["App Data","5,333"]].map(([l,v]) => (
                  <div key={l} className="flex justify-between text-slate-400">
                    <span>{l}</span><span className="text-cyan-300/80">{v}</span>
                  </div>
                ))}
              </div>
              <div className="mt-3 rounded-lg border border-cyan-400/12 bg-cyan-400/6 py-2 text-center text-[11px] font-semibold text-cyan-200">
                18,456 Total
              </div>
            </div>
          </div>
        </section>

        {/* ── PLATFORM ── */}
        <section id="platform" className="mx-auto max-w-[1480px] px-5 py-16 lg:px-8 lg:py-24">
          <div className="mb-12 grid gap-6 lg:grid-cols-2">
            <div>
              <p className="text-[11px] uppercase tracking-[0.3em] text-cyan-300/60">Platform</p>
              <h2 className="mt-3 font-['Space_Grotesk',sans-serif] text-4xl font-bold tracking-tight text-white sm:text-5xl">
                A forensic workflow that favors clarity.
              </h2>
            </div>
            <div className="flex flex-col justify-center gap-4 text-base leading-relaxed text-slate-400">
              <p>ForensiX is built for investigators who need to explain <em className="text-slate-300 not-italic">how</em> evidence was collected, validated, and preserved — not just what was extracted.</p>
              <p>Every step is capability-gated, sealed, and auditable from a single workstation.</p>
            </div>
          </div>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {features.map(({ title, copy, icon: Icon }) => (
              <div key={title} className="card-hover rounded-2xl border border-cyan-400/10 bg-[linear-gradient(160deg,rgba(8,18,30,0.95),rgba(3,10,18,0.9))] p-6">
                <div className="mb-4 grid size-11 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-400/8 text-cyan-300">
                  <Icon size={20} />
                </div>
                <h3 className="text-base font-semibold text-white">{title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-500">{copy}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── WORKFLOW ── */}
        <section id="workflow" className="mx-auto max-w-[1480px] px-5 py-16 lg:px-8 lg:py-24">
          <div className="grid gap-8 lg:grid-cols-[1fr_360px]">
            <div className="rounded-2xl border border-cyan-400/10 bg-[linear-gradient(160deg,rgba(7,18,30,0.96),rgba(3,9,18,0.92))] p-6 lg:p-8">
              <p className="text-[11px] uppercase tracking-[0.3em] text-cyan-300/60">Workflow</p>
              <h2 className="mt-3 font-['Space_Grotesk',sans-serif] text-3xl font-bold tracking-tight text-white sm:text-4xl">
                Device to defensible report.
              </h2>
              <div className="relative mt-8 space-y-3">
                <div className="absolute left-[18px] top-0 h-full w-px bg-gradient-to-b from-cyan-400/40 via-cyan-400/20 to-transparent" />
                {workflow.map(({ label, detail }, i) => (
                  <div key={label} className="relative flex items-start gap-4 rounded-xl border border-white/5 bg-white/[0.02] px-4 py-3.5 transition hover:border-cyan-400/20 hover:bg-cyan-400/[0.03]">
                    <div className="relative z-10 grid size-9 shrink-0 place-items-center rounded-full border border-cyan-300/30 bg-[#02070d] text-xs font-bold text-cyan-300">
                      {String(i + 1).padStart(2, "0")}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-slate-200">{label}</p>
                      <p className="mt-0.5 text-xs text-slate-500">{detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Stats */}
            <div className="flex flex-col gap-4">
              {[
                { label: "Acquisition Integrity", value: "72%", detail: "Verified progress demo", icon: Cpu },
                { label: "Evidence Items", value: "18,456", detail: "Explorer-ready artifacts", icon: FileCheck2 },
                { label: "Custody Stages", value: "5", detail: "Collection to reporting", icon: Fingerprint },
              ].map(({ label, value, detail, icon: Icon }) => (
                <div key={label} className="card-hover flex-1 rounded-2xl border border-cyan-400/10 bg-[linear-gradient(160deg,rgba(7,18,30,0.96),rgba(3,9,18,0.92))] p-6">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs text-slate-500">{label}</p>
                      <p className="mt-2 text-4xl font-bold text-white">{value}</p>
                      <p className="mt-1 text-xs text-cyan-300/70">{detail}</p>
                    </div>
                    <div className="grid size-10 place-items-center rounded-xl border border-cyan-300/15 bg-cyan-400/6 text-cyan-400">
                      <Icon size={18} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── ARCHITECTURE ── */}
        <section id="architecture" className="mx-auto max-w-[1480px] px-5 py-16 lg:px-8 lg:py-24">
          <p className="text-[11px] uppercase tracking-[0.3em] text-cyan-300/60">Architecture</p>
          <h2 className="mt-3 font-['Space_Grotesk',sans-serif] text-3xl font-bold tracking-tight text-white sm:text-4xl">
            A living forensic pipeline.
          </h2>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-0">
            {arch.map((node, i) => (
              <div key={node} className="flex items-center">
                <div className="card-hover rounded-xl border border-cyan-400/18 bg-[linear-gradient(160deg,rgba(8,20,34,0.97),rgba(3,10,20,0.95))] px-5 py-3 text-center shadow-[0_0_20px_rgba(34,211,238,0.06)]">
                  <p className="text-xs font-medium text-slate-300">{node}</p>
                </div>
                {i < arch.length - 1 && (
                  <div className="flex flex-col items-center px-1">
                    <div className="h-px w-6 bg-gradient-to-r from-cyan-400/60 to-cyan-400/20" />
                    <div className="mt-0.5 size-1 rounded-full bg-cyan-400/60" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* ── CTA ── */}
        <section className="mx-auto max-w-[1480px] px-5 py-16 lg:px-8 lg:py-24">
          <div className="relative overflow-hidden rounded-3xl border border-cyan-400/18 bg-[linear-gradient(135deg,rgba(7,20,36,0.98),rgba(3,10,22,0.97))] p-10 text-center shadow-[0_0_80px_rgba(34,211,238,0.08)] lg:p-16">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_60%_50%_at_50%_0%,rgba(34,211,238,0.1),transparent)]" />
            <div className="pointer-events-none absolute inset-0 opacity-[0.05] [background-image:linear-gradient(rgba(34,211,238,0.5)_1px,transparent_1px),linear-gradient(90deg,rgba(34,211,238,0.5)_1px,transparent_1px)] [background-size:60px_60px]" />
            <div className="relative">
              <div className="mx-auto mb-6 grid size-16 place-items-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10 text-cyan-300 glow-card">
                <Shield size={28} />
              </div>
              <h2 className="font-['Space_Grotesk',sans-serif] text-4xl font-bold tracking-tight text-white sm:text-5xl lg:text-6xl">
                Android Forensics<br />
                <span className="bg-gradient-to-r from-cyan-300 to-sky-400 bg-clip-text text-transparent">Built for Scrutiny.</span>
              </h2>
              <p className="mx-auto mt-6 max-w-xl text-lg text-slate-400">
                Join DFIR teams, law enforcement, and enterprise security teams who trust ForensiX for defensible evidence collection.
              </p>
              <div className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
                <Link to="/devices" className="inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-8 py-4 text-base font-bold text-slate-950 shadow-[0_8px_40px_rgba(34,211,238,0.35)] transition hover:bg-cyan-300 hover:shadow-[0_8px_50px_rgba(34,211,238,0.5)]">
                  Request Demo <ArrowRight size={18} />
                </Link>
                <Link to="/devices" className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-8 py-4 text-base font-medium text-slate-200 transition hover:border-cyan-400/30 hover:bg-cyan-400/5">
                  Open Workstation
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="relative z-10 border-t border-white/[0.04] py-8 text-center text-xs text-slate-600">
        © {new Date().getFullYear()} ForensiX · Android Digital Forensics Platform
      </footer>
    </div>
  );
}

function TwinCube({ accent }: { accent: "cyan" | "orange" }) {
  const b = accent === "cyan" ? "border-cyan-300/70 shadow-[0_0_24px_rgba(34,211,238,0.2)]" : "border-orange-300/70 shadow-[0_0_24px_rgba(251,146,60,0.15)]";
  const g = accent === "cyan" ? "bg-cyan-300/12" : "bg-orange-300/12";
  return (
    <div className="relative mx-auto h-20 w-20">
      <div className={`absolute inset-0 rounded-xl border ${b}`} />
      <div className={`absolute inset-3 rounded-lg border ${b} ${g}`} />
      <div className={`absolute inset-0 rotate-45 rounded-xl border ${b} opacity-25`} />
    </div>
  );
}

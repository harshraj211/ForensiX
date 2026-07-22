import {
  Camera,
  LoaderCircle,
  Maximize2,
  Minimize2,
  Monitor,
  Square,
} from "lucide-react";
import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  captureDeviceScreenshot,
  fetchWebsiteLivePreviewFrame,
  startWebsiteLivePreview,
  stopWebsiteLivePreview,
} from "../../lib/api";
import {
  LiveScreenContext,
  type LiveScreenTarget,
  useLiveScreenPreview,
} from "./liveScreenContext";

export function LiveScreenPreviewProvider({ children }: { children: ReactNode }) {
  const [target, setTarget] = useState<LiveScreenTarget | null>(null);

  const start = useCallback(async (nextTarget: LiveScreenTarget) => {
    await startWebsiteLivePreview(
      nextTarget.caseId,
      nextTarget.deviceId,
      nextTarget.serial,
    );
    setTarget(nextTarget);
  }, []);

  const stop = useCallback(async () => {
    const activeTarget = target;
    setTarget(null);
    if (activeTarget) {
      await stopWebsiteLivePreview(
        activeTarget.caseId,
        activeTarget.deviceId,
        activeTarget.serial,
      );
    }
  }, [target]);

  const value = useMemo(() => ({ target, start, stop }), [start, stop, target]);
  return (
    <LiveScreenContext.Provider value={value}>
      {children}
      {target && <LiveScreenDock key={`${target.caseId}:${target.deviceId}`} target={target} />}
    </LiveScreenContext.Provider>
  );
}

function LiveScreenDock({ target }: { target: LiveScreenTarget }) {
  const { stop } = useLiveScreenPreview();
  const [minimized, setMinimized] = useState(false);
  const [frameUrl, setFrameUrl] = useState<string | null>(null);
  const [frameError, setFrameError] = useState<string | null>(null);
  const [frameCount, setFrameCount] = useState(0);
  const [stopping, setStopping] = useState(false);
  const [sealing, setSealing] = useState(false);
  const [sealResult, setSealResult] = useState<string | null>(null);

  useEffect(() => {
    if (minimized) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController | undefined;

    const loadFrame = async () => {
      controller = new AbortController();
      try {
        const blob = await fetchWebsiteLivePreviewFrame(
          target.caseId,
          target.deviceId,
          target.serial,
          controller.signal,
        );
        if (cancelled) return;
        const nextUrl = URL.createObjectURL(blob);
        setFrameUrl((previous) => {
          if (previous) URL.revokeObjectURL(previous);
          return nextUrl;
        });
        setFrameError(null);
        setFrameCount((count) => count + 1);
      } catch (error) {
        if (!cancelled && !(error instanceof DOMException && error.name === "AbortError")) {
          setFrameError(error instanceof Error ? error.message : "Live preview interrupted.");
        }
      } finally {
        if (!cancelled) timer = setTimeout(() => void loadFrame(), 900);
      }
    };

    void loadFrame();
    return () => {
      cancelled = true;
      controller?.abort();
      if (timer) clearTimeout(timer);
    };
  }, [minimized, target]);

  useEffect(
    () => () => {
      if (frameUrl) URL.revokeObjectURL(frameUrl);
    },
    [frameUrl],
  );

  const sealCurrentScreen = async () => {
    setSealing(true);
    setSealResult(null);
    try {
      const source = await captureDeviceScreenshot(
        target.caseId,
        target.deviceId,
        target.serial,
      );
      setSealResult(`Sealed ${source.sha256?.slice(0, 12) ?? source.id.slice(0, 8)}â€¦`);
    } catch (error) {
      setSealResult(error instanceof Error ? error.message : "Screenshot could not be sealed.");
    } finally {
      setSealing(false);
    }
  };

  const stopPreview = async () => {
    setStopping(true);
    try {
      await stop();
    } finally {
      setStopping(false);
    }
  };

  return (
    <aside
      aria-label="Live Android screen preview"
      className="fixed bottom-4 right-4 z-40 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-2xl border border-cyan-200/20 bg-[#071016]/98 shadow-2xl shadow-black/60 backdrop-blur"
    >
      <div className="flex items-center justify-between gap-3 border-b border-white/8 px-4 py-3">
        <div className="flex min-w-0 items-center gap-2">
          <span className="relative flex size-2">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-300 opacity-60" />
            <span className="relative inline-flex size-2 rounded-full bg-emerald-300" />
          </span>
          <div className="min-w-0">
            <p className="truncate text-xs font-semibold text-white">{target.label}</p>
            <p className="text-[10px] uppercase tracking-wider text-cyan-200/60">
              Website live preview
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            aria-label={minimized ? "Restore live preview" : "Minimize live preview"}
            onClick={() => {
              setMinimized((value) => !value);
            }}
            className="grid size-8 place-items-center rounded-lg text-slate-400 hover:bg-white/6 hover:text-white"
          >
            {minimized ? <Maximize2 size={14} /> : <Minimize2 size={14} />}
          </button>
          <button
            type="button"
            aria-label="Stop live preview"
            disabled={stopping}
            onClick={() => {
              void stopPreview();
            }}
            className="grid size-8 place-items-center rounded-lg text-rose-300 hover:bg-rose-300/8 disabled:opacity-40"
          >
            {stopping ? <LoaderCircle className="animate-spin" size={14} /> : <Square size={13} />}
          </button>
        </div>
      </div>
      {!minimized && (
        <>
          <div className="relative grid min-h-52 place-items-center bg-black">
            {frameUrl ? (
              <img
                src={frameUrl}
                alt={`Live screen from ${target.label}`}
                className="max-h-[58vh] w-full object-contain"
              />
            ) : (
              <div className="text-center text-slate-500">
                <Monitor className="mx-auto" size={24} />
                <p className="mt-2 text-xs">Waiting for the first USB frameâ€¦</p>
              </div>
            )}
            {frameError && (
              <div role="alert" className="absolute inset-x-3 bottom-3 rounded-lg bg-rose-950/90 p-2 text-[11px] text-rose-100">
                {frameError}
              </div>
            )}
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
            <div>
              <p className="text-[10px] text-slate-500">{frameCount} temporary frame(s)</p>
              <p className="text-[10px] text-amber-100/55">Not evidence until sealed</p>
            </div>
            <button
              type="button"
              disabled={sealing}
              onClick={() => void sealCurrentScreen()}
              className="inline-flex min-h-9 items-center gap-2 rounded-lg bg-cyan-300 px-3 text-xs font-semibold text-slate-950 disabled:opacity-40"
            >
              {sealing ? <LoaderCircle className="animate-spin" size={14} /> : <Camera size={14} />}
              Seal screenshot
            </button>
            {sealResult && <p className="w-full text-[10px] text-emerald-200">{sealResult}</p>}
          </div>
        </>
      )}
    </aside>
  );
}

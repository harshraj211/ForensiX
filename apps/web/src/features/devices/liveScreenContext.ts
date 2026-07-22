import { createContext, useContext } from "react";

export interface LiveScreenTarget {
  caseId: string;
  deviceId: string;
  serial: string;
  label: string;
}

export interface LiveScreenContextValue {
  target: LiveScreenTarget | null;
  start: (target: LiveScreenTarget) => Promise<void>;
  stop: () => Promise<void>;
}

export const LiveScreenContext = createContext<LiveScreenContextValue | null>(null);

export function useLiveScreenPreview(): LiveScreenContextValue {
  const value = useContext(LiveScreenContext);
  if (!value) throw new Error("Live screen preview must be used inside its provider.");
  return value;
}

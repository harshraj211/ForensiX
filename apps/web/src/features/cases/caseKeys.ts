export const caseKeys = {
  all: ["cases"] as const,
  detail: (caseId: string) => ["cases", caseId] as const,
  commandCenter: (caseId: string) => ["cases", caseId, "command-center"] as const,
  devices: (caseId: string) => ["cases", caseId, "devices"] as const,
  deviceAssessments: (caseId: string, deviceId: string) =>
    ["cases", caseId, "devices", deviceId, "assessments"] as const,
  acquisitionPlans: (caseId: string) => ["cases", caseId, "acquisition-plans"] as const,
  acquisitionJobs: (caseId: string) => ["cases", caseId, "acquisition-jobs"] as const,
  custody: (caseId: string) => ["cases", caseId, "custody"] as const,
  custodyVerification: (caseId: string) =>
    ["cases", caseId, "custody-verification"] as const,
  custodyCheckpoints: (caseId: string) =>
    ["cases", caseId, "custody-checkpoints"] as const,
  custodyCheckpointAnchors: (caseId: string, checkpointId: string) =>
    ["cases", caseId, "custody-checkpoints", checkpointId, "anchors"] as const,
  custodyCheckpointSignatures: (caseId: string, checkpointId: string) =>
    ["cases", caseId, "custody-checkpoints", checkpointId, "signatures"] as const,
  artifacts: (caseId: string, filters: Record<string, string>) =>
    ["cases", caseId, "artifacts", filters] as const,
  timeline: (caseId: string) => ["cases", caseId, "timeline"] as const,
  correlations: (caseId: string) => ["cases", caseId, "correlations"] as const,
  mediaMap: (caseId: string) => ["cases", caseId, "media-map"] as const,
  artifactSearch: (caseId: string, filters: Record<string, string>) =>
    ["cases", caseId, "artifact-search", filters] as const,
};

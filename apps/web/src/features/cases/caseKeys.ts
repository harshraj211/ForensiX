export const caseKeys = {
  all: ["cases"] as const,
  detail: (caseId: string) => ["cases", caseId] as const,
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
  artifacts: (caseId: string, filters: Record<string, string>) =>
    ["cases", caseId, "artifacts", filters] as const,
  timeline: (caseId: string) => ["cases", caseId, "timeline"] as const,
};

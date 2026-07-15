export const caseKeys = {
  all: ["cases"] as const,
  detail: (caseId: string) => ["cases", caseId] as const,
  devices: (caseId: string) => ["cases", caseId, "devices"] as const,
  deviceAssessments: (caseId: string, deviceId: string) =>
    ["cases", caseId, "devices", deviceId, "assessments"] as const,
  acquisitionPlans: (caseId: string) => ["cases", caseId, "acquisition-plans"] as const,
};

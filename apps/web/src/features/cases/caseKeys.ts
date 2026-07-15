export const caseKeys = {
  all: ["cases"] as const,
  detail: (caseId: string) => ["cases", caseId] as const,
};

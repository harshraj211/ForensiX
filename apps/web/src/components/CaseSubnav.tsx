export interface CaseSubnavProps {
  caseId: string;
  caseNumber?: string;
}

/**
 * Case navigation has been unified into the primary left workstation sidebar.
 * This component returns null to eliminate top horizontal navbar duplication.
 */
export function CaseSubnav(_props: CaseSubnavProps) {
  return null;
}

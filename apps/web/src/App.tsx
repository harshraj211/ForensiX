import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/AppShell";
import { AcquisitionPlanningPage } from "./features/acquisitions/AcquisitionPlanningPage";
import { AuditLogPage } from "./features/audit/AuditLogPage";
import { AuthBoundary } from "./features/auth/AuthBoundary";
import { CaseDetailPage } from "./features/cases/CaseDetailPage";
import { CasesPage } from "./features/cases/CasesPage";
import { DeviceDetectionPage } from "./features/devices/DeviceDetectionPage";
import { EvidenceCasesPage, EvidenceExplorerPage } from "./features/evidence/EvidenceExplorerPage";
import { TimelinePage } from "./features/evidence/TimelinePage";
import { EvidenceTwinPage } from "./features/evidence-twin/EvidenceTwinPage";
import { CaseReportsPage, ReportsCasesPage } from "./features/reports/ReportsPage";

export function App() {
  return (
    <Routes>
      <Route element={<AuthBoundary />}>
        <Route element={<AppShell />}>
          <Route path="/devices" element={<DeviceDetectionPage />} />
          <Route path="/cases" element={<CasesPage />} />
          <Route path="/cases/:caseId" element={<CaseDetailPage />} />
          <Route path="/cases/:caseId/devices" element={<DeviceDetectionPage />} />
          <Route path="/cases/:caseId/acquisitions" element={<AcquisitionPlanningPage />} />
          <Route path="/cases/:caseId/evidence" element={<EvidenceExplorerPage />} />
          <Route path="/cases/:caseId/evidence-twin" element={<EvidenceTwinPage />} />
          <Route path="/cases/:caseId/timeline" element={<TimelinePage />} />
          <Route path="/evidence" element={<EvidenceCasesPage />} />
          <Route path="/reports" element={<ReportsCasesPage />} />
          <Route path="/audit" element={<AuditLogPage />} />
          <Route path="/cases/:caseId/reports" element={<CaseReportsPage />} />
          <Route path="*" element={<Navigate to="/devices" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}

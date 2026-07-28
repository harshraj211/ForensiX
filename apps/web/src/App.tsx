import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/AppShell";
import { AcquisitionPlanningPage } from "./features/acquisitions/AcquisitionPlanningPage";
import { AuditLogPage } from "./features/audit/AuditLogPage";
import { AuthBoundary } from "./features/auth/AuthBoundary";
import { CaseDetailPage } from "./features/cases/CaseDetailPage";
import { CasesPage } from "./features/cases/CasesPage";
import { CommandCenterPage } from "./features/cases/CommandCenterPage";
import { DeviceDetectionPage } from "./features/devices/DeviceDetectionPage";
import { ArtifactBrowserPage } from "./features/artifacts/ArtifactBrowserPage";
import { EvidenceCasesPage, EvidenceExplorerPage } from "./features/evidence/EvidenceExplorerPage";
import { CorrelationGraphPage } from "./features/evidence/CorrelationGraphPage";
import { TimelinePage } from "./features/evidence/TimelinePage";
import { EvidenceTwinPage } from "./features/evidence-twin/EvidenceTwinPage";
import { LandingPage } from "./features/marketing/LandingPage";
import { CaseReportsPage, ReportsCasesPage } from "./features/reports/ReportsPage";
import { ValidationDashboardPage } from "./features/validation/ValidationDashboardPage";
import { MediaMapPage } from "./features/evidence/MediaMapPage";
import { ArtifactSearchPage } from "./features/evidence/ArtifactSearchPage";
import { KeyEvidencePage } from "./features/evidence/KeyEvidencePage";
import { InvestigationStoryboardPage } from "./features/evidence/InvestigationStoryboardPage";

export function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route element={<AuthBoundary />}>
        <Route element={<AppShell />}>
          <Route path="/devices" element={<DeviceDetectionPage />} />
          <Route path="/cases" element={<CasesPage />} />
          <Route path="/cases/:caseId" element={<CaseDetailPage />} />
          <Route path="/cases/:caseId/command-center" element={<CommandCenterPage />} />
          <Route path="/cases/:caseId/devices" element={<DeviceDetectionPage />} />
          <Route path="/cases/:caseId/acquisitions" element={<AcquisitionPlanningPage />} />
          <Route path="/cases/:caseId/evidence" element={<EvidenceExplorerPage />} />
          <Route path="/cases/:caseId/artifacts" element={<ArtifactBrowserPage />} />
          <Route path="/cases/:caseId/media-map" element={<MediaMapPage />} />
          <Route path="/cases/:caseId/artifact-search" element={<ArtifactSearchPage />} />
          <Route path="/cases/:caseId/key-evidence" element={<KeyEvidencePage />} />
          <Route path="/cases/:caseId/storyboard" element={<InvestigationStoryboardPage />} />
          <Route path="/cases/:caseId/evidence-twin" element={<EvidenceTwinPage />} />
          <Route path="/cases/:caseId/timeline" element={<TimelinePage />} />
          <Route path="/cases/:caseId/correlations" element={<CorrelationGraphPage />} />
          <Route path="/evidence" element={<EvidenceCasesPage />} />
          <Route path="/reports" element={<ReportsCasesPage />} />
          <Route path="/audit" element={<AuditLogPage />} />
          <Route path="/validation" element={<ValidationDashboardPage />} />
          <Route path="/cases/:caseId/reports" element={<CaseReportsPage />} />
          <Route path="*" element={<Navigate to="/devices" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}

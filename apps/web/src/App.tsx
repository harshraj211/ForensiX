import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/AppShell";
import { AuthBoundary } from "./features/auth/AuthBoundary";
import { DeviceDetectionPage } from "./features/devices/DeviceDetectionPage";

export function App() {
  return (
    <Routes>
      <Route element={<AuthBoundary />}>
        <Route element={<AppShell />}>
          <Route path="/devices" element={<DeviceDetectionPage />} />
          <Route path="*" element={<Navigate to="/devices" replace />} />
        </Route>
      </Route>
    </Routes>
  );
}

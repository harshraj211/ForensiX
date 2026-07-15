import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/AppShell";
import { DeviceDetectionPage } from "./features/devices/DeviceDetectionPage";

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/devices" element={<DeviceDetectionPage />} />
        <Route path="*" element={<Navigate to="/devices" replace />} />
      </Route>
    </Routes>
  );
}

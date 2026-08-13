import { Navigate, Route, Routes } from "react-router-dom";
import LoginPage from "./pages/LoginPage";
import UnlockPage from "./pages/UnlockPage";
import InviteAcceptPage from "./pages/InviteAcceptPage";
import ClientsDashboardPage from "./pages/ClientsDashboardPage";
import VaultUnlockGate from "./components/VaultUnlockGate";

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/unlock" element={<UnlockPage />} />
      <Route path="/invite/:token" element={<InviteAcceptPage />} />
      <Route
        path="/clients"
        element={
          <VaultUnlockGate>
            <ClientsDashboardPage />
          </VaultUnlockGate>
        }
      />
      <Route path="/" element={<Navigate to="/clients" replace />} />
      <Route path="*" element={<Navigate to="/clients" replace />} />
    </Routes>
  );
}

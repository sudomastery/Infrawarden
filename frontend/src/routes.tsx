import { Navigate, Route, Routes } from "react-router-dom";
import LoginPage from "./pages/LoginPage";
import UnlockPage from "./pages/UnlockPage";
import InviteAcceptPage from "./pages/InviteAcceptPage";
import ClientsDashboardPage from "./pages/ClientsDashboardPage";
import ClientDetailPage from "./pages/ClientDetailPage";
import ClientAccessPage from "./pages/ClientAccessPage";
import ResourceDetailPage from "./pages/ResourceDetailPage";
import AdminUsersPage from "./pages/AdminUsersPage";
import VaultUnlockGate from "./components/VaultUnlockGate";
import AdminRouteGate from "./components/AdminRouteGate";

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
      <Route
        path="/clients/:clientId"
        element={
          <VaultUnlockGate>
            <ClientDetailPage />
          </VaultUnlockGate>
        }
      />
      <Route
        path="/clients/:clientId/access"
        element={
          <VaultUnlockGate>
            <ClientAccessPage />
          </VaultUnlockGate>
        }
      />
      <Route
        path="/clients/:clientId/resources/:resourceId"
        element={
          <VaultUnlockGate>
            <ResourceDetailPage />
          </VaultUnlockGate>
        }
      />
      <Route
        path="/admin/users"
        element={
          <VaultUnlockGate>
            <AdminRouteGate>
              <AdminUsersPage />
            </AdminRouteGate>
          </VaultUnlockGate>
        }
      />
      <Route path="/" element={<Navigate to="/clients" replace />} />
      <Route path="*" element={<Navigate to="/clients" replace />} />
    </Routes>
  );
}

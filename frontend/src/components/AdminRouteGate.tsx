import { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useVaultStore } from "../store/vaultStore";

export default function AdminRouteGate({ children }: { children: ReactNode }) {
  const currentUser = useVaultStore((s) => s.currentUser);
  if (currentUser?.role !== "admin") {
    return <Navigate to="/clients" replace />;
  }
  return <>{children}</>;
}

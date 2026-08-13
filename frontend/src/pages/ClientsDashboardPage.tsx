import { useVaultStore } from "../store/vaultStore";

export default function ClientsDashboardPage() {
  const currentUser = useVaultStore((s) => s.currentUser);

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-4">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-primary-600 text-sm font-bold text-white">
            IW
          </div>
          <span className="text-lg font-semibold text-gray-900">Infrawarden</span>
          {currentUser?.role === "admin" && (
            <span className="ml-1 rounded bg-primary-100 px-2 py-0.5 text-xs font-medium text-primary-700">
              superadmin
            </span>
          )}
          <span className="ml-auto text-sm text-gray-500">{currentUser?.email}</span>
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-6 py-12 text-center">
        <p className="text-sm text-gray-500">
          No clients yet. Client creation, credential resources, and sharing land in the next
          milestone.
        </p>
      </main>
    </div>
  );
}

import { useEffect, useState } from "react";
import { checkHealth } from "./lib/api";

type BackendStatus = "checking" | "ok" | "unreachable";

export default function App() {
  const [status, setStatus] = useState<BackendStatus>("checking");

  useEffect(() => {
    checkHealth()
      .then(() => setStatus("ok"))
      .catch(() => setStatus("unreachable"));
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50">
      <div className="w-full max-w-sm rounded-lg border border-gray-200 bg-white p-8 shadow-sm">
        <div className="mb-6 flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-primary-600 text-sm font-bold text-white">
            IW
          </div>
          <span className="text-lg font-semibold text-gray-900">Infrawarden</span>
        </div>
        <p className="text-sm text-gray-600">
          Backend status:{" "}
          <span
            className={
              status === "ok"
                ? "font-medium text-success-700"
                : status === "unreachable"
                  ? "font-medium text-danger-700"
                  : "font-medium text-gray-400"
            }
          >
            {status}
          </span>
        </p>
      </div>
    </div>
  );
}

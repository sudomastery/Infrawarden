import { useVaultStore } from "../store/vaultStore";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init: RequestInit = {}, auth = false): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(init.headers as Record<string, string>) };
  if (auth) {
    const token = useVaultStore.getState().accessToken;
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new ApiError(response.status, body.detail ?? `Request failed: ${response.status}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json();
}

export async function checkHealth(): Promise<{ status: string }> {
  return request("/api/v1/health");
}

export interface PreloginResponse {
  kdf_salt: string;
  kdf_ops_limit: number;
  kdf_mem_limit: number;
}

export async function prelogin(email: string): Promise<PreloginResponse> {
  return request("/api/v1/auth/prelogin", { method: "POST", body: JSON.stringify({ email }) });
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export async function login(email: string, authHash: string): Promise<TokenPair> {
  return request("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ email, auth_hash: authHash }) });
}

export interface InvitePublic {
  email: string;
  role: "admin" | "user";
  expires_at: string;
}

export async function getInvite(token: string): Promise<InvitePublic> {
  return request(`/api/v1/invites/${token}`);
}

export interface InviteAcceptPayload {
  public_key: string;
  wrapped_private_key: string;
  wrapped_private_key_nonce: string;
  kdf_salt: string;
  kdf_ops_limit: number;
  kdf_mem_limit: number;
  auth_hash: string;
}

export async function acceptInvite(token: string, payload: InviteAcceptPayload): Promise<TokenPair> {
  return request(`/api/v1/invites/${token}/accept`, { method: "POST", body: JSON.stringify(payload) });
}

export interface UserMeResponse {
  id: string;
  email: string;
  role: "admin" | "user";
  status: string;
  public_key: string;
  wrapped_private_key: string;
  wrapped_private_key_nonce: string;
  kdf_salt: string;
  kdf_ops_limit: number;
  kdf_mem_limit: number;
}

export async function getMe(): Promise<UserMeResponse> {
  return request("/api/v1/users/me", {}, true);
}

export { ApiError };

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

export interface UserPublicResponse {
  id: string;
  email: string;
  role: "admin" | "user";
  public_key: string;
}

export async function listUsers(): Promise<UserPublicResponse[]> {
  return request("/api/v1/users", {}, true);
}

export interface ClientGrantIn {
  user_id: string;
  wrapped_data_key: string;
}

export interface ClientResponse {
  id: string;
  name: string;
  description: string | null;
  created_by_user_id: string;
  wrapped_data_key: string;
  created_at: string;
  updated_at: string;
}

export async function createClient(
  name: string,
  description: string | null,
  grants: ClientGrantIn[],
): Promise<ClientResponse> {
  return request("/api/v1/clients", { method: "POST", body: JSON.stringify({ name, description, grants }) }, true);
}

export async function listClients(): Promise<ClientResponse[]> {
  return request("/api/v1/clients", {}, true);
}

export async function getClient(clientId: string): Promise<ClientResponse> {
  return request(`/api/v1/clients/${clientId}`, {}, true);
}

export type ResourceType = "host" | "vm" | "storage" | "network_device";

export interface ResourceVersionResponse {
  id: string;
  changed_by_user_id: string;
  ciphertext: string;
  nonce: string;
  created_at: string;
}

export interface ResourceResponse {
  id: string;
  client_id: string;
  resource_type: ResourceType;
  created_by_user_id: string;
  status: "active" | "pending_delete";
  latest_version_id: string;
  current_version: ResourceVersionResponse;
  has_pending_change: boolean;
  hidden: boolean;
  created_at: string;
  updated_at: string;
}

export async function createResource(
  clientId: string,
  resourceType: ResourceType,
  ciphertext: string,
  nonce: string,
): Promise<ResourceResponse> {
  return request(
    `/api/v1/clients/${clientId}/resources`,
    { method: "POST", body: JSON.stringify({ resource_type: resourceType, ciphertext, nonce }) },
    true,
  );
}

export async function listResources(clientId: string): Promise<ResourceResponse[]> {
  return request(`/api/v1/clients/${clientId}/resources`, {}, true);
}

export async function getResource(resourceId: string): Promise<ResourceResponse> {
  return request(`/api/v1/resources/${resourceId}`, {}, true);
}

export async function createResourceVersion(
  resourceId: string,
  ciphertext: string,
  nonce: string,
): Promise<ResourceResponse> {
  return request(`/api/v1/resources/${resourceId}/versions`, { method: "POST", body: JSON.stringify({ ciphertext, nonce }) }, true);
}

export async function listResourceVersions(resourceId: string): Promise<ResourceVersionResponse[]> {
  return request(`/api/v1/resources/${resourceId}/versions`, {}, true);
}

export async function acceptResourceChange(resourceId: string): Promise<void> {
  await request(`/api/v1/resources/${resourceId}/accept`, { method: "POST" }, true);
}

export async function ignoreResourceChange(resourceId: string): Promise<void> {
  await request(`/api/v1/resources/${resourceId}/ignore`, { method: "POST" }, true);
}

export async function deleteResource(resourceId: string): Promise<void> {
  await request(`/api/v1/resources/${resourceId}`, { method: "DELETE" }, true);
}

export async function hideResource(resourceId: string): Promise<void> {
  await request(`/api/v1/resources/${resourceId}/hide`, { method: "POST" }, true);
}

export async function unhideResource(resourceId: string): Promise<void> {
  await request(`/api/v1/resources/${resourceId}/unhide`, { method: "POST" }, true);
}

export interface ResourceNoteResponse {
  id: string;
  author_user_id: string;
  ciphertext: string;
  nonce: string;
  created_at: string;
}

export async function createResourceNote(
  resourceId: string,
  ciphertext: string,
  nonce: string,
): Promise<ResourceNoteResponse> {
  return request(`/api/v1/resources/${resourceId}/notes`, { method: "POST", body: JSON.stringify({ ciphertext, nonce }) }, true);
}

export async function listResourceNotes(resourceId: string): Promise<ResourceNoteResponse[]> {
  return request(`/api/v1/resources/${resourceId}/notes`, {}, true);
}

export interface AccessGrantResponse {
  user_id: string;
  email: string;
  granted_by_user_id: string;
  granted_at: string;
}

export async function shareClientAccess(
  clientId: string,
  userId: string,
  wrappedDataKey: string,
): Promise<AccessGrantResponse> {
  return request(
    `/api/v1/clients/${clientId}/access`,
    { method: "POST", body: JSON.stringify({ user_id: userId, wrapped_data_key: wrappedDataKey }) },
    true,
  );
}

export async function listClientAccess(clientId: string): Promise<AccessGrantResponse[]> {
  return request(`/api/v1/clients/${clientId}/access`, {}, true);
}

export async function revokeClientAccess(clientId: string, userId: string): Promise<void> {
  await request(`/api/v1/clients/${clientId}/access/${userId}`, { method: "DELETE" }, true);
}

export interface PromoteResponse {
  user_id: string;
  clients_needing_reconciliation: string[];
}

export async function promoteUser(userId: string): Promise<PromoteResponse> {
  return request(`/api/v1/admin/users/${userId}/promote`, { method: "POST" }, true);
}

export type TokenScopeType = "all_resources" | "selected_resources";

export interface TokenCreateBody {
  token_id: string;
  scope_type: TokenScopeType;
  resource_ids: string[] | null;
  ttl_seconds: number;
  token_hash: string;
  wrapped_data_key: string;
  wrapped_data_key_nonce: string;
}

export interface TokenCreatedResponse {
  id: string;
  scope_type: TokenScopeType;
  resource_ids: string[];
  expires_at: string;
}

export async function createToken(clientId: string, body: TokenCreateBody): Promise<TokenCreatedResponse> {
  return request(`/api/v1/clients/${clientId}/tokens`, { method: "POST", body: JSON.stringify(body) }, true);
}

export interface TokenResponse {
  id: string;
  created_by_user_id: string;
  scope_type: TokenScopeType;
  resource_ids: string[];
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export async function listTokens(clientId: string): Promise<TokenResponse[]> {
  return request(`/api/v1/clients/${clientId}/tokens`, {}, true);
}

export async function revokeToken(clientId: string, tokenId: string): Promise<void> {
  await request(`/api/v1/clients/${clientId}/tokens/${tokenId}`, { method: "DELETE" }, true);
}

export { ApiError };

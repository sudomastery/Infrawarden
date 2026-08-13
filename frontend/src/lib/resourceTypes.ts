import { ResourceType } from "./api";

export interface FieldSpec {
  key: string;
  label: string;
  kind: "text" | "secret" | "tags";
  placeholder?: string;
}

export interface ManagementInterface {
  label: string;
  ip: string;
  username: string;
  password: string;
}

// Fixed field templates for the four MVP resource types. A real infra dump (see
// project notes) showed hosts commonly have a separate BMC/iLO/iDRAC/XCC
// out-of-band management interface distinct from primary SSH access, so that's
// modeled as its own repeatable section rather than a flat field.
export const RESOURCE_TYPE_LABELS: Record<ResourceType, string> = {
  host: "Host",
  vm: "VM",
  storage: "Storage",
  network_device: "Network Device",
};

export const RESOURCE_TYPE_FIELDS: Record<ResourceType, FieldSpec[]> = {
  host: [
    { key: "name", label: "Name", kind: "text" },
    { key: "ip", label: "IP address", kind: "text" },
    { key: "hostname", label: "Hostname", kind: "text" },
    { key: "username", label: "Username", kind: "text" },
    { key: "secret", label: "Password / key", kind: "secret" },
    { key: "tags", label: "Tags (comma separated)", kind: "tags" },
  ],
  vm: [
    { key: "name", label: "Name", kind: "text" },
    { key: "hypervisor", label: "Hypervisor", kind: "text" },
    { key: "vm_id", label: "VM ID", kind: "text" },
    { key: "ip", label: "IP address", kind: "text" },
    { key: "username", label: "Username", kind: "text" },
    { key: "secret", label: "Password / key", kind: "secret" },
    { key: "tags", label: "Tags (comma separated)", kind: "tags" },
  ],
  storage: [
    { key: "name", label: "Name", kind: "text" },
    { key: "type", label: "Type (e.g. NetApp, S3)", kind: "text" },
    { key: "endpoint", label: "Endpoint", kind: "text" },
    { key: "access_key", label: "Access key / username", kind: "text" },
    { key: "secret_key", label: "Secret key / password", kind: "secret" },
    { key: "tags", label: "Tags (comma separated)", kind: "tags" },
  ],
  network_device: [
    { key: "name", label: "Name", kind: "text" },
    { key: "ip", label: "Management IP", kind: "text" },
    { key: "mgmt_user", label: "Management username", kind: "text" },
    { key: "mgmt_password", label: "Management password", kind: "secret" },
    { key: "vlan", label: "VLAN", kind: "text" },
    { key: "tags", label: "Tags (comma separated)", kind: "tags" },
  ],
};

export type ResourceFieldValues = Record<string, string> & {
  management_interfaces?: ManagementInterface[];
};

/** Looks up the human label for a field key within a resource type's template,
 * falling back to the raw key for anything not in the template (e.g. future
 * fields). Used so the read-only view and the edit form always agree - the edit
 * form already showed "IP address" via FieldSpec.label, the read view was
 * printing the raw "ip" key instead. */
export function fieldLabel(resourceType: ResourceType, key: string): string {
  return RESOURCE_TYPE_FIELDS[resourceType].find((f) => f.key === key)?.label ?? key;
}

export function isSecretField(resourceType: ResourceType, key: string): boolean {
  return RESOURCE_TYPE_FIELDS[resourceType].find((f) => f.key === key)?.kind === "secret";
}

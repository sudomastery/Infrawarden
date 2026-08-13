import { FormEvent, useState } from "react";
import { ResourceType } from "../lib/api";
import { RESOURCE_TYPE_FIELDS, ResourceFieldValues } from "../lib/resourceTypes";
import { FormInput, FormLabel, PrimaryButton } from "./form";

export default function ResourceTypeForm({
  resourceType,
  initialValues,
  submitLabel,
  onSubmit,
}: {
  resourceType: ResourceType;
  initialValues?: ResourceFieldValues;
  submitLabel: string;
  onSubmit: (values: ResourceFieldValues) => Promise<void>;
}) {
  const fields = RESOURCE_TYPE_FIELDS[resourceType];
  const [values, setValues] = useState<ResourceFieldValues>(initialValues ?? {});
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await onSubmit(values);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      {fields.map((field) => (
        <div key={field.key}>
          <FormLabel htmlFor={field.key}>{field.label}</FormLabel>
          <FormInput
            id={field.key}
            type={field.kind === "secret" ? "password" : "text"}
            value={values[field.key] ?? ""}
            onChange={(e) => setValues((v) => ({ ...v, [field.key]: e.target.value }))}
          />
        </div>
      ))}
      <PrimaryButton type="submit" disabled={submitting}>
        {submitting ? "Saving..." : submitLabel}
      </PrimaryButton>
    </form>
  );
}

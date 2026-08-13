import { InputHTMLAttributes, LabelHTMLAttributes, ButtonHTMLAttributes } from "react";

export function FormLabel(props: LabelHTMLAttributes<HTMLLabelElement>) {
  return <label {...props} className="mb-1 block text-sm font-medium text-gray-700" />;
}

export function FormInput(props: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className="mb-4 w-full rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 outline-none focus:border-primary-600 focus:ring-1 focus:ring-primary-600"
    />
  );
}

export function PrimaryButton(props: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className="w-full rounded bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-60"
    />
  );
}

export function ErrorText({ children }: { children: string | null }) {
  if (!children) return null;
  return <p className="mb-4 text-sm font-medium text-danger-700">{children}</p>;
}

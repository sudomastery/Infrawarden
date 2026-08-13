import { InputHTMLAttributes, LabelHTMLAttributes, ButtonHTMLAttributes, SelectHTMLAttributes } from "react";

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

/** Layout-neutral (no forced width/margin, unlike FormInput) since selects in
 * this app are mostly inline toolbar controls rather than stacked form fields -
 * pass className to add w-full/mb-4 for a stacked-form context. Shares
 * FormInput's border/padding/focus treatment either way, so tabbing to a
 * dropdown shows the same red focus ring as every text input, not the browser
 * default. */
export function FormSelect({ className = "", ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={`rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 outline-none focus:border-primary-600 focus:ring-1 focus:ring-primary-600 ${className}`}
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

/** Inline (not full-width) variant for toolbars/headers - same visual as
 * PrimaryButton, sized for sitting next to other controls rather than filling a
 * form column. */
export function InlineButton(props: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className="rounded bg-primary-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-primary-700 disabled:cursor-not-allowed disabled:opacity-60"
    />
  );
}

export function ErrorText({ children }: { children: string | null }) {
  if (!children) return null;
  return <p className="mb-4 text-sm font-medium text-danger-700">{children}</p>;
}

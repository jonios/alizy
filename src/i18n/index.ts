// UI translation. The English text is the key (gettext style): `t("Connect")`
// renders the Persian entry when Persian is selected, the English otherwise.
// `scripts/check-i18n.mjs` fails the build when a `t("…")`/`tk("…")` string
// has no Persian entry.
import { fa } from "./fa";

export type Lang = "en" | "fa";
export const LANGS: { value: Lang; label: string }[] = [
  { value: "en", label: "English" },
  { value: "fa", label: "فارسی" },
];

let current: Lang = "en";

export function lang(): Lang {
  return current;
}

/** Switch language and text direction. Callers re-render the tree. */
export function setLang(l: string | null | undefined) {
  current = l === "fa" ? "fa" : "en";
  const root = document.documentElement;
  root.lang = current;
  root.dir = current === "fa" ? "rtl" : "ltr";
}

type Vars = Record<string, string | number>;

/** Translate `s`; `{name}` placeholders are filled from `vars`. */
export function t(s: string, vars?: Vars): string {
  const out = current === "fa" ? (fa[s] ?? s) : s;
  return vars ? out.replace(/\{(\w+)\}/g, (m: string, k: string) => (k in vars ? String(vars[k]) : m)) : out;
}

/** Marks a string for translation where it is defined (tables, constants);
 * translate it with `t()` where it is shown. */
export function tk(s: string): string {
  return s;
}

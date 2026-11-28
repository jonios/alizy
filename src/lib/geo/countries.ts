// Country helpers for the map: names in the UI language, flags, and where
// the user is. Everything here is offline.
import countries from "i18n-iso-countries";
import { lang } from "../../i18n";
import { TZ_COUNTRY } from "./tzCountry";

// Square flags (flag-icons, MIT), bundled; only the URL strings load eagerly.
const FLAGS = import.meta.glob("/node_modules/flag-icons/flags/1x1/*.svg", {
  query: "?url",
  import: "default",
  eager: true,
}) as Record<string, string>;

export function flagUrl(cc: string | null | undefined): string | null {
  if (!cc) return null;
  return FLAGS[`/node_modules/flag-icons/flags/1x1/${cc.toLowerCase()}.svg`] ?? null;
}

const names = new Map<string, Intl.DisplayNames | null>();
export function countryName(cc: string | null | undefined): string | null {
  if (!cc) return null;
  const l = lang();
  if (!names.has(l)) {
    try {
      names.set(l, new Intl.DisplayNames([l], { type: "region" }));
    } catch {
      names.set(l, null);
    }
  }
  try {
    return names.get(l)?.of(cc.toUpperCase()) ?? cc.toUpperCase();
  } catch {
    return cc.toUpperCase();
  }
}

/** World-atlas features are keyed by ISO 3166-1 numeric ids; a few have none. */
const UNNUMBERED: Record<string, string> = { Kosovo: "XK" };
export function featureCountry(id: string | number | undefined, name: string | undefined): string | null {
  if (id != null && id !== "") return countries.numericToAlpha2(String(id).padStart(3, "0")) ?? null;
  return (name && UNNUMBERED[name]) || null;
}

/** The user's country, from the system time zone. */
export function homeCountry(): string | null {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return TZ_COUNTRY[tz] ?? null;
  } catch {
    return null;
  }
}

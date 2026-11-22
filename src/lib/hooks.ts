import { useEffect, useRef, useState } from "react";
import { nowSec } from "./format";

/** Current unix time in seconds, re-rendering every `intervalMs`. */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(nowSec);
  useEffect(() => {
    const t = window.setInterval(() => setNow(nowSec()), intervalMs);
    return () => window.clearInterval(t);
  }, [intervalMs]);
  return now;
}

/** Live result of a CSS media query. */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const mql = window.matchMedia(query);
    const onChange = () => setMatches(mql.matches);
    onChange();
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, [query]);
  return matches;
}

export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}

/** Calls `cb` every `ms` while enabled and the document is visible. */
export function useInterval(cb: () => void, ms: number, enabled = true): void {
  const ref = useRef(cb);
  ref.current = cb;
  useEffect(() => {
    if (!enabled) return;
    const t = window.setInterval(() => {
      if (document.visibilityState === "visible") ref.current();
    }, ms);
    return () => window.clearInterval(t);
  }, [ms, enabled]);
}

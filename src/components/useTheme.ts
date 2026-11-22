import { useEffect } from "react";
import { useSettings } from "../store/settings";

/** Applies settings.theme by toggling the `dark` class on <html>. Dark until settings load. */
export function useTheme() {
  const theme = useSettings((s) => s.settings?.theme ?? "dark");
  useEffect(() => {
    const root = document.documentElement;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const dark = theme === "dark" || (theme === "system" && mq.matches);
      root.classList.toggle("dark", dark);
    };
    apply();
    if (theme !== "system") return;
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, [theme]);
}

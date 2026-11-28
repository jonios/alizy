import { FileCode2, Globe2, Network, ScrollText, Settings, Split, type LucideIcon } from "lucide-react";
import { useLayoutEffect, useRef, useState } from "react";
import { useNav, type Screen } from "../store/nav";
import { useProfiles } from "../store/profiles";
import { cn } from "../lib/utils";
import { LogoMark } from "./Logo";
import { Tooltip } from "./ui/tooltip";
import { t, tk } from "../i18n";

const NAV: { id: Screen; label: string; icon: LucideIcon }[] = [
  { id: "dashboard", label: tk("Map"), icon: Globe2 },
  { id: "configurations", label: tk("Configs"), icon: FileCode2 },
  { id: "split", label: tk("Split Tunneling"), icon: Split },
  { id: "network", label: tk("Network"), icon: Network },
  { id: "general", label: tk("Settings"), icon: Settings },
  { id: "logs", label: tk("Logs"), icon: ScrollText },
];

/** Floating navigation, centred at the top of the element it is placed in.
 * It drops to icons only when that element is too narrow for the labels. */
export function Dock() {
  const screen = useNav((s) => s.screen);
  const go = useNav((s) => s.go);
  const count = useProfiles((s) => s.profiles.length);
  const nav = useRef<HTMLElement>(null);
  const [compact, setCompact] = useState(false);
  const refs = useRef(new Map<Screen, HTMLButtonElement>());
  const [pill, setPill] = useState<{ left: number; width: number } | null>(null);

  useLayoutEffect(() => {
    const host = nav.current?.parentElement;
    if (!host) return;
    const ro = new ResizeObserver(([e]) => setCompact(e.contentRect.width < 760));
    ro.observe(host);
    return () => ro.disconnect();
  }, []);

  useLayoutEffect(() => {
    const el = refs.current.get(screen);
    if (!el) return;
    const place = () => setPill({ left: el.offsetLeft, width: el.offsetWidth });
    place();
    const ro = new ResizeObserver(place);
    ro.observe(el);
    return () => ro.disconnect();
  }, [screen, compact, count]);

  return (
    <nav
      ref={nav}
      aria-label={t("Main")}
      className="absolute top-3 left-1/2 z-30 flex -translate-x-1/2 items-center gap-0.5 rounded-2xl border border-border bg-surface/80 p-1 shadow-card backdrop-blur-xl"
    >
      <span className="flex size-8 items-center justify-center" aria-hidden>
        <LogoMark className="size-5" />
      </span>
      <span className="mx-0.5 h-5 w-px bg-border" aria-hidden />
      <div className="relative flex items-center gap-0.5">
        {pill && (
          <span
            className="absolute inset-y-0 rounded-xl bg-surface-3 transition-[left,width] duration-250 ease-[cubic-bezier(0.3,0.7,0.2,1)]"
            style={{ left: pill.left, width: pill.width }}
            aria-hidden
          />
        )}
        {NAV.map(({ id, label: key, icon: Icon }) => {
          const label = t(key);
          const active = id === screen;
          const button = (
            <button
              key={id}
              ref={(el) => {
                if (el) refs.current.set(id, el);
                else refs.current.delete(id);
              }}
              type="button"
              onClick={() => go(id)}
              aria-current={active ? "page" : undefined}
              aria-label={compact ? label : undefined}
              className={cn(
                "relative flex h-8 items-center gap-2 rounded-xl text-[13px] font-medium whitespace-nowrap transition-colors focus-visible:outline-2 focus-visible:outline-ring",
                compact ? "w-9 justify-center" : "px-3",
                active ? "text-fg" : "text-muted hover:text-fg",
              )}
            >
              <Icon className={cn("size-[15px] shrink-0", active && "text-primary")} />
              {!compact && label}
              {!compact && id === "configurations" && count > 0 && <span className="text-[11px] text-faint tabular">{count}</span>}
            </button>
          );
          return compact ? (
            <Tooltip key={id} content={label} side="bottom">
              {button}
            </Tooltip>
          ) : (
            button
          );
        })}
      </div>
    </nav>
  );
}

import { useId } from "react";
import type { RatePoint } from "../../store/status";

/** Two-series area sparkline (download + upload rate), no chart library. */
export function Sparkline({ points, height = 64, capacity = 60 }: { points: RatePoint[]; height?: number; capacity?: number }) {
  const id = useId().replace(/:/g, "");
  const W = 300;
  const H = height;
  const max = Math.max(1024, ...points.map((p) => Math.max(p.rx, p.tx))) * 1.15;
  const step = W / (capacity - 1);
  const offset = capacity - points.length;

  const path = (key: "rx" | "tx") => {
    if (points.length < 2) return { line: "", area: "" };
    const coords = points.map((p, i) => [(offset + i) * step, H - (p[key] / max) * (H - 4) - 2] as const);
    const line = coords.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
    const area = `${line} L${coords[coords.length - 1][0].toFixed(1)},${H} L${coords[0][0].toFixed(1)},${H} Z`;
    return { line, area };
  };
  const rx = path("rx");
  const tx = path("tx");

  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="h-full w-full" role="img" aria-label="Throughput over the last minute">
      <defs>
        <linearGradient id={`rx-${id}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="var(--primary)" stopOpacity="0.35" />
          <stop offset="1" stopColor="var(--primary)" stopOpacity="0" />
        </linearGradient>
        <linearGradient id={`tx-${id}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="var(--success)" stopOpacity="0.25" />
          <stop offset="1" stopColor="var(--success)" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1="0" x2={W} y1={H * f} y2={H * f} stroke="var(--border)" strokeWidth="1" strokeDasharray="2 4" vectorEffect="non-scaling-stroke" />
      ))}
      {points.length >= 2 && (
        <>
          <path d={rx.area} fill={`url(#rx-${id})`} />
          <path d={tx.area} fill={`url(#tx-${id})`} />
          <path d={tx.line} fill="none" stroke="var(--success)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
          <path d={rx.line} fill="none" stroke="var(--primary)" strokeWidth="1.75" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
        </>
      )}
    </svg>
  );
}

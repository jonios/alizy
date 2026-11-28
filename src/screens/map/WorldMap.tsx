import { geoArea, geoCentroid, geoNaturalEarth1, geoPath, type GeoProjection } from "d3-geo";
import { feature } from "topojson-client";
import type { Feature, FeatureCollection, MultiPolygon, Polygon } from "geojson";
import type { GeometryCollection, Topology } from "topojson-specification";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import atlasUrl from "world-atlas/countries-50m.json?url";
import { countryName, featureCountry } from "../../lib/geo/countries";
import { Flag } from "../../components/Flag";
import { cn } from "../../lib/utils";
import { t } from "../../i18n";

type Land = Feature<Polygon | MultiPolygon, { name?: string }>;
interface Country {
  cc: string | null;
  f: Land;
  /** lon/lat centre of the country's largest polygon, where its pin sits */
  centre: [number, number];
}

const STEP = 7; // px between land dots

let atlas: Promise<Country[]> | null = null;
function loadAtlas(): Promise<Country[]> {
  atlas ??= fetch(atlasUrl)
    .then((r) => r.json() as Promise<Topology<{ countries: GeometryCollection<{ name?: string }> }>>)
    .then((topo) => {
      const fc = feature(topo, topo.objects.countries) as unknown as FeatureCollection<Polygon | MultiPolygon, { name?: string }>;
      return fc.features
        .filter((f) => f.id !== "010") // Antarctica
        .map((f) => {
          const polys: Feature<Polygon>[] =
            f.geometry.type === "Polygon"
              ? [f as Feature<Polygon>]
              : f.geometry.coordinates.map((coordinates) => ({ type: "Feature", properties: {}, geometry: { type: "Polygon", coordinates } }));
          let biggest = polys[0];
          for (const p of polys) if (geoArea(p) > geoArea(biggest)) biggest = p;
          return { cc: featureCountry(f.id, f.properties?.name), f, centre: geoCentroid(biggest) };
        });
    });
  return atlas;
}

export interface MapPin {
  cc: string;
  count: number;
}

interface Props {
  /** countries that have configs, with how many each */
  pins: MapPin[];
  selected: string | null;
  live: string | null;
  home: string | null;
  connected: boolean;
  onPick: (cc: string, at: { x: number; y: number }) => void;
  /** reserve this much space on the right (the detail panel overlaps the map) */
  className?: string;
}

/** Dotted world map. Countries are painted once into a hidden canvas in
 * index-encoded colours; the visible map samples it on a grid (one dot per
 * land cell) and the same lookup answers hover and click. */
export function WorldMap({ pins, selected, live, home, connected, onPick, className }: Props) {
  const box = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [land, setLand] = useState<Country[] | null>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [hover, setHover] = useState<{ cc: string; x: number; y: number } | null>(null);
  const [theme, setTheme] = useState(0);

  useEffect(() => {
    let live = true;
    loadAtlas().then((c) => live && setLand(c)).catch((e) => console.warn("map data unavailable:", e));
    return () => {
      live = false;
    };
  }, []);

  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setSize({ w: Math.round(e.contentRect.width), h: Math.round(e.contentRect.height) }));
    ro.observe(el);
    // Repaint when the theme flips (the dots read their colours from CSS).
    const mo = new MutationObserver(() => setTheme((n) => n + 1));
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => {
      ro.disconnect();
      mo.disconnect();
    };
  }, []);

  // Projection, hit-test lookup and dot cells: only on resize.
  const geo = useMemo(() => {
    if (!land || size.w < 50 || size.h < 50) return null;
    const { w, h } = size;
    const projection: GeoProjection = geoNaturalEarth1().fitExtent(
      [
        [24, 72],
        [w - 24, h - 56],
      ],
      { type: "FeatureCollection", features: land.map((c) => c.f) },
    );
    const hidden = document.createElement("canvas");
    hidden.width = w;
    hidden.height = h;
    const hctx = hidden.getContext("2d", { willReadFrequently: true });
    if (!hctx) return null;
    const path = geoPath(projection, hctx);
    land.forEach((c, i) => {
      hctx.beginPath();
      path(c.f);
      hctx.fillStyle = `rgb(${(i + 1) & 255},${(i + 1) >> 8},0)`;
      hctx.fill();
    });
    const data = hctx.getImageData(0, 0, w, h).data;
    const at = (x: number, y: number): Country | null => {
      x |= 0;
      y |= 0;
      if (x < 0 || y < 0 || x >= w || y >= h) return null;
      const o = (y * w + x) * 4;
      return data[o + 3] > 200 ? (land[data[o] + (data[o + 1] << 8) - 1] ?? null) : null;
    };
    const cells: { x: number; y: number; cc: string | null }[] = [];
    for (let y = STEP / 2; y < h; y += STEP)
      for (let x = STEP / 2; x < w; x += STEP) {
        const c = at(x, y);
        if (c) cells.push({ x, y, cc: c.cc });
      }
    const centre = new Map<string, [number, number]>();
    for (const c of land) if (c.cc && !centre.has(c.cc)) centre.set(c.cc, c.centre);
    return { projection, at, cells, centre };
  }, [land, size]);

  const pinned = useMemo(() => new Set(pins.map((p) => p.cc)), [pins]);

  // Paint the dots.
  useEffect(() => {
    const cv = canvas.current;
    if (!cv || !geo) return;
    const dpr = window.devicePixelRatio || 1;
    cv.width = size.w * dpr;
    cv.height = size.h * dpr;
    const ctx = cv.getContext("2d");
    if (!ctx) return;
    const css = getComputedStyle(cv);
    const v = (n: string) => css.getPropertyValue(n).trim();
    const base = v("--surface-3");
    const has = v("--border-strong");
    const primary = v("--primary");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, size.w, size.h);
    for (const c of geo.cells) {
      let col = base;
      let r = 1.5;
      let a = 1;
      if (c.cc && pinned.has(c.cc)) {
        col = has;
        r = 1.8;
      }
      if (c.cc && c.cc === hover?.cc && pinned.has(c.cc)) {
        col = primary;
        a = 0.55;
        r = 2;
      }
      if (c.cc && c.cc === selected) {
        col = primary;
        a = c.cc === live ? 1 : 0.85;
        r = 2.1;
      }
      ctx.globalAlpha = a;
      ctx.fillStyle = col;
      ctx.beginPath();
      ctx.arc(c.x, c.y, r, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;
  }, [geo, size, pinned, hover?.cc, selected, live, theme]);

  // Pin positions, pushed apart where countries are small and close (Europe).
  const pinPos = useMemo(() => {
    const out = new Map<string, [number, number]>();
    if (!geo) return out;
    const pts = pins
      .map((p) => {
        const c = geo.centre.get(p.cc);
        const xy = c && geo.projection(c);
        return xy ? { cc: p.cc, x: xy[0], y: xy[1] } : null;
      })
      .filter((p): p is { cc: string; x: number; y: number } => p !== null);
    const MIN = 26;
    for (let k = 0; k < 40; k++)
      for (const a of pts)
        for (const b of pts) {
          if (a === b) continue;
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const d = Math.hypot(dx, dy) || 1;
          if (d < MIN) {
            const m = (MIN - d) / 2 / d;
            a.x -= dx * m;
            a.y -= dy * m;
            b.x += dx * m;
            b.y += dy * m;
          }
        }
    for (const p of pts) out.set(p.cc, [p.x, p.y]);
    return out;
  }, [geo, pins]);

  const homeXY = useMemo(() => {
    if (!geo || !home) return null;
    const c = geo.centre.get(home);
    return c ? geo.projection(c) : null;
  }, [geo, home]);

  const route = useMemo(() => {
    const b = selected ? pinPos.get(selected) : null;
    if (!homeXY || !b || selected === home) return null;
    const [ax, ay] = homeXY;
    const [bx, by] = b;
    const d = Math.hypot(bx - ax, by - ay);
    return `M${ax},${ay} Q${(ax + bx) / 2},${(ay + by) / 2 - d * 0.32} ${bx},${by}`;
  }, [homeXY, pinPos, selected, home]);

  const routeLive = connected && selected !== null && selected === live;

  const onMove = (e: React.MouseEvent) => {
    const r = box.current!.getBoundingClientRect();
    const c = geo?.at(e.clientX - r.left, e.clientY - r.top);
    const cc = c?.cc && pinned.has(c.cc) ? c.cc : null;
    setHover(cc ? { cc, x: e.clientX - r.left, y: e.clientY - r.top } : null);
  };
  const onClick = (e: React.MouseEvent) => {
    const r = box.current!.getBoundingClientRect();
    const c = geo?.at(e.clientX - r.left, e.clientY - r.top);
    if (c?.cc && pinned.has(c.cc)) onPick(c.cc, { x: e.clientX - r.left, y: e.clientY - r.top });
  };

  const hovered = hover ? pins.find((p) => p.cc === hover.cc) : null;

  return (
    <div ref={box} className={cn("absolute inset-0 overflow-hidden", className)}>
      <canvas
        ref={canvas}
        className={cn("absolute inset-0 size-full transition-opacity duration-500", geo ? "opacity-100" : "opacity-0", hover && "cursor-pointer")}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
        onClick={onClick}
        role="img"
        aria-label={t("World map of your configurations")}
      />
      {geo && (
        <svg className="pointer-events-none absolute inset-0 size-full" aria-hidden>
          <defs>
            <linearGradient id="map-route" gradientUnits="userSpaceOnUse" x1={homeXY?.[0]} y1={homeXY?.[1]} x2={selected ? pinPos.get(selected)?.[0] : 0} y2={selected ? pinPos.get(selected)?.[1] : 0}>
              <stop offset="0" stopColor="var(--fg)" stopOpacity="0.35" />
              <stop offset="1" stopColor="var(--primary)" />
            </linearGradient>
          </defs>
          {route && (
            <>
              <path
                d={route}
                fill="none"
                stroke="url(#map-route)"
                strokeWidth={routeLive ? 1.8 : 1.5}
                strokeLinecap="round"
                strokeDasharray={routeLive ? undefined : "2 6"}
              />
              {routeLive && (
                <circle r="2.6" fill="var(--fg)" style={{ filter: "drop-shadow(0 0 5px var(--primary))" }}>
                  <animateMotion dur="1.6s" repeatCount="indefinite" path={route} />
                </circle>
              )}
            </>
          )}
          {homeXY && (
            <g transform={`translate(${homeXY[0]},${homeXY[1]})`}>
              <circle r="8" fill="none" stroke="var(--fg)" strokeOpacity="0.3" />
              <circle r="3.5" fill="var(--fg)" />
              <text x="12" y="4" fill="var(--muted)" fontSize="10" fontWeight="600" letterSpacing="0.6">
                {t("YOU")}
              </text>
            </g>
          )}
          {pins.map((p) => {
            const xy = pinPos.get(p.cc);
            if (!xy) return null;
            const active = p.cc === selected;
            const isLive = p.cc === live && connected;
            return (
              <g key={p.cc} transform={`translate(${xy[0]},${xy[1]})`} className="pointer-events-auto cursor-pointer" onClick={(e) => {
                const r = box.current!.getBoundingClientRect();
                onPick(p.cc, { x: e.clientX - r.left, y: e.clientY - r.top });
              }}
                onMouseEnter={() => setHover({ cc: p.cc, x: xy[0], y: xy[1] + 6 })}
                onMouseLeave={() => setHover(null)}
              >
                {active && <circle r="18" fill="var(--primary)" opacity="0.14" />}
                {isLive && (
                  <circle r="12" fill="none" stroke="var(--primary)" className="map-ripple" />
                )}
                <circle r="11" fill={active ? "var(--primary)" : "var(--surface)"} stroke="var(--primary)" strokeWidth="1.5" />
                <text textAnchor="middle" dominantBaseline="central" fontSize="11" fontWeight="600" fill={active ? "var(--primary-fg)" : "var(--fg)"}>
                  {p.count}
                </text>
              </g>
            );
          })}
        </svg>
      )}
      {hover && hovered && (
        <div
          className="pointer-events-none absolute z-10 flex items-center gap-2 rounded-lg border border-border bg-surface/90 py-1.5 ps-1.5 pe-2.5 text-xs whitespace-nowrap text-fg shadow-card backdrop-blur"
          style={{ left: hover.x + 14, top: hover.y + 14 }}
        >
          <Flag cc={hovered.cc} className="size-5" />
          {countryName(hovered.cc)}
          <span className="text-faint">{hovered.count === 1 ? t("1 config") : t("{n} configs", { n: hovered.count })}</span>
        </div>
      )}
    </div>
  );
}

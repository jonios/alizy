import { useId } from "react";

export function LogoMark({ className }: { className?: string }) {
  const id = `alizy-g-${useId().replace(/:/g, "")}`;
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <defs>
        <linearGradient id={id} x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#60a5fa" />
          <stop offset="1" stopColor="#1d4ed8" />
        </linearGradient>
      </defs>
      <rect x="1" y="1" width="30" height="30" rx="9" fill={`url(#${id})`} />
      <path
        d="M16 7.5 9.5 23.5h3.4l1.3-3.4h3.6l1.3 3.4h3.4L16 7.5Zm0 6.6 1.1 3.2h-2.2l1.1-3.2Z"
        fill="#fff"
        fillOpacity=".95"
      />
    </svg>
  );
}

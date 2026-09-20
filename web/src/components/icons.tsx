// Small inline-SVG icon set for the case navbar (NavGroups in CaseView.tsx)
// and its per-tab entries. Kept hand-rolled rather than pulling in an icon
// library -- this is the only place in the app that needs icons, so a
// dependency wasn't worth it. Every icon shares the same 16x16 stroke style
// so they sit flush at any nav width.
import type { ReactNode, SVGProps } from 'react'

type IconProps = SVGProps<SVGSVGElement>

function base(props: IconProps, children: ReactNode) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      width="1em"
      height="1em"
      {...props}
    >
      {children}
    </svg>
  )
}

export const IconFolder = (p: IconProps) =>
  base(p, <path d="M3 7a1 1 0 0 1 1-1h4.5l2 2H20a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V7Z" />)

export const IconRadar = (p: IconProps) =>
  base(
    p,
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 12 6 8" />
      <path d="M12 4v3" />
      <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
    </>,
  )

export const IconScan = (p: IconProps) =>
  base(
    p,
    <>
      <path d="M4 8V5a1 1 0 0 1 1-1h3" />
      <path d="M16 4h3a1 1 0 0 1 1 1v3" />
      <path d="M20 16v3a1 1 0 0 1-1 1h-3" />
      <path d="M8 20H5a1 1 0 0 1-1-1v-3" />
      <path d="M4 12h16" />
    </>,
  )

export const IconWrench = (p: IconProps) =>
  base(
    p,
    <path d="M14.5 6.5a4 4 0 0 0-5.4 4.9L4 16.5V20h3.5l5.1-5.1a4 4 0 0 0 4.9-5.4l-2.6 2.6-2-2 2.6-2.6Z" />,
  )

export const IconChart = (p: IconProps) =>
  base(
    p,
    <>
      <path d="M4 20V10" />
      <path d="M12 20V4" />
      <path d="M20 20v-7" />
    </>,
  )

export const IconTarget = (p: IconProps) =>
  base(
    p,
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="4" />
      <circle cx="12" cy="12" r="0.6" fill="currentColor" stroke="none" />
    </>,
  )

export const IconKey = (p: IconProps) =>
  base(
    p,
    <>
      <circle cx="8" cy="15" r="3.5" />
      <path d="M10.4 12.6 18 5" />
      <path d="M15.5 7.5 18 10" />
      <path d="M18.5 6.5 21 9" />
    </>,
  )

export const IconFolderSearch = (p: IconProps) =>
  base(
    p,
    <>
      <path d="M3 7a1 1 0 0 1 1-1h4.5l2 2H20a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V7Z" />
      <circle cx="12.5" cy="13.5" r="2" />
      <path d="m15 16 1.5 1.5" />
    </>,
  )

export const IconSitemap = (p: IconProps) =>
  base(
    p,
    <>
      <rect x="9.5" y="3" width="5" height="4" rx="1" />
      <rect x="3" y="17" width="5" height="4" rx="1" />
      <rect x="16" y="17" width="5" height="4" rx="1" />
      <path d="M12 7v4M12 11H5.5v6M12 11h6.5v6" />
    </>,
  )

export const IconServer = (p: IconProps) =>
  base(
    p,
    <>
      <rect x="3" y="4" width="18" height="7" rx="1.5" />
      <rect x="3" y="13" width="18" height="7" rx="1.5" />
      <path d="M7 7.5h.01M7 16.5h.01" />
    </>,
  )

export const IconLightning = (p: IconProps) =>
  base(p, <path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z" />)

export const IconShieldKey = (p: IconProps) =>
  base(
    p,
    <>
      <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3Z" />
      <circle cx="10.5" cy="12" r="1.8" />
      <path d="M12.3 12h3.2M14 12v1.5" />
    </>,
  )

export const IconCrosshair = (p: IconProps) =>
  base(
    p,
    <>
      <circle cx="12" cy="12" r="7" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
    </>,
  )

export const IconLock = (p: IconProps) =>
  base(
    p,
    <>
      <rect x="5" y="11" width="14" height="9" rx="1.5" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </>,
  )

export const IconRepeat = (p: IconProps) =>
  base(
    p,
    <>
      <path d="M4 12a7 7 0 0 1 11.5-5.3L18 9" />
      <path d="M18 5v4h-4" />
      <path d="M20 12a7 7 0 0 1-11.5 5.3L6 15" />
      <path d="M6 19v-4h4" />
    </>,
  )

export const IconWarning = (p: IconProps) =>
  base(
    p,
    <>
      <path d="M12 3 2 20h20L12 3Z" />
      <path d="M12 10v4M12 17h.01" />
    </>,
  )

export const IconActivity = (p: IconProps) =>
  base(p, <path d="M3 12h4l2-7 4 14 2-7h6" />)

export const IconGlobe = (p: IconProps) =>
  base(
    p,
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M4 12h16M12 4a13 13 0 0 1 0 16 13 13 0 0 1 0-16Z" />
    </>,
  )

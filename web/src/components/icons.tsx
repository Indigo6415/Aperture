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

export const IconUnlock = (p: IconProps) =>
  base(
    p,
    <>
      <rect x="5" y="11" width="14" height="9" rx="1.5" />
      <path d="M8 11V7a4 4 0 0 1 7.5-1.8" />
    </>,
  )

export const IconGlobe = (p: IconProps) =>
  base(
    p,
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M4 12h16M12 4a13 13 0 0 1 0 16 13 13 0 0 1 0-16Z" />
    </>,
  )

export const IconBug = (p: IconProps) =>
  base(
    p,
    <>
      <rect x="8" y="8" width="8" height="10" rx="4" />
      <path d="M12 8V6M9.5 8.5 7 6M14.5 8.5 17 6M4 12h4M16 12h4M5 17l3-1.5M19 17l-3-1.5M5 8l3 1.5M19 8l-3 1.5" />
    </>,
  )

// IconMailQuestion is an envelope with a "?" badge -- the Password Reset
// Scanner tab's icon, standing in for a "forgot password" request-an-email
// flow. The "?" is a filled <text> glyph rather than a hand-drawn path,
// unlike every other icon here, since a stroked question-mark curve at this
// size reads as illegible noise.
export const IconMailQuestion = (p: IconProps) =>
  base(
    p,
    <>
      <rect x="2.5" y="5" width="16" height="13" rx="2" />
      <path d="m2.5 6.5 8 5.5 8-5.5" />
      <circle cx="18.5" cy="16.5" r="4.5" fill="currentColor" stroke="none" />
      <text x="18.5" y="19.3" fontSize="6.5" fontWeight="700" textAnchor="middle" fill="#171717" stroke="none">
        ?
      </text>
    </>,
  )

// IconBraces is a pair of curly braces -- the GraphQL Enumeration tab's
// icon, standing in for a query/schema document the way "{}" reads in any
// GraphQL client or spec doc.
export const IconBraces = (p: IconProps) =>
  base(
    p,
    <path d="M8 4c-2 0-2.5 1-2.5 2.5v2c0 1.2-.5 2-1.5 2.5 1 .5 1.5 1.3 1.5 2.5v2C5.5 19 6 20 8 20M16 4c2 0 2.5 1 2.5 2.5v2c0 1.2.5 2 1.5 2.5-1 .5-1.5 1.3-1.5 2.5v2c0 1.5-.5 2.5-2.5 2.5" />,
  )

// IconSend is a paper airplane -- the Tester tab's icon, standing in for
// "send this request" the way a chat/mail app's send button does.
export const IconSend = (p: IconProps) =>
  base(p, <path d="M21 3 3 10.5l7.5 2.99L13.5 21 21 3Zm0 0-10.49 10.49" />)

// IconCookie is a round cookie with a few "chips" -- the Cookie Vault tab's
// icon.
export const IconCookie = (p: IconProps) =>
  base(
    p,
    <>
      <path d="M20.5 11.5a8.5 8.5 0 1 1-9-9c-.2 1.3.6 2.6 1.9 2.9a2.3 2.3 0 0 0 2.8-1.6c1.4.9 2.3 2.4 2.4 4.1a2.1 2.1 0 1 0 1.9 3.6Z" />
      <circle cx="8.5" cy="11.5" r="1" fill="currentColor" stroke="none" />
      <circle cx="12" cy="16" r="1" fill="currentColor" stroke="none" />
      <circle cx="15.5" cy="12.5" r="1" fill="currentColor" stroke="none" />
    </>,
  )

// IconCode is a "</>" bracket glyph -- the XSS Scanner tab's icon, standing
// in for injected markup/script the way IconBraces stands in for GraphQL's
// own query syntax.
export const IconCode = (p: IconProps) => base(p, <path d="M9.5 6 4 12l5.5 6M14.5 6 20 12l-5.5 6" />)

// IconGitBranch is two commit nodes joined by a branch line -- the Git Dump
// tab's icon, standing in for a repository's history.
export const IconGitBranch = (p: IconProps) =>
  base(
    p,
    <>
      <circle cx="6" cy="5" r="2" />
      <circle cx="6" cy="19" r="2" />
      <circle cx="18" cy="7" r="2" />
      <path d="M6 7v10M18 9c0 5-7 4-12 8" />
    </>,
  )

// IconRouteTree is a root node branching into leaves -- the API Enumerator
// tab's icon, standing in for the grouped route tree the tool's own
// results view renders.
export const IconRouteTree = (p: IconProps) =>
  base(
    p,
    <>
      <circle cx="5" cy="6" r="1.6" />
      <path d="M5 7.6V12M5 12h5M5 12v5.4" />
      <circle cx="12" cy="12" r="1.6" />
      <path d="M12 13.6V17" />
      <circle cx="19" cy="17.5" r="1.6" />
      <circle cx="12" cy="18.6" r="1.6" />
    </>,
  )

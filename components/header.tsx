"use client"

import Link from "next/link"
import { Github } from "lucide-react"

/**
 * Intentionally bare header. Just a wordmark on the left (with a tiny
 * geometric glyph as a logomark) and a silent GitHub icon on the right.
 * Anything heavier competes with the hero type.
 */
export default function Header() {
  return (
    <header className="relative z-20 w-full">
      <div className="max-w-[1180px] mx-auto px-5 md:px-8 h-14 flex items-center justify-between">
        <Link
          href="/"
          className="flex items-center gap-2.5 group"
          aria-label="PyGuard home"
        >
          <Logomark />
          <span className="text-[14px] font-medium tracking-[-0.01em] text-white/90 group-hover:text-white transition-colors">
            pyguard
          </span>
        </Link>

        <a
          href="https://github.com/InsanelyAvner/pyguard"
          target="_blank"
          rel="noopener noreferrer"
          aria-label="GitHub"
          className="h-8 w-8 rounded-md flex items-center justify-center text-white/40 hover:text-white hover:bg-white/5 transition-colors"
        >
          <Github className="h-4 w-4" strokeWidth={2} />
        </a>
      </div>
      {/* Hairline divider under the header */}
      <div className="absolute left-0 right-0 bottom-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
    </header>
  )
}

/**
 * 12×12 geometric logomark. Thin-stroke squares nested, echoing the
 * corner-bracket motif used around the main panel. Scales crisply.
 */
function Logomark() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 14 14"
      fill="none"
      className="text-white/80"
      aria-hidden
    >
      <rect
        x="1"
        y="1"
        width="12"
        height="12"
        rx="2"
        stroke="currentColor"
        strokeWidth="1"
        opacity="0.55"
      />
      <rect
        x="4"
        y="4"
        width="6"
        height="6"
        rx="1"
        fill="currentColor"
        opacity="0.9"
      />
    </svg>
  )
}

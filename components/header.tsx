"use client"

import Link from "next/link"
import { Github } from "lucide-react"

/**
 * Bare top bar — wordmark on the left, a single GitHub icon on the right,
 * a solid hairline divider underneath. No gradients, no pills, no chips.
 */
export default function Header() {
  return (
    <header className="relative z-20 w-full border-b border-line">
      <div className="max-w-[1180px] mx-auto px-5 md:px-8 h-14 flex items-center justify-between">
        <Link
          href="/"
          className="flex items-center gap-2.5 group"
          aria-label="PyGuard home"
        >
          <Logomark />
          <span className="text-[14px] font-medium tracking-[-0.005em] text-ink group-hover:text-white transition-colors">
            pyguard
          </span>
          <span className="hidden sm:inline ml-2 text-[10.5px] font-mono text-ink-dim tracking-wider">
            v5.2
          </span>
        </Link>

        <nav className="flex items-center gap-1">
          <a
            href="https://github.com/InsanelyAvner/pyguard"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub"
            className="h-8 w-8 rounded-md flex items-center justify-center text-ink-muted hover:text-ink hover:bg-white/[0.04] transition-colors"
          >
            <Github className="h-[15px] w-[15px]" strokeWidth={1.75} />
          </a>
        </nav>
      </div>
    </header>
  )
}

/**
 * 14×14 logomark — thin-stroke square with a solid inner square.
 * Uses the accent blue so it echoes the hero title colour without
 * resorting to a gradient badge.
 */
function Logomark() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 14 14"
      fill="none"
      aria-hidden
    >
      <rect
        x="1"
        y="1"
        width="12"
        height="12"
        rx="2"
        stroke="#93c5fd"
        strokeOpacity="0.55"
        strokeWidth="1"
      />
      <rect x="4" y="4" width="6" height="6" rx="1" fill="#93c5fd" />
    </svg>
  )
}

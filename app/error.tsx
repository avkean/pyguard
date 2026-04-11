"use client"

import { useEffect } from "react"
import { AlertCircle, RotateCcw } from "lucide-react"

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    // Log to the console for devs; the user just sees the graceful fallback.
    console.error("[pyguard] page error:", error)
  }, [error])

  return (
    <div className="min-h-[100dvh] w-full flex items-center justify-center bg-[#070708] text-white px-6">
      <div className="max-w-md w-full border border-red-500/20 bg-red-500/5 rounded-xl p-6">
        <div className="flex items-start gap-3 mb-4">
          <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-medium text-red-300 mb-1">
              Something went wrong
            </h2>
            <p className="text-xs text-red-200/70 font-mono break-words">
              {error?.message || "An unexpected error occurred."}
            </p>
            {error?.digest && (
              <p className="text-[10px] text-red-200/40 font-mono mt-2">
                digest: {error.digest}
              </p>
            )}
          </div>
        </div>
        <button
          onClick={() => reset()}
          className="inline-flex items-center gap-1.5 h-8 px-3 rounded-md text-xs font-medium bg-white/10 hover:bg-white/15 text-white transition-colors"
        >
          <RotateCcw className="h-3.5 w-3.5" />
          Try again
        </button>
      </div>
    </div>
  )
}

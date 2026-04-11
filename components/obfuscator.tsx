"use client"

import { useState, useEffect, useCallback } from "react"
import CodeEditor from "./code-editor"
import { Copy, Check, Wand2, AlertCircle } from "lucide-react"
import { obfuscatePythonCode } from "@/lib/obfuscate"
import { buildV5IR, BuildIRError } from "@/lib/v5/pyodide_loader"
import { cn } from "@/lib/utils"

const SAMPLE = `def greet(name):
    """Greet the given person."""
    print(f"Hello, {name}!")
    return f"Hello, {name}!"


if __name__ == "__main__":
    result = greet("World")
    print(result)
`

type Tab = "input" | "output"

type UiError = {
  kind: "syntax" | "python" | "internal" | "empty"
  title: string
  message: string
}

export default function Obfuscator() {
  const [inputCode, setInputCode] = useState<string>(SAMPLE)
  const [outputCode, setOutputCode] = useState<string>("")
  const [tab, setTab] = useState<Tab>("input")
  const [isWorking, setIsWorking] = useState(false)
  const [error, setError] = useState<UiError | null>(null)
  const [isCopied, setIsCopied] = useState(false)

  // Clear any error banner as soon as the user edits their input. We
  // intentionally only depend on `inputCode` — putting `error` here would
  // cause the effect to re-run the tick after clearing and mask further
  // typing updates.
  useEffect(() => {
    setError(null)
  }, [inputCode])

  const handleObfuscate = useCallback(async () => {
    if (!inputCode.trim()) {
      setError({
        kind: "empty",
        title: "Nothing to obfuscate",
        message: "Paste or type some Python code in the Input tab first.",
      })
      setTab("input")
      return
    }

    setIsWorking(true)
    setError(null)
    setOutputCode("")

    try {
      const v5IR = await buildV5IR(inputCode)
      const obfuscated = obfuscatePythonCode(inputCode, { v5IR })
      setOutputCode(obfuscated)
      setTab("output")
    } catch (e) {
      // console.warn (not .error) — Next.js 15 dev overlay counts console.error
      // calls as dev errors and flashes a red badge. We've already surfaced
      // this in the UI; this is just a debug trail.
      console.warn("[pyguard] obfuscation failed:", e)
      if (e instanceof BuildIRError) {
        const titles: Record<BuildIRError["kind"], string> = {
          syntax: "Python syntax error",
          python: "Python compile error",
          internal: "Internal error",
        }
        setError({ kind: e.kind, title: titles[e.kind], message: e.message })
      } else {
        setError({
          kind: "internal",
          title: "Obfuscation failed",
          message: e instanceof Error ? e.message : String(e),
        })
      }
    } finally {
      setIsWorking(false)
    }
  }, [inputCode])

  const copyOutput = useCallback(() => {
    if (!outputCode) return
    navigator.clipboard.writeText(outputCode)
    setIsCopied(true)
    setTimeout(() => setIsCopied(false), 1500)
  }, [outputCode])

  // Cmd/Ctrl+Enter from anywhere on the page triggers an obfuscation run.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault()
        if (!isWorking) handleObfuscate()
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [handleObfuscate, isWorking])

  const lineCount = (tab === "input" ? inputCode : outputCode).split("\n").length
  const charCount = (tab === "input" ? inputCode : outputCode).length

  return (
    <div className="relative w-full max-w-[1180px] mx-auto px-5 md:px-8 flex flex-col items-center">
      {/* ------------------------------------------------------------------ */}
      {/* Hero — intentionally short. The real content is the panel below.   */}
      {/* ------------------------------------------------------------------ */}
      <section className="pt-8 md:pt-12 pb-6 md:pb-8 text-center relative">
        <h1 className="font-serif font-normal text-[52px] md:text-[76px] leading-[0.98] tracking-[-0.02em] text-white mb-3">
          Obfuscate your <em className="italic font-light text-white/85">Python</em>.
        </h1>
        <p className="text-[14px] md:text-[15.5px] text-white/50 leading-relaxed">
          Ship code that static analysers, LLMs, and{" "}
          <code className="font-mono text-white/70 text-[0.92em]">dis</code>{" "}
          can&rsquo;t read.
        </p>
      </section>

      {/* ------------------------------------------------------------------ */}
      {/* Main panel                                                          */}
      {/* ------------------------------------------------------------------ */}
      <div className="relative w-full">
        {/* Zed-style corner brackets sitting just outside the panel edges */}
        <CornerBrackets />

        <div className="relative w-full rounded-[10px] border border-white/[0.08] bg-[#0a0a0b] overflow-hidden shadow-[0_40px_120px_-20px_rgba(0,0,0,0.8)]">
          {/* Progress shimmer along the very top */}
          <div
            className={cn(
              "absolute top-0 left-0 right-0 h-[1.5px] overflow-hidden pointer-events-none z-20 transition-opacity duration-200",
              isWorking ? "opacity-100" : "opacity-0",
            )}
          >
            <div className="h-full w-1/3 bg-gradient-to-r from-transparent via-blue-400 to-transparent animate-shimmer" />
          </div>

          {/* Tab bar */}
          <div className="flex items-stretch justify-between border-b border-white/[0.06] h-12 bg-[#0c0c0d]">
            <div className="flex items-stretch">
              <TabButton
                active={tab === "input"}
                onClick={() => setTab("input")}
                label="Input"
                sublabel="python"
              />
              <TabButton
                active={tab === "output"}
                onClick={() => outputCode && setTab("output")}
                label="Output"
                sublabel={outputCode ? `${outputCode.split("\n").length} lines` : "—"}
                disabled={!outputCode}
              />
            </div>

            <div className="flex items-center gap-1.5 pr-2.5">
              {tab === "output" && outputCode && (
                <button
                  onClick={copyOutput}
                  className="h-8 px-3 rounded-md text-[12px] font-medium text-white/55 hover:text-white hover:bg-white/[0.05] flex items-center gap-1.5 transition-colors"
                >
                  {isCopied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      Copy
                    </>
                  )}
                </button>
              )}
              <button
                onClick={handleObfuscate}
                disabled={isWorking}
                className={cn(
                  "h-8 px-3.5 rounded-md text-[12px] font-medium flex items-center gap-1.5 transition-all",
                  "bg-white text-black hover:bg-white/90",
                  "disabled:opacity-50 disabled:cursor-not-allowed",
                )}
              >
                {isWorking ? (
                  <>
                    <span className="inline-block h-1.5 w-1.5 rounded-full bg-black/70 animate-pulse" />
                    Working
                  </>
                ) : (
                  <>
                    <Wand2 className="h-3.5 w-3.5" strokeWidth={2.25} />
                    Obfuscate
                    <kbd className="hidden md:inline-flex ml-0.5 items-center gap-px rounded-sm bg-black/15 px-1 py-px text-[10px] font-mono text-black/60">
                      ⌘↵
                    </kbd>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Editor body — distinct `key` per tab guarantees the CodeEditor
              instance is torn down between input and output. Defence in depth
              on top of the ref-based stale-closure fix inside CodeEditor. */}
          <div className="relative h-[62vh] min-h-[380px] max-h-[720px]">
            {tab === "input" ? (
              <CodeEditor
                key="input"
                value={inputCode}
                onChange={setInputCode}
                language="python"
                readOnly={isWorking}
              />
            ) : (
              <CodeEditor
                key="output"
                value={outputCode}
                language="python"
                readOnly
              />
            )}

            {tab === "output" && !outputCode && (
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="text-center text-white/25">
                  <Wand2 className="h-5 w-5 mx-auto mb-2 opacity-60" />
                  <p className="text-[12px]">Run Obfuscate to see the output</p>
                </div>
              </div>
            )}
          </div>

          {/* Error banner */}
          {error && (
            <div className="border-t border-red-500/15 bg-red-500/[0.04] px-4 py-2.5 flex items-start gap-3">
              <AlertCircle className="h-3.5 w-3.5 text-red-400/90 flex-shrink-0 mt-[3px]" />
              <div className="flex-1 min-w-0">
                <div className="text-[11px] font-medium text-red-300/95 tracking-wide">
                  {error.title}
                </div>
                <div className="mt-0.5 text-[11px] text-red-200/60 font-mono break-words leading-relaxed">
                  {error.message}
                </div>
              </div>
              <button
                onClick={() => setError(null)}
                className="text-red-400/40 hover:text-red-300 text-base leading-none shrink-0 px-1"
                aria-label="Dismiss"
              >
                ×
              </button>
            </div>
          )}

          {/* Status bar */}
          <div className="border-t border-white/[0.06] bg-[#08080a] px-4 h-8 flex items-center justify-between text-[11px] text-white/40 font-mono tracking-wide">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5">
                <span className="h-1 w-1 rounded-full bg-white/30" />
                python
              </span>
              <span className="text-white/15">·</span>
              <span>utf-8</span>
              <span className="text-white/15">·</span>
              <span>lf</span>
            </div>
            <div className="flex items-center gap-3">
              <span>{lineCount} lines</span>
              <span className="text-white/15">·</span>
              <span>{charCount.toLocaleString()} ch</span>
            </div>
          </div>
        </div>
      </div>

      {/* Caption under the panel */}
      <p className="text-[10.5px] font-mono text-white/25 mt-4 text-center tracking-wide">
        first run downloads ~10 MB of pyodide &nbsp;·&nbsp; subsequent runs reuse the cached runtime
      </p>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Sub-components                                                              */
/* -------------------------------------------------------------------------- */

function TabButton({
  active,
  onClick,
  label,
  sublabel,
  disabled,
}: {
  active: boolean
  onClick: () => void
  label: string
  sublabel?: string
  disabled?: boolean
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "relative h-full px-5 flex items-center gap-2.5 text-[12.5px] font-medium transition-colors border-r border-white/[0.06]",
        active
          ? "text-white bg-[#0a0a0b]"
          : "text-white/40 hover:text-white/70 hover:bg-white/[0.02]",
        disabled && "opacity-40 cursor-not-allowed hover:bg-transparent hover:text-white/40",
      )}
    >
      <span className="tracking-wide">{label}</span>
      {sublabel && (
        <span className="text-[10px] text-white/30 font-mono uppercase tracking-[0.12em]">
          {sublabel}
        </span>
      )}
      {/* Active indicator: single blue hairline flush with the bottom of the tab bar */}
      {active && (
        <span className="absolute left-0 right-0 -bottom-px h-px bg-blue-400/80" />
      )}
    </button>
  )
}

/**
 * Decorative cross-mark brackets offset just outside the four corners of
 * the panel. This is the "architectural drawing" motif Zed uses — they
 * ground the panel in the grid without adding visual weight.
 */
function CornerBrackets() {
  const base =
    "absolute w-2 h-2 pointer-events-none text-white/25"
  return (
    <>
      <svg className={cn(base, "-top-[3px] -left-[3px]")} viewBox="0 0 8 8" fill="none">
        <path d="M0 4H8M4 0V8" stroke="currentColor" strokeWidth="1" />
      </svg>
      <svg className={cn(base, "-top-[3px] -right-[3px]")} viewBox="0 0 8 8" fill="none">
        <path d="M0 4H8M4 0V8" stroke="currentColor" strokeWidth="1" />
      </svg>
      <svg className={cn(base, "-bottom-[3px] -left-[3px]")} viewBox="0 0 8 8" fill="none">
        <path d="M0 4H8M4 0V8" stroke="currentColor" strokeWidth="1" />
      </svg>
      <svg className={cn(base, "-bottom-[3px] -right-[3px]")} viewBox="0 0 8 8" fill="none">
        <path d="M0 4H8M4 0V8" stroke="currentColor" strokeWidth="1" />
      </svg>
    </>
  )
}

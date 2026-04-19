"use client"

import { useState, useEffect, useCallback } from "react"
import CodeEditor from "./code-editor"
import { Copy, Check, AlertCircle, CornerDownLeft } from "lucide-react"
import { cn } from "@/lib/utils"

class BuildIRError extends Error {
  kind: "syntax" | "python" | "internal"
  constructor(message: string, kind: "syntax" | "python" | "internal") {
    super(message)
    this.name = "BuildIRError"
    this.kind = kind
  }
}

async function obfuscateViaServer(source: string): Promise<string> {
  const res = await fetch("/api/obfuscate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source }),
  })
  if (!res.ok) {
    let payload: { error?: string; kind?: "syntax" | "python" | "internal" } = {}
    try {
      payload = await res.json()
    } catch {
      // non-JSON error (e.g. HTML error page from middleware)
    }
    const kind = payload.kind ?? "internal"
    const message = payload.error ?? `HTTP ${res.status}`
    throw new BuildIRError(message, kind)
  }
  return await res.text()
}

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

  // Clear the error banner as soon as the user edits their input. Only
  // inputCode in deps — adding `error` would re-run the effect after clear
  // and mask further typing updates.
  useEffect(() => {
    setError(null)
  }, [inputCode])

  const handleObfuscate = useCallback(async () => {
    if (!inputCode.trim()) {
      setError({
        kind: "empty",
        title: "Nothing to obfuscate",
        message: "Paste or type some Python in the Input tab first.",
      })
      setTab("input")
      return
    }

    setIsWorking(true)
    setError(null)
    setOutputCode("")

    try {
      const obfuscated = await obfuscateViaServer(inputCode)
      setOutputCode(obfuscated)
      setTab("output")
    } catch (e) {
      // console.warn (not .error) — Next.js dev overlay treats console.error
      // as a dev error and flashes a red badge.
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

  // Cmd/Ctrl+Enter runs obfuscation from anywhere on the page.
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

  const activeCode = tab === "input" ? inputCode : outputCode
  const lineCount = activeCode.split("\n").length
  const charCount = activeCode.length

  return (
    <div className="relative w-full max-w-[1180px] mx-auto px-5 md:px-8 flex flex-col items-center">
      {/* ------------------------------------------------------------------ */}
      {/* Hero                                                                */}
      {/* ------------------------------------------------------------------ */}
      <section className="pt-14 md:pt-20 pb-12 md:pb-16 text-center">
        <h1 className="font-serif font-medium text-[56px] md:text-[84px] leading-[0.97] tracking-[-0.028em] text-accent mb-5">
          Obfuscate your{" "}
          <em className="italic font-normal">Python</em>.
        </h1>
        <p className="mx-auto max-w-[560px] text-[15px] md:text-[16.5px] leading-[1.55] text-ink-muted">
          Ship code that static analysers, LLMs, and{" "}
          <code className="font-mono text-[0.88em] text-ink">dis</code>{" "}
          can&rsquo;t read.
        </p>
        <p className="mt-4 text-[12px] text-ink-dim font-sans tracking-wide">
          Stubs target Python 3.9&ndash;3.14 &middot; built server-side for multi-version support
        </p>
      </section>

      {/* ------------------------------------------------------------------ */}
      {/* Panel                                                               */}
      {/* ------------------------------------------------------------------ */}
      <div
        className={cn(
          "relative w-full rounded-[10px] overflow-hidden",
          "border border-line-strong bg-surface-raised",
          // One carefully-tuned inset highlight + one very soft shadow.
          // No decorative glows, no stacked drop shadows.
          "shadow-[0_1px_0_0_rgba(255,255,255,0.04)_inset,0_30px_80px_-30px_rgba(0,0,0,0.9)]",
        )}
      >
        {/* Progress shimmer along the very top of the panel */}
        <div
          className={cn(
            "absolute top-0 left-0 right-0 h-[1.5px] overflow-hidden pointer-events-none z-20 transition-opacity duration-200",
            isWorking ? "opacity-100" : "opacity-0",
          )}
        >
          <div className="h-full w-1/3 bg-gradient-to-r from-transparent via-accent to-transparent animate-shimmer" />
        </div>

        {/* Tab bar */}
        <div className="flex items-stretch justify-between h-12 bg-surface-sunken border-b border-line">
          <div className="flex items-stretch">
            <TabButton
              active={tab === "input"}
              onClick={() => setTab("input")}
              label="Input"
            />
            <TabButton
              active={tab === "output"}
              onClick={() => outputCode && setTab("output")}
              label="Output"
              disabled={!outputCode}
            />
          </div>

          <div className="flex items-center gap-1.5 pr-2">
            {tab === "output" && outputCode && (
              <button
                onClick={copyOutput}
                className="h-8 px-3 rounded-md text-[12.5px] font-medium text-ink-muted hover:text-ink hover:bg-white/[0.04] flex items-center gap-1.5 transition-colors"
              >
                {isCopied ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-success" />
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
                "h-8 pl-3 pr-2 rounded-md text-[12.5px] font-medium flex items-center gap-2 transition-colors",
                "bg-accent-strong text-white hover:bg-[#3c6be0] active:bg-[#335fd4]",
                "disabled:opacity-60 disabled:cursor-not-allowed",
              )}
            >
              {isWorking ? (
                <>
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-white/70 animate-pulse" />
                  <span>Running</span>
                </>
              ) : (
                <>
                  <span>Obfuscate</span>
                  <kbd className="hidden md:inline-flex items-center gap-0.5 rounded-[3px] bg-white/15 px-1 py-px text-[10px] font-mono text-white/90">
                    <span className="text-[11px] leading-none">&#8984;</span>
                    <CornerDownLeft className="h-2.5 w-2.5" strokeWidth={2.5} />
                  </kbd>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Editor body — distinct `key` per tab guarantees the CodeEditor
            instance is torn down between input and output. Defence in depth
            on top of the ref-based stale-closure fix inside CodeEditor. */}
        <div className="relative h-[54vh] min-h-[380px] max-h-[640px]">
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
              <p className="text-[13px] text-ink-dim">
                Run Obfuscate to see the output
              </p>
            </div>
          )}
        </div>

        {/* Error banner */}
        {error && (
          <div className="border-t border-danger/15 bg-danger/[0.05] px-4 py-3 flex items-start gap-3">
            <AlertCircle className="h-4 w-4 text-danger/90 flex-shrink-0 mt-[2px]" />
            <div className="flex-1 min-w-0">
              <div className="text-[12px] font-medium text-[#ff8b8f]">
                {error.title}
              </div>
              <div className="mt-0.5 text-[12px] text-[#ff8b8f]/70 font-mono break-words leading-relaxed">
                {error.message}
              </div>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-danger/40 hover:text-danger text-base leading-none shrink-0 px-1"
              aria-label="Dismiss"
            >
              &times;
            </button>
          </div>
        )}

        {/* Status bar */}
        <div className="border-t border-line bg-surface-sunken px-4 h-8 flex items-center justify-between text-[11px] text-ink-dim font-mono">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5">
              <span className="h-1 w-1 rounded-full bg-accent/70" />
              python
            </span>
            <span className="text-ink-faint">&middot;</span>
            <span>utf-8</span>
            <span className="text-ink-faint">&middot;</span>
            <span>lf</span>
          </div>
          <div className="flex items-center gap-3">
            <span>
              <span className="text-ink-muted">{lineCount}</span> lines
            </span>
            <span className="text-ink-faint">&middot;</span>
            <span>
              <span className="text-ink-muted">
                {charCount.toLocaleString()}
              </span>{" "}
              ch
            </span>
          </div>
        </div>
      </div>

      {/* Small caption under the panel */}
      <p className="text-[11.5px] text-ink-dim mt-5 text-center font-sans">
        Your source is sent to the server for obfuscation and returned as a single self-contained stub.
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
  disabled,
}: {
  active: boolean
  onClick: () => void
  label: string
  disabled?: boolean
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "relative h-full px-5 flex items-center text-[13px] font-medium transition-colors",
        active
          ? "text-ink bg-surface-raised"
          : "text-ink-muted hover:text-ink",
        disabled && "opacity-40 cursor-not-allowed hover:text-ink-muted",
      )}
    >
      <span>{label}</span>
      {active && (
        <span className="absolute left-0 right-0 -bottom-px h-px bg-accent" />
      )}
    </button>
  )
}

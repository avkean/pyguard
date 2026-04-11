"use client"

import { useEffect, useRef, useState } from "react"
import { EditorView, basicSetup } from "codemirror"
import { EditorState, Compartment } from "@codemirror/state"
import { python } from "@codemirror/lang-python"
import type { ViewUpdate } from "@codemirror/view"
import { pyguardTheme, pyguardHighlight } from "@/lib/editor-theme"

interface CodeEditorProps {
  value: string
  onChange?: (value: string) => void
  language?: "python" | "javascript"
  readOnly?: boolean
}

/**
 * Thin CodeMirror 6 wrapper.
 *
 * Two subtle footguns we explicitly dodge:
 *
 * 1. **Stale onChange closure.** The editor is created once and its
 *    updateListener closes over the `onChange` prop from the first render.
 *    When the parent swaps in a new `onChange` (e.g. switching between
 *    input/output tabs), the listener would keep calling the OLD one,
 *    silently writing obfuscated text back into `inputCode`. We fix this
 *    by routing through a ref that always points at the latest prop.
 *
 * 2. **Programmatic updates re-firing onChange.** When the parent changes
 *    `value`, we dispatch a replace into the doc. CM6 sees this as a user
 *    edit and fires updateListener with docChanged=true. Without a guard,
 *    that would also re-emit into `onChange` and cause the exact input↔
 *    output bleed above. We flip an `isProgrammatic` ref around the
 *    dispatch so the listener ignores that one update.
 */
export default function CodeEditor({
  value,
  onChange,
  language = "python",
  readOnly = false,
}: CodeEditorProps) {
  const [element, setElement] = useState<HTMLDivElement | null>(null)
  const viewRef = useRef<EditorView | null>(null)
  const onChangeRef = useRef(onChange)
  const isProgrammaticRef = useRef(false)
  const readOnlyCompartment = useRef(new Compartment())

  // Keep the latest onChange addressable from the (static) updateListener.
  useEffect(() => {
    onChangeRef.current = onChange
  }, [onChange])

  // Mount the editor exactly once per element. Language/readOnly changes
  // are reconfigured in place via Compartment rather than destroying.
  useEffect(() => {
    if (!element) return

    const languageExtension = language === "python" ? python() : python()

    const startState = EditorState.create({
      doc: value,
      extensions: [
        basicSetup,
        languageExtension,
        pyguardTheme,
        pyguardHighlight,
        readOnlyCompartment.current.of(EditorState.readOnly.of(readOnly)),
        EditorView.updateListener.of((update: ViewUpdate) => {
          if (!update.docChanged) return
          if (isProgrammaticRef.current) return
          onChangeRef.current?.(update.state.doc.toString())
        }),
      ],
    })

    const view = new EditorView({ state: startState, parent: element })
    viewRef.current = view

    return () => {
      view.destroy()
      viewRef.current = null
    }
    // Only re-mount when the backing DOM element or language swaps.
    // readOnly is reconfigured via Compartment below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [element, language])

  // Reconfigure readOnly without tearing down the editor.
  useEffect(() => {
    const view = viewRef.current
    if (!view) return
    view.dispatch({
      effects: readOnlyCompartment.current.reconfigure(
        EditorState.readOnly.of(readOnly),
      ),
    })
  }, [readOnly])

  // Sync external value → editor doc. Guarded so the resulting updateListener
  // call doesn't boomerang back into onChange.
  useEffect(() => {
    const view = viewRef.current
    if (!view) return
    const current = view.state.doc.toString()
    if (current === value) return
    isProgrammaticRef.current = true
    try {
      view.dispatch({
        changes: { from: 0, to: current.length, insert: value },
      })
    } finally {
      isProgrammaticRef.current = false
    }
  }, [value])

  return <div ref={setElement} className="code-editor w-full h-full" />
}

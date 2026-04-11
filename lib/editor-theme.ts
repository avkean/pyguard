/**
 * CodeMirror 6 theme — handcrafted, monochrome-leaning palette designed to
 * pair with the rest of the page. Replaces the stock oneDark theme, which
 * is too blue/saturated for the Zed-inspired surface we render against.
 *
 * Syntax colours are deliberately muted (the background is #0b0b0c so any
 * high-chroma hue punches too hard). Accents land on the cool side so
 * everything reads as a single coherent tool, not a paint chip.
 */

import { EditorView } from "@codemirror/view"
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language"
import { tags as t } from "@lezer/highlight"

const bg = "transparent"
const fg = "#e5e7ea"
const faint = "rgba(255,255,255,0.04)"
const gutterFg = "rgba(255,255,255,0.22)"
const cursor = "#93c5fd"
const selection = "rgba(96,165,250,0.22)"

export const pyguardTheme = EditorView.theme(
  {
    "&": {
      color: fg,
      backgroundColor: bg,
      height: "100%",
      fontSize: "15px",
      lineHeight: "1.7",
    },
    ".cm-scroller": {
      fontFamily:
        'var(--font-mono), ui-monospace, "SF Mono", Menlo, Consolas, monospace',
      overflow: "auto",
      height: "100%",
      // Hide scrollbars in Firefox
      scrollbarWidth: "none" as unknown as string,
      msOverflowStyle: "none" as unknown as string,
    },
    // Hide scrollbars in WebKit — we still allow scrolling via drag/wheel
    ".cm-scroller::-webkit-scrollbar": {
      display: "none",
      width: "0",
      height: "0",
    },
    ".cm-content": {
      caretColor: cursor,
      padding: "16px 0",
    },
    ".cm-line": {
      padding: "0 16px 0 10px",
    },
    "&.cm-focused .cm-cursor": {
      borderLeftColor: cursor,
      borderLeftWidth: "1.5px",
    },
    "&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection":
      {
        backgroundColor: selection,
      },
    ".cm-activeLine": {
      backgroundColor: faint,
    },
    ".cm-gutters": {
      backgroundColor: bg,
      color: gutterFg,
      border: "none",
      borderRight: "1px solid rgba(255,255,255,0.04)",
      paddingRight: "2px",
    },
    ".cm-activeLineGutter": {
      backgroundColor: faint,
      color: "rgba(255,255,255,0.55)",
    },
    ".cm-lineNumbers .cm-gutterElement": {
      padding: "0 12px 0 18px",
      minWidth: "32px",
      fontVariantNumeric: "tabular-nums",
      fontSize: "13px",
    },
    "&.cm-focused": { outline: "none" },
    ".cm-foldPlaceholder": {
      background: "rgba(255,255,255,0.05)",
      border: "1px solid rgba(255,255,255,0.08)",
      color: "rgba(255,255,255,0.5)",
    },
  },
  { dark: true },
)

// Monochrome-leaning highlight. Keywords cool, strings warm, comments faded.
export const pyguardHighlight = syntaxHighlighting(
  HighlightStyle.define([
    { tag: t.keyword, color: "#a5b4fc", fontWeight: "400" },
    { tag: [t.controlKeyword, t.moduleKeyword], color: "#c4b5fd" },
    { tag: [t.operator, t.operatorKeyword], color: "rgba(255,255,255,0.55)" },
    { tag: [t.definition(t.variableName)], color: "#e5e7ea" },
    { tag: [t.variableName], color: "#e5e7ea" },
    { tag: [t.function(t.variableName), t.function(t.propertyName)], color: "#93c5fd" },
    { tag: [t.propertyName], color: "#d1d5db" },
    { tag: [t.className, t.typeName], color: "#7dd3fc" },
    { tag: [t.string, t.special(t.string)], color: "#f6c177" },
    { tag: [t.number, t.bool, t.null], color: "#fda4af" },
    { tag: [t.comment, t.lineComment, t.blockComment, t.docComment], color: "rgba(255,255,255,0.32)", fontStyle: "italic" },
    { tag: [t.meta, t.processingInstruction], color: "rgba(255,255,255,0.4)" },
    { tag: [t.bracket, t.punctuation, t.separator], color: "rgba(255,255,255,0.5)" },
    { tag: [t.invalid], color: "#fca5a5" },
    { tag: [t.regexp], color: "#fbbf24" },
    { tag: [t.self, t.atom], color: "#c4b5fd" },
  ]),
)

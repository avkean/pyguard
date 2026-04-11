/**
 * CodeMirror 6 theme — pulls from the same palette as the rest of the site.
 * Deliberately restrained: one accent blue, one amber for strings, one rose
 * for numbers, everything else neutral gray. Zero saturated hues. The goal
 * is for the editor to read as part of the page, not as a carnival.
 */

import { EditorView } from "@codemirror/view"
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language"
import { tags as t } from "@lezer/highlight"

// Palette — single source of truth, mirrors tailwind.config.ts
const bg = "transparent" // inherits from panel
const fg = "#c7cad2" // ink primary (slightly dimmer inside editor)
const fgBright = "#e9eaec"
const gutterFg = "#3a3d47" // ink.faint
const gutterActive = "#6b6e78"
const activeLine = "rgba(255,255,255,0.025)"
const cursor = "#93c5fd" // blue-300
const selection = "rgba(147,197,253,0.20)" // blue-300 @ 20%
const ruleLine = "rgba(255,255,255,0.04)"

// Syntax hues — pinned to Tailwind's blue scale, zero violet cast
const accent = "#93c5fd" // blue-300 — keywords, types
const accentDim = "#60a5fa" // blue-400 — operators at lower emphasis
const amber = "#d9a47a" // strings
const rose = "#d68fa7" // numbers, bools
const comment = "#55585f" // ink.dim
const punctuation = "#6b6e78"

export const pyguardTheme = EditorView.theme(
  {
    "&": {
      color: fg,
      backgroundColor: bg,
      height: "100%",
      fontSize: "15px",
      lineHeight: "1.72",
    },
    ".cm-scroller": {
      fontFamily:
        'var(--font-mono), ui-monospace, "SF Mono", Menlo, Consolas, monospace',
      overflow: "auto",
      height: "100%",
      scrollbarWidth: "none" as unknown as string,
      msOverflowStyle: "none" as unknown as string,
    },
    ".cm-scroller::-webkit-scrollbar": {
      display: "none",
      width: "0",
      height: "0",
    },
    ".cm-content": {
      caretColor: cursor,
      padding: "18px 0",
    },
    ".cm-line": {
      padding: "0 18px 0 12px",
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
      backgroundColor: activeLine,
    },
    ".cm-gutters": {
      backgroundColor: bg,
      color: gutterFg,
      border: "none",
      borderRight: `1px solid ${ruleLine}`,
      paddingRight: "2px",
    },
    ".cm-activeLineGutter": {
      backgroundColor: activeLine,
      color: gutterActive,
    },
    ".cm-lineNumbers .cm-gutterElement": {
      padding: "0 14px 0 20px",
      minWidth: "36px",
      fontVariantNumeric: "tabular-nums",
      fontSize: "13px",
    },
    "&.cm-focused": { outline: "none" },
    ".cm-foldPlaceholder": {
      background: "rgba(255,255,255,0.04)",
      border: "1px solid rgba(255,255,255,0.08)",
      color: fg,
    },
  },
  { dark: true },
)

export const pyguardHighlight = syntaxHighlighting(
  HighlightStyle.define([
    // Keywords and control flow — the accent blue
    { tag: [t.keyword, t.controlKeyword, t.moduleKeyword], color: accent },
    { tag: [t.self, t.atom, t.null, t.bool], color: rose },

    // Operators and punctuation — muted
    { tag: [t.operator, t.operatorKeyword], color: accentDim },
    { tag: [t.bracket, t.punctuation, t.separator], color: punctuation },

    // Identifiers and variables — neutral text
    { tag: [t.variableName, t.definition(t.variableName)], color: fgBright },
    { tag: [t.propertyName], color: fg },

    // Functions and types — a lighter blue-200 to differentiate from
    // keywords without introducing a second hue
    {
      tag: [t.function(t.variableName), t.function(t.propertyName)],
      color: "#bfdbfe", // blue-200
    },
    { tag: [t.className, t.typeName], color: "#bfdbfe" }, // blue-200

    // Strings — warm, desaturated amber
    { tag: [t.string, t.special(t.string), t.regexp], color: amber },

    // Numbers — muted rose
    { tag: [t.number], color: rose },

    // Comments — faded, italic
    {
      tag: [t.comment, t.lineComment, t.blockComment, t.docComment],
      color: comment,
      fontStyle: "italic",
    },

    // Meta / decorators
    { tag: [t.meta, t.processingInstruction], color: "#6b6e78" },

    // Errors
    { tag: [t.invalid], color: "#e5484d" },
  ]),
)

import type { Config } from "tailwindcss"

/**
 * Palette is defined here so every component pulls from a single source of
 * truth. Tokens are split into four groups:
 *
 *   surface — flat backgrounds (page, panel, sunken, elevated)
 *   line    — hairline borders at two emphases
 *   ink     — text at four steps of emphasis
 *   accent  — the ONE brand blue and its solid / soft variants
 *
 * Plus two editor-only warm tones (amber for strings, rose for numbers)
 * that are deliberately desaturated so they sit next to the blue without
 * ever reading as rainbow.
 */
export default {
  darkMode: ["class"],
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
        serif: ["var(--font-serif)", "ui-serif", "Georgia", "serif"],
      },
      colors: {
        // Page + panel surfaces — neutral near-black with the faintest
        // cool cast. Luminance ~8–12%. This is the zone Zed / Linear /
        // Vercel sit in: dark enough to feel like proper dark mode, not
        // so dark that the UI disappears into a void.
        surface: {
          DEFAULT: "#13141a",  // page — hsl(232, 16%, 9%)
          raised: "#191a20",   // panel body — one step up
          sunken: "#0f1014",   // tab bar, status bar — half a step down
          elevated: "#1e1f26", // hover / selected states
        },

        // Hairline borders. Still neutral white-on-dark so they read as
        // structural, not coloured — the blue should come from the accent.
        line: {
          DEFAULT: "rgba(255,255,255,0.06)",
          strong: "rgba(255,255,255,0.14)",
        },

        // Text emphases
        ink: {
          DEFAULT: "#e9eaec",
          muted: "#8a8c94",
          dim: "#55585f",
          faint: "#3a3d47",
        },

        // The ONE brand accent. Pinned to Tailwind's blue scale so there
        // is zero violet cast: blue-300 for headings/links (clearly blue,
        // readable on dark surfaces), blue-500 for solid affordances like
        // the primary button.
        accent: {
          DEFAULT: "#93c5fd",  // blue-300
          strong: "#3b82f6",   // blue-500
          soft: "rgba(147,197,253,0.10)",
        },

        // Editor-only secondary hues (deliberately desaturated)
        amber: "#d9a47a",
        rose: "#d68fa7",

        danger: "#e5484d",
        success: "#46a758",

        // shadcn/radix tokens kept for third-party components
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
} satisfies Config

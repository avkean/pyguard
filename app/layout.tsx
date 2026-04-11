import "./globals.css"
import type { Metadata } from "next"
import { JetBrains_Mono, Inter, IBM_Plex_Serif } from "next/font/google"
import { Toaster } from "@/components/ui/toaster"

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
})

const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
})

// IBM Plex Serif is the engineering-grade serif companion to Plex Sans /
// Plex Mono. It reads practical and grown-up at display sizes — none of the
// thin "editorial blog" energy of Instrument Serif — which suits a dev tool.
const serif = IBM_Plex_Serif({
  subsets: ["latin"],
  weight: ["300", "400", "500"],
  style: ["normal", "italic"],
  variable: "--font-serif",
  display: "swap",
})

export const metadata: Metadata = {
  title: "PyGuard — Python Obfuscator",
  description:
    "Multi-layer Python obfuscation against static analysis, LLM recovery, and runtime introspection. Runs entirely in your browser.",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.variable} ${mono.variable} ${serif.variable} font-sans antialiased bg-[#070708] text-white min-h-[100dvh]`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  )
}

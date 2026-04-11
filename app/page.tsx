import Obfuscator from "@/components/obfuscator"
import Header from "@/components/header"
import Footer from "@/components/footer"

/**
 * Page shell.
 *
 * Background composition is intentional and layered:
 *
 *   1. Solid surface colour (`#13141a`, neutral near-black)
 *   2. Fractal-noise texture (SVG fragment, baked as data URL). Very low
 *      opacity, tiled 200×200. This is what makes the dark background feel
 *      physical instead of flat. Without it the page reads as a dead void.
 *   3. One soft blue glow at top-centre, one even softer at bottom-centre,
 *      to give the page subtle vertical depth without introducing coloured
 *      gradients.
 *   4. Two solid vertical hairlines at the edges of the content column,
 *      running full-height. These are the structural rails you see on the
 *      Zed landing page — they anchor the layout to the grid.
 *
 * Every element here serves the grid. Nothing is decoration for its own
 * sake.
 */

// Fractal noise, saturation 0 (grayscale), tile-stitched so it seams
// cleanly. The `opacity` inside the SVG plus the outer CSS opacity compose
// to give us the very faint grain we want.
const NOISE_SVG =
  "data:image/svg+xml;utf8," +
  encodeURIComponent(
    `<svg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'>` +
      `<filter id='n'>` +
      `<feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/>` +
      `<feColorMatrix type='saturate' values='0'/>` +
      `</filter>` +
      `<rect width='100%' height='100%' filter='url(#n)' opacity='0.65'/>` +
      `</svg>`,
  )

export default function Home() {
  return (
    <div className="relative min-h-[100dvh] w-full flex flex-col bg-surface text-ink overflow-x-hidden">
      {/* ── Layer 1: fractal noise grain (fixed, full viewport) ── */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 z-0 opacity-[0.055] mix-blend-overlay"
        style={{
          backgroundImage: `url("${NOISE_SVG}")`,
          backgroundSize: "200px 200px",
          backgroundRepeat: "repeat",
        }}
      />

      {/* ── Layer 2: top-centre ambient glow ── */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-x-0 top-0 h-[760px] z-0"
        style={{
          // blue-500 @ 14% — one accent hue, no second tone
          background:
            "radial-gradient(ellipse 55% 60% at 50% -10%, rgba(59,130,246,0.16), transparent 60%)",
        }}
      />

      {/* ── Layer 3: faint bottom ambient ── */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-x-0 bottom-0 h-[400px] z-0"
        style={{
          // blue-500 @ 6%
          background:
            "radial-gradient(ellipse 50% 100% at 50% 120%, rgba(59,130,246,0.06), transparent 60%)",
        }}
      />

      {/* ── Layer 4: solid vertical hairlines at content column edges ── */}
      <ColumnRails />

      <Header />
      <main className="relative flex-1 flex flex-col items-center z-10 w-full">
        <Obfuscator />
      </main>
      <Footer />
    </div>
  )
}

/**
 * Two solid 1px hairlines at the left/right edges of the 1180px content
 * column, running full viewport height behind the content. On smaller
 * viewports they hide so they don't clip into the content.
 */
function ColumnRails() {
  return (
    <div
      aria-hidden
      className="pointer-events-none fixed inset-0 hidden lg:flex justify-center z-0"
    >
      <div className="relative w-full max-w-[1180px] h-full">
        <div className="absolute top-0 bottom-0 left-0 w-px bg-line" />
        <div className="absolute top-0 bottom-0 right-0 w-px bg-line" />
      </div>
    </div>
  )
}

import Obfuscator from "@/components/obfuscator"
import Header from "@/components/header"
import Footer from "@/components/footer"

export default function Home() {
  return (
    <div className="relative min-h-[100dvh] w-full flex flex-col bg-[#070708] text-white overflow-x-hidden">
      {/* Cool radial glow seated at the top of the viewport */}
      <div
        className="pointer-events-none fixed inset-0 opacity-70"
        style={{
          background:
            "radial-gradient(ellipse 70% 45% at 50% -10%, rgba(99,140,255,0.14), transparent 70%)",
        }}
      />

      {/* Very faint square grid, masked so it fades to black off-centre */}
      <div
        className="pointer-events-none fixed inset-0 opacity-[0.035]"
        style={{
          backgroundImage:
            "linear-gradient(to right, white 1px, transparent 1px), linear-gradient(to bottom, white 1px, transparent 1px)",
          backgroundSize: "56px 56px",
          maskImage:
            "radial-gradient(ellipse 75% 55% at 50% 25%, black 35%, transparent 100%)",
          WebkitMaskImage:
            "radial-gradient(ellipse 75% 55% at 50% 25%, black 35%, transparent 100%)",
        }}
      />

      {/* Dashed architectural guide rails flanking the centred column. These
          are the narrow vertical lines you see on zed.dev — pure decoration
          but they anchor the composition and give scale. */}
      <SideRails />

      <Header />
      <main className="relative flex-1 flex flex-col items-center z-10">
        <Obfuscator />
      </main>
      <Footer />
    </div>
  )
}

function SideRails() {
  return (
    <div
      aria-hidden
      className="pointer-events-none fixed inset-0 hidden lg:flex justify-center"
    >
      <div className="relative w-full max-w-[1232px]">
        <div
          className="absolute top-0 bottom-0 left-0 w-px opacity-[0.10]"
          style={{
            backgroundImage:
              "linear-gradient(to bottom, rgba(255,255,255,0.8) 50%, transparent 0)",
            backgroundSize: "1px 6px",
          }}
        />
        <div
          className="absolute top-0 bottom-0 right-0 w-px opacity-[0.10]"
          style={{
            backgroundImage:
              "linear-gradient(to bottom, rgba(255,255,255,0.8) 50%, transparent 0)",
            backgroundSize: "1px 6px",
          }}
        />
      </div>
    </div>
  )
}

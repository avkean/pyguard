export default function Footer() {
  return (
    <footer className="relative z-10 w-full mt-6">
      <div className="relative">
        <div className="absolute left-0 right-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
        <div className="max-w-[1180px] mx-auto px-5 md:px-8 h-9 flex items-center justify-between text-[10.5px] text-white/35 font-mono tracking-wide">
          <span>
            &copy; {new Date().getFullYear()}{" "}
            <a
              href="https://github.com/InsanelyAvner"
              target="_blank"
              rel="noreferrer"
              className="hover:text-white/70 transition-colors"
            >
              avner
            </a>
          </span>
          <span className="hidden sm:inline text-white/30">
            obfuscation is not encryption &nbsp;·&nbsp;{" "}
            <a
              href="https://github.com/InsanelyAvner/pyguard#security-what-pyguard-actually-defends-against"
              target="_blank"
              rel="noreferrer"
              className="hover:text-white/70 underline underline-offset-2 decoration-white/15"
            >
              threat model
            </a>
          </span>
        </div>
      </div>
    </footer>
  )
}

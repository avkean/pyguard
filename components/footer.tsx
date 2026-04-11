export default function Footer() {
  return (
    <footer className="relative z-10 w-full border-t border-line mt-16">
      <div className="max-w-[1180px] mx-auto px-5 md:px-8 h-12 flex items-center justify-between text-[11px] text-ink-dim">
        <span className="font-sans">
          &copy; {new Date().getFullYear()}{" "}
          <a
            href="https://github.com/InsanelyAvner"
            target="_blank"
            rel="noreferrer"
            className="hover:text-ink-muted transition-colors"
          >
            Avner Yeoh
          </a>
        </span>
        <span className="hidden sm:inline text-ink-dim">
          Obfuscation is not encryption.{" "}
          <a
            href="https://github.com/InsanelyAvner/pyguard#security-what-pyguard-actually-defends-against"
            target="_blank"
            rel="noreferrer"
            className="text-ink-muted hover:text-ink underline underline-offset-2 decoration-line-strong transition-colors"
          >
            Read the threat model &rarr;
          </a>
        </span>
      </div>
    </footer>
  )
}

"use client"

// Next.js global-error: used when even the root layout throws. Must
// render its own <html>/<body>. Keep it dependency-free so it can never
// itself crash.

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <html>
      <body
        style={{
          background: "#070708",
          color: "#ffffff",
          fontFamily:
            "ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "24px",
        }}
      >
        <div
          style={{
            maxWidth: "480px",
            width: "100%",
            border: "1px solid rgba(239,68,68,0.2)",
            background: "rgba(239,68,68,0.05)",
            borderRadius: "12px",
            padding: "24px",
          }}
        >
          <h2
            style={{
              fontSize: "14px",
              fontWeight: 500,
              color: "rgb(252,165,165)",
              marginBottom: "8px",
              marginTop: 0,
            }}
          >
            Fatal error
          </h2>
          <p
            style={{
              fontSize: "12px",
              color: "rgba(254,202,202,0.7)",
              fontFamily:
                "ui-monospace, SFMono-Regular, Menlo, Monaco, monospace",
              wordBreak: "break-word",
              margin: "0 0 16px",
            }}
          >
            {error?.message || "An unexpected error occurred."}
          </p>
          <button
            onClick={() => reset()}
            style={{
              height: "32px",
              padding: "0 12px",
              borderRadius: "6px",
              background: "rgba(255,255,255,0.1)",
              color: "#ffffff",
              border: "none",
              fontSize: "12px",
              fontWeight: 500,
              cursor: "pointer",
            }}
          >
            Reload
          </button>
        </div>
      </body>
    </html>
  )
}

// Minimal per-IP sliding-window rate limiter for Node-runtime API routes.
//
// Intentionally process-local: the obfuscate endpoint is CPU-bound (1–30 s
// per request end-to-end), so a single Node worker is the natural back-pressure
// point and external state stores (Redis, etc.) would add more moving parts
// than the limiter is worth. Horizontal scaling can sit behind per-replica
// limits plus reverse-proxy caps.

type Bucket = { windowStart: number; count: number };

export interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    resetAt: number; // epoch ms when the current window ends
}

export interface RateLimiterConfig {
    capacity: number;    // max requests per window per key
    windowMs: number;    // window length
    maxTrackedKeys?: number; // cap memory by evicting oldest idle keys
}

export function createRateLimiter(cfg: RateLimiterConfig) {
    const capacity = cfg.capacity;
    const windowMs = cfg.windowMs;
    const maxKeys = cfg.maxTrackedKeys ?? 10_000;
    const buckets = new Map<string, Bucket>();

    function prune(now: number) {
        if (buckets.size <= maxKeys) return;
        // Evict keys whose window has already elapsed. If that's not enough,
        // evict the oldest by insertion order (Map preserves it).
        for (const [k, b] of buckets) {
            if (now - b.windowStart >= windowMs) buckets.delete(k);
            if (buckets.size <= maxKeys) return;
        }
        const overflow = buckets.size - maxKeys;
        let i = 0;
        for (const k of buckets.keys()) {
            if (i++ >= overflow) break;
            buckets.delete(k);
        }
    }

    return function take(key: string): RateLimitResult {
        const now = Date.now();
        let b = buckets.get(key);
        if (!b || now - b.windowStart >= windowMs) {
            b = { windowStart: now, count: 0 };
            buckets.set(key, b);
            prune(now);
        }
        b.count += 1;
        const allowed = b.count <= capacity;
        return {
            allowed,
            remaining: Math.max(0, capacity - b.count),
            resetAt: b.windowStart + windowMs,
        };
    };
}

// Best-effort client-IP extraction. Trusts x-forwarded-for only as a hint;
// behind a reverse proxy set TRUSTED_PROXY=1 to use the leftmost hop.
export function clientIp(headers: Headers, remote: string | null): string {
    if (process.env.TRUSTED_PROXY === "1") {
        const xff = headers.get("x-forwarded-for");
        if (xff) {
            const first = xff.split(",")[0]?.trim();
            if (first) return first;
        }
        const real = headers.get("x-real-ip");
        if (real) return real.trim();
    }
    return remote || "unknown";
}

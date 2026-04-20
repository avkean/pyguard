import { NextRequest, NextResponse } from "next/server";
import { spawnSync } from "node:child_process";
import zlib from "node:zlib";
import path from "node:path";
import { obfuscatePythonCode } from "@/lib/obfuscate";
import { makeV5Schema } from "@/lib/v5/schema";
import { INTERPRETER_SRC_B64 } from "@/lib/v5/interpreter_src";
import {
    discoverPythons,
    createCompileAndMarshal,
} from "@/scripts/multi_marshal.mjs";

// ---------------------------------------------------------------------------
// Route config
// ---------------------------------------------------------------------------

export const runtime = "nodejs";
export const maxDuration = 60;

/** Refuse pathologically large inputs upfront (both to avoid DoS and because
 *  the obfuscator's own complexity becomes quadratic above this). */
const MAX_SOURCE_BYTES = 1_000_000;

const BUILD_IR_PATH = path.join(process.cwd(), "lib/v5/build_ir.py");

const LZMA_COMPRESS_SNIPPET = [
    "import sys, lzma",
    "sys.stdout.buffer.write(",
    "    lzma.compress(sys.stdin.buffer.read(),",
    "                  preset=9 | lzma.PRESET_EXTREME))",
].join("\n");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type PyInfo = { bin: string; major: number; minor: number };
type ErrorKind = "syntax" | "python" | "internal";

function jsonError(
    status: number,
    message: string,
    kind: ErrorKind = "internal",
) {
    return NextResponse.json({ error: message, kind }, { status });
}

function makeLzmaCompressor(pyBin: string): (b: Uint8Array) => Uint8Array {
    return (bytes) => {
        const r = spawnSync(pyBin, ["-c", LZMA_COMPRESS_SNIPPET], {
            input: Buffer.from(bytes),
            maxBuffer: 256 * 1024 * 1024,
        });
        if (r.status !== 0) {
            throw new Error(`lzma compress failed: ${r.stderr?.toString()}`);
        }
        return Uint8Array.from(r.stdout);
    };
}

/** Normalize Python's `SyntaxError: (...)` traceback to something the UI can
 *  render without the `<stdin>` / `<unknown>` noise. */
function formatPyError(stderr: string): { message: string; kind: ErrorKind } {
    const lines = stderr
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
    const last = lines[lines.length - 1] || "build_ir failed";
    const isSyntax = /^(SyntaxError|IndentationError|TabError)\b/.test(last);
    return {
        message: last.replace(/\(<(?:unknown|stdin)>,\s*/, "("),
        kind: isSyntax ? "syntax" : "python",
    };
}

function parseSource(body: unknown): string | NextResponse {
    if (typeof body !== "object" || body === null) {
        return jsonError(400, "invalid JSON body");
    }
    const source = (body as { source?: unknown }).source;
    if (typeof source !== "string" || !source.trim()) {
        return jsonError(400, "source required");
    }
    if (Buffer.byteLength(source, "utf-8") > MAX_SOURCE_BYTES) {
        return jsonError(413, `source exceeds ${MAX_SOURCE_BYTES} bytes`);
    }
    return source;
}

// ---------------------------------------------------------------------------
// Toolchain discovery (cached for the lifetime of the Node process)
// ---------------------------------------------------------------------------

let cachedPythons: PyInfo[] | null = null;

function getPythons(): PyInfo[] {
    if (cachedPythons) return cachedPythons;
    const found = discoverPythons() as PyInfo[];
    if (found.length === 0) {
        throw new Error("no CPython toolchains discovered on server");
    }
    cachedPythons = found;
    return found;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
    // 1. Validate input
    let body: unknown;
    try {
        body = await req.json();
    } catch {
        return jsonError(400, "invalid JSON body");
    }
    const maybeSource = parseSource(body);
    if (maybeSource instanceof NextResponse) return maybeSource;
    const source = maybeSource;

    // 2. Discover toolchains
    let pythons: PyInfo[];
    try {
        pythons = getPythons();
    } catch (e) {
        return jsonError(
            500,
            `server build toolchain missing: ${
                e instanceof Error ? e.message : String(e)
            }`,
        );
    }

    // 3. Lift user source → IR (any single discovered Python works — the
    //    emitted IR is marshal-independent JSON).
    const schema = makeV5Schema();
    const ir = spawnSync(pythons[0].bin, [BUILD_IR_PATH], {
        input: source,
        encoding: "utf-8",
        env: { ...process.env, PYGUARD_V5_SCHEMA: JSON.stringify(schema) },
        maxBuffer: 64 * 1024 * 1024,
    });
    if (ir.status !== 0) {
        const { message, kind } = formatPyError(ir.stderr || "");
        return jsonError(400, message, kind);
    }

    let artifacts: { compressed: string; manifest: string };
    try {
        artifacts = JSON.parse((ir.stdout || "").trim());
    } catch (e) {
        return jsonError(
            500,
            `build_ir output invalid: ${
                e instanceof Error ? e.message : String(e)
            }`,
        );
    }

    // 4. Compile + marshal the interpreter for every discovered CPython minor
    //    and LZMA-compress the resulting PGMV blob.
    let interpMarshalCompressed: Uint8Array;
    let compileAndMarshal: (src: string, fn?: string) => Uint8Array;
    const compress = makeLzmaCompressor(pythons[0].bin);
    try {
        compileAndMarshal = createCompileAndMarshal(pythons);
        const interpSrc = zlib
            .inflateRawSync(Buffer.from(INTERPRETER_SRC_B64, "base64"))
            .toString("utf-8");
        interpMarshalCompressed = compress(
            compileAndMarshal(interpSrc, "<pg_interp>"),
        );
    } catch (e) {
        return jsonError(
            500,
            `interpreter compile failed: ${
                e instanceof Error ? e.message : String(e)
            }`,
        );
    }

    // 5. Produce the stub
    let stub: string;
    try {
        stub = obfuscatePythonCode(source, {
            v5IR: {
                compressed: Uint8Array.from(
                    Buffer.from(artifacts.compressed, "base64"),
                ),
                manifest: Uint8Array.from(
                    Buffer.from(artifacts.manifest, "base64"),
                ),
                schema,
            },
            compileAndMarshal,
            interpreterMarshalCompressed: interpMarshalCompressed,
            compress,
        });
    } catch (e) {
        return jsonError(500, e instanceof Error ? e.message : String(e));
    }

    return new NextResponse(stub, {
        status: 200,
        headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "X-PyGuard-Targets": pythons
                .map((p) => `${p.major}.${p.minor}`)
                .join(","),
        },
    });
}

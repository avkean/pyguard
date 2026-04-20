import { NextRequest, NextResponse } from "next/server";
import { spawnSync } from "node:child_process";
import zlib from "node:zlib";
import path from "node:path";
import { obfuscatePythonCode } from "@/lib/obfuscate";
import { makeV5Schema } from "@/lib/v5/schema";
import { INTERPRETER_SRC_B64 } from "@/lib/v5/interpreter_src";
import { discoverPythons, createCompileAndMarshal } from "@/scripts/multi_marshal.mjs";

function makeLzmaCompressor(pyBin: string): (b: Uint8Array) => Uint8Array {
    return (bytes: Uint8Array) => {
        const r = spawnSync(
            pyBin,
            [
                "-c",
                "import sys, lzma; sys.stdout.buffer.write(lzma.compress(sys.stdin.buffer.read(), preset=9|lzma.PRESET_EXTREME))",
            ],
            { input: Buffer.from(bytes), maxBuffer: 256 * 1024 * 1024 },
        );
        if (r.status !== 0) {
            throw new Error(`lzma compress failed: ${r.stderr?.toString()}`);
        }
        return Uint8Array.from(r.stdout);
    };
}

export const runtime = "nodejs";
export const maxDuration = 60;

const BUILD_IR_PATH = path.join(process.cwd(), "lib/v5/build_ir.py");

// Cap input source to a sane size (users uploading 10 MB files aren't
// doing legitimate work — the obfuscator also gets slow there).
const MAX_SOURCE_BYTES = 1_000_000;

type PyInfo = { bin: string; major: number; minor: number };

export async function POST(req: NextRequest) {
    let source: string;
    try {
        const body = await req.json();
        source = body?.source;
        if (typeof source !== "string" || !source.trim()) {
            return NextResponse.json(
                { error: "source required", kind: "internal" },
                { status: 400 },
            );
        }
        if (Buffer.byteLength(source, "utf-8") > MAX_SOURCE_BYTES) {
            return NextResponse.json(
                {
                    error: `source exceeds ${MAX_SOURCE_BYTES} bytes`,
                    kind: "internal",
                },
                { status: 413 },
            );
        }
    } catch {
        return NextResponse.json(
            { error: "invalid JSON body", kind: "internal" },
            { status: 400 },
        );
    }

    let pythons: PyInfo[];
    try {
        pythons = discoverPythons();
        if (pythons.length === 0) {
            throw new Error("no CPython toolchains discovered on server");
        }
    } catch (e) {
        return NextResponse.json(
            {
                error: `server build toolchain missing: ${
                    e instanceof Error ? e.message : String(e)
                }`,
                kind: "internal",
            },
            { status: 500 },
        );
    }

    // Step 1: lift user source to IR via build_ir.py (any discovered
    // Python works — IR is marshal-independent JSON).
    const schema = makeV5Schema();
    const ir = spawnSync(pythons[0].bin, [BUILD_IR_PATH], {
        input: source,
        encoding: "utf-8",
        env: { ...process.env, PYGUARD_V5_SCHEMA: JSON.stringify(schema) },
        maxBuffer: 64 * 1024 * 1024,
    });
    if (ir.status !== 0) {
        const tail = (ir.stderr || "")
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter(Boolean);
        const last = tail[tail.length - 1] || "build_ir failed";
        const isSyntax = /^(SyntaxError|IndentationError|TabError)\b/.test(
            last,
        );
        return NextResponse.json(
            {
                error: last.replace(/\(<(?:unknown|stdin)>,\s*/, "("),
                kind: isSyntax ? "syntax" : "python",
            },
            { status: 400 },
        );
    }

    let artifacts: { compressed: string; manifest: string };
    try {
        artifacts = JSON.parse((ir.stdout || "").trim());
    } catch (e) {
        return NextResponse.json(
            {
                error: `build_ir output invalid: ${
                    e instanceof Error ? e.message : String(e)
                }`,
                kind: "internal",
            },
            { status: 500 },
        );
    }

    // Step 2: compile+marshal the interpreter source for every discovered
    // Python minor, wrap as PGMV, deflate. One scan of `pythons` drives
    // every per-minor subprocess (interpreter + stage1 + stage2).
    let interpMarshalCompressed: Uint8Array;
    let compileAndMarshal: (src: string, fn?: string) => Uint8Array;
    const compress = makeLzmaCompressor(pythons[0].bin);
    try {
        compileAndMarshal = createCompileAndMarshal(pythons);
        const interpSrc = zlib
            .inflateRawSync(Buffer.from(INTERPRETER_SRC_B64, "base64"))
            .toString("utf-8");
        const interpMarshalRaw = compileAndMarshal(interpSrc, "<pg_interp>");
        interpMarshalCompressed = compress(interpMarshalRaw);
    } catch (e) {
        return NextResponse.json(
            {
                error: `interpreter compile failed: ${
                    e instanceof Error ? e.message : String(e)
                }`,
                kind: "internal",
            },
            { status: 500 },
        );
    }

    // Step 3: produce the stub.
    let stub: string;
    try {
        const compressed = Uint8Array.from(
            Buffer.from(artifacts.compressed, "base64"),
        );
        const manifest = Uint8Array.from(
            Buffer.from(artifacts.manifest, "base64"),
        );
        stub = obfuscatePythonCode(source, {
            v5IR: { compressed, manifest, schema },
            compileAndMarshal,
            interpreterMarshalCompressed: interpMarshalCompressed,
            compress,
        });
    } catch (e) {
        return NextResponse.json(
            {
                error: e instanceof Error ? e.message : String(e),
                kind: "internal",
            },
            { status: 500 },
        );
    }

    const versions = pythons.map((p) => `${p.major}.${p.minor}`).join(",");
    return new NextResponse(stub, {
        status: 200,
        headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "X-PyGuard-Targets": versions,
        },
    });
}

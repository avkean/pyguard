// tests/run_tests.ts
//
// Compatibility test harness for the PyGuard obfuscator.
//
// For each .py file in tests/cases/:
//   1. Compile it to v5 IR via lib/v5/build_ir.py.
//   2. Obfuscate it through the v5 path.
//   3. Write the obfuscated source to tests/out_v5/<name>.py.
//   3. Execute the original with python3, capture stdout/stderr/exit.
//   4. Execute the obfuscated stub with python3, capture the same.
//   5. Compare. PASS if outputs and exit codes match exactly.
//
// Run with: ./node_modules/.bin/sucrase-node tests/run_tests.ts

import * as fs from "fs";
import * as path from "path";
import * as zlib from "zlib";
import { execFileSync } from "child_process";
import { obfuscatePythonCode } from "../lib/obfuscate";
import { makeV5Schema } from "../lib/v5/schema";
import { INTERPRETER_SRC_B64 } from "../lib/v5/interpreter_src";
import type { V5IR } from "../lib/v5/assemble";

const ROOT = path.resolve(__dirname, "..");
const CASES_DIR = path.join(ROOT, "tests", "cases");
const OUT_DIR = path.join(ROOT, "tests", "out_v5");

interface RunResult {
    stdout: string;
    stderr: string;
    code: number;
}

function runPython(file: string, timeoutMs = 15000): RunResult {
    try {
        const stdout = execFileSync("python3", [file], {
            timeout: timeoutMs,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
        });
        return { stdout, stderr: "", code: 0 };
    } catch (err: any) {
        return {
            stdout: err.stdout?.toString() ?? "",
            stderr: err.stderr?.toString() ?? String(err.message ?? err),
            code: typeof err.status === "number" ? err.status : -1,
        };
    }
}

function buildV5IR(source: string, schema: object): V5IR {
    const out = execFileSync("python3", [path.join(ROOT, "lib", "v5", "build_ir.py")], {
        input: source,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
        maxBuffer: 32 * 1024 * 1024,
        env: { ...process.env, PYGUARD_V5_SCHEMA: JSON.stringify(schema) },
    }).trim();
    const parsed = JSON.parse(out);
    return {
        compressed: Uint8Array.from(Buffer.from(parsed.compressed, "base64")),
        manifest: Uint8Array.from(Buffer.from(parsed.manifest, "base64")),
        schema: schema as any,
    };
}

// Multi-version marshal packer. Mirrors scripts/multi_marshal.mjs so the
// test harness is agnostic to the Python minor it runs under — every
// compiled stub carries marshal blobs for every discovered CPython
// toolchain on the build host, wrapped in a PGMV container.
interface PyBuild { bin: string; major: number; minor: number; }

function probePy(bin: string): PyBuild | null {
    try {
        const out = execFileSync(bin, ["-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"], {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
        }).trim();
        const m = out.match(/^(\d+)\.(\d+)$/);
        if (!m) return null;
        return { bin, major: parseInt(m[1], 10), minor: parseInt(m[2], 10) };
    } catch {
        return null;
    }
}

function discoverPythons(): PyBuild[] {
    const seen = new Map<string, PyBuild>();
    const add = (bin: string) => {
        const info = probePy(bin);
        if (!info) return;
        const key = `${info.major}.${info.minor}`;
        if (!seen.has(key)) seen.set(key, info);
    };
    const envList = process.env.PYGUARD_PYTHON_BINS;
    if (envList) {
        for (const b of envList.split(":").filter(Boolean)) add(b);
    } else {
        const minors = ["3.9", "3.10", "3.11", "3.12", "3.13", "3.14"];
        for (const v of minors) {
            for (const c of [
                `/opt/homebrew/opt/python@${v}/bin/python${v}`,
                `/opt/homebrew/bin/python${v}`,
                `/usr/local/opt/python@${v}/bin/python${v}`,
                `/usr/local/bin/python${v}`,
                `/usr/bin/python${v}`,
                `${process.env.HOME || ""}/.local/bin/python${v}`,
                `python${v}`,
            ]) add(c);
        }
        add("python3");
    }
    return Array.from(seen.values()).sort((a, b) =>
        a.major !== b.major ? a.major - b.major : a.minor - b.minor,
    );
}

const PYTHONS = discoverPythons();
if (PYTHONS.length === 0) throw new Error("no Python build toolchains discovered");

function compileAndMarshalOne(py: PyBuild, source: string, filename: string): { major: number; minor: number; bytes: Uint8Array } {
    const out = execFileSync(py.bin, [path.join(ROOT, "lib", "v5", "build_ir.py")], {
        input: source,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
        maxBuffer: 64 * 1024 * 1024,
        env: {
            ...process.env,
            PYGUARD_MODE: "marshal",
            PYGUARD_FILENAME: filename,
        },
    }).trim();
    const buf = Buffer.from(out, "base64");
    if (buf.length < 6 || buf[0] !== 0x50 || buf[1] !== 0x47 || buf[2] !== 0x4d || buf[3] !== 0x31) {
        throw new Error(`compile_and_marshal: missing PGM1 tag from ${py.bin}`);
    }
    return { major: buf[4], minor: buf[5], bytes: Uint8Array.from(buf.subarray(6)) };
}

function packPGMV(entries: { major: number; minor: number; bytes: Uint8Array }[]): Uint8Array {
    if (entries.length === 0 || entries.length > 255) throw new Error("packPGMV: invalid entry count");
    let total = 5;
    for (const e of entries) total += 6 + e.bytes.length;
    const out = new Uint8Array(total);
    out[0] = 0x50; out[1] = 0x47; out[2] = 0x4d; out[3] = 0x56;
    out[4] = entries.length;
    let off = 5;
    for (const e of entries) {
        out[off] = e.major & 0xff;
        out[off + 1] = e.minor & 0xff;
        const L = e.bytes.length;
        out[off + 2] = L & 0xff;
        out[off + 3] = (L >>> 8) & 0xff;
        out[off + 4] = (L >>> 16) & 0xff;
        out[off + 5] = (L >>> 24) & 0xff;
        off += 6;
        out.set(e.bytes, off);
        off += e.bytes.length;
    }
    return out;
}

function compileAndMarshal(source: string, filename?: string): Uint8Array {
    const entries: { major: number; minor: number; bytes: Uint8Array }[] = [];
    const seen = new Set<string>();
    for (const py of PYTHONS) {
        const e = compileAndMarshalOne(py, source, filename ?? "<pg>");
        const key = `${e.major}.${e.minor}`;
        if (seen.has(key)) continue;
        seen.add(key);
        entries.push(e);
    }
    return packPGMV(entries);
}

function prepareInterpreterMarshalCompressed(): Uint8Array {
    const src = zlib.inflateRawSync(Buffer.from(INTERPRETER_SRC_B64, "base64")).toString("utf-8");
    const marshaled = compileAndMarshal(src, "<pg_interp>");
    return Uint8Array.from(zlib.deflateRawSync(Buffer.from(marshaled)));
}

function main() {
    if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

    // One-shot: marshal the interpreter for this run. The bytes are
    // identical across every test case, so we pay the subprocess cost
    // once rather than per test.
    const interpreterMarshalCompressed = prepareInterpreterMarshalCompressed();

    const cases = fs
        .readdirSync(CASES_DIR)
        .filter((f) => f.endsWith(".py"))
        .sort();

    let pass = 0;
    let fail = 0;
    const failures: string[] = [];

    for (const name of cases) {
        const srcPath = path.join(CASES_DIR, name);
        const src = fs.readFileSync(srcPath, "utf8");
        const schema = makeV5Schema();

        const obf = obfuscatePythonCode(src, {
            v5IR: buildV5IR(src, schema),
            compileAndMarshal,
            interpreterMarshalCompressed,
        });
        const outPath = path.join(OUT_DIR, name);
        fs.writeFileSync(outPath, obf);

        const expected = runPython(srcPath);
        const actual = runPython(outPath);

        const ok =
            expected.stdout === actual.stdout &&
            expected.code === actual.code;

        if (ok) {
            pass++;
            console.log(`PASS  ${name}`);
        } else {
            fail++;
            failures.push(name);
            console.log(`FAIL  ${name}`);
            console.log(`  expected.code=${expected.code}  actual.code=${actual.code}`);
            console.log(`  expected.stdout=${JSON.stringify(expected.stdout)}`);
            console.log(`  actual.stdout=${JSON.stringify(actual.stdout)}`);
            if (actual.stderr.trim()) {
                console.log(`  actual.stderr=${actual.stderr.trim().split("\n").slice(-10).join("\n  ")}`);
            }
        }
    }

    console.log(`\n${pass} passed, ${fail} failed (of ${cases.length})`);
    if (fail > 0) {
        console.log("failures:", failures.join(", "));
        process.exit(1);
    }
}

main();

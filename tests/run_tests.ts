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

function lzmaCompress(bytes: Uint8Array): Uint8Array {
    const r = execFileSync(
        PYTHONS[0].bin,
        ["-c", "import sys, lzma; sys.stdout.buffer.write(lzma.compress(sys.stdin.buffer.read(), preset=9|lzma.PRESET_EXTREME))"],
        { input: Buffer.from(bytes), maxBuffer: 256 * 1024 * 1024 },
    );
    return Uint8Array.from(r);
}

function prepareInterpreterSourceCompressed(): Uint8Array {
    const src = zlib.inflateRawSync(Buffer.from(INTERPRETER_SRC_B64, "base64"));
    return lzmaCompress(src);
}

function main() {
    if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

    const interpreterSourceCompressed = prepareInterpreterSourceCompressed();

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
            interpreterSourceCompressed,
            compress: lzmaCompress,
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

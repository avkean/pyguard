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

function buildV5IR(source: string, schema: object): Uint8Array {
    const out = execFileSync("python3", [path.join(ROOT, "lib", "v5", "build_ir.py")], {
        input: source,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
        maxBuffer: 32 * 1024 * 1024,
        env: { ...process.env, PYGUARD_V5_SCHEMA: JSON.stringify(schema) },
    }).trim();
    return Uint8Array.from(Buffer.from(out, "base64"));
}

// v7: stage1/stage2/interpreter are shipped as marshaled code objects,
// so the harness shells out to python3 to do compile+marshal.dumps and
// pre-computes the interpreter's marshaled+zlib blob once per run.
function compileAndMarshal(source: string, filename?: string): Uint8Array {
    const out = execFileSync("python3", [path.join(ROOT, "lib", "v5", "build_ir.py")], {
        input: source,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
        maxBuffer: 64 * 1024 * 1024,
        env: {
            ...process.env,
            PYGUARD_MODE: "marshal",
            PYGUARD_FILENAME: filename ?? "<pg>",
        },
    }).trim();
    return Uint8Array.from(Buffer.from(out, "base64"));
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
            v5IR: { compressed: buildV5IR(src, schema), schema },
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

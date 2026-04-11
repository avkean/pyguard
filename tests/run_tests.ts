// tests/run_tests.ts
//
// Compatibility test harness for the PyGuard obfuscator.
//
// For each .py file in tests/cases/:
//   1. Run it through the obfuscator.
//   2. Write the obfuscated source to tests/out/<name>.py.
//   3. Execute the original with python3, capture stdout/stderr/exit.
//   4. Execute the obfuscated stub with python3, capture the same.
//   5. Compare. PASS if outputs and exit codes match exactly.
//
// Run with: ./node_modules/.bin/sucrase-node tests/run_tests.ts

import * as fs from "fs";
import * as path from "path";
import { execFileSync } from "child_process";
import { obfuscatePythonCode } from "../lib/obfuscate";

const ROOT = path.resolve(__dirname, "..");
const CASES_DIR = path.join(ROOT, "tests", "cases");
const OUT_DIR = path.join(ROOT, "tests", "out");

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

function main() {
    if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

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

        const obf = obfuscatePythonCode(src);
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

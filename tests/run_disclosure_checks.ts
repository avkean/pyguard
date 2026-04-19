import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";

const ROOT = path.resolve(__dirname, "..");

function runCmd(cmd: string, args: string[], maxBuffer = 64 * 1024 * 1024): string {
    return execFileSync(cmd, args, {
        cwd: ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        maxBuffer,
    });
}

function buildStub(srcPath: string, outPath: string): void {
    runCmd("node", ["--import", "tsx", path.join(ROOT, "scripts", "gen-v5-stub.mjs"), srcPath, "-o", outPath]);
}

function assertNoCompileLeak(stubPath: string): void {
    const out = runCmd("python3", [path.join(ROOT, "tests", "pentest", "attack8_audit_hook_dumper.py"), stubPath]);
    const forbidden = [
        "compile filename='<pg_s1>'",
        "compile filename='<pg_s2>'",
        "compile filename='<pg_i>'",
    ];
    for (const needle of forbidden) {
        if (out.includes(needle)) {
            throw new Error(`compile-audit disclosure regression: saw ${needle}`);
        }
    }
}

function assertImportProxyHeld(stubPath: string, fingerprint: string): void {
    const out = runCmd("python3", [path.join(ROOT, "tests", "pentest", "c18_attack_sysmodules_proxy.py"), stubPath]);
    if (out.includes(fingerprint)) {
        throw new Error(`import-proxy disclosure regression: recovered ${fingerprint}`);
    }
}

function main(): void {
    const td = fs.mkdtempSync(path.join(os.tmpdir(), "pyguard-disclosure-"));
    try {
        const auditStub = path.join(td, "01_print.py");
        buildStub(path.join(ROOT, "tests", "cases", "01_print.py"), auditStub);
        assertNoCompileLeak(auditStub);
        console.log("PASS  audit leak gate");

        const cases: Array<[string, string]> = [
            ["06_imports_stdlib.py", "from collections import Counter"],
            // `dataclasses` and `typing` both perform broad reflective stdlib
            // traffic once imported, so their naked import lines are poor
            // discriminators for user-source recovery under a late
            // sys.modules proxy. This fixture uses a user-specific class-body
            // line instead: if the attack cannot recover this, it still has
            // not reconstructed a small clean equivalent program.
            ["09_dataclass_and_typing.py", "tags: List[str] = field(default_factory=list)"],
            ["14_lambda_and_higher_order.py", "from functools import reduce"],
        ];
        for (const [name, fingerprint] of cases) {
            const stubPath = path.join(td, name);
            buildStub(path.join(ROOT, "tests", "cases", name), stubPath);
            assertImportProxyHeld(stubPath, fingerprint);
            console.log(`PASS  ${name}`);
        }
    } finally {
        try {
            fs.rmSync(td, { recursive: true, force: true });
        } catch {}
    }
}

main();

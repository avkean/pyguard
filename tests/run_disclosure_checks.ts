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

function assertSemanticIslands(srcPath: string, expectedCount: number, minLargestPayloadBytes: number): void {
    const script = `
from pathlib import Path
from lib.v5.build_ir import compile_to_json

src = Path(${JSON.stringify(srcPath)}).read_text()
payload, _manifest = compile_to_json(src)
stack = [payload[2]]
count = 0
largest = 0
while stack:
    cur = stack.pop()
    if isinstance(cur, dict):
        if cur.get('op') == 'IIsland':
            count += 1
            largest = max(largest, len(cur.get('payload', ())))
        for v in cur.values():
            if isinstance(v, (dict, list)):
                stack.append(v)
    elif isinstance(cur, list):
        stack.extend(cur)
print(count, largest)
`;
    const out = runCmd("python3", ["-c", script]).trim().split(/\s+/);
    const count = Number(out[0]);
    const largest = Number(out[1]);
    if (!Number.isFinite(count) || count !== expectedCount) {
        throw new Error(`semantic-island regression: expected ${expectedCount} decisive island(s), saw ${out.join(" ")}`);
    }
    if (!Number.isFinite(largest) || largest < minLargestPayloadBytes) {
        throw new Error(`semantic-island regression: expected largest payload >= ${minLargestPayloadBytes} bytes, saw ${out.join(" ")}`);
    }
}

function assertNoPlainIslandDisclosure(srcPath: string, forbidden: string[]): void {
    const script = `
from pathlib import Path
import ast, json
from lib.v5.transform_ast import transform_ast_tree

src = Path(${JSON.stringify(srcPath)}).read_text()
tree = transform_ast_tree(ast.parse(src))
payloads = []
for node in ast.walk(tree):
    if isinstance(node, ast.Call) and isinstance(getattr(node, 'func', None), ast.Name):
        if node.func.id == '__pyguard_semantic_island__' and len(getattr(node, 'args', ())) == 1:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, (bytes, bytearray)):
                payloads.append(bytes(arg.value))
print(json.dumps([p.hex() for p in payloads]))
`;
    const payloads = JSON.parse(runCmd("python3", ["-c", script])) as string[];
    for (const hex of payloads) {
        const raw = Buffer.from(hex, "hex");
        for (const needle of forbidden) {
            if (raw.includes(Buffer.from(needle, "utf8"))) {
                throw new Error(`semantic-island disclosure regression: payload still contains ${JSON.stringify(needle)}`);
            }
        }
    }
}

function main(): void {
    const td = fs.mkdtempSync(path.join(os.tmpdir(), "pyguard-disclosure-"));
    try {
        assertSemanticIslands(path.join(ROOT, "tests", "test_rev", "dist.py"), 1, 400);
        console.log("PASS  semantic island closure");
        assertNoPlainIslandDisclosure(path.join(ROOT, "tests", "test_rev", "dist.py"), [
            "EC3{REDACTED}",
            "Congratulations!",
            "rock",
            "paper",
            "scissors",
            "Invalid input.",
        ]);
        console.log("PASS  semantic island payload disclosure");

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

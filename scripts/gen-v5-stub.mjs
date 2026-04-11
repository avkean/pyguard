#!/usr/bin/env node
// scripts/gen-v5-stub.mjs
//
// End-to-end v5 stub generation for local testing.
//
// 1. Shell out to `python3 lib/v5/build_ir.py` to compile user source → IR JSON.
// 2. Run lib/obfuscate.ts (via tsx) with opts.v5IR to produce the stub.
// 3. Write the stub to stdout (or to a file with -o).
//
// Usage:
//   node scripts/gen-v5-stub.mjs tests/cases/01_print.py > out.py
//   node scripts/gen-v5-stub.mjs tests/cases/02_function_calls_function.py -o out.py

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

function parseArgs(argv) {
    const args = { src: null, out: null };
    for (let i = 2; i < argv.length; i++) {
        const a = argv[i];
        if (a === '-o' || a === '--out') {
            args.out = argv[++i];
        } else if (a.startsWith('-')) {
            console.error(`unknown flag: ${a}`);
            process.exit(2);
        } else if (!args.src) {
            args.src = a;
        }
    }
    if (!args.src) {
        console.error('usage: gen-v5-stub.mjs <source.py> [-o <out.py>]');
        process.exit(2);
    }
    return args;
}

const args = parseArgs(process.argv);
const userSource = fs.readFileSync(args.src, 'utf-8');

// Step 1: compile IR via python3 + build_ir.py.
// build_ir's __main__ reads source from stdin and writes base64(zlib(JSON))
// to stdout — the TS obfuscator treats these bytes as an opaque blob.
const py = spawnSync('python3', [path.join(root, 'lib/v5/build_ir.py')], {
    input: userSource,
    encoding: 'utf-8',
});
if (py.status !== 0) {
    console.error('build_ir.py failed:');
    console.error(py.stderr);
    process.exit(py.status || 1);
}
const irCompressedB64 = py.stdout.trim();

// Step 2: call the TS obfuscator. We use tsx to run the TS directly.
// To avoid process overhead, write a tiny driver script that imports
// obfuscate, calls it, and prints the result.
// Note: static imports of .ts files break under Node 24's native type
// stripping (the re-export graph ends up empty). Dynamic import via tsx
// works correctly, so we use that instead.
const driver = `
const { obfuscatePythonCode } = await import('./lib/obfuscate.ts');
const fs = await import('node:fs');
const userSource = fs.readFileSync(${JSON.stringify(args.src)}, 'utf-8');
const compressed = Uint8Array.from(Buffer.from(${JSON.stringify(irCompressedB64)}, 'base64'));
const stub = obfuscatePythonCode(userSource, { v5IR: { compressed } });
process.stdout.write(stub);
`;

const driverPath = path.join(root, '.v5-driver.mjs');
fs.writeFileSync(driverPath, driver);
try {
    const ts = spawnSync(path.join(root, 'node_modules/.bin/tsx'), [driverPath], {
        cwd: root,
        encoding: 'utf-8',
        maxBuffer: 64 * 1024 * 1024,
    });
    if (ts.status !== 0) {
        console.error('tsx driver failed:');
        console.error(ts.stderr);
        process.exit(ts.status || 1);
    }
    const stub = ts.stdout;
    if (args.out) {
        fs.writeFileSync(args.out, stub);
        console.error(`wrote ${args.out} (${stub.length} chars)`);
    } else {
        process.stdout.write(stub);
    }
} finally {
    try { fs.unlinkSync(driverPath); } catch {}
}

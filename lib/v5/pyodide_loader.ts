// lib/v5/pyodide_loader.ts
//
// Browser-side Pyodide loader for v5 IR compilation.
//
// The v5 path needs Python's own `ast` module to lift user source into the
// interpreter's IR tree. Rather than shipping a hand-rolled parser to the
// browser, we load Pyodide on-demand, pipe `lib/v5/build_ir.py` into it,
// and call `compile_to_json(src)` through Pyodide's globals bridge.
//
// Pyodide is ~10 MB; we lazy-load it so non-v5 users and initial page paint
// don't pay that cost. The single cached instance is reused for subsequent
// obfuscations.
//
// This file is browser-only — do not import it from Node test harnesses.
// Node uses `python3 lib/v5/build_ir.py` directly via gen-v5-stub.mjs.

import { BUILD_IR_SRC } from './build_ir_src';
import type { V5IR } from './assemble';
import { makeV5Schema } from './schema';
import { obfuscatePythonCode } from '../obfuscate';
import { INTERPRETER_SRC_B64 } from './interpreter_src';

// Keep the Pyodide type surface minimal so we don't need @types/pyodide.
interface PyodideInstance {
    runPython(src: string): unknown;
    globals: {
        set(name: string, value: unknown): void;
        get(name: string): unknown;
    };
}

let pyodidePromise: Promise<PyodideInstance> | null = null;

// Pin the version so the browser loads the same Pyodide that matches the
// `pyodide` npm package in package.json. Bumping the npm package should
// bump this constant in the same commit.
const PYODIDE_VERSION = '0.29.3';
const PYODIDE_CDN = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;

// Dynamic script-tag load of pyodide.js. We deliberately do not import
// from the npm package: the npm 'pyodide' entry point uses Node's fs to
// locate its WASM assets, which breaks in the browser. Loading from the
// CDN is the officially supported browser path and gives us lock-step
// versioning with the WASM + stdlib zip.
function loadPyodideScript(): Promise<void> {
    return new Promise((resolve, reject) => {
        if (typeof window === 'undefined') {
            reject(new Error('pyodide_loader: must run in a browser'));
            return;
        }
        const w = window as unknown as { loadPyodide?: unknown };
        if (w.loadPyodide) {
            resolve();
            return;
        }
        const script = document.createElement('script');
        script.src = PYODIDE_CDN + 'pyodide.js';
        script.async = true;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error('failed to load pyodide.js from CDN'));
        document.head.appendChild(script);
    });
}

export async function getPyodide(): Promise<PyodideInstance> {
    if (pyodidePromise) return pyodidePromise;
    pyodidePromise = (async () => {
        await loadPyodideScript();
        const w = window as unknown as {
            loadPyodide: (opts: { indexURL: string }) => Promise<PyodideInstance>;
        };
        const py = await w.loadPyodide({ indexURL: PYODIDE_CDN });
        // Pipe build_ir.py into Pyodide's main namespace once so subsequent
        // calls only need to invoke compile_to_json(src).
        py.runPython(BUILD_IR_SRC);
        // v7+: install the compile_and_marshal helper so the browser side
        // can produce marshaled code-object bytes (same primitive the Node
        // driver shells out to python3 for). Pyodide ships marshal/zlib in
        // its stdlib, so this is a one-line definition with no extras.
        py.runPython(
            `import marshal as _pg_marshal, zlib as _pg_zlib, base64 as _pg_b64\n` +
            `def _pg_compile_marshal_b64(src, filename):\n` +
            `    return _pg_b64.b64encode(_pg_marshal.dumps(compile(src, filename, 'exec'))).decode('ascii')\n` +
            `def _pg_raw_deflate_b64(blob_b64):\n` +
            `    raw = _pg_b64.b64decode(blob_b64)\n` +
            `    co = _pg_zlib.compressobj(9, _pg_zlib.DEFLATED, -15)\n` +
            `    return _pg_b64.b64encode(co.compress(raw) + co.flush()).decode('ascii')\n`,
        );
        return py;
    })();
    return pyodidePromise;
}

// Call into Pyodide to lift `source` into a zlib-compressed IR byte blob.
// v5.2: compression happens inside Pyodide (where zlib is free) so the TS
// side doesn't need a JS zlib dependency. The blob is a raw-deflate of a
// JSON *list* `[strings, consts, tree]` — list (not dict) to defeat
// attack 12's frame-local heuristic (see lib/v5/build_ir.py).
// Custom error subclass so the UI layer can distinguish user-facing
// Python errors (syntax error in their source, unsupported feature, etc.)
// from infrastructure failures (Pyodide failed to load, internal bug).
export class BuildIRError extends Error {
    kind: 'syntax' | 'python' | 'internal';
    constructor(message: string, kind: 'syntax' | 'python' | 'internal') {
        super(message);
        this.name = 'BuildIRError';
        this.kind = kind;
    }
}

// Strip the noisy Pyodide/Emscripten traceback frames and pull out the
// last two meaningful lines (the error type + the caret line above it).
function cleanPyodideError(raw: string): { kind: 'syntax' | 'python'; message: string } {
    // Pyodide PythonError messages look like:
    //   "Traceback (most recent call last):\n  File \"<exec>\", line 1, in <module>\n  ...\nSyntaxError: invalid syntax (<unknown>, line 3)"
    // We want just "SyntaxError: invalid syntax (line 3)".
    const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    // Find the last non-traceback line — that's the real error.
    let last = lines[lines.length - 1] || raw;
    // Trim "(<unknown>, " file noise.
    last = last.replace(/\(<unknown>,\s*/, '(').replace(/\(<exec>,\s*/, '(');
    const isSyntax = /^\s*(SyntaxError|IndentationError|TabError)\b/.test(last);
    return { kind: isSyntax ? 'syntax' : 'python', message: last };
}

// base64 → Uint8Array (browser-safe; no Buffer dep).
function b64ToBytes(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

// v7+: synchronous compile-and-marshal via the already-loaded Pyodide.
// Caller MUST have awaited getPyodide() once first; otherwise the helper
// throws because Pyodide's runPython is itself sync but loading is async.
function compileAndMarshalViaPyodide(
    py: PyodideInstance,
    source: string,
    filename?: string,
): Uint8Array {
    py.globals.set('_pg_cm_src', source);
    py.globals.set('_pg_cm_fn', filename || '<pg>');
    py.runPython(`_pg_cm_out = _pg_compile_marshal_b64(_pg_cm_src, _pg_cm_fn)\n`);
    const b64 = py.globals.get('_pg_cm_out') as string;
    return b64ToBytes(b64);
}

// v7+: pre-compute interpreterMarshalCompressed once per session.
// The interpreter source is the same across user inputs, so we cache
// the marshal+raw-deflate result. ~50 ms first call, free thereafter.
let interpMarshalCompressedCache: Uint8Array | null = null;
async function getInterpreterMarshalCompressed(
    py: PyodideInstance,
): Promise<Uint8Array> {
    if (interpMarshalCompressedCache) return interpMarshalCompressedCache;
    // Decompress the embedded interpreter source (raw-deflate base64).
    py.globals.set('_pg_iSrcB64', INTERPRETER_SRC_B64);
    py.runPython(
        `_pg_iSrc = _pg_zlib.decompress(_pg_b64.b64decode(_pg_iSrcB64), -15).decode('utf-8')\n` +
        `_pg_iMarshalRawB64 = _pg_b64.b64encode(_pg_marshal.dumps(compile(_pg_iSrc, '<pg_interp>', 'exec'))).decode('ascii')\n` +
        `_pg_iMarshalCompressedB64 = _pg_raw_deflate_b64(_pg_iMarshalRawB64)\n`,
    );
    const compressedB64 = py.globals.get('_pg_iMarshalCompressedB64') as string;
    interpMarshalCompressedCache = b64ToBytes(compressedB64);
    return interpMarshalCompressedCache;
}

// v7+: full browser-side obfuscation pipeline. The UI calls only this;
// it hides the Pyodide bootstrapping and wires the v7+ contract that
// obfuscatePythonCode() expects (compileAndMarshal + interpreterMarshal-
// Compressed). Throws BuildIRError on user-facing failures.
export async function obfuscatePythonInBrowser(source: string): Promise<string> {
    let py: PyodideInstance;
    try {
        py = await getPyodide();
    } catch (e) {
        throw new BuildIRError(
            `Failed to load Pyodide runtime: ${e instanceof Error ? e.message : String(e)}`,
            'internal',
        );
    }
    const v5IR = await buildV5IR(source);
    let interpreterMarshalCompressed: Uint8Array;
    try {
        interpreterMarshalCompressed = await getInterpreterMarshalCompressed(py);
    } catch (e) {
        const raw = e instanceof Error ? e.message : String(e);
        throw new BuildIRError(
            `Failed to prepare interpreter bytecode: ${raw}`,
            'internal',
        );
    }
    try {
        return obfuscatePythonCode(source, {
            v5IR,
            compileAndMarshal: (src, filename) =>
                compileAndMarshalViaPyodide(py, src, filename),
            interpreterMarshalCompressed,
        });
    } catch (e) {
        const raw = e instanceof Error ? e.message : String(e);
        const { kind, message } = cleanPyodideError(raw);
        throw new BuildIRError(message, kind);
    }
}

export async function buildV5IR(source: string): Promise<V5IR> {
    const schema = makeV5Schema();
    let py: PyodideInstance;
    try {
        py = await getPyodide();
    } catch (e) {
        throw new BuildIRError(
            `Failed to load Pyodide runtime: ${e instanceof Error ? e.message : String(e)}`,
            'internal',
        );
    }
    try {
        py.globals.set('_pg_user_src', source);
        py.globals.set('_pg_schema_json', JSON.stringify(schema));
        py.runPython(
            `import base64 as _pg_b64\n` +
            `_pg_art = compile_to_artifacts(_pg_user_src, _pg_schema_json)\n` +
            `_pg_ir_b64 = _pg_b64.b64encode(_pg_art['compressed']).decode('ascii')\n` +
            `_pg_manifest_b64 = _pg_b64.b64encode(_pg_art['manifest']).decode('ascii')\n`,
        );
    } catch (e) {
        const raw = e instanceof Error ? e.message : String(e);
        const { kind, message } = cleanPyodideError(raw);
        throw new BuildIRError(message, kind);
    }
    const b64 = py.globals.get('_pg_ir_b64') as string;
    const manifestB64 = py.globals.get('_pg_manifest_b64') as string;
    if (typeof b64 !== 'string') {
        throw new BuildIRError(
            'Internal error: compile_to_artifacts did not return IR bytes',
            'internal',
        );
    }
    if (typeof manifestB64 !== 'string') {
        throw new BuildIRError(
            'Internal error: compile_to_artifacts did not return a manifest',
            'internal',
        );
    }
    // Decode base64 to Uint8Array (browser-safe).
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    const manifestBin = atob(manifestB64);
    const manifest = new Uint8Array(manifestBin.length);
    for (let i = 0; i < manifestBin.length; i++) manifest[i] = manifestBin.charCodeAt(i);
    return { compressed: out, manifest, schema };
}

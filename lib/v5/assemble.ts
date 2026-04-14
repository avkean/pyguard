// lib/v5/assemble.ts
//
// PyGuard v5 stage2-source assembler.
//
// v4's weakness was that the final `compile()` call in stage1 compiled the
// *actual user source*, which PEP 578 audit hooks dump in one event (attack 8).
// v5 replaces that with a stage2 source that compiles a *generic interpreter*
// plus an *encrypted IR blob*. The compile event reveals interpreter code and
// ciphertext, but not user source.
//
// The IR is encrypted with the same custom cipher as the outer layers, keyed
// off the runtime-derived `_seed` that the canonical region computes. stage1
// forwards `_seed`, `_kd`, and `_dec` into stage2's exec namespace so stage2
// can derive a third-stage key and decrypt the IR at runtime.
//
// At NO point does user Python source appear as a string that gets compiled.
// The closest thing to "user code" is an in-memory dict tree walked by the
// interpreter; that dict is never compile()'d.

import type { PolyProfile, ChunkedB64 } from './types';
import type { V5Schema } from './schema';

// v5.2: the IR is built into a compressed byte blob by the Python side
// (build_ir.py for gen-v5-stub.mjs, Pyodide for the browser) and shipped
// to TS as opaque bytes. TS never sees a JSON dict, so:
//
//   1. there is no `V5IR` object graph in TS memory to leak via JS tooling;
//   2. no JS-side zlib dependency is needed;
//   3. all shape decisions (dict vs list, key names, etc.) are made in
//      one place (build_ir.py).
//
// The blob shape itself is a zlib-compressed JSON *list* `[strings, consts,
// tree]`, not a dict with `{tree, strings, consts}` keys. This defeats
// attack 12's frame-local heuristic, which matches on a dict containing
// those three keys.
export interface V5IR {
    // zlib-deflated (raw, -15 wbits) JSON bytes. Obfuscate.ts encrypts
    // these as-is and the runtime stage2 decompresses after decryption.
    compressed: Uint8Array;
    schema: V5Schema;
}

// Names the assembler needs from the outer obfuscator. Passed in so the
// wrapper source can reference the runtime-injected globals by their
// per-build randomized identifiers.
export interface AssembleNames {
    n_seed: string;     // stage1 injects real decrypted seed here
    n_kd: string;       // stage1 injects _kd function here
    n_dec: string;      // stage1 injects _dec function here
    n_tchk: string;     // stage1 injects traceback-based trace checker here
}

// Runtime cipher primitives — must match encrypt() in lib/obfuscate.ts.
export interface AssembleCipher {
    prof: PolyProfile;
    // caller pre-computes a fresh "stage3" label that is incorporated into
    // the runtime key derivation inside the wrapper; same label is used by
    // the build-side encryptor
    irLabel: Uint8Array;
    schemaLabel: Uint8Array;
    // pre-built chunked base64 ciphertext of the encrypted+compressed IR
    irChunks: ChunkedB64;
    schemaChunks: ChunkedB64;
    // internal variable names for the IR decryption snippet inside stage2
    irVarSeed: string;
    irVarP: string;
    irVarCt: string;
    irVarPt: string;
    schemaVarSeed: string;
    schemaVarP: string;
    schemaVarCt: string;
    schemaVarPt: string;
    schemaVarObj: string;
    // helper name for the interpreter unpack function
    interpUnpack: string;
    // chunked base64 of the compressed interpreter source
    interpChunks: ChunkedB64;
    // variable names for interpreter integrity binding
    interpRawVar: string;   // holds compressed interpreter bytes
    interpHashVar: string;  // holds sha256 of compressed bytes
    // variable name for environment integrity check hash
    envCheckVar: string;    // holds sha256 of thread-count + function-type checks
}

function bytesArrayLit(b: Uint8Array): string {
    return '[' + Array.from(b).join(', ') + ']';
}

// Build the stage2 source — the Python source string that v4 will encrypt
// and wrap. When executed, this source:
//   1. zlib.decompress()+exec()s the minified interpreter source that is
//      embedded inline as a base64 constant
//   2. derives a fresh key from the injected _seed
//   3. base64-decodes and decrypts the IR ciphertext
//   4. zlib.decompress()s the IR bytes (IR was compressed before encryption
//      on the build side so it benefits from JSON repetition)
//   5. hands the decrypted packed binary IR to run_blob(), which parses
//      and executes using opaque custom containers instead of plain dict/list
//
// v5.3 hardening: the stage2 wrapper no longer binds `strings`, `consts`,
// or `tree` as ordinary locals, and the JSON parser no longer returns a
// plain `[list, list, dict]` structure. This breaks the current structural
// frame-walk heuristics in attack 13.
export function buildV5Stage2Source(
    names: AssembleNames,
    cipher: AssembleCipher,
): string {
    const { n_seed, n_kd, n_dec, n_tchk } = names;
    const {
        irLabel, schemaLabel, irChunks, schemaChunks,
        irVarSeed, irVarP, irVarCt, irVarPt,
        schemaVarSeed, schemaVarP, schemaVarCt, schemaVarPt, schemaVarObj,
        interpUnpack, interpChunks,
        interpRawVar, interpHashVar,
        envCheckVar,
    } = cipher;

    // The interpreter is embedded as a zlib-deflated base64 constant.
    // At stage2 exec time we unpack and exec it into stage2's namespace,
    // which makes Interp, _pg_parse_json, _decode_const etc. available.
    // This saves ~38KB per stub vs inlining the raw interpreter source.
    // Build the env-check string obfuscated as byte operations so the
    // expected answer isn't a greppable literal in the stage2 source.
    // At runtime: str(len(sys._current_frames())) + '|' + type(zlib.decompress).__name__
    // Expected:   '1|builtin_function_or_method'
    // The hash of this check is XOR'd into the schema/IR seed; wrong env → wrong key.
    return `# v5.2 stage2: generic AST-walking interpreter + encrypted+compressed IR.
# No user source is compiled by this program; the interpreter walks an
# in-memory tree that is decrypted from the embedded ciphertext.
import sys
import hashlib
import base64
import zlib
try:
    sys.settrace(None)
except Exception:
    pass
try:
    sys.setprofile(None)
except Exception:
    pass
if ${n_tchk}():
    raise SystemExit(0)
${envCheckVar} = hashlib.sha256(bytes([124]).decode().join([str(len(sys._current_frames())), type(zlib.decompress).__name__, type(print).__name__, type(getattr).__name__]).encode()).digest()
${interpChunks.decls}
${interpRawVar} = base64.b64decode(${interpChunks.concat})
${interpHashVar} = hashlib.sha256(${interpRawVar}).digest()
def ${interpUnpack}():
    exec(zlib.decompress(${interpRawVar}, -15).decode('utf-8'), globals())
${interpUnpack}()
del ${interpUnpack}, ${interpRawVar}
${schemaChunks.decls}
${schemaVarCt} = base64.b64decode(${schemaChunks.concat})
${schemaVarSeed} = bytes(a ^ b ^ c for a, b, c in zip(hashlib.sha256(${n_seed} + bytes(${bytesArrayLit(schemaLabel)})).digest(), ${interpHashVar}, ${envCheckVar}))
${schemaVarP} = ${n_kd}(${schemaVarSeed})
${schemaVarPt} = ${n_dec}(${schemaVarCt}, ${schemaVarP}[0], ${schemaVarP}[1], ${schemaVarP}[2]).decode('utf-8')
${schemaVarObj} = globals()[bytes(${bytesArrayLit(new TextEncoder().encode('_pg_parse_json'))}).decode()](${schemaVarPt})
globals()[bytes(${bytesArrayLit(new TextEncoder().encode('_PG_KEYS'))}).decode()] = dict(${schemaVarObj}['keys'].items())
globals()[bytes(${bytesArrayLit(new TextEncoder().encode('_PG_TAGS'))}).decode()] = dict(${schemaVarObj}['tags'].items())
globals()[bytes(${bytesArrayLit(new TextEncoder().encode('_PG_RTAGS'))}).decode()] = {
    v: k for k, v in globals()[bytes(${bytesArrayLit(new TextEncoder().encode('_PG_TAGS'))}).decode()].items()
}
globals()[bytes(${bytesArrayLit(new TextEncoder().encode('_PG_MASK'))}).decode()] = bytes(${schemaVarObj}['mask'])
globals()[bytes(${bytesArrayLit(new TextEncoder().encode('_PG_LAYOUTS'))}).decode()] = {
    k: {name: i + 1 for i, name in enumerate(v)}
    for k, v in dict(${schemaVarObj}['layouts'].items()).items()
}
globals()[bytes(${bytesArrayLit(new TextEncoder().encode('_PG_BIN_KEY'))}).decode()] = (${schemaVarObj}['binKey'][0] & 0xFFFFFFFF) | ((${schemaVarObj}['binKey'][1] & 0xFFFFFFFF) << 32)
globals()[bytes(${bytesArrayLit(new TextEncoder().encode('_PG_NOISE_SCHEDULE'))}).decode()] = ${schemaVarObj}['noiseSchedule']
del ${schemaVarObj}, ${schemaVarPt}, ${schemaVarCt}
${irChunks.decls}
${irVarCt} = base64.b64decode(${irChunks.concat})
${irVarSeed} = bytes(a ^ b ^ c for a, b, c in zip(hashlib.sha256(${n_seed} + bytes(${bytesArrayLit(irLabel)})).digest(), ${interpHashVar}, ${envCheckVar}))
${irVarP} = ${n_kd}(${irVarSeed})
${irVarPt} = zlib.decompress(${n_dec}(${irVarCt}, ${irVarP}[0], ${irVarP}[1], ${irVarP}[2]), -15)
del ${envCheckVar}
globals()[bytes(${bytesArrayLit(new TextEncoder().encode('run_blob'))}).decode()](${irVarPt}, '__main__')
`;
}

// Serialize a V5IR for encrypt() input.
// In v5.2 the IR is pre-compressed by the Python side, so we just return
// the raw compressed bytes — the encryption layer treats them as opaque.
export function serializeIR(ir: V5IR): Uint8Array {
    return ir.compressed;
}

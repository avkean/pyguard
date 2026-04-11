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
import { INTERPRETER_SRC_B64 } from './interpreter_src';

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
}

// Names the assembler needs from the outer obfuscator. Passed in so the
// wrapper source can reference the runtime-injected globals by their
// per-build randomized identifiers.
export interface AssembleNames {
    n_seed: string;     // stage1 injects real decrypted seed here
    n_kd: string;       // stage1 injects _kd function here
    n_dec: string;      // stage1 injects _dec function here
}

// Runtime cipher primitives — must match encrypt() in lib/obfuscate.ts.
export interface AssembleCipher {
    prof: PolyProfile;
    // caller pre-computes a fresh "stage3" label that is incorporated into
    // the runtime key derivation inside the wrapper; same label is used by
    // the build-side encryptor
    irLabel: Uint8Array;
    // pre-built chunked base64 ciphertext of the encrypted+compressed IR
    irChunks: ChunkedB64;
    // internal variable names for the IR decryption snippet inside stage2
    irVarSeed: string;
    irVarP: string;
    irVarCt: string;
    irVarPt: string;
    // irVarJson holds the decompressed JSON string (transient)
    irVarJson: string;
    // irVarLoaded holds the parsed list [strings, consts, tree] (transient)
    irVarLoaded: string;
    irVarStrings: string;
    irVarConsts: string;
    irVarTree: string;
    irVarInterp: string;
    // helper name for the interpreter unpack function
    interpUnpack: string;
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
//   5. _pg_parse_json's the plaintext into a LIST [strings, consts, tree]
//   6. destructures into three locals and immediately deletes the
//      intermediate list (frame-walk attacker sees only the list briefly)
//   7. decodes tagged constants and runs the interpreter on `tree`
//
// Shape change from v5.1: the top-level IR container is a JSON list, not
// a dict. Attack 12's frame-walk heuristic matches on
// `isinstance(v, dict) and {'tree','strings','consts'} <= v.keys()`, so
// it now fails at the isinstance check.
export function buildV5Stage2Source(
    names: AssembleNames,
    cipher: AssembleCipher,
): string {
    const { n_seed, n_kd, n_dec } = names;
    const {
        irLabel, irChunks,
        irVarSeed, irVarP, irVarCt, irVarPt, irVarJson, irVarLoaded,
        irVarStrings, irVarConsts, irVarTree, irVarInterp, interpUnpack,
    } = cipher;

    // The interpreter is embedded as a zlib-deflated base64 constant.
    // At stage2 exec time we unpack and exec it into stage2's namespace,
    // which makes Interp, _pg_parse_json, _decode_const etc. available.
    // This saves ~38KB per stub vs inlining the raw interpreter source.
    return `# v5.2 stage2: generic AST-walking interpreter + encrypted+compressed IR.
# No user source is compiled by this program; the interpreter walks an
# in-memory tree that is decrypted from the embedded ciphertext.
import hashlib
import base64
import zlib
def ${interpUnpack}():
    exec(zlib.decompress(base64.b64decode(${JSON.stringify(INTERPRETER_SRC_B64)}), -15).decode('utf-8'), globals())
${interpUnpack}()
del ${interpUnpack}
${irChunks.decls}
${irVarCt} = base64.b64decode(${irChunks.concat})
${irVarSeed} = hashlib.sha256(${n_seed} + bytes(${bytesArrayLit(irLabel)})).digest()
${irVarP} = ${n_kd}(${irVarSeed})
${irVarPt} = zlib.decompress(${n_dec}(${irVarCt}, ${irVarP}[0], ${irVarP}[1], ${irVarP}[2]), -15)
${irVarJson} = ${irVarPt}.decode('utf-8')
${irVarLoaded} = _pg_parse_json(${irVarJson})
${irVarStrings} = ${irVarLoaded}[0]
${irVarConsts} = [_decode_const(_c) for _c in ${irVarLoaded}[1]]
${irVarTree} = ${irVarLoaded}[2]
del ${irVarLoaded}, ${irVarJson}, ${irVarPt}, ${irVarCt}
${irVarInterp} = Interp(${irVarStrings}, ${irVarConsts})
${irVarInterp}.run(${irVarTree}, '__main__')
`;
}

// Serialize a V5IR for encrypt() input.
// In v5.2 the IR is pre-compressed by the Python side, so we just return
// the raw compressed bytes — the encryption layer treats them as opaque.
export function serializeIR(ir: V5IR): Uint8Array {
    return ir.compressed;
}

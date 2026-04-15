// lib/v5/assemble.ts
//
// PyGuard stage2-source assembler (current generation: v11).
//
// ARCHITECTURAL HISTORY (v5/v6 → v7+):
//
// v5/v6's weakness was that stage2 was embedded as a Python SOURCE string and
// stage1 called `compile(stage2_src, ...)` on it. Every PEP 578 audit hook
// installed via sitecustomize.py received that source verbatim — the most
// recent successful attack captured all three stages (stage1, stage2,
// interpreter) purely by listening to `compile` audit events. The same attack
// grabbed `exec(interpreter_source, globals())` because exec on a string
// implicitly compiles.
//
// v7 eliminates source compilation at runtime:
//
//   * The interpreter is shipped as a *marshaled code object* — the build side
//     does `marshal.dumps(compile(src, ...))` and the stub does
//     `marshal.loads(bytes)` + `FunctionType(code, ns)()`. No `compile` audit.
//   * Stage2 is likewise marshaled: stage1 does `marshal.loads` to get a code
//     object and runs it in an isolated namespace. No `compile` audit.
//   * Schema (_PG_KEYS / _PG_TAGS / _PG_MASK / _PG_LAYOUTS / _PG_BIN_KEY /
//     _PG_NOISE_SCHEDULE) is NEVER written to any globals dict. It is decrypted
//     *inside* the interpreter's own namespace by a `_pg_boot` entry point and
//     captured as frame locals of the boot function, which hands them to
//     Interp as constructor arguments.
//   * `run_blob` is not aliased back to globals. The entry point is reachable
//     only via `_interp_ns['_pg_boot']` (which itself has a randomized name).
//
// Net effect on the known attack chain:
//   - Audit capture no longer yields any stage source
//   - Profile-hook on the old top-level run_blob frame finds nothing: there is
//     no such frame; the decryption lives inside the interpreter's _pg_boot
//     and the schema is local there, not global.
//   - Offline replay still needs interpreter bytecode + per-build polymorphic
//     schema + encrypted-envelope plaintext, which requires decompilation
//     of marshaled bytecode (much harder than reading source).

import type { PolyProfile, ChunkedB64 } from './types';
import type { V5Schema } from './schema';

// v5.2: the IR is built into a compressed byte blob by the Python side
// (build_ir.py for gen-v5-stub.mjs, Pyodide for the browser) and shipped
// to TS as opaque bytes. TS never sees a JSON dict in memory.
export interface V5IR {
    // zlib-deflated (raw, -15 wbits) JSON bytes. Obfuscate.ts encrypts
    // these as-is and the runtime stage2 decompresses after decryption.
    compressed: Uint8Array;
    schema: V5Schema;
}

// Names the assembler needs from the outer obfuscator.
export interface AssembleNames {
    n_seed: string;     // stage1 injects real decrypted seed here
    n_kd: string;       // stage1 injects _kd function here
    n_dec: string;      // stage1 injects _dec function here
    n_tchk: string;     // stage1 injects traceback-based trace checker here
}

// Runtime cipher primitives — must match encrypt() in lib/obfuscate.ts.
export interface AssembleCipher {
    prof: PolyProfile;
    // per-build labels mixed into the runtime key derivation
    interpLabel: Uint8Array;
    irLabel: Uint8Array;
    schemaLabel: Uint8Array;
    // pre-built chunked base64 ciphertexts
    interpChunks: ChunkedB64;   // encrypted+compressed MARSHALED interpreter code object
    irChunks: ChunkedB64;       // encrypted+compressed IR bytes
    schemaChunks: ChunkedB64;   // encrypted schema JSON
    // internal variable names used in the stage2 source
    envCheckVar: string;    // sha256 of runtime env fingerprint
    interpCtVar: string;    // encrypted interpreter marshaled bytes
    interpHashVar: string;  // sha256 of encrypted interpreter blob
    interpSeedVar: string;
    interpPVar: string;
    interpMarshalVar: string; // decrypted marshal bytes
    interpCodeVar: string;    // marshal.loads result (code object)
    interpNsVar: string;      // isolated namespace for interpreter exec
    schemaCtVar: string;
    irCtVar: string;
    // v9: randomized bytes-key under which the interpreter module
    // registers its renamed `_pg_boot`. Stage2 indexes `interp_ns` by
    // this bytes object; no original name ("_pg_boot") is ever present.
    bootKeyBytes: Uint8Array;
    // v11: inert-bytes versions of the crypto profile, handed to
    // _pg_boot instead of stage1's `_kd` / `_dec` closures. The
    // interpreter has its own inline `_k_derive` / `_c_dec` helpers
    // which consume these bytes. Removing the callables from the args
    // tuple defeats the v10 `boot_args_sniff` attack (wrap `dec` →
    // log plaintexts) since there is nothing callable to wrap.
    pepBytes: Uint8Array;       // 32-byte pepper (= obfuscate.ts `pep`)
    profileBytes: Uint8Array;   // 15-byte packed PolyProfile:
                                //   [0] rounds
                                //   [1] rotMod
                                //   [2] sbxNudge
                                //   [3..7]  rkLabel (4B)
                                //   [7..11] rotLabel (4B)
                                //   [11..15] sbxLabel (4B)
}

function bytesArrayLit(b: Uint8Array): string {
    return '[' + Array.from(b).join(', ') + ']';
}

// Build the stage2 source — the Python source string that the obfuscator
// will compile-and-marshal, then encrypt and wrap inside stage1.
//
// When executed (via FunctionType(marshaled_code, isolated_ns)), this code:
//   1. Trace/profile nullification + env-integrity hash
//   2. base64-decode + decrypt the *marshaled* interpreter code object
//   3. base64-decode the encrypted schema + IR blobs (ciphertexts only — no
//      decryption happens in stage2)
//   4. Pre-seed the boot argument tuple into `interp_ns[bytes(bootKey)]`
//      BEFORE running the interpreter module body.
//   5. marshal.loads + FunctionType(code, interp_ns)() — the interpreter
//      module body itself reads the pre-seeded tuple, deletes the slot, and
//      calls `_pg_boot(*args)` inline. No external `interp_ns[bytes(k)](...)`
//      call ever happens — an attacker hooking FunctionType sees either
//      (a) pre-body: a raw args tuple at a random bytes key with no callable
//      named `_pg_boot` anywhere in globals, or (b) post-body: the slot
//      deleted and all decrypted state gone.
//
// The schema is NEVER written to any globals dict outside the boot frame.
// `run_blob` is NEVER assigned to a globals name. Profile-hooking stage2's
// frame yields only encrypted ciphertexts and hash material.
export function buildV5Stage2Source(
    names: AssembleNames,
    cipher: AssembleCipher,
): string {
    const { n_seed, n_kd, n_dec, n_tchk } = names;
    const {
        interpLabel, irLabel, schemaLabel,
        interpChunks, irChunks, schemaChunks,
        envCheckVar,
        interpCtVar, interpHashVar,
        interpSeedVar, interpPVar, interpMarshalVar, interpCodeVar, interpNsVar,
        schemaCtVar, irCtVar,
        bootKeyBytes,
        pepBytes, profileBytes,
    } = cipher;

    // v9: `bootKeyLit` is the bytes-object literal used to index interp_ns.
    // The interpreter module's final statement is
    //     globals()[bytes([...these bytes...])] = <renamed_pg_boot>
    // so stage2 retrieves the boot fn via `interp_ns[bytes([...])]`.
    const bootKeyLit = bytesArrayLit(bootKeyBytes);
    const pepLit = bytesArrayLit(pepBytes);
    const profileLit = bytesArrayLit(profileBytes);

    return `# PyGuard v7 stage2 (marshaled): generic AST interpreter + encrypted+compressed IR.
# No user source is compiled by this program at any point. The interpreter
# is loaded via marshal.loads (not compile), the schema is decrypted inside
# the interpreter's own boot frame (never stage2 globals), and the IR is
# walked by an in-memory tree the attacker cannot lift without decompiling
# the marshaled interpreter first.
import sys
import hashlib
import base64
import zlib
import marshal
from types import FunctionType
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
${envCheckVar} = hashlib.sha256(bytes([124]).decode().join([str(len(sys._current_frames())), type(zlib.decompress).__name__, type(print).__name__, type(getattr).__name__, type(sys.settrace).__name__, type(sys.setprofile).__name__, type(sys.gettrace).__name__, type(sys.getprofile).__name__, type(exec).__name__, type(marshal.loads).__name__, type(hashlib.scrypt).__name__, str(type(sys.settrace) is type(zlib.decompress)), str(type(sys.setprofile) is type(zlib.decompress)), str(type(sys.gettrace) is type(zlib.decompress)), str(type(sys.getprofile) is type(zlib.decompress)), str(type(exec) is type(zlib.decompress)), str(type(marshal.loads) is type(zlib.decompress)), str(type(hashlib.scrypt) is type(zlib.decompress))]).encode()).digest()
${interpChunks.decls}
${interpCtVar} = base64.b64decode(${interpChunks.concat})
${interpHashVar} = hashlib.sha256(${interpCtVar}).digest()
${interpSeedVar} = bytes(a ^ b for a, b in zip(hashlib.sha256(${n_seed} + bytes(${bytesArrayLit(interpLabel)})).digest(), ${envCheckVar}))
${interpPVar} = ${n_kd}(${interpSeedVar})
${interpMarshalVar} = zlib.decompress(${n_dec}(${interpCtVar}, ${interpPVar}[0], ${interpPVar}[1], ${interpPVar}[2]), -15)
${interpCodeVar} = marshal.loads(${interpMarshalVar})
${interpNsVar} = {bytes([95, 95, 98, 117, 105, 108, 116, 105, 110, 115, 95, 95]).decode(): __builtins__, bytes([95, 95, 110, 97, 109, 101, 95, 95]).decode(): bytes([60, 112, 103, 95, 105, 62]).decode()}
${schemaChunks.decls}
${schemaCtVar} = base64.b64decode(${schemaChunks.concat})
${irChunks.decls}
${irCtVar} = base64.b64decode(${irChunks.concat})
${interpNsVar}[bytes(${bootKeyLit})] = (${schemaCtVar}, bytes(${bytesArrayLit(schemaLabel)}), ${irCtVar}, bytes(${bytesArrayLit(irLabel)}), ${n_seed}, ${interpHashVar}, ${envCheckVar}, bytes(${pepLit}), bytes(${profileLit}), bytes([95, 95, 109, 97, 105, 110, 95, 95]).decode())
FunctionType(${interpCodeVar}, ${interpNsVar})()
del ${interpMarshalVar}, ${interpCodeVar}, ${interpCtVar}
`;
}

// Serialize a V5IR for encrypt() input.
// In v5.2 the IR is pre-compressed by the Python side, so we just return
// the raw compressed bytes — the encryption layer treats them as opaque.
export function serializeIR(ir: V5IR): Uint8Array {
    return ir.compressed;
}

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
    // zlib-deflated (raw, -15 wbits) static import manifest bytes.
    manifest: Uint8Array;
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
    manifestLabel: Uint8Array;
    // pre-built chunked base64 ciphertexts
    interpChunks: ChunkedB64;   // encrypted+compressed MARSHALED interpreter code object
    irChunks: ChunkedB64;       // encrypted+compressed IR bytes
    schemaChunks: ChunkedB64;   // encrypted schema JSON
    manifestChunks: ChunkedB64; // encrypted static import manifest bytes
    // internal variable names used in the stage2 source
    envCheckVar: string;    // sha256 of runtime env fingerprint
    interpCtVar: string;    // encrypted interpreter marshaled bytes
    interpHashVar: string;  // sha256 of encrypted interpreter blob
    interpSeedVar: string;
    interpPVar: string;
    interpMarshalVar: string; // decrypted marshal bytes
    interpCodeVar: string;    // marshal.loads result (code object)
    interpNsVar: string;      // isolated namespace for interpreter exec
    interpFTVar: string;      // FunctionType recovered via `type(lambda:0)` — bypasses types.FunctionType hook (C7.1)
    schemaCtVar: string;
    irCtVar: string;
    manifestCtVar: string;
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
        interpLabel, irLabel, schemaLabel, manifestLabel,
        interpChunks, irChunks, schemaChunks, manifestChunks,
        envCheckVar,
        interpCtVar, interpHashVar,
        interpSeedVar, interpPVar, interpMarshalVar, interpCodeVar, interpNsVar, interpFTVar,
        schemaCtVar, irCtVar, manifestCtVar,
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

    // Stage2 source (marshaled before shipping):
    //   - no user source is compile()d here — the interpreter is
    //     marshal.loads'd so no PEP-578 compile audit event fires
    //   - the schema is decrypted inside the interpreter's own boot
    //     frame, never in stage2 globals (no settrace-at-globals leak)
    //   - FunctionType is recovered via (lambda: 0).__class__ — a C-slot
    //     read on object.__class__ (Py_TYPE) that routes around both
    //     'from types import FunctionType' (rebindable module attr) and
    //     'type(lambda: 0)' (rebindable builtins.type). Mutating
    //     FT.__name__/__module__ is possible but the envCheck witnesses
    //     fold those attributes into the key, silently poisoning the seed.
    //   - envCheck witnesses below include type-identity checks on every
    //     trace-surface builtin (settrace/setprofile/gettrace/getprofile/
    //     exec/marshal.loads/hashlib.scrypt) against zlib.decompress, so
    //     any Python-level wrapper flips the 'function' vs
    //     'builtin_function_or_method' discriminator.
    // Keep this Python code-only — no # comments in the emitted stub.
    return `import sys
import hashlib
import base64
import zlib
import marshal
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
${interpFTVar} = (lambda: 0).__class__
${envCheckVar} = hashlib.sha256(bytes([124]).decode().join([str(len(sys._current_frames())), type(zlib.decompress).__name__, type(print).__name__, type(getattr).__name__, type(sys.settrace).__name__, type(sys.setprofile).__name__, type(sys.gettrace).__name__, type(sys.getprofile).__name__, type(exec).__name__, type(marshal.loads).__name__, type(hashlib.scrypt).__name__, str(type(sys.settrace) is type(zlib.decompress)), str(type(sys.setprofile) is type(zlib.decompress)), str(type(sys.gettrace) is type(zlib.decompress)), str(type(sys.getprofile) is type(zlib.decompress)), str(type(exec) is type(zlib.decompress)), str(type(marshal.loads) is type(zlib.decompress)), str(type(hashlib.scrypt) is type(zlib.decompress)), ${interpFTVar}.__name__, str(${interpFTVar} is (lambda: None).__class__), ${interpFTVar}.__class__.__name__, ${interpFTVar}.__module__]).encode()).digest()
_pg_bi_snap = dict(__builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__)
${interpChunks.decls}
${interpCtVar} = base64.b85decode(${interpChunks.concat})
${interpHashVar} = hashlib.sha256(${interpCtVar}).digest()
${manifestChunks.decls}
${manifestCtVar} = base64.b85decode(${manifestChunks.concat})
_pg_manifest_seed = bytes(a ^ b ^ c for a, b, c in zip(hashlib.sha256(${n_seed} + bytes(${bytesArrayLit(manifestLabel)})).digest(), ${interpHashVar}, ${envCheckVar}))
_pg_manifest_p = ${n_kd}(_pg_manifest_seed)
_pg_manifest_blob = zlib.decompress(${n_dec}(${manifestCtVar}, _pg_manifest_p[0], _pg_manifest_p[1], _pg_manifest_p[2]), -15)
_pg_manifest_lut = {}
_pg_manifest_mods = {}
_pg_mod_type = type(sys)
_pg_manifest_off = 0
_pg_manifest_cnt = int.from_bytes(_pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + 4], bytes([108, 105, 116, 116, 108, 101]).decode())
_pg_manifest_off += 4
for _ in range(_pg_manifest_cnt):
    _pg_mid = int.from_bytes(_pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + 4], bytes([108, 105, 116, 116, 108, 101]).decode())
    _pg_manifest_off += 4
    _pg_ml = int.from_bytes(_pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + 2], bytes([108, 105, 116, 116, 108, 101]).decode())
    _pg_manifest_off += 2
    _pg_mod_name = _pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + _pg_ml].decode(bytes([117, 116, 102, 45, 56]).decode())
    _pg_manifest_off += _pg_ml
    _pg_al = int.from_bytes(_pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + 2], bytes([108, 105, 116, 116, 108, 101]).decode())
    _pg_manifest_off += 2
    _pg_attr_name = None if _pg_al == 65535 else _pg_manifest_blob[_pg_manifest_off:_pg_manifest_off + _pg_al].decode(bytes([117, 116, 102, 45, 56]).decode())
    if _pg_al != 65535:
        _pg_manifest_off += _pg_al
    try:
        _pg_mod = _pg_manifest_mods.get(_pg_mod_name)
        if _pg_mod is None:
            _pg_mod = sys.modules.get(_pg_mod_name)
            if type(_pg_mod) is not _pg_mod_type:
                sys.modules.pop(_pg_mod_name, None)
                _pg_mod = _pg_bi_snap[bytes([95, 95, 105, 109, 112, 111, 114, 116, 95, 95]).decode()](_pg_mod_name, None, None, (bytes([95]).decode(),), 0)
                _pg_live_mod = sys.modules.get(_pg_mod_name)
                if type(_pg_live_mod) is _pg_mod_type:
                    _pg_mod = _pg_live_mod
            _pg_manifest_mods[_pg_mod_name] = _pg_mod
        if _pg_attr_name is None:
            _pg_manifest_lut[_pg_mid] = _pg_mod
        else:
            _pg_val = _pg_mod.__dict__.get(_pg_attr_name, _pg_manifest_mods)
            if _pg_val is _pg_manifest_mods:
                _pg_val = getattr(_pg_mod, _pg_attr_name)
            _pg_manifest_lut[_pg_mid] = _pg_val
    except BaseException as _pg_exc:
        _pg_manifest_lut[_pg_mid] = _pg_exc
${interpSeedVar} = bytes(a ^ b for a, b in zip(hashlib.sha256(${n_seed} + bytes(${bytesArrayLit(interpLabel)})).digest(), ${envCheckVar}))
${interpPVar} = ${n_kd}(${interpSeedVar})
${interpMarshalVar} = zlib.decompress(${n_dec}(${interpCtVar}, ${interpPVar}[0], ${interpPVar}[1], ${interpPVar}[2]), -15)
${interpCodeVar} = marshal.loads(${interpMarshalVar})
${interpNsVar} = {bytes([95, 95, 98, 117, 105, 108, 116, 105, 110, 115, 95, 95]).decode(): __builtins__, bytes([95, 95, 110, 97, 109, 101, 95, 95]).decode(): bytes([60, 112, 103, 95, 105, 62]).decode()}
${schemaChunks.decls}
${schemaCtVar} = base64.b85decode(${schemaChunks.concat})
${irChunks.decls}
${irCtVar} = base64.b85decode(${irChunks.concat})
${interpNsVar}[bytes(${bootKeyLit})] = (${schemaCtVar}, bytes(${bytesArrayLit(schemaLabel)}), ${irCtVar}, bytes(${bytesArrayLit(irLabel)}), ${n_seed}, ${interpHashVar}, ${envCheckVar}, bytes(${pepLit}), bytes(${profileLit}), bytes([95, 95, 109, 97, 105, 110, 95, 95]).decode(), _pg_bi_snap, _pg_manifest_lut)
${interpFTVar}(${interpCodeVar}, ${interpNsVar})()
del ${interpMarshalVar}, ${interpCodeVar}, ${interpCtVar}, _pg_manifest_blob, _pg_manifest_lut, _pg_manifest_mods
`;
}

// Serialize a V5IR for encrypt() input.
// In v5.2 the IR is pre-compressed by the Python side, so we just return
// the raw compressed bytes — the encryption layer treats them as opaque.
export function serializeIR(ir: V5IR): Uint8Array {
    return ir.compressed;
}

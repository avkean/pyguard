// lib/v5/assemble.ts
//
// PyGuard stage2-source assembler (current generation: v12).
//
// ARCHITECTURE:
//
// Stage2 source is assembled here, marshaled at build time, and then
// packed with a binary boot bundle by lib/obfuscate.ts. At stub runtime
// the outer canonical region decrypts stage1, stage1 decrypts the stage2
// payload package, and stage2 decrypts the interpreter as a TAGGED
// marshal blob:
//   b'PGM1' + major + minor + marshal.dumps(code)
//
// The 6-byte header lets runtime fail closed before marshal.loads on
// interpreter-version mismatch, instead of reverting to compile() on stage
// source and handing audit hooks the whole launcher.
//
// v12 packaging change: stage2 no longer embeds encrypted interpreter /
// IR / schema / manifest blobs as Python source literals. Those payloads
// now travel once, in a binary boot bundle passed from stage1 to the
// marshaled stage2 launcher. This removes the largest fixed-size cost in
// every stub and avoids re-encoding the same payload structure as nested
// source text.

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
export interface V5BootBundle {
    // Per-build labels mixed into runtime key derivation.
    interpLabel: Uint8Array;
    irLabel: Uint8Array;
    schemaLabel: Uint8Array;
    manifestLabel: Uint8Array;
    // Encrypted runtime payloads. These are opaque until stage2 decrypts
    // them inside the proper runtime context.
    interpCiphertext: Uint8Array;
    irCiphertext: Uint8Array;
    schemaCiphertext: Uint8Array;
    manifestCiphertext: Uint8Array;
    // Randomized bytes-key under which the interpreter module registers
    // its renamed `_pg_boot`.
    bootKeyBytes: Uint8Array;
    // Inert-bytes versions of the crypto profile, handed to `_pg_boot`
    // instead of stage1's `_kd` / `_dec` closures.
    pepBytes: Uint8Array;       // 32-byte pepper (= obfuscate.ts `pep`)
    profileBytes: Uint8Array;   // 15-byte packed PolyProfile
}

export interface AssembleStage2 {
    bootBundleVar: string;
}

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const a of arrs) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}

function u32le(n: number): Uint8Array {
    return new Uint8Array([
        n & 0xff,
        (n >>> 8) & 0xff,
        (n >>> 16) & 0xff,
        (n >>> 24) & 0xff,
    ]);
}

const BOOT_BUNDLE_MAGIC = new Uint8Array([80, 71, 66, 49]);    // PGB1
const STAGE2_PAYLOAD_MAGIC = new Uint8Array([80, 71, 83, 50]); // PGS2

export function packV5BootBundle(bundle: V5BootBundle): Uint8Array {
    if (bundle.interpLabel.length !== 6 ||
        bundle.irLabel.length !== 6 ||
        bundle.schemaLabel.length !== 6 ||
        bundle.manifestLabel.length !== 6) {
        throw new Error('packV5BootBundle: expected 6-byte labels');
    }
    if (bundle.bootKeyBytes.length !== 12) {
        throw new Error('packV5BootBundle: expected 12-byte boot key');
    }
    if (bundle.pepBytes.length !== 32) {
        throw new Error('packV5BootBundle: expected 32-byte pepper');
    }
    if (bundle.profileBytes.length !== 15) {
        throw new Error('packV5BootBundle: expected 15-byte profile');
    }
    return concatBytes(
        BOOT_BUNDLE_MAGIC,
        u32le(bundle.interpCiphertext.length),
        u32le(bundle.manifestCiphertext.length),
        u32le(bundle.schemaCiphertext.length),
        u32le(bundle.irCiphertext.length),
        bundle.interpLabel,
        bundle.manifestLabel,
        bundle.schemaLabel,
        bundle.irLabel,
        bundle.bootKeyBytes,
        bundle.pepBytes,
        bundle.profileBytes,
        bundle.interpCiphertext,
        bundle.manifestCiphertext,
        bundle.schemaCiphertext,
        bundle.irCiphertext,
    );
}

export function packV5Stage2Payload(
    stage2Marshal: Uint8Array,
    bootBundle: Uint8Array,
): Uint8Array {
    return concatBytes(
        STAGE2_PAYLOAD_MAGIC,
        u32le(stage2Marshal.length),
        stage2Marshal,
        bootBundle,
    );
}

// Build the stage2 source — the Python source string that the obfuscator
// will compile+marshal at build time, then encrypt + wrap inside stage1.
//
// When executed (via FunctionType(marshaled_code, isolated_ns)), this code:
//   1. Trace/profile nullification + env-integrity hash
//   2. Unpack the binary boot bundle supplied by stage1
//   3. Decrypt the encrypted manifest blob and resolve it into opaque
//      `(id, value)` pairs BEFORE the interpreter marshal.loads event fires
//   4. Decrypt the tagged interpreter marshal blob and version-check it
//   5. Pre-seed the boot argument tuple into `interp_ns[bootKey]`
//   6. marshal.loads() + FunctionType(code, interp_ns)()
//
// The schema is NEVER written to any globals dict outside the boot frame.
// `run_blob` is NEVER assigned to a globals name. Profile-hooking stage2's
// frame yields only encrypted ciphertexts and hash material.
export function buildV5Stage2Source(
    names: AssembleNames,
    stage2: AssembleStage2,
): string {
    const { n_seed, n_kd, n_dec, n_tchk } = names;
    const { bootBundleVar } = stage2;

    // Stage2 source (compiled+marshaled at build time):
    //   - stage2 reads one binary boot bundle from its globals dict, then
    //     deletes that slot before touching the interpreter
    //   - the schema is decrypted inside the interpreter's own boot frame,
    //     never in stage2 globals
    //   - FunctionType is recovered via (lambda: 0).__class__
    return `import sys
import hashlib
import zlib
import lzma
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
_pg_ft = (lambda: 0).__class__
_pg_env = hashlib.sha256(bytes([124]).decode().join([str(len(sys._current_frames())), type(zlib.decompress).__name__, type(print).__name__, type(getattr).__name__, type(sys.settrace).__name__, type(sys.setprofile).__name__, type(sys.gettrace).__name__, type(sys.getprofile).__name__, type(exec).__name__, type(marshal.loads).__name__, type(hashlib.scrypt).__name__, str(type(sys.settrace) is type(zlib.decompress)), str(type(sys.setprofile) is type(zlib.decompress)), str(type(sys.gettrace) is type(zlib.decompress)), str(type(sys.getprofile) is type(zlib.decompress)), str(type(exec) is type(zlib.decompress)), str(type(marshal.loads) is type(zlib.decompress)), str(type(hashlib.scrypt) is type(zlib.decompress)), _pg_ft.__name__, str(_pg_ft is (lambda: None).__class__), _pg_ft.__class__.__name__, _pg_ft.__module__]).encode()).digest()
_pg_bi_snap = dict(__builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__)
_pg_pkg = ${bootBundleVar}
del ${bootBundleVar}
if len(_pg_pkg) < 103 or _pg_pkg[:4] != bytes([80, 71, 66, 49]):
    raise SystemExit(0)
_pg_o = 4
_pg_interp_len = int.from_bytes(_pg_pkg[_pg_o:_pg_o + 4], 'little'); _pg_o += 4
_pg_manifest_len = int.from_bytes(_pg_pkg[_pg_o:_pg_o + 4], 'little'); _pg_o += 4
_pg_schema_len = int.from_bytes(_pg_pkg[_pg_o:_pg_o + 4], 'little'); _pg_o += 4
_pg_ir_len = int.from_bytes(_pg_pkg[_pg_o:_pg_o + 4], 'little'); _pg_o += 4
_pg_interp_label = _pg_pkg[_pg_o:_pg_o + 6]; _pg_o += 6
_pg_manifest_label = _pg_pkg[_pg_o:_pg_o + 6]; _pg_o += 6
_pg_schema_label = _pg_pkg[_pg_o:_pg_o + 6]; _pg_o += 6
_pg_ir_label = _pg_pkg[_pg_o:_pg_o + 6]; _pg_o += 6
_pg_boot_key = _pg_pkg[_pg_o:_pg_o + 12]; _pg_o += 12
_pg_pep = _pg_pkg[_pg_o:_pg_o + 32]; _pg_o += 32
_pg_profile = _pg_pkg[_pg_o:_pg_o + 15]; _pg_o += 15
if _pg_o + _pg_interp_len + _pg_manifest_len + _pg_schema_len + _pg_ir_len != len(_pg_pkg):
    raise SystemExit(0)
_pg_interp_ct = _pg_pkg[_pg_o:_pg_o + _pg_interp_len]; _pg_o += _pg_interp_len
_pg_manifest_ct = _pg_pkg[_pg_o:_pg_o + _pg_manifest_len]; _pg_o += _pg_manifest_len
_pg_schema_ct = _pg_pkg[_pg_o:_pg_o + _pg_schema_len]; _pg_o += _pg_schema_len
_pg_ir_ct = _pg_pkg[_pg_o:_pg_o + _pg_ir_len]
_pg_interp_hash = hashlib.sha256(_pg_interp_ct).digest()
_pg_manifest_seed = bytes(a ^ b ^ c for a, b, c in zip(hashlib.sha256(${n_seed} + _pg_manifest_label).digest(), _pg_interp_hash, _pg_env))
_pg_manifest_p = ${n_kd}(_pg_manifest_seed)
_pg_manifest_blob = zlib.decompress(${n_dec}(_pg_manifest_ct, _pg_manifest_p[0], _pg_manifest_p[1], _pg_manifest_p[2]), -15)
_pg_manifest_pairs = []
_pg_manifest_mods = {}
_pg_mod_type = type(sys)
_pg_mod_dict = _pg_mod_type.__dict__.get(bytes([95, 95, 100, 105, 99, 116, 95, 95]).decode())
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
            _pg_val = _pg_mod
        else:
            _pg_val = _pg_manifest_mods
            if _pg_mod_dict is not None and type(_pg_mod) is _pg_mod_type:
                try:
                    _pg_dict = _pg_mod_dict.__get__(_pg_mod)
                except Exception:
                    _pg_dict = None
                if isinstance(_pg_dict, dict):
                    _pg_val = _pg_dict.get(_pg_attr_name, _pg_manifest_mods)
            if _pg_val is _pg_manifest_mods:
                _pg_val = getattr(_pg_mod, _pg_attr_name)
        _pg_manifest_pairs.append((_pg_mid, _pg_val))
    except BaseException as _pg_exc:
        _pg_manifest_pairs.append((_pg_mid, _pg_exc))
_pg_manifest_pairs = tuple(_pg_manifest_pairs)
_pg_interp_seed = bytes(a ^ b for a, b in zip(hashlib.sha256(${n_seed} + _pg_interp_label).digest(), _pg_env))
_pg_interp_p = ${n_kd}(_pg_interp_seed)
_pg_interp_m = lzma.decompress(${n_dec}(_pg_interp_ct, _pg_interp_p[0], _pg_interp_p[1], _pg_interp_p[2]))
if _pg_interp_m[:4] != bytes([80, 71, 77, 86]) or len(_pg_interp_m) < 5:
    raise SystemExit(0)
_pg_pv_n = _pg_interp_m[4]
_pg_pv_i = 5
_pg_pv_mj = sys.version_info[0]
_pg_pv_mn = sys.version_info[1]
_pg_pv_bytes = None
while _pg_pv_n > 0:
    _pg_pv_n -= 1
    if _pg_pv_i + 6 > len(_pg_interp_m):
        raise SystemExit(0)
    _pg_pv_a = _pg_interp_m[_pg_pv_i]
    _pg_pv_b = _pg_interp_m[_pg_pv_i+1]
    _pg_pv_l = int.from_bytes(_pg_interp_m[_pg_pv_i+2:_pg_pv_i+6], 'little')
    _pg_pv_i += 6
    if _pg_pv_i + _pg_pv_l > len(_pg_interp_m):
        raise SystemExit(0)
    if _pg_pv_a == _pg_pv_mj and _pg_pv_b == _pg_pv_mn:
        _pg_pv_bytes = _pg_interp_m[_pg_pv_i:_pg_pv_i+_pg_pv_l]
        break
    _pg_pv_i += _pg_pv_l
if _pg_pv_bytes is None:
    raise SystemExit(0)
_pg_interp_code = marshal.loads(_pg_pv_bytes)
for _pg_mod_name, _pg_mod in _pg_manifest_mods.items():
    try:
        sys.modules[_pg_mod_name] = _pg_mod
    except Exception:
        pass
_pg_interp_ns = {bytes([95, 95, 98, 117, 105, 108, 116, 105, 110, 115, 95, 95]).decode(): __builtins__, bytes([95, 95, 110, 97, 109, 101, 95, 95]).decode(): bytes([60, 112, 103, 95, 105, 62]).decode()}
_pg_interp_ns[_pg_boot_key] = (_pg_schema_ct, _pg_schema_label, _pg_ir_ct, _pg_ir_label, ${n_seed}, _pg_interp_hash, _pg_env, _pg_pep, _pg_profile, bytes([95, 95, 109, 97, 105, 110, 95, 95]).decode(), _pg_bi_snap, _pg_manifest_pairs)
_pg_ft(_pg_interp_code, _pg_interp_ns)()
del _pg_pkg, _pg_interp_ct, _pg_manifest_ct, _pg_schema_ct, _pg_ir_ct, _pg_manifest_blob, _pg_manifest_mods, _pg_manifest_pairs
`;
}

// Serialize a V5IR for encrypt() input.
// In v5.2 the IR is pre-compressed by the Python side, so we just return
// the raw compressed bytes — the encryption layer treats them as opaque.
export function serializeIR(ir: V5IR): Uint8Array {
    return ir.compressed;
}

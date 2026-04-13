// lib/obfuscate.ts
//
// PyGuard v4/v5 — hardened Python obfuscator.
//
// v5 adds an AST-walking interpreter path: when caller provides a pre-built
// IR dict (from lib/v5/build_ir.py, run in Pyodide or a subprocess), the
// user source is replaced with a generic interpreter + encrypted IR blob,
// so the final compile() call never sees user Python source.
//
// ============================================================================
// Threat model: motivated humans AND adversarial LLMs.
// ============================================================================
//
// The primary adversary is an AI system (an LLM) instructed to deobfuscate
// the stub. LLMs are strong at pattern matching, descriptive-name reasoning,
// small-graph control flow, and common cipher detection. They are weaker at:
//
//   - tracking many simultaneously-live identifiers with no semantic names,
//   - un-flattening state machines with opaque state values,
//   - holding long strings of random data in working memory,
//   - tracing scattered data fragments with interleaved decoys,
//   - recognizing that junk arithmetic is a no-op without simulating it.
//
// This module exploits every one of those weaknesses while keeping the
// "stdlib only" design constraint and full Python compatibility.
//
// Defences layered in the generated stub:
//
//   1.  FULL PYTHON COMPATIBILITY. User payload runs inside a single
//       namespace dict passed as the only globals/locals to a captured
//       `exec`. Functions, classes, closures, decorators, generators,
//       async, and `__main__` guards all work.
//
//   2.  PER-STUB POLYMORPHIC CIPHER. Number of SPN rounds, every KDF
//       label, the rotation modulus, the S-box nudge, and three
//       anti-debug poison masks are all randomized per stub. A generic
//       unpacker that hardcodes any of them fails on the next stub.
//
//   3.  RANDOMIZED CONFUSABLE IDENTIFIERS. Every top-level variable,
//       helper function, loop counter, and intermediate value in the
//       canonical region is named with a fresh identifier drawn from
//       {_, l, I, O, 0, 1}. Distinct names look nearly identical under
//       fast scanning and carry zero semantic information to an LLM.
//
//   4.  RANDOMLY PERMUTED CAPTURED-BUILTIN TUPLE. The tuple
//       `(compile, getattr, type, __import__, open, exec)` is shuffled
//       per stub. `_O[3](...)` might be `__import__` in one stub and
//       `exec` in the next. Semantic reasoning about indices breaks.
//
//   5.  CONTROL-FLOW-FLATTENED DECRYPTOR. `_dec` is rewritten as an
//       opaque state machine: a single `while` loop dispatching on a
//       state variable whose values are random bytes with no mnemonic.
//       Nested-loop pattern matching fails.
//
//   6.  CIPHERTEXT SPLITTING WITH DECOY CHUNKS. The base64 ciphertexts
//       for Stage 1 and the user payload are split into random-sized
//       fragments. Decoys of the same form (random base64) are
//       interleaved and shuffled into the source. The final concat
//       expression names only the real fragments, in order. A reverser
//       must visually trace the exact concat list to reconstruct the
//       ciphertext.
//
//   7.  DECOY KEY-LIKE BYTE ARRAYS. Multiple 32-byte arrays that look
//       identical to the real stored-XOR key are emitted above the
//       canonical region. The real one is selected by the runtime via
//       its randomized name.
//
//   8.  JUNK ARITHMETIC NO-OPS. The hash-transform chain includes
//       decoy operations that compute value-dependent masks and then
//       cancel them out. A reverser must trace each one to confirm it
//       is a no-op; a pattern-matching LLM is likely to treat them as
//       meaningful and derive a wrong key.
//
//   9.  TWO-LAYER ENCRYPTION. User payload is encrypted with one set
//       of cipher params, embedded in Stage 1 source, which is itself
//       encrypted with a different set. Both decrypt through the same
//       obfuscated `_dec`.
//
//   10. SELF-INTEGRITY HASH BINDING. Master seed is stored as
//       `_X = seed XOR sha256(canonical_region)`. Modifying any byte
//       between markers — including junk and decoys — changes the
//       hash, corrupts the seed, and silently produces unparseable
//       plaintext. No visible error.
//
//   11. SPLIT HASH UPDATES. The canonical hash is computed via two
//       `hashlib.sha256().update()` calls over non-overlapping halves
//       of the input, not the obvious one-liner. Pattern search for
//       `hashlib.sha256(x).digest()` does not find the integrity hash.
//
//   12. ANTI-DEBUG VIA HASH POISONING. `sys.gettrace()` or
//       `sys.getprofile()` being non-None silently XORs the hash with
//       a per-stub poison mask. No `if debugger: exit()` to NOP out.
//
//   13. CAPTURED-BUILTIN IDENTITY + __class__.__name__ CHECKS.
//       `compile`, `exec`, `getattr`, `__import__`, `open`, `type`
//       must still be their original C-level builtins. Monkey-patching
//       or replacement with Python wrappers triggers another poison
//       mask.
//
// Honest security caveat:
//
//   Pure-software obfuscation against an attacker with the source, a
//   Python interpreter, and a debugger is, in the limit, defeatable.
//   The goal here is not "uncrackable". It is "hard enough that
//   automated analysis fails, pattern matching fails, generic
//   unpackers fail, and even a sophisticated LLM with the full stub in
//   context will miss on first pass." A determined human with time
//   and tools can still win.

// ---------------------------------------------------------------------------
// SHA-256 (synchronous, for use in both browser and Node).
// ---------------------------------------------------------------------------

const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256(data: Uint8Array): Uint8Array {
    const H = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const len = data.length;
    const bitLenLo = (len * 8) >>> 0;
    const bitLenHi = Math.floor((len * 8) / 0x100000000);
    const padLen = ((len + 9 + 63) >> 6) << 6;
    const m = new Uint8Array(padLen);
    m.set(data);
    m[len] = 0x80;
    const dv = new DataView(m.buffer);
    dv.setUint32(padLen - 8, bitLenHi, false);
    dv.setUint32(padLen - 4, bitLenLo, false);

    const w = new Uint32Array(64);
    const ROTR = (x: number, n: number): number =>
        ((x >>> n) | (x << (32 - n))) >>> 0;

    for (let i = 0; i < padLen; i += 64) {
        for (let t = 0; t < 16; t++) {
            w[t] = dv.getUint32(i + t * 4, false);
        }
        for (let t = 16; t < 64; t++) {
            const s0 =
                ROTR(w[t - 15], 7) ^ ROTR(w[t - 15], 18) ^ (w[t - 15] >>> 3);
            const s1 =
                ROTR(w[t - 2], 17) ^ ROTR(w[t - 2], 19) ^ (w[t - 2] >>> 10);
            w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
        }
        let a = H[0], b = H[1], c = H[2], d = H[3];
        let e = H[4], f = H[5], g = H[6], h = H[7];
        for (let t = 0; t < 64; t++) {
            const S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
            const ch = ((e & f) ^ ((~e) & g)) >>> 0;
            const t1 = (h + S1 + ch + SHA256_K[t] + w[t]) >>> 0;
            const S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
            const mj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
            const t2 = (S0 + mj) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + t1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) >>> 0;
        }
        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i], false);
    return out;
}

// ---------------------------------------------------------------------------
// Byte and string helpers.
// ---------------------------------------------------------------------------

function strToUtf8(s: string): Uint8Array {
    return new TextEncoder().encode(s);
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

function bytesToBase64(bytes: Uint8Array): string {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    if (typeof btoa === "function") return btoa(s);
    // Node fallback
    return Buffer.from(s, "binary").toString("base64");
}

function randomBytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    const g: any = typeof globalThis !== "undefined" ? globalThis : {};
    if (g.crypto && typeof g.crypto.getRandomValues === "function") {
        g.crypto.getRandomValues(out);
        return out;
    }
    for (let i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
    return out;
}

function findBytes(haystack: Uint8Array, needle: Uint8Array): number {
    outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
        for (let j = 0; j < needle.length; j++) {
            if (haystack[i + j] !== needle[j]) continue outer;
        }
        return i;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// Custom 8-round substitution-permutation cipher.
//
// Per byte i of plaintext:
//
//     b = pt[i] XOR prev_ct       # CBC chaining
//     for r in 0..7:
//         b ^= round_key[r][i % 32]
//         b = sbox[b]
//         b = rotl(b, rot_key[r])
//     ct[i] = b
//     prev_ct = b
//
// Decryption inverts each round in reverse order.
//
// Round keys, rotation table, and S-box are all derived deterministically
// from a 32-byte master `seed` via SHA-256, so the same TS code and the
// same Python code produce identical parameters from identical seeds.
// ---------------------------------------------------------------------------

interface CipherParams {
    rks: Uint8Array[];
    rotk: number[];
    sbox: number[];
    inv: number[];
}

// Polymorphism profile. Different per stub. Embedded in both the stub
// source AND the TS-side encryption code, so the same TS code and the
// same Python code produce identical parameters from identical seeds.
//
// Two stubs generated back-to-back use different round counts, different
// KDF labels, different rotation moduli, and different "salt" bytes
// folded into the S-box derivation. A single generic unpacker that
// hardcodes these constants will fail against an arbitrary stub.
interface PolyProfile {
    rounds: number;        // 6..10
    rkLabel: Uint8Array;   // random 4 bytes
    rotLabel: Uint8Array;  // random 4 bytes
    sbxLabel: Uint8Array;  // random 4 bytes
    rotMod: number;        // 5..7 (rot key in [1, rotMod])
    sbxNudge: number;      // 0..255, mixed into S-box generation
    poison1: number;       // 1..255, anti-debug XOR mask
    poison2: number;       // 1..255, identity-check XOR mask
    poison3: number;       // 1..255, builtin-class XOR mask
}

function makeProfile(): PolyProfile {
    const r = randomBytes(16);
    const rounds = 6 + (r[0] % 5); // 6..10
    return {
        rounds,
        rkLabel: randomBytes(4),
        rotLabel: randomBytes(4),
        sbxLabel: randomBytes(4),
        rotMod: 5 + (r[1] % 3),     // 5..7
        sbxNudge: r[2],
        poison1: 1 + (r[3] % 255),
        poison2: 1 + (r[4] % 255),
        poison3: 1 + (r[5] % 255),
    };
}

function kdf(seed: Uint8Array, prof: PolyProfile): CipherParams {
    const rks: Uint8Array[] = [];
    let h: Uint8Array = seed;
    for (let i = 0; i < prof.rounds; i++) {
        h = sha256(concatBytes(h, prof.rkLabel));
        rks.push(h);
    }
    const rotSeed = sha256(concatBytes(seed, prof.rotLabel));
    const rotk: number[] = [];
    for (let i = 0; i < prof.rounds; i++) {
        rotk.push((rotSeed[i] % prof.rotMod) + 1);
    }

    const sbxSeed = sha256(concatBytes(seed, prof.sbxLabel));
    const sbox: number[] = [];
    for (let i = 0; i < 256; i++) sbox.push(i);
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + sbox[i] + sbxSeed[i % 32] + prof.sbxNudge) % 256;
        const t = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = t;
    }
    const inv = new Array<number>(256);
    for (let i = 0; i < 256; i++) inv[sbox[i]] = i;

    return { rks, rotk, sbox, inv };
}

function encrypt(
    plaintext: Uint8Array,
    p: CipherParams,
    prof: PolyProfile,
): Uint8Array {
    const out = new Uint8Array(plaintext.length);
    let prev = 0;
    for (let i = 0; i < plaintext.length; i++) {
        let b = plaintext[i];
        b ^= prev;
        for (let r = 0; r < prof.rounds; r++) {
            b ^= p.rks[r][i % 32];
            b = p.sbox[b];
            const k = p.rotk[r];
            b = ((b << k) | (b >>> (8 - k))) & 0xff;
        }
        out[i] = b;
        prev = b;
    }
    return out;
}

function bytesArrayLit(b: Uint8Array): string {
    return "[" + Array.from(b).join(", ") + "]";
}

// ---------------------------------------------------------------------------
// Anti-LLM obfuscation helpers.
// ---------------------------------------------------------------------------

// Python reserved words and common builtins we must not shadow with a
// randomly-generated identifier.
const PY_RESERVED = new Set<string>([
    "False", "None", "True", "and", "as", "assert", "async", "await",
    "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is",
    "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
    "while", "with", "yield", "match", "case",
    "compile", "exec", "getattr", "type", "open", "hashlib", "sys",
    "base64", "bytes", "bytearray", "list", "dict", "tuple", "range",
    "len", "zip", "int", "str", "__name__", "__main__", "__builtins__",
    "__file__", "__import__", "__package__", "__doc__", "__loader__",
    "__spec__",
]);

interface NameGen {
    gen(): string;
}

// Random-identifier generator. Emits names of the form `_<letters>` where
// every character is drawn uniformly from the 52-letter mixed-case Latin
// alphabet. Names carry zero semantic value — the anti-LLM defence is the
// absence of meaning, not visual confusability. A wider alphabet also
// makes the output readable enough to debug without diluting the core
// property that identifiers tell a reader nothing about what they hold.
function makeNameGen(): NameGen {
    const used = new Set<string>();
    const pool =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    return {
        gen(): string {
            for (let attempts = 0; attempts < 256; attempts++) {
                const r = randomBytes(16);
                const len = 8 + (r[0] % 5); // 8..12
                let s = "_" + pool[r[1] % pool.length];
                for (let i = 2; i < len; i++) {
                    s += pool[r[i] % pool.length];
                }
                if (!used.has(s) && !PY_RESERVED.has(s)) {
                    used.add(s);
                    return s;
                }
            }
            throw new Error("NameGen: exhausted attempts");
        },
    };
}

interface BuiltinCapture {
    tupleSource: string;             // e.g. "(exec, type, compile, ...)"
    idx: Record<string, number>;     // name -> position in the shuffled tuple
}

// Randomly permute the captured-builtin tuple so that `_O[3](...)` means
// a different builtin in every generated stub. Cross-stub index-based
// reasoning is broken.
function captureBuiltins(): BuiltinCapture {
    const names = ["compile", "getattr", "type", "__import__", "open", "exec"];
    const r = randomBytes(16);
    const perm = [...names];
    for (let i = perm.length - 1; i > 0; i--) {
        const j = r[i] % (i + 1);
        const t = perm[i]; perm[i] = perm[j]; perm[j] = t;
    }
    const idx: Record<string, number> = {};
    perm.forEach((n, i) => { idx[n] = i; });
    return { tupleSource: `(${perm.join(", ")})`, idx };
}

function makeRandomB64Chunk(len: number): string {
    const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const r = randomBytes(len);
    let s = "";
    for (let i = 0; i < len; i++) s += chars[r[i] % 64];
    return s;
}

function shuffleArr<T>(a: T[]): void {
    const r = randomBytes(Math.max(1, a.length + 1));
    for (let i = a.length - 1; i > 0; i--) {
        const j = r[i % r.length] % (i + 1);
        const t = a[i]; a[i] = a[j]; a[j] = t;
    }
}

interface ChunkedB64 {
    decls: string;   // Python-source lines declaring every chunk
    concat: string;  // Python concat expression of ONLY the real chunks
}

// Split a base64 ciphertext into random-sized fragments, interleave decoy
// fragments of the same form, shuffle the declarations, and return:
//
//   - decls:  one "<random_name> = \"<chunk>\"" line per real AND decoy
//             fragment, in shuffled order.
//   - concat: Python expression "<real_name_0> + <real_name_1> + ..."
//             concatenating ONLY the real fragments in their original
//             order, by name.
//
// A reverser must visually trace the concat expression to locate the real
// fragments among the decoys, then reconstruct the ciphertext. An LLM that
// skims the declarations and picks out "large base64 strings" gets a
// random superset of real + decoy bytes that does not decrypt.
function chunkB64(b64: string, ng: NameGen): ChunkedB64 {
    // Chunk-size selection is a direct size/analysis tradeoff.
    //
    // Smaller chunks -> more `_name = "..."` lines -> more decoy budget per
    // unit of real data, more visual noise in the declaration block, but
    // also dramatically more lines in the final stub and a longer concat
    // expression at runtime.
    //
    // The v5 stage2 payload embeds a ~50KB interpreter source plus the
    // encrypted IR, so at chunk size 24..63 we previously emitted ~13k
    // decl lines per stub — 98% of the file. Bumping to 320..640 cuts
    // that to ~200-400 decl lines with no measurable security change:
    // the reverser still has to trace the concat expression to pick
    // real chunks out of decoys, and one 512-char base64 fragment is
    // no easier to reason about than ten 48-char fragments.
    const pieces: string[] = [];
    let i = 0;
    while (i < b64.length) {
        const r = randomBytes(1);
        const sz = 320 + (r[0] % 321); // 320..640
        pieces.push(b64.slice(i, i + sz));
        i += sz;
    }
    const realNames = pieces.map(() => ng.gen());

    interface Entry { name: string; value: string; }
    const all: Entry[] = [];
    for (let k = 0; k < pieces.length; k++) {
        all.push({ name: realNames[k], value: pieces[k] });
        const r = randomBytes(1);
        // 0..1 decoys per real chunk (was 0..2). With larger chunk sizes,
        // a ~50% decoy rate still doubles the declaration block visually
        // but costs only half as many lines as the previous 0..2 range.
        const decoys = r[0] % 2;
        for (let d = 0; d < decoys; d++) {
            const decoyLen = 320 + (randomBytes(1)[0] % 321);
            all.push({ name: ng.gen(), value: makeRandomB64Chunk(decoyLen) });
        }
    }
    shuffleArr(all);
    const decls = all.map(e => `${e.name} = "${e.value}"`).join("\n");
    const concat = realNames.join(" + ");
    return { decls, concat };
}

// Pick four distinct random state-machine state bytes for the flattened
// `_dec` dispatcher.
function makeStates(): { s0: number; s1: number; s2: number; sEnd: number } {
    const r = randomBytes(32);
    const picks: number[] = [];
    for (let i = 0; i < r.length && picks.length < 4; i++) {
        if (!picks.includes(r[i])) picks.push(r[i]);
    }
    while (picks.length < 4) picks.push((picks[picks.length - 1] + 37) & 0xff);
    return { s0: picks[0], s1: picks[1], s2: picks[2], sEnd: picks[3] };
}

// ---------------------------------------------------------------------------
// Main entry point.
// ---------------------------------------------------------------------------

// Markers must NOT appear as a substring anywhere else in the generated
// stub. We reference them at runtime only via `bytes([...])` literals so
// that the textual representation never reappears in the canonical region.
// The marker lines themselves are the only occurrences of these byte
// sequences in the file.
const BEGIN_MARKER = "#PYG4S";
const END_MARKER = "#PYG4E";
const BEGIN_MARKER_BYTES_LIT = "[35, 80, 89, 71, 52, 83]"; // '#PYG4S'
const END_MARKER_BYTES_LIT = "[35, 80, 89, 71, 52, 69]";   // '#PYG4E'

// v5 imports — kept inline so non-v5 code paths don't pull in the
// interpreter source string.
import { buildV5Stage2Source, serializeIR } from './v5/assemble';
import type { V5IR } from './v5/assemble';

export interface ObfuscateOpts {
    // When provided, uses the v5 AST-walking interpreter path:
    // the IR is encrypted and the stage2 source becomes a generic
    // interpreter plus an encrypted blob, so the final compile() event
    // never sees user source. Build the IR with lib/v5/build_ir.py
    // (in Pyodide for browser, or via subprocess for Node testing).
    v5IR?: V5IR;
}

export function obfuscatePythonCode(input: string, opts?: ObfuscateOpts): string {
    if (typeof input !== "string") {
        throw new Error("obfuscatePythonCode: input must be a string");
    }

    // 1. Polymorphism profile, name generator, shuffled builtin tuple,
    //    random state-machine states, random stage-2 KDF label.
    const prof = makeProfile();
    const stage2Label = randomBytes(6);
    const ng = makeNameGen();
    const bcap = captureBuiltins();
    const bi = bcap.idx;
    const st = makeStates();

    // 2. Random confusable identifier for every logical symbol in the stub.
    //    Grouped here so the template-literal substitutions below are
    //    compact and mechanical.
    const n_X        = ng.gen();
    const n_O        = ng.gen();
    const n_kd       = ng.gen();
    const n_dec      = ng.gen();
    const n_path     = ng.gen();
    const n_srcRaw   = ng.gen();
    const n_f        = ng.gen();
    const n_s        = ng.gen();
    const n_e        = ng.gen();
    const n_half     = ng.gen();
    const n_hasher   = ng.gen();
    const n_h        = ng.gen();
    const n_bn       = ng.gen();
    const n_seed     = ng.gen();
    const n_p1       = ng.gen();
    const n_S1       = ng.gen();
    const n_pt1      = ng.gen();
    const n_src1     = ng.gen();
    const n_ns       = ng.gen();
    const n_co       = ng.gen();
    const n_mask     = ng.gen(); // junk no-op mask var
    const n_mask2    = ng.gen(); // junk no-op mask var
    const n_chainA   = ng.gen(); // junk chain var
    const n_chainB   = ng.gen(); // junk chain var
    const n_ftype    = ng.gen(); // type(lambda: 0) — FunctionType without importing types
    const n_rec_mod  = ng.gen(); // recompiled-from-disk module code object
    const n_cod      = ng.gen(); // deep co_code-tree digest helper
    const n_tchk     = ng.gen(); // traceback-based trace detector
    const n_live_d   = ng.gen(); // deep digest of currently-executing module
    const n_rec_d    = ng.gen(); // deep digest of recompiled-from-disk module
    const n_cod_c    = ng.gen(); // parameter name for _cod helper
    const n_cod_h    = ng.gen(); // internal hasher name for _cod
    const n_cod_s    = ng.gen(); // internal stack name for _cod
    const n_cod_x    = ng.gen(); // internal pop var for _cod
    const n_cod_k    = ng.gen(); // internal inner const var for _cod
    const n_gf       = ng.gen(); // getframe alias (hides from Attribute('_getframe') walkers)
    const n_te       = ng.gen(); // traceback helper exception
    const n_ttb      = ng.gen(); // traceback helper tb
    const n_tfr      = ng.gen(); // traceback helper frame

    // _kd internal names
    const k_seed     = ng.gen();
    const k_h2       = ng.gen();
    const k_rks      = ng.gen();
    const k_rotk     = ng.gen();
    const k_sbx      = ng.gen();
    const k_sbox     = ng.gen();
    const k_inv      = ng.gen();
    const k_i        = ng.gen();
    const k_j        = ng.gen();
    const k_disk     = ng.gen(); // raw bytes re-read from disk
    const k_recc     = ng.gen(); // recompiled-from-disk co_code
    const k_corr     = ng.gen(); // hidden self-cancelling correction

    // _dec internal names
    const d_ct       = ng.gen();
    const d_rks      = ng.gen();
    const d_rotk     = ng.gen();
    const d_inv      = ng.gen();
    const d_out      = ng.gen();
    const d_N        = ng.gen();
    const d_i        = ng.gen();
    const d_r        = ng.gen();
    const d_prev     = ng.gen();
    const d_b        = ng.gen();
    const d_st       = ng.gen();
    const d_k        = ng.gen();

    // Stage 1 internal names
    const s1_b       = ng.gen();
    const s1_bn      = ng.gen();
    const s1_seed2   = ng.gen();
    const s1_p2      = ng.gen();
    const s1_S2      = ng.gen();
    const s1_pt2     = ng.gen();
    const s1_src2    = ng.gen();
    const s1_uns     = ng.gen();
    const s1_co2     = ng.gen();

    // _vfy (second-layer bytecode-integrity defence) names
    const n_vfy      = ng.gen();
    const v_in       = ng.gen();
    const v_out      = ng.gen();

    // 3. Pepper graph. A chain of sha256-derived module-level byte arrays,
    //    referenced FROM INSIDE `_kd` as a closure global. An attacker who
    //    extracts `_kd` via `ast.unparse` and execs it in an isolated
    //    namespace triggers `NameError` on the pepper lookup — the
    //    function is simply not callable outside the full canonical
    //    context. A smarter attacker who also captures top-level
    //    assignments must walk a dependency graph of multiple sha256
    //    computations, most of which are decoys that never reach `_kd`.
    const n_pepSeed   = ng.gen();
    const n_pepA      = ng.gen();
    const n_pepB      = ng.gen();
    const n_pepC      = ng.gen();
    const n_pep       = ng.gen();
    const n_pepDecoy1 = ng.gen();
    const n_pepDecoy2 = ng.gen();
    const n_pepDecoy3 = ng.gen();

    const pepSeedBytes = randomBytes(32);
    const pepA = sha256(pepSeedBytes);
    const pepB = sha256(concatBytes(pepA, pepSeedBytes));
    const pepC = sha256(concatBytes(pepB, pepA));
    const pep = pepC;

    // 4. Derive cipher parameters and encrypt user payload.
    //    The runtime `_kd` XORs its input with `pep` before any sha256.
    //    We reproduce that here so encryption matches the stub runtime.
    //    `seed` is the VALUE THE STUB STORES (post-formula, pre-pepper).
    //    `pepperedSeed` is what the cipher rounds actually consume.
    const seed = randomBytes(32);

    // _vfy returns sha256(seed || 32-byte-zero-corr) on honest run.
    // Its output (not the raw seed) is what _kd receives for stage 1.
    // Stage 1 itself still uses the raw `seed` via `_seed` for stage 2
    // derivation, so seed2 computation below stays keyed on `seed`.
    const vfySeed1 = sha256(concatBytes(seed, new Uint8Array(32)));
    const pepperedSeed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) pepperedSeed[i] = vfySeed1[i] ^ pep[i];

    const params1 = kdf(pepperedSeed, prof);

    // Stage-2 seed derivation: sha256(storedSeed || stage2Label). The runtime
    // uses `_seed` (the formula-seed, before pepper) here, matching.
    const seed2 = sha256(concatBytes(seed, stage2Label));
    const pepperedSeed2 = new Uint8Array(32);
    for (let i = 0; i < 32; i++) pepperedSeed2[i] = seed2[i] ^ pep[i];
    const params2 = kdf(pepperedSeed2, prof);

    // In v5 mode, replace the user Python source with a stage2 wrapper
    // containing the AST-walking interpreter and an encrypted IR blob.
    // The IR is encrypted with a separate third-stage key derived from
    // the same runtime-recovered `_seed`, so there is never a moment at
    // which user Python source appears as a compile() argument.
    let payloadBytes: Uint8Array;
    if (opts && opts.v5IR) {
        // Fresh names for the IR decryption snippet inside stage2.
        const irVarSeed    = ng.gen();
        const irVarP       = ng.gen();
        const irVarCt      = ng.gen();
        const irVarPt      = ng.gen();
        const schemaVarSeed = ng.gen();
        const schemaVarP    = ng.gen();
        const schemaVarCt   = ng.gen();
        const schemaVarPt   = ng.gen();
        const schemaVarObj  = ng.gen();
        const interpUnpack = ng.gen();

        // Third-stage cipher: derived from the same seed with a fresh label.
        const irLabel = randomBytes(6);
        const irSeed3 = sha256(concatBytes(seed, irLabel));
        const pepperedSeed3 = new Uint8Array(32);
        for (let i = 0; i < 32; i++) pepperedSeed3[i] = irSeed3[i] ^ pep[i];
        const params3 = kdf(pepperedSeed3, prof);

        // Encrypt the (already compressed) IR bytes with the v4 cipher.
        const irJsonBytes = serializeIR(opts.v5IR);
        const encIR = encrypt(irJsonBytes, params3, prof);
        const encIRB64 = bytesToBase64(encIR);
        const irChunks = chunkB64(encIRB64, ng);

        const schemaLabel = randomBytes(6);
        const schemaSeed4 = sha256(concatBytes(seed, schemaLabel));
        const pepperedSeed4 = new Uint8Array(32);
        for (let i = 0; i < 32; i++) pepperedSeed4[i] = schemaSeed4[i] ^ pep[i];
        const params4 = kdf(pepperedSeed4, prof);
        const schemaBytes = strToUtf8(JSON.stringify(opts.v5IR.schema));
        const encSchema = encrypt(schemaBytes, params4, prof);
        const encSchemaB64 = bytesToBase64(encSchema);
        const schemaChunks = chunkB64(encSchemaB64, ng);

        const stage2Src = buildV5Stage2Source(
            { n_seed, n_kd, n_dec, n_tchk },
            {
                prof,
                irLabel,
                schemaLabel,
                irChunks,
                schemaChunks,
                irVarSeed, irVarP, irVarCt, irVarPt,
                schemaVarSeed, schemaVarP, schemaVarCt, schemaVarPt, schemaVarObj,
                interpUnpack,
            },
        );
        payloadBytes = strToUtf8(stage2Src);
    } else {
        payloadBytes = strToUtf8(input);
    }
    const encUser = encrypt(payloadBytes, params2, prof);
    const encUserB64 = bytesToBase64(encUser);
    const userChunks = chunkB64(encUserB64, ng);

    // 4. Build Stage 1 source. Runs in a namespace where the canonical
    //    region has injected: __builtins__, the randomized `_O` tuple,
    //    the randomized seed/kd/dec names, sys, hashlib, base64, __file__.
    const stage1Src = `${s1_b} = ${n_O}[${bi['__import__']}]('builtins')
try:
    ${n_O}[${bi['getattr']}](sys, 'settrace')(None)
except Exception:
    pass
try:
    ${n_O}[${bi['getattr']}](sys, 'setprofile')(None)
except Exception:
    pass
if ${n_tchk}(): ${s1_b}.exit(1)
if ${n_O}[${bi['getattr']}](sys, 'gettrace')() is not None: ${s1_b}.exit(1)
if ${n_O}[${bi['getattr']}](sys, 'getprofile')() is not None: ${s1_b}.exit(1)
if compile is not ${n_O}[${bi['compile']}]: ${s1_b}.exit(1)
if getattr is not ${n_O}[${bi['getattr']}]: ${s1_b}.exit(1)
if type is not ${n_O}[${bi['type']}]: ${s1_b}.exit(1)
if __import__ is not ${n_O}[${bi['__import__']}]: ${s1_b}.exit(1)
if open is not ${n_O}[${bi['open']}]: ${s1_b}.exit(1)
if exec is not ${n_O}[${bi['exec']}]: ${s1_b}.exit(1)
${s1_bn} = 'builtin_function_or_method'
if (compile.__class__.__name__ != ${s1_bn} or exec.__class__.__name__ != ${s1_bn} or
    getattr.__class__.__name__ != ${s1_bn} or __import__.__class__.__name__ != ${s1_bn} or
    open.__class__.__name__ != ${s1_bn} or
    compile.__module__ != 'builtins' or exec.__module__ != 'builtins'):
    ${s1_b}.exit(1)
${s1_seed2} = hashlib.sha256(${n_seed} + bytes(${bytesArrayLit(stage2Label)})).digest()
${s1_p2} = ${n_kd}(${s1_seed2})
${userChunks.decls}
${s1_S2} = base64.b64decode(${userChunks.concat})
${s1_pt2} = ${n_dec}(${s1_S2}, ${s1_p2}[0], ${s1_p2}[1], ${s1_p2}[2])
try:
    ${s1_src2} = ${s1_pt2}.decode('utf-8')
except Exception:
    sys.exit(0)
${s1_uns} = {'__name__': '__main__', '__builtins__': ${s1_b}, '__file__': __file__, '__package__': None, '__doc__': None, '__loader__': None, '__spec__': None${opts && opts.v5IR ? `, '${n_seed}': ${n_seed}, '${n_kd}': ${n_kd}, '${n_dec}': ${n_dec}, '${n_tchk}': ${n_tchk}` : ''}}
try:
    ${s1_co2} = ${n_O}[${bi['compile']}](${s1_src2}, __file__, 'exec')
except Exception:
    sys.exit(0)
${n_ftype}(${s1_co2}, ${s1_uns})()
`;

    const stage1Bytes = strToUtf8(stage1Src);
    const encStage1 = encrypt(stage1Bytes, params1, prof);
    const encStage1B64 = bytesToBase64(encStage1);
    const stage1Chunks = chunkB64(encStage1B64, ng);

    // 5. Build the canonical region. Every named identifier is randomized;
    //    _dec is a flattened state machine; hash is computed via two
    //    update() calls; junk no-op XORs are folded into the chain.
    // Pepper graph: chained sha256 computations producing the actual
    // pepper used by `_kd`, interleaved with decoys of identical shape.
    // The real chain is `pepSeed -> pepA -> pepB -> pepC -> pep`, and
    // `_kd` references only `${n_pep}`. Extracting just `_kd` in
    // isolation NameErrors on `${n_pep}`.
    const pepLines: string[] = [];
    pepLines.push(`${n_pepSeed} = bytes(${bytesArrayLit(pepSeedBytes)})`);
    pepLines.push(`${n_pepA} = hashlib.sha256(${n_pepSeed}).digest()`);
    pepLines.push(`${n_pepB} = hashlib.sha256(${n_pepA} + ${n_pepSeed}).digest()`);
    pepLines.push(`${n_pepC} = hashlib.sha256(${n_pepB} + ${n_pepA}).digest()`);
    pepLines.push(`${n_pep} = ${n_pepC}`);
    // Decoy pepper computations with the same visual shape.
    pepLines.push(`${n_pepDecoy1} = hashlib.sha256(bytes(${bytesArrayLit(randomBytes(32))})).digest()`);
    pepLines.push(`${n_pepDecoy2} = hashlib.sha256(${n_pepDecoy1} + bytes(${bytesArrayLit(randomBytes(16))})).digest()`);
    pepLines.push(`${n_pepDecoy3} = hashlib.sha256(${n_pepDecoy2} + ${n_pepDecoy1}).digest()`);
    shuffleArr(pepLines);
    // But the first line MUST define pepSeed and the sha256 chain must run
    // in dependency order. Easier: just keep a topological order, skip the
    // full shuffle, and only shuffle the three decoys relative to the real
    // chain. Simplest: emit real chain in order, then append decoys, then
    // interleave a handful of reads-that-do-nothing.
    const realChain = [
        `${n_pepSeed} = bytes(${bytesArrayLit(pepSeedBytes)})`,
        `${n_pepA} = hashlib.sha256(${n_pepSeed}).digest()`,
        `${n_pepB} = hashlib.sha256(${n_pepA} + ${n_pepSeed}).digest()`,
        `${n_pepC} = hashlib.sha256(${n_pepB} + ${n_pepA}).digest()`,
        `${n_pep} = ${n_pepC}`,
    ];
    const decoyChain = [
        `${n_pepDecoy1} = hashlib.sha256(bytes(${bytesArrayLit(randomBytes(32))})).digest()`,
        `${n_pepDecoy2} = hashlib.sha256(${n_pepDecoy1} + bytes(${bytesArrayLit(randomBytes(16))})).digest()`,
        `${n_pepDecoy3} = hashlib.sha256(${n_pepDecoy2} + ${n_pepDecoy1}).digest()`,
    ];
    // Interleave without breaking the real chain's internal dependency order.
    const interleaved: string[] = [];
    let ri = 0, di = 0;
    const rpick = randomBytes(realChain.length + decoyChain.length);
    while (ri < realChain.length || di < decoyChain.length) {
        const tryDecoy =
            di < decoyChain.length &&
            (ri >= realChain.length || (rpick[ri + di] & 1) === 0);
        if (tryDecoy) {
            interleaved.push(decoyChain[di++]);
        } else {
            interleaved.push(realChain[ri++]);
        }
    }
    const pepperBlock = interleaved.join("\n");

    const canonicalRegion =
`${BEGIN_MARKER}
import sys, hashlib, base64
${n_ftype} = type(lambda: 0)
${n_O} = ${bcap.tupleSource}
${n_gf} = ${n_O}[${bi['getattr']}](sys, '_getf' + 'rame')
try:
    ${n_O}[${bi['getattr']}](sys, 'settrace')(None)
except Exception:
    pass
try:
    ${n_O}[${bi['getattr']}](sys, 'setprofile')(None)
except Exception:
    pass
${pepperBlock}
def ${n_kd}(${k_seed}):
    ${k_seed} = bytes(a ^ b for a, b in zip(${k_seed}, ${n_pep}))
    ${k_rks} = []
    ${k_h2} = ${k_seed}
    for _ in range(${prof.rounds}):
        ${k_h2} = hashlib.sha256(${k_h2} + bytes(${bytesArrayLit(prof.rkLabel)})).digest()
        ${k_rks}.append(${k_h2})
    ${k_rotk} = [(b % ${prof.rotMod}) + 1 for b in hashlib.sha256(${k_seed} + bytes(${bytesArrayLit(prof.rotLabel)})).digest()[:${prof.rounds}]]
    ${k_sbx} = hashlib.sha256(${k_seed} + bytes(${bytesArrayLit(prof.sbxLabel)})).digest()
    ${k_sbox} = list(range(256))
    ${k_j} = 0
    for ${k_i} in range(256):
        ${k_j} = (${k_j} + ${k_sbox}[${k_i}] + ${k_sbx}[${k_i} % 32] + ${prof.sbxNudge}) % 256
        ${k_sbox}[${k_i}], ${k_sbox}[${k_j}] = ${k_sbox}[${k_j}], ${k_sbox}[${k_i}]
    ${k_inv} = [0] * 256
    for ${k_i} in range(256):
        ${k_inv}[${k_sbox}[${k_i}]] = ${k_i}
    return ${k_rks}, ${k_rotk}, ${k_inv}
def ${n_dec}(${d_ct}, ${d_rks}, ${d_rotk}, ${d_inv}):
    ${d_out} = bytearray(len(${d_ct}))
    ${d_N} = ${prof.rounds}
    ${d_i} = 0
    ${d_r} = 0
    ${d_prev} = 0
    ${d_b} = 0
    ${d_st} = ${st.s0}
    while True:
        if ${d_st} == ${st.sEnd}:
            break
        if ${d_st} == ${st.s0}:
            if ${d_i} >= len(${d_ct}):
                ${d_st} = ${st.sEnd}
                continue
            ${d_b} = ${d_ct}[${d_i}]
            ${d_r} = ${d_N} - 1
            ${d_st} = ${st.s1}
            continue
        if ${d_st} == ${st.s1}:
            if ${d_r} < 0:
                ${d_st} = ${st.s2}
                continue
            ${d_k} = ${d_rotk}[${d_r}]
            ${d_b} = ((${d_b} >> ${d_k}) | (${d_b} << (8 - ${d_k}))) & 0xFF
            ${d_b} = ${d_inv}[${d_b}]
            ${d_b} ^= ${d_rks}[${d_r}][${d_i} % 32]
            ${d_r} -= 1
            continue
        if ${d_st} == ${st.s2}:
            ${d_b} ^= ${d_prev}
            ${d_out}[${d_i}] = ${d_b}
            ${d_prev} = ${d_ct}[${d_i}]
            ${d_i} += 1
            ${d_st} = ${st.s0}
            continue
    return bytes(${d_out})
def ${n_cod}(${n_cod_c}):
    ${n_cod_h} = hashlib.sha256()
    ${n_cod_s} = [${n_cod_c}]
    while ${n_cod_s}:
        ${n_cod_x} = ${n_cod_s}.pop()
        ${n_cod_h}.update(${n_cod_x}.co_code)
        for ${n_cod_k} in ${n_cod_x}.co_consts:
            if type(${n_cod_k}).__name__ == 'code':
                ${n_cod_s}.append(${n_cod_k})
    return ${n_cod_h}.digest()
def ${n_tchk}():
    try:
        raise Exception()
    except Exception as ${n_te}:
        ${n_ttb} = ${n_te}.__traceback__
    ${n_tfr} = ${n_ttb}.tb_frame if ${n_ttb} is not None else None
    while ${n_tfr} is not None:
        if ${n_O}[${bi['getattr']}](${n_tfr}, 'f_trace', None) is not None:
            return True
        ${n_tfr} = ${n_tfr}.f_back
    return False
def ${n_vfy}(${v_in}):
    try:
        ${k_corr} = bytes(a ^ b for a, b in zip(
            hashlib.sha256(${n_rec_d} + ${n_cod}(${n_gf}(1).f_code)).digest(),
            hashlib.sha256(${n_rec_d} + ${n_rec_d}).digest()))
        return hashlib.sha256(${v_in} + ${k_corr}).digest()
    except Exception:
        return hashlib.sha256(${v_in} + bytes(32 * [255])).digest()
if ${n_tchk}():
    sys.exit(0)
try:
    ${n_path} = __file__
except NameError:
    ${n_path} = sys.argv[0] if sys.argv else ''
try:
    with ${n_O}[${bi['open']}](${n_path}, 'rb') as ${n_f}:
        ${n_srcRaw} = ${n_f}.read()
except Exception:
    sys.exit(0)
${n_srcRaw} = ${n_srcRaw}.replace(b'\\r\\n', b'\\n').replace(b'\\r', b'\\n')
if ${n_srcRaw}[:3] == b'\\xef\\xbb\\xbf':
    ${n_srcRaw} = ${n_srcRaw}[3:]
${n_s} = ${n_srcRaw}.find(bytes(${BEGIN_MARKER_BYTES_LIT}))
${n_e} = ${n_srcRaw}.find(bytes(${END_MARKER_BYTES_LIT}))
if ${n_s} < 0 or ${n_e} < 0:
    sys.exit(0)
${n_half} = (${n_s} + ${n_e}) // 2
try:
    ${n_rec_mod} = ${n_O}[${bi['compile']}](${n_srcRaw}, ${n_path}, 'exec')
    ${n_live_d} = ${n_cod}(${n_gf}(0).f_code)
    ${n_rec_d} = ${n_cod}(${n_rec_mod})
except Exception:
    ${n_live_d} = bytes(32)
    ${n_rec_d} = bytes(32 * [255])
${n_hasher} = hashlib.sha256()
${n_hasher}.update(${n_srcRaw}[${n_s}:${n_half}])
${n_hasher}.update(bytes(a ^ b for a, b in zip(
    hashlib.sha256(${n_live_d} + ${n_rec_d}).digest(),
    hashlib.sha256(${n_rec_d} + ${n_rec_d}).digest())))
${n_hasher}.update(${n_srcRaw}[${n_half}:${n_e}])
${n_h} = ${n_hasher}.digest()
if ${n_O}[${bi['getattr']}](sys, 'gettrace')() is not None or ${n_O}[${bi['getattr']}](sys, 'getprofile')() is not None:
    ${n_h} = bytes((b ^ ${prof.poison1}) for b in ${n_h})
if compile is not ${n_O}[${bi['compile']}] or exec is not ${n_O}[${bi['exec']}] or getattr is not ${n_O}[${bi['getattr']}]:
    ${n_h} = bytes((b ^ ${prof.poison2}) for b in ${n_h})
${n_bn} = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != ${n_bn} or exec.__class__.__name__ != ${n_bn} or
        getattr.__class__.__name__ != ${n_bn} or __import__.__class__.__name__ != ${n_bn} or
        open.__class__.__name__ != ${n_bn} or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins' or
        getattr.__module__ != 'builtins'):
        ${n_h} = bytes((b ^ ${prof.poison3}) for b in ${n_h})
except Exception:
    ${n_h} = bytes((b ^ ${prof.poison3}) for b in ${n_h})
${n_mask} = sum(b for b in ${n_h}) & 0xFF
${n_mask2} = ${n_mask}
${n_h} = bytes((b ^ ${n_mask} ^ ${n_mask2}) for b in ${n_h})
${n_chainA} = hashlib.sha256(${n_h}).digest()
${n_chainB} = hashlib.sha256(${n_h}).digest()
${n_h} = bytes((a ^ b ^ c) for a, b, c in zip(${n_h}, ${n_chainA}, ${n_chainB}))
${n_seed} = bytes(a ^ b for a, b in zip(${n_X}, ${n_h}))
${n_p1} = ${n_kd}(${n_vfy}(${n_seed}))
${stage1Chunks.decls}
${n_S1} = base64.b64decode(${stage1Chunks.concat})
${n_pt1} = ${n_dec}(${n_S1}, ${n_p1}[0], ${n_p1}[1], ${n_p1}[2])
try:
    ${n_src1} = ${n_pt1}.decode('utf-8')
except Exception:
    sys.exit(0)
${n_ns} = {'__builtins__': __builtins__, '${n_O}': ${n_O}, '${n_seed}': ${n_seed}, '${n_kd}': ${n_kd}, '${n_dec}': ${n_dec}, '${n_tchk}': ${n_tchk}, '${n_ftype}': ${n_ftype}, 'sys': sys, 'hashlib': hashlib, 'base64': base64, '__file__': ${n_path}}
try:
    ${n_co} = ${n_O}[${bi['compile']}](${n_src1}, '<s1>', 'exec')
except Exception:
    sys.exit(0)
${n_ftype}(${n_co}, ${n_ns})()
${END_MARKER}
`;

    // 6. Compute canonical-region hash → stored XOR blob.
    const canonicalBytes = strToUtf8(canonicalRegion);
    const startBytes = strToUtf8(BEGIN_MARKER);
    const endBytes = strToUtf8(END_MARKER);
    const sIdx = findBytes(canonicalBytes, startBytes);
    const eIdx = findBytes(canonicalBytes, endBytes);
    if (sIdx < 0 || eIdx < 0) {
        throw new Error("internal: integrity markers not found in template");
    }
    // Runtime feeds the hasher three chunks:
    //   1. canonical bytes [s : half]
    //   2. a 32-byte term that is self-cancelling to zeros on honest run
    //      (sha256(live_deep_digest + rec_deep_digest) XOR sha256(rec||rec))
    //   3. canonical bytes [half : e]
    // so the baked hash must include 32 zero bytes at the midpoint.
    const halfOffset = Math.floor((eIdx - sIdx) / 2);
    const hashInput = concatBytes(
        canonicalBytes.slice(sIdx, sIdx + halfOffset),
        new Uint8Array(32),
        canonicalBytes.slice(sIdx + halfOffset, eIdx),
    );
    const hashOut = sha256(hashInput);

    const stored = new Uint8Array(32);
    for (let i = 0; i < 32; i++) stored[i] = seed[i] ^ hashOut[i];
    const storedLit = bytesArrayLit(stored);

    // 7. Preamble with the real stored key and several decoy byte arrays
    //    of the exact same form. The real one is identified only by its
    //    randomized name; every other reference in the canonical region
    //    names it explicitly via `${n_X}`.
    const numDecoys = 3 + (randomBytes(1)[0] % 3); // 3..5
    const keyDecls: string[] = [];
    keyDecls.push(`${n_X} = bytes(${storedLit})`);
    for (let i = 0; i < numDecoys; i++) {
        const dName = ng.gen();
        const dBytes = randomBytes(32);
        keyDecls.push(`${dName} = bytes(${bytesArrayLit(dBytes)})`);
    }
    shuffleArr(keyDecls);

    return `#!/usr/bin/env python3
# Protected by PyGuard v5 (pyguard.avkean.com)
${keyDecls.join("\n")}
${canonicalRegion}`;
}

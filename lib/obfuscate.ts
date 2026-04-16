// lib/obfuscate.ts
//
// PyGuard — hardened Python obfuscator (current generation: v11).
//
// Caller provides a pre-built IR (from lib/v5/build_ir.py, run in Pyodide
// or a subprocess) and a marshaled, compressed interpreter code object.
// The user source is replaced with a stub that wraps the encrypted IR and
// loads the interpreter via marshal.loads (no compile() of user source at
// runtime). See lib/v5/assemble.ts for the stage2 architecture.
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
//   3.  RANDOMIZED MEANINGLESS IDENTIFIERS. Every top-level variable,
//       helper function, loop counter, and intermediate value in the
//       canonical region is named with a fresh short alphanumeric
//       identifier. Names carry zero semantic information to an LLM and
//       a reverser cannot grep for "the key variable".
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
//   6.  CIPHERTEXT SPLITTING. The base64 ciphertexts for stage1, stage2,
//       the interpreter, the schema, the IR, and the user payload are
//       split into random-sized 2KB..4KB fragments with shuffled
//       declaration order. The concat expression names the fragments
//       in their original order. A reverser must visually trace the
//       concat list to reconstruct the ciphertext.
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

// O5 (2026-04-16): RFC-1924 base85 ("b85") encoder matching Python's
// `base64.b85encode(data, pad=False)`. Alphabet is 85 chars selected to
// be safe inside a Python `"..."` literal — no `"` or `\` or `'`. 85^5
// = 4.43B per 5 chars (for 4 bytes), giving a 5/4 expansion ratio vs
// base64's 4/3 — ~6.25% denser. Saves ~14 KB per stub on the ~200 KB
// of ciphertext chunks the outer stub carries. Partial trailing
// bytes encode as `rem+1` chars, matching Python's `pad=False` mode.
const _B85_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
    "abcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

function bytesToBase85(bytes: Uint8Array): string {
    const out: string[] = [];
    const fullChunks = Math.floor(bytes.length / 4);
    for (let i = 0; i < fullChunks; i++) {
        const base = i * 4;
        // Use regular arithmetic, not bit-shift, to stay in unsigned
        // 32-bit range (JS bit-shifts are signed).
        let n = bytes[base] * 16777216 +
                bytes[base + 1] * 65536 +
                bytes[base + 2] * 256 +
                bytes[base + 3];
        const chars = ["", "", "", "", ""];
        for (let j = 4; j >= 0; j--) {
            chars[j] = _B85_ALPHABET[n % 85];
            n = Math.floor(n / 85);
        }
        out.push(chars.join(""));
    }
    const rem = bytes.length - fullChunks * 4;
    if (rem > 0) {
        const base = fullChunks * 4;
        let n = 0;
        for (let k = 0; k < 4; k++) {
            n = n * 256 + (k < rem ? bytes[base + k] : 0);
        }
        const chars = ["", "", "", "", ""];
        for (let j = 4; j >= 0; j--) {
            chars[j] = _B85_ALPHABET[n % 85];
            n = Math.floor(n / 85);
        }
        out.push(chars.slice(0, rem + 1).join(""));
    }
    return out.join("");
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

// Random-identifier generator. v11: emits short names `_<2-4 alphanum>`
// where the body is drawn from the 62-char mixed-case alphanumeric pool.
//
// Length rationale: 62^2 = 3844 distinct 2-char bodies, 62^3 = 238k. A
// typical stub consumes ~500 names (chunk vars + state-machine vars +
// API surface) so 3-char bodies suffice with ample collision headroom.
// Previously we emitted 8..12 char names; that's ~3x longer per ref and
// stubs reference each name many times.
//
// Security: name length and visual shape are independent. A reader
// trying to reverse cares about what a name REFERS TO, not how long it
// is. Confusability and meaning-absence are preserved; the size cost of
// padding every identifier with ~6 extra bytes is not.
function makeNameGen(): NameGen {
    const used = new Set<string>();
    const pool =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const poolNoDigit =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    return {
        gen(): string {
            for (let attempts = 0; attempts < 512; attempts++) {
                const r = randomBytes(8);
                // Length: 2..4 body chars. First char must be non-digit
                // because identifiers can't start with a digit after the
                // leading underscore would otherwise allow it (`_9abc`
                // is legal, but keep things uniform).
                const len = 2 + (r[0] % 3); // 2..4
                let s = "_" + poolNoDigit[r[1] % poolNoDigit.length];
                for (let i = 2; i < len + 1; i++) {
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

function shuffleArr<T>(a: T[]): void {
    const r = randomBytes(Math.max(1, a.length + 1));
    for (let i = a.length - 1; i > 0; i--) {
        const j = r[i % r.length] % (i + 1);
        const t = a[i]; a[i] = a[j]; a[j] = t;
    }
}

function xor32(a: Uint8Array, b: Uint8Array): Uint8Array {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = a[i] ^ b[i];
    return out;
}

interface ChunkedB64 {
    decls: string;   // Python-source lines declaring every chunk
    concat: string;  // Python concat expression of ONLY the real chunks
}

// Split a base64 ciphertext into random-sized fragments and return:
//
//   - decls:  one "<random_name> = \"<chunk>\"" line per fragment, in
//             shuffled order.
//   - concat: Python expression "<name_0> + <name_1> + ..." concatenating
//             the fragments in their original order, by name.
//
// A reverser must visually trace the concat expression to locate the
// fragments in the right order to reconstruct the ciphertext. The
// fragments themselves are large base64 blobs that no static analyzer
// can decrypt without recovering the runtime key.
function chunkB64(b64: string, ng: NameGen): ChunkedB64 {
    // Chunk size 2KB..4KB. Earlier versions used 24..63 char chunks with
    // interleaved decoys, which inflated the stub by ~50× without adding
    // any defense against an attacker who follows the `concat` expression.
    // Larger chunks shrink the per-chunk overhead (`_NAME = "..." + \n +
    // concat `+`) and reduce startup-time string concat count from ~500
    // to ~75 across all five ciphertexts.
    const pieces: string[] = [];
    let i = 0;
    while (i < b64.length) {
        const r = randomBytes(2);
        const sz = 2048 + ((r[0] | (r[1] << 8)) % 2049); // 2048..4096
        pieces.push(b64.slice(i, i + sz));
        i += sz;
    }
    const realNames = pieces.map(() => ng.gen());

    interface Entry { name: string; value: string; }
    const all: Entry[] = [];
    for (let k = 0; k < pieces.length; k++) {
        all.push({ name: realNames[k], value: pieces[k] });
    }
    shuffleArr(all);
    const decls = all.map(e => `${e.name} = "${e.value}"`).join("\n");
    const concat = realNames.join(" + ");
    return { decls, concat };
}

// v5.1 / C3: fixed-count chunking. Pre-allocate N names at canonical
// assembly time (so the concat expression can appear inside canonical
// bytes BEFORE the ciphertext is known). After the ciphertext is
// encrypted with the canonical-hash-derived key, slice it into the same
// N pieces and emit shuffled decls *outside* the canonical region.
//
// Rationale: the old flow embedded stage1 ciphertext inside canonical,
// which forced the master seed to be stored as `seed XOR canonical_hash`
// in the preamble — A35 inverted that XOR in one line. By moving
// ciphertext out of canonical we decouple the hash from the ciphertext,
// letting `seed = KDF(canonical_hash, pep)` be derived directly at
// runtime without any stored XOR blob.
function chunkB64Plan(ng: NameGen, count: number): { names: string[], concat: string } {
    const names: string[] = [];
    for (let i = 0; i < count; i++) names.push(ng.gen());
    return { names, concat: names.join(" + ") };
}

function chunkB64Apply(b64: string, names: string[]): string {
    const n = names.length;
    const each = Math.ceil(b64.length / n);
    const pieces: string[] = [];
    for (let i = 0; i < n; i++) {
        pieces.push(b64.slice(i * each, (i + 1) * each));
    }
    // Last chunk can be shorter or empty — that's fine, the runtime
    // just base64-decodes the concat. Empty trailing pieces yield ''.
    interface Entry { name: string; value: string; }
    const all: Entry[] = [];
    for (let k = 0; k < n; k++) {
        all.push({ name: names[k], value: pieces[k] });
    }
    shuffleArr(all);
    return all.map(e => `${e.name} = "${e.value}"`).join("\n");
}

// Pick N distinct random state-machine state values for the flattened
// `_dec` dispatcher. v6: expanded from 4 to 20 states to defeat LLM tracing.
function pickDistinct(n: number): number[] {
    const r = randomBytes(64);
    const picks: number[] = [];
    for (let i = 0; i < r.length && picks.length < n; i++) {
        if (!picks.includes(r[i])) picks.push(r[i]);
    }
    while (picks.length < n) picks.push((picks[picks.length - 1] + 37) & 0xff);
    return picks;
}
// v6 state machine: 9 real states + 7 dead states + sEnd = 17 states total.
// Dead states do plausible-looking crypto ops but never affect the output.
function makeStates(): {
    s0: number; s1: number; s2: number; sEnd: number; // legacy compat
    // real states (split from 3 → 9)
    sCheck: number; sLoad: number; sRoundInit: number; sRoundCk: number;
    sRotate: number; sSbox: number; sXorKey: number; sCbc: number; sAdv: number;
    // dead states
    d0: number; d1: number; d2: number; d3: number; d4: number; d5: number; d6: number;
} {
    const p = pickDistinct(17);
    return {
        s0: p[0], s1: p[1], s2: p[2], sEnd: p[3], // legacy (kept for type compat)
        sCheck: p[0], sLoad: p[4], sRoundInit: p[5], sRoundCk: p[1],
        sRotate: p[6], sSbox: p[7], sXorKey: p[8], sCbc: p[2], sAdv: p[9],
        d0: p[10], d1: p[11], d2: p[12], d3: p[13], d4: p[14], d5: p[15], d6: p[16],
    };
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

// v8: binary schema serializer.
//
// Previously the schema was shipped as JSON (`{"keys":{...},"tags":{...},
// "mask":[...],"layouts":{...},"binKey":[lo,hi],"noiseSchedule":[...]}`).
// Those dict-keys are a stable structural fingerprint: any attacker who
// hooks the stub's JSON parser (or `dict.__init__`, or `_pg_parse_json`'s
// return value) and filters for an object containing `keys`+`tags`+`mask`
// recovers the schema regardless of how we rename build-time symbols.
//
// The binary format has NO named fields. The parser inside _pg_boot reads
// positional sections directly into local vars (_S_K, _S_RT, _S_M, _S_L,
// _bin_key, _noise) without ever materializing a dict that carries those
// names as keys. A frame-walk attack on _pg_boot sees only opaque ints
// and byte slices until the locals are already in their final consumed
// form, and the locals are deleted before Interp.run begins.
//
// All ASCII strings — tokens are 7-char `_XXXXXX`, keys/tags max ~20
// chars — so u8 length prefixes are sufficient everywhere. Counts are
// u16 LE (keys+tags+layouts can each exceed 255 entries).
//
// Layout:
//   [u8 mask_len][mask bytes]
//   [u32 LE bin_key_lo][u32 LE bin_key_hi]
//   [u8 noise_count] [(u16 LE pos, u8 len) * noise_count]
//   [u16 LE keys_count]    [(u8 klen, k, u8 vlen, v) * keys_count]
//   [u16 LE tags_count]    [(u8 klen, k, u8 vlen, v) * tags_count]
//   [u16 LE layouts_count] [(u8 tag_len, tag, u8 field_count,
//                            (u8 flen, f) * field_count) * layouts_count]
function serializeSchemaBinary(schema: {
    keys: Record<string, string>;
    tags: Record<string, string>;
    mask: number[];
    layouts: Record<string, string[]>;
    binKey: [number, number];
    noiseSchedule: [number, number][];
}): Uint8Array {
    const parts: Uint8Array[] = [];
    const enc = (s: string) => strToUtf8(s);
    const u8 = (n: number) => new Uint8Array([n & 0xff]);
    const u16 = (n: number) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
    const u32 = (n: number) => new Uint8Array([
        n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff,
    ]);
    const writeStr = (s: string) => {
        const b = enc(s);
        if (b.length > 255) throw new Error("schema string > 255 bytes");
        parts.push(u8(b.length), b);
    };

    // mask
    if (schema.mask.length > 255) throw new Error("mask > 255 bytes");
    parts.push(u8(schema.mask.length), new Uint8Array(schema.mask));

    // bin_key (two u32 LE)
    parts.push(u32(schema.binKey[0] >>> 0), u32(schema.binKey[1] >>> 0));

    // noise schedule
    if (schema.noiseSchedule.length > 255) throw new Error("noise > 255 entries");
    parts.push(u8(schema.noiseSchedule.length));
    for (const [pos, len] of schema.noiseSchedule) {
        if (len > 255) throw new Error("noise len > 255");
        parts.push(u16(pos & 0xffff), u8(len));
    }

    // keys
    const keyEntries = Object.entries(schema.keys);
    parts.push(u16(keyEntries.length));
    for (const [k, v] of keyEntries) { writeStr(k); writeStr(v); }

    // tags
    const tagEntries = Object.entries(schema.tags);
    parts.push(u16(tagEntries.length));
    for (const [k, v] of tagEntries) { writeStr(k); writeStr(v); }

    // layouts
    const layoutEntries = Object.entries(schema.layouts);
    parts.push(u16(layoutEntries.length));
    for (const [tag, fields] of layoutEntries) {
        writeStr(tag);
        if (fields.length > 255) throw new Error("layout fields > 255");
        parts.push(u8(fields.length));
        for (const f of fields) writeStr(f);
    }

    return concatBytes(...parts);
}

// v5 imports — kept inline so non-v5 code paths don't pull in the
// interpreter source string.
import { buildV5Stage2Source, serializeIR } from './v5/assemble';
import type { V5IR } from './v5/assemble';
import { INTERPRETER_SRC_B64, BOOT_KEY_BYTES } from './v5/interpreter_src';

export interface ObfuscateOpts {
    // When provided, uses the v5 AST-walking interpreter path:
    // the IR is encrypted and the stage2 source becomes a generic
    // interpreter plus an encrypted blob, so the final compile() event
    // never sees user source. Build the IR with lib/v5/build_ir.py
    // (in Pyodide for browser, or via subprocess for Node testing).
    v5IR?: V5IR;
    // v7: compile Python source → bytecode → marshal.dumps bytes. Used
    // for stage1 and stage2 (which remain small enough not to need
    // compression). The Node driver shells out to python3; the browser
    // driver uses Pyodide. Required when v5IR is present.
    compileAndMarshal?: (source: string, filename?: string) => Uint8Array;
    // v7: zlib-raw-deflated (-15 wbits) marshal.dumps bytes for the
    // interpreter module. The caller prepares this by decompressing
    // INTERPRETER_SRC_B64, compiling with the Python version the stub
    // will run against, marshaling, and re-compressing. Required when
    // v5IR is present. Pushed to caller so obfuscate.ts stays
    // browser-bundle-friendly (no node:zlib import).
    interpreterMarshalCompressed?: Uint8Array;
}

export function obfuscatePythonCode(input: string, opts?: ObfuscateOpts): string {
    if (typeof input !== "string") {
        throw new Error("obfuscatePythonCode: input must be a string");
    }

    // 1. Polymorphism profile, name generator, shuffled builtin tuple,
    //    random state-machine states, random stage-2 KDF label.
    const prof = makeProfile();
    const stage2Label = randomBytes(6);
    const hashFoldByte = randomBytes(1)[0];   // v6: canonical-region hash fold constant
    const ng = makeNameGen();
    const bcap = captureBuiltins();
    const bi = bcap.idx;
    const st = makeStates();

    // 2. Random confusable identifier for every logical symbol in the stub.
    //    Grouped here so the template-literal substitutions below are
    //    compact and mechanical.
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
    const n_ns       = ng.gen();
    const n_co       = ng.gen();
    const n_chainA   = ng.gen(); // canonical region hash-fold variable
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
    const n_mon      = ng.gen(); // sys.monitoring busy-slot fingerprint (C8)
    const n_mon_var  = ng.gen(); // sys.monitoring module alias
    const n_mon_busy = ng.gen(); // sys.monitoring busy-slot bitmap
    const n_mon_i    = ng.gen(); // sys.monitoring loop counter
    const n_hk       = ng.gen(); // C9 orthogonal-hook witness byte
    const n_hk_acc   = ng.gen(); // C9 accumulator
    const n_hk_gc    = ng.gen(); // C9 gc module alias
    const n_hk_tm    = ng.gen(); // C9 tracemalloc module alias
    const n_sg       = ng.gen(); // C10 signal/faulthandler witness byte
    const n_sg_acc   = ng.gen(); // C10 accumulator
    const n_sg_sig   = ng.gen(); // C10 signal module alias
    const n_sg_fh    = ng.gen(); // C10 faulthandler module alias

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
    // v6 dead-state internal names (plausible crypto-looking variables)
    const d_acc      = ng.gen(); // dead accumulator
    const d_tmp      = ng.gen(); // dead temporary
    const d_chk      = ng.gen(); // dead checksum
    const d_p2       = ng.gen(); // dead pointer
    const d_m        = ng.gen(); // dead mask

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

    // Frame-depth anti-analysis names
    const n_fdFrame  = ng.gen();
    const n_fdCnt    = ng.gen();

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

    // v5.1 / C3 — master seed is DERIVED FROM the canonical-region hash,
    // not stored XOR'd with it. A35 closed (as written): the stub contains
    // no `_X = bytes(...)` preamble literal and no `seed = zip(X,h) XOR`
    // regex pattern. To match runtime, we first build the full canonical
    // region (below), compute its hash, then set `seed = sha256(h || pep)`.
    //
    // Pre-allocate 32 stage-1-chunk names NOW. Canonical references them
    // via `s1Plan.concat` (names only). Their VALUES (base64 ciphertext)
    // are injected into the stub preamble OUTSIDE canonical, after
    // encryption, via chunkB64Apply below.
    const s1Plan = chunkB64Plan(ng, 32);

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
    const interleavedPep: string[] = [];
    {
        let ri = 0, di = 0;
        const rpick = randomBytes(realChain.length + decoyChain.length);
        while (ri < realChain.length || di < decoyChain.length) {
            const tryDecoy =
                di < decoyChain.length &&
                (ri >= realChain.length || (rpick[ri + di] & 1) === 0);
            if (tryDecoy) {
                interleavedPep.push(decoyChain[di++]);
            } else {
                interleavedPep.push(realChain[ri++]);
            }
        }
    }
    const pepperBlock = interleavedPep.join("\n");

    // Canonical region — built BEFORE seed derivation. References only
    // NAMES (n_seed, n_h, n_pep, s1Plan.concat) and deterministic byte
    // literals. Does NOT embed seed or seed-derived ciphertext; those
    // are derived at runtime inside canonical via
    //   ${n_seed} = hashlib.sha256(${n_h} + ${n_pep} + ${n_mon} + ${n_hk} + ${n_sg}).digest()
    // and consumed against the stage1 chunk names, whose values live in
    // the stub preamble (outside canonical).
    //
    // IMPORTANT: do NOT embed # Python comments inside the template
    // literal below — anything that ships in the canonical region
    // doubles as a free defense map for attackers (citing attack file
    // paths, bit layouts, version numbers). Keep rationale in these
    // TS-side // comments; the emitted Python stays code-only.
    //
    // Witness bytes folded into the seed (all yield 0x00 in a clean env):
    //   n_mon (C8): bitmap of sys.monitoring tool_ids 0..5 busy; sweep
    //     uses use_tool_id+set_events(0)+free_tool_id which ValueErrors
    //     on any slot an attacker pre-reserved.
    //   n_hk (C9): low nibble = len(gc.callbacks) & 0x0F; bit 6 =
    //     gc.get_debug() nonzero; bit 5 = tracemalloc.is_tracing().
    //   n_sg (C10/C11): signal/faulthandler/excepthook composite —
    //     bit 0 SIGPROF != SIG_DFL, bits 1-3 ITIMER_{PROF,VIRTUAL,REAL}
    //     armed, bit 4 faulthandler.is_enabled(), bit 5 SIGUSR1/2 handler
    //     callable, bit 6 SIGXCPU/FSZ handler callable (uses callable()
    //     because SIGXFSZ defaults to SIG_IGN not SIG_DFL on POSIX),
    //     bit 7 sys.excepthook/unraisablehook replaced.
    // Any bit flip → seed diverges → silent AES-CTR garbage → marshal
    // fails → SystemExit(0) before interpreter bytecode runs.
    const canonicalRegion =
`${BEGIN_MARKER}
import sys, hashlib, base64, marshal
${n_ftype} = (lambda: 0).__class__
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
try:
    ${n_mon_var} = sys.monitoring
    ${n_mon_busy} = 0
    for ${n_mon_i} in range(6):
        try:
            ${n_mon_var}.use_tool_id(${n_mon_i}, 'pg')
            ${n_mon_var}.set_events(${n_mon_i}, 0)
            ${n_mon_var}.free_tool_id(${n_mon_i})
        except Exception:
            ${n_mon_busy} |= (1 << ${n_mon_i})
    ${n_mon} = bytes([${n_mon_busy} & 0xFF])
except AttributeError:
    ${n_mon} = bytes([0])
try:
    import gc as ${n_hk_gc}
    ${n_hk_acc} = len(${n_hk_gc}.callbacks) & 0x0F
    if ${n_hk_gc}.get_debug():
        ${n_hk_acc} |= 0x40
except Exception:
    ${n_hk_acc} = 0
try:
    import tracemalloc as ${n_hk_tm}
    if ${n_hk_tm}.is_tracing():
        ${n_hk_acc} |= 0x20
except Exception:
    pass
${n_hk} = bytes([${n_hk_acc} & 0xFF])
try:
    import signal as ${n_sg_sig}
    ${n_sg_acc} = 0
    if ${n_sg_sig}.getsignal(${n_sg_sig}.SIGPROF) is not ${n_sg_sig}.SIG_DFL:
        ${n_sg_acc} |= 0x01
    if ${n_sg_sig}.getitimer(${n_sg_sig}.ITIMER_PROF)[0] > 0:
        ${n_sg_acc} |= 0x02
    if ${n_sg_sig}.getitimer(${n_sg_sig}.ITIMER_VIRTUAL)[0] > 0:
        ${n_sg_acc} |= 0x04
    if ${n_sg_sig}.getitimer(${n_sg_sig}.ITIMER_REAL)[0] > 0:
        ${n_sg_acc} |= 0x08
    for _pg_sg_name in ('SIGUSR1', 'SIGUSR2'):
        _pg_sg_sn = getattr(${n_sg_sig}, _pg_sg_name, None)
        if _pg_sg_sn is not None and callable(${n_sg_sig}.getsignal(_pg_sg_sn)):
            ${n_sg_acc} |= 0x20
            break
    for _pg_sg_name in ('SIGXCPU', 'SIGXFSZ'):
        _pg_sg_sn = getattr(${n_sg_sig}, _pg_sg_name, None)
        if _pg_sg_sn is not None and callable(${n_sg_sig}.getsignal(_pg_sg_sn)):
            ${n_sg_acc} |= 0x40
            break
    del _pg_sg_name, _pg_sg_sn
except Exception:
    ${n_sg_acc} = 0
try:
    import faulthandler as ${n_sg_fh}
    if ${n_sg_fh}.is_enabled():
        ${n_sg_acc} |= 0x10
except Exception:
    pass
try:
    if sys.excepthook is not sys.__excepthook__:
        ${n_sg_acc} |= 0x80
except Exception:
    pass
try:
    if sys.unraisablehook is not sys.__unraisablehook__:
        ${n_sg_acc} |= 0x80
except Exception:
    pass
${n_sg} = bytes([${n_sg_acc} & 0xFF])
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
    ${d_acc} = 0
    ${d_tmp} = 0
    ${d_chk} = 0
    ${d_p2} = 0
    ${d_m} = 0xFF
    ${d_st} = ${st.sCheck}
    while True:
        if ${d_st} == ${st.sEnd}:
            break
        if ${d_st} == ${st.sCheck}:
            if ${d_i} >= len(${d_ct}):
                ${d_st} = ${st.sEnd}
            else:
                ${d_st} = ${st.sLoad}
            continue
        if ${d_st} == ${st.sLoad}:
            ${d_b} = ${d_ct}[${d_i}]
            ${d_tmp} = ${d_b}
            ${d_st} = ${st.sRoundInit}
            continue
        if ${d_st} == ${st.sRoundInit}:
            ${d_r} = ${d_N} - 1
            ${d_acc} = (${d_acc} + ${d_b}) & 0xFF
            ${d_st} = ${st.sRoundCk}
            continue
        if ${d_st} == ${st.sRoundCk}:
            if ${d_r} < 0:
                ${d_st} = ${st.sCbc}
            else:
                ${d_st} = ${st.sRotate}
            continue
        if ${d_st} == ${st.sRotate}:
            ${d_k} = ${d_rotk}[${d_r}]
            ${d_b} = ((${d_b} >> ${d_k}) | (${d_b} << (8 - ${d_k}))) & 0xFF
            ${d_st} = ${st.sSbox}
            continue
        if ${d_st} == ${st.sSbox}:
            ${d_b} = ${d_inv}[${d_b}]
            ${d_chk} = (${d_chk} ^ ${d_b}) & 0xFF
            ${d_st} = ${st.sXorKey}
            continue
        if ${d_st} == ${st.sXorKey}:
            ${d_b} ^= ${d_rks}[${d_r}][${d_i} % 32]
            ${d_r} -= 1
            ${d_st} = ${st.sRoundCk}
            continue
        if ${d_st} == ${st.sCbc}:
            ${d_b} ^= ${d_prev}
            ${d_out}[${d_i}] = ${d_b}
            ${d_st} = ${st.sAdv}
            continue
        if ${d_st} == ${st.sAdv}:
            ${d_prev} = ${d_ct}[${d_i}]
            ${d_i} += 1
            ${d_p2} = (${d_p2} + 1) & ${d_m}
            ${d_st} = ${st.sCheck}
            continue
        if ${d_st} == ${st.d0}:
            ${d_tmp} = (${d_tmp} * 31 + ${d_acc}) & 0xFF
            ${d_st} = ${st.d1}
            continue
        if ${d_st} == ${st.d1}:
            ${d_chk} = (${d_chk} + ${d_tmp}) & 0xFF
            if ${d_p2} > 0:
                ${d_st} = ${st.d2}
            else:
                ${d_st} = ${st.sCheck}
            continue
        if ${d_st} == ${st.d2}:
            ${d_acc} ^= ${d_inv}[${d_chk}]
            ${d_p2} = (${d_p2} - 1) & ${d_m}
            ${d_st} = ${st.d3}
            continue
        if ${d_st} == ${st.d3}:
            ${d_tmp} = (${d_tmp} ^ ${d_rks}[0][${d_p2} % 32]) & 0xFF
            ${d_st} = ${st.d4}
            continue
        if ${d_st} == ${st.d4}:
            ${d_k} = ${d_rotk}[${d_p2} % ${d_N}]
            ${d_b} = ((${d_acc} >> ${d_k}) | (${d_acc} << (8 - ${d_k}))) & 0xFF
            ${d_st} = ${st.d5}
            continue
        if ${d_st} == ${st.d5}:
            ${d_chk} = (${d_chk} ^ ${d_b} ^ ${d_prev}) & 0xFF
            ${d_st} = ${st.d6}
            continue
        if ${d_st} == ${st.d6}:
            ${d_acc} = (${d_acc} + ${d_chk}) & 0xFF
            ${d_st} = ${st.sCheck}
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
${n_chainA} = hashlib.sha256(${n_h} + bytes([${hashFoldByte}])).digest()
${n_h} = bytes(a ^ b for a, b in zip(${n_h}, ${n_chainA}))
try:
    ${n_fdFrame} = ${n_gf}(0)
    ${n_fdCnt} = 0
    while ${n_fdFrame} is not None:
        ${n_fdCnt} += 1
        ${n_fdFrame} = ${n_fdFrame}.f_back
    if ${n_fdCnt} > 12:
        ${n_h} = bytes((b ^ ${prof.poison1} ^ ${prof.poison2}) for b in ${n_h})
except Exception:
    pass
try:
    if hasattr(sys, '_audit_hooks') or any(v is not None for v in ${n_O}[${bi['getattr']}](sys, '_current_exceptions', lambda: {})().values()):
        ${n_h} = bytes((b ^ ${prof.poison3}) for b in ${n_h})
except Exception:
    pass
${n_seed} = hashlib.sha256(${n_h} + ${n_pep} + ${n_mon} + ${n_hk} + ${n_sg}).digest()
${n_p1} = ${n_kd}(${n_vfy}(${n_seed}))
${n_S1} = base64.b85decode(${s1Plan.concat})
${n_pt1} = ${n_dec}(${n_S1}, ${n_p1}[0], ${n_p1}[1], ${n_p1}[2])
${n_ns} = {'__builtins__': __builtins__, '${n_O}': ${n_O}, '${n_seed}': ${n_seed}, '${n_kd}': ${n_kd}, '${n_dec}': ${n_dec}, '${n_tchk}': ${n_tchk}, '${n_ftype}': ${n_ftype}, 'sys': sys, 'hashlib': hashlib, 'base64': base64, 'marshal': marshal, '__file__': ${n_path}}
try:
    ${n_co} = marshal.loads(${n_pt1})
except Exception:
    sys.exit(0)
${n_ftype}(${n_co}, ${n_ns})()
${END_MARKER}
`;

    // Canonical-region hash (with runtime-substituted 32-zero midpoint)
    // and single-byte fold. Matches the runtime sequence above exactly.
    const canonicalBytes = strToUtf8(canonicalRegion);
    const startBytes = strToUtf8(BEGIN_MARKER);
    const endBytes = strToUtf8(END_MARKER);
    const sIdx = findBytes(canonicalBytes, startBytes);
    const eIdx = findBytes(canonicalBytes, endBytes);
    if (sIdx < 0 || eIdx < 0) {
        throw new Error("internal: integrity markers not found in template");
    }
    const halfOffset = Math.floor((eIdx - sIdx) / 2);
    const hashInput = concatBytes(
        canonicalBytes.slice(sIdx, sIdx + halfOffset),
        new Uint8Array(32),
        canonicalBytes.slice(sIdx + halfOffset, eIdx),
    );
    let hashOut = sha256(hashInput);
    const foldKey = sha256(concatBytes(hashOut, new Uint8Array([hashFoldByte])));
    hashOut = new Uint8Array(hashOut.map((b, i) => b ^ foldKey[i]));

    // v5.1 / C3 — master seed = sha256(canonical_hash || pep || mon || hk || sg).
    // Not stored anywhere; any byte flip inside canonical → different hash
    // → garbage seed → silent decryption failure downstream.
    //
    // v6.1 / C8 — `mon` byte = bitmap of sys.monitoring tool IDs 0..5 that
    // were ALREADY in use when stage0 ran. An honest run on a clean
    // interpreter observes 0; any attacker probe that reserved a tool ID
    // before exec flips a bit and the seed diverges silently.
    //
    // v6.2 / C9 — `hk` byte = orthogonal-hook witness:
    //   bits 0..3 = len(gc.callbacks) & 0x0F
    //   bit    5  = tracemalloc.is_tracing()
    //   bit    6  = gc.get_debug() != 0
    // Blocks gc-walker attacks (c9_attack_gc_walk) that use gc.callbacks
    // as a trace surface to reach decoded user-source strings via
    // gc.get_referents(). Clean env = 0.
    //
    // v6.3 / C10 + v6.4 / C11 — `sg` byte = signal / faulthandler /
    // excepthook witness:
    //   bit 0 = SIGPROF handler != SIG_DFL (pre-installed spy)
    //   bit 1 = ITIMER_PROF armed
    //   bit 2 = ITIMER_VIRTUAL armed
    //   bit 3 = ITIMER_REAL armed
    //   bit 4 = faulthandler.is_enabled()
    //   bit 5 = SIGUSR1 or SIGUSR2 handler != SIG_DFL   (C11)
    //   bit 6 = SIGXCPU or SIGXFSZ handler != SIG_DFL   (C11)
    //   bit 7 = sys.excepthook or sys.unraisablehook   (C11)
    //           replaced (!= sys.__excepthook__ / __unraisablehook__)
    // Blocks SIGPROF-driven frame-walking (c10) and
    // excepthook-via-SIGUSR-interrupt-main traceback leak (c11).
    // Clean env = 0.
    //
    // Build-side uses 0 for all three bytes so stubs ship keyed for the
    // clean-environment case.
    const seed = sha256(concatBytes(concatBytes(hashOut, pep), new Uint8Array([0, 0, 0])));

    // 4. Derive cipher parameters and encrypt user payload.
    //    The runtime `_kd` XORs its input with `pep` before any sha256.
    //    We reproduce that here so encryption matches the stub runtime.
    //    `pepperedSeed` is what the cipher rounds actually consume.
    //
    // _vfy returns sha256(seed || 32-byte-zero-corr) on honest run.
    // Its output (not the raw seed) is what _kd receives for stage 1.
    // Stage 1 itself still uses the raw `seed` via `_seed` for stage 2
    // derivation, so seed2 computation below stays keyed on `seed`.
    const vfySeed1 = sha256(concatBytes(seed, new Uint8Array(32)));
    const pepperedSeed = xor32(vfySeed1, pep);

    const params1 = kdf(pepperedSeed, prof);

    // Stage-2 seed derivation: sha256(storedSeed || stage2Label). The runtime
    // uses `_seed` (the formula-seed, before pepper) here, matching.
    const seed2 = sha256(concatBytes(seed, stage2Label));
    const pepperedSeed2 = xor32(seed2, pep);
    const params2 = kdf(pepperedSeed2, prof);

    // In v5/v6 this block built a stage2 *source* string, encrypted it, and
    // let stage1 call compile() on the decrypted text. v7 replaces the
    // source-round-trip with marshaled code objects so no `compile()` audit
    // event ever sees the text of stage2 or the interpreter:
    //
    //   1. Decompress the interpreter source once, compile+marshal it on the
    //      build machine via `opts.compileAndMarshal`, zlib-compress the
    //      marshaled bytes, encrypt+base64+chunk that as `interpChunks`.
    //   2. Build the stage2 *source* as before (only so we can compile+marshal
    //      it ourselves) — then throw away the source; only the marshaled
    //      bytecode is embedded.
    //   3. Stage1 (see below) is likewise compiled+marshaled and the
    //      canonical region does `marshal.loads` on it instead of `compile`.
    //
    // The attacker who installs an audit hook no longer sees stage1/stage2/
    // interpreter source at any point — only marshaled bytecode, which
    // requires a Python-version-specific decompiler pass to approach source
    // fidelity.
    let payloadBytes: Uint8Array;
    if (opts && opts.v5IR) {
        if (!opts.compileAndMarshal) {
            throw new Error(
                'v7 obfuscation requires opts.compileAndMarshal. ' +
                'The Node driver (gen-v5-stub.mjs) and the browser driver ' +
                '(pyodide_loader.ts) each supply one; callers that embed ' +
                'the library directly must provide a callback that returns ' +
                '`marshal.dumps(compile(source, filename, "exec"))` bytes.',
            );
        }
        if (!opts.interpreterMarshalCompressed) {
            throw new Error(
                'v7 obfuscation requires opts.interpreterMarshalCompressed — ' +
                'zlib-deflated (raw, -15) marshal.dumps bytes for the ' +
                'interpreter. Callers prepare this by decompressing ' +
                'INTERPRETER_SRC_B64, compile+marshal+deflate in the target ' +
                "Python. See build_ir.py's compile_and_marshal helper.",
            );
        }
        // Fresh names used inside stage2's Python source.
        const envCheckVar        = ng.gen();
        const interpCtVar        = ng.gen();
        const interpHashVar      = ng.gen();
        const interpSeedVar      = ng.gen();
        const interpPVar         = ng.gen();
        const interpMarshalVar   = ng.gen();
        const interpCodeVar      = ng.gen();
        const interpNsVar        = ng.gen();
        const interpFTVar        = ng.gen();   // C7.1: FunctionType via type(lambda:0)
        const schemaCtVar        = ng.gen();
        const irCtVar            = ng.gen();

        // v9: boot entry point indexed by a RANDOMIZED BYTES KEY, not by
        // the literal string "_pg_boot". The bytes come from
        // interpreter_src.ts (generated by gen-interpreter-src.mjs,
        // which captures them from obfuscate_runtime.py). No original
        // API name exists in interp_ns; stage2 looks up
        // `interp_ns[bytes([...random...])]`.
        const bootKeyBytes = BOOT_KEY_BYTES;

        // Environment integrity binding. The runtime hash mixes
        //   * thread count (1),
        //   * types of three builtins (zlib.decompress / print / getattr),
        //   * v12.3: types of the four sys trace/profile hook functions.
        // An attacker who replaces sys.settrace / sys.setprofile /
        // sys.gettrace / sys.getprofile with Python-level shims (A5 style)
        // turns their type from 'builtin_function_or_method' into
        // 'function', which mismatches this hash, which mismatches the
        // derived interpreter / IR / schema keys, which turns every AEAD
        // decrypt into garbage. The build side precomputes the SAME hash
        // and XORs it into the three key-derivation paths.
        const envCheckExpected = sha256(
            new TextEncoder().encode(
                '1|builtin_function_or_method|builtin_function_or_method|builtin_function_or_method'
                // v12.3: sys.settrace/setprofile/gettrace/getprofile types.
                + '|builtin_function_or_method|builtin_function_or_method'
                + '|builtin_function_or_method|builtin_function_or_method'
                // v12.4: exec / marshal.loads / hashlib.scrypt types. A6's
                // attack hooks all three; any of them being a Python-level
                // function flips this check to 'function' and crashes crypto.
                + '|builtin_function_or_method|builtin_function_or_method'
                + '|builtin_function_or_method'
                // v12.3 strengthening: identity check `type(sys.settrace) is
                // type(zlib.decompress)`. A8's attack spoofs __name__ with a
                // custom class named 'builtin_function_or_method'; but that
                // class's TYPE is not the C-level builtin_function_or_method,
                // so the `is` comparison flips to 'False'.
                + '|True|True|True|True'
                // v12.4: same identity check for exec / marshal.loads /
                // hashlib.scrypt. All three are hooked by A6 with Python
                // shims; the `is type(zlib.decompress)` check catches them.
                + '|True|True|True'
                // v6.1 / C7.2: FunctionType identity defense-in-depth.
                // Stage2 no longer imports types.FunctionType, and no
                // longer calls type(lambda: 0) — both are rebindable
                // Python-level names. It now recovers FT via
                //   interpFT = (lambda: 0).__class__
                // which goes through the object.__class__ C-slot
                // descriptor and bypasses builtins.type entirely. An
                // attacker who still hooks builtins.type achieves
                // nothing — interpFT is already the real FT when the
                // witnesses below run.
                // Witnesses (all computed off interpFT directly, so
                // they too bypass builtins.type):
                //   interpFT.__name__                  -> 'function'
                //   interpFT is (lambda: None).__class__ -> 'True'
                //     (real FT has object identity, proxy never can)
                //   interpFT.__class__.__name__        -> 'type'
                //     (metaclass of a real Python class; attacker
                //      replacing FT with a non-type instance flips this)
                //   interpFT.__module__                -> 'builtins'
                //     (functions' FT.__module__ is always 'builtins' in
                //      CPython; Python-level proxies generally leak
                //      their defining module instead)
                + '|function|True|type|builtins')
        );

        // ---- 1. Encrypt the pre-marshaled interpreter --------------------
        // The caller has already decompressed INTERPRETER_SRC_B64, compiled
        // the interpreter in the target Python, marshaled, and re-compressed.
        // We just encrypt + chunk. (Zlib work is pushed to the caller so
        // obfuscate.ts doesn't need node:zlib in the browser bundle.)
        const interpMarshalCompressed = opts.interpreterMarshalCompressed;

        // Interpreter cipher: derived from seed + interpLabel + envCheck.
        // NOT XOR'd with interpHash because interpHash IS the hash of the
        // interpreter ciphertext (known at stage2 runtime only after decode).
        const interpLabel = randomBytes(6);
        const interpSeedPre = sha256(concatBytes(seed, interpLabel));
        const interpSeed = xor32(interpSeedPre, envCheckExpected);
        const pepperedInterpSeed = xor32(interpSeed, pep);
        const paramsInterp = kdf(pepperedInterpSeed, prof);
        const encInterp = encrypt(interpMarshalCompressed, paramsInterp, prof);
        // O5: base85 is ~6.25% denser than base64 (5 chars/4 bytes vs
        // 4 chars/3 bytes). Python decodes via base64.b85decode(), no
        // new imports. Across the 4 stage2-embedded blobs (interp/IR/
        // schema + the outer stage1 chunks + userChunks), this saves
        // ~14 KB per stub on top of O4.
        const encInterpB64 = bytesToBase85(encInterp);
        const interpChunks = chunkB64(encInterpB64, ng);

        // ---- 2. Interp-hash binding for schema + IR ----------------------
        // The schema and IR keys XOR in the hash of the *encrypted*
        // interpreter blob. Any tampering (e.g. attacker swaps interpreter
        // ciphertext for a debug version) changes this hash and silently
        // corrupts schema+IR decryption.
        const interpHash = sha256(encInterp);

        // Third-stage cipher: IR. Seed = sha256(seed || irLabel) ^ interpHash ^ envCheck.
        const irLabel = randomBytes(6);
        const irSeed3Pre = sha256(concatBytes(seed, irLabel));
        const irSeed3 = xor32(xor32(irSeed3Pre, interpHash), envCheckExpected);
        const pepperedSeed3 = xor32(irSeed3, pep);
        const params3 = kdf(pepperedSeed3, prof);
        const irJsonBytes = serializeIR(opts.v5IR);
        const encIR = encrypt(irJsonBytes, params3, prof);
        const encIRB64 = bytesToBase85(encIR);
        const irChunks = chunkB64(encIRB64, ng);

        // Schema cipher: same pattern.
        const schemaLabel = randomBytes(6);
        const schemaSeed4Pre = sha256(concatBytes(seed, schemaLabel));
        const schemaSeed4 = xor32(xor32(schemaSeed4Pre, interpHash), envCheckExpected);
        const pepperedSeed4 = xor32(schemaSeed4, pep);
        const params4 = kdf(pepperedSeed4, prof);
        const schemaBytes = serializeSchemaBinary(opts.v5IR.schema);
        const encSchema = encrypt(schemaBytes, params4, prof);
        const encSchemaB64 = bytesToBase85(encSchema);
        const schemaChunks = chunkB64(encSchemaB64, ng);

        // ---- 3. Build + marshal stage2 -----------------------------------
        // v11: pack PolyProfile into 15 bytes for inline _k_derive inside
        // the interpreter. Layout must match the `_pg_boot` unpack in
        // lib/v5/runtime_interp.py:
        //   [0] rounds, [1] rotMod, [2] sbxNudge,
        //   [3..7] rkLabel, [7..11] rotLabel, [11..15] sbxLabel.
        const profileBytes = new Uint8Array(15);
        profileBytes[0] = prof.rounds;
        profileBytes[1] = prof.rotMod;
        profileBytes[2] = prof.sbxNudge;
        profileBytes.set(prof.rkLabel, 3);
        profileBytes.set(prof.rotLabel, 7);
        profileBytes.set(prof.sbxLabel, 11);
        // `pep` is already the 32-byte sha256 chain result computed at the
        // top of this function. Re-expose it here for stage2 consumption.
        const pepBytes = pep;
        const stage2Src = buildV5Stage2Source(
            { n_seed, n_kd, n_dec, n_tchk },
            {
                prof,
                interpLabel, irLabel, schemaLabel,
                interpChunks, irChunks, schemaChunks,
                envCheckVar,
                interpCtVar, interpHashVar,
                interpSeedVar, interpPVar, interpMarshalVar,
                interpCodeVar, interpNsVar, interpFTVar,
                schemaCtVar, irCtVar,
                bootKeyBytes,
                pepBytes, profileBytes,
            },
        );
        // Marshal stage2 to bytecode. The bytes we embed (and that stage1
        // will `marshal.loads`) are version-locked to the Python that ran
        // `opts.compileAndMarshal`, i.e. the same Python the end user will
        // use to run the stub. No `compile()` call happens at stub runtime.
        payloadBytes = opts.compileAndMarshal(stage2Src, '<pg_s2>');
    } else {
        payloadBytes = strToUtf8(input);
    }
    const encUser = encrypt(payloadBytes, params2, prof);
    const encUserB64 = bytesToBase85(encUser);  // O5: b85 denser
    const userChunks = chunkB64(encUserB64, ng);

    // 4. Build Stage 1 source. Runs in a namespace where the canonical
    //    region has injected: __builtins__, the randomized `_O` tuple,
    //    the randomized seed/kd/dec names, sys, hashlib, base64, __file__.
    // Stage 1 anti-analysis: CRYPTOGRAPHIC BINDING.
    //
    // Instead of `if debugger: exit()` (trivially NOP'd), detection of
    // analysis tools POISONS the seed used for Stage 2 key derivation.
    // No visible error — decryption produces garbage, the decode('utf-8')
    // fails silently, and the stub exits. An attacker who patches out
    // the checks gets a different seed and wrong decryption.
    //
    // The poison is accumulated into a "taint" variable that XORs the
    // seed. On honest runs, taint == 0 (no XOR). Under analysis, taint
    // is non-zero, silently corrupting all downstream crypto.
    const s1_taint = ng.gen();
    const s1_tpois1 = randomBytes(1)[0] | 1;  // non-zero
    const s1_tpois2 = randomBytes(1)[0] | 1;
    const s1_tpois3 = randomBytes(1)[0] | 1;
    const s1_tpois4 = randomBytes(1)[0] | 1;
    const s1_tpois5 = randomBytes(1)[0] | 1;
    const s1_tcnt = ng.gen(); // timing counter
    const s1_tstart = ng.gen(); // timing start

    const stage1Src = `${s1_b} = ${n_O}[${bi['__import__']}]('builtins')
${s1_taint} = 0
try:
    ${n_O}[${bi['getattr']}](sys, 'settrace')(None)
except Exception:
    pass
try:
    ${n_O}[${bi['getattr']}](sys, 'setprofile')(None)
except Exception:
    pass
if ${n_tchk}():
    ${s1_taint} ^= ${s1_tpois1}
if ${n_O}[${bi['getattr']}](sys, 'gettrace')() is not None:
    ${s1_taint} ^= ${s1_tpois2}
if ${n_O}[${bi['getattr']}](sys, 'getprofile')() is not None:
    ${s1_taint} ^= ${s1_tpois2}
if compile is not ${n_O}[${bi['compile']}] or getattr is not ${n_O}[${bi['getattr']}] or type is not ${n_O}[${bi['type']}]:
    ${s1_taint} ^= ${s1_tpois3}
if __import__ is not ${n_O}[${bi['__import__']}] or open is not ${n_O}[${bi['open']}] or exec is not ${n_O}[${bi['exec']}]:
    ${s1_taint} ^= ${s1_tpois4}
${s1_bn} = 'builtin_function_or_method'
try:
    if (compile.__class__.__name__ != ${s1_bn} or exec.__class__.__name__ != ${s1_bn} or
        getattr.__class__.__name__ != ${s1_bn} or __import__.__class__.__name__ != ${s1_bn} or
        open.__class__.__name__ != ${s1_bn} or
        compile.__module__ != 'builtins' or exec.__module__ != 'builtins'):
        ${s1_taint} ^= ${s1_tpois5}
except Exception:
    ${s1_taint} ^= ${s1_tpois5}
try:
    ${s1_tstart} = ${n_O}[${bi['__import__']}]('time').monotonic()
except Exception:
    ${s1_tstart} = 0
${s1_seed2} = hashlib.sha256(bytes(a ^ ${s1_taint} for a in ${n_seed}) + bytes(${bytesArrayLit(stage2Label)})).digest()
${s1_p2} = ${n_kd}(${s1_seed2})
${userChunks.decls}
${s1_S2} = base64.b85decode(${userChunks.concat})
${s1_pt2} = ${n_dec}(${s1_S2}, ${s1_p2}[0], ${s1_p2}[1], ${s1_p2}[2])
try:
    if ${s1_tstart} > 0 and ${n_O}[${bi['__import__']}]('time').monotonic() - ${s1_tstart} > 2.0:
        ${s1_pt2} = ${s1_pt2}[::-1]
except Exception:
    pass
${s1_uns} = {'__name__': '__main__', '__builtins__': ${s1_b}, '__file__': __file__, '__package__': None, '__doc__': None, '__loader__': None, '__spec__': None, 'marshal': marshal${opts && opts.v5IR ? `, '${n_seed}': ${n_seed}, '${n_kd}': ${n_kd}, '${n_dec}': ${n_dec}, '${n_tchk}': ${n_tchk}` : ''}}
try:
    ${s1_co2} = marshal.loads(${s1_pt2})
except Exception:
    sys.exit(0)
${n_ftype}(${s1_co2}, ${s1_uns})()
`;

    // v7: stage1 itself is marshaled (compile+marshal.dumps) so that the
    // outer canonical region's `marshal.loads` consumes bytecode directly.
    // No `compile()` audit event fires for stage1 source at runtime.
    const stage1Bytes = opts && opts.v5IR && opts.compileAndMarshal
        ? opts.compileAndMarshal(stage1Src, '<pg_s1>')
        : strToUtf8(stage1Src);
    const encStage1 = encrypt(stage1Bytes, params1, prof);
    const encStage1B64 = bytesToBase85(encStage1);  // O5: b85 denser
    // v5.1 / C3 — emit stage1 ciphertext chunks OUTSIDE canonical, into
    // the stub preamble. Canonical already references them by NAME via
    // s1Plan.concat; we now fill in the VALUES. Shuffle order so the
    // declaration sequence does not itself fingerprint the concat order.
    const stage1DeclsBlock = chunkB64Apply(encStage1B64, s1Plan.names);

    return `#!/usr/bin/env python3
# Protected by PyGuard v5 (pyguard.avkean.com)
${stage1DeclsBlock}
${canonicalRegion}`;
}

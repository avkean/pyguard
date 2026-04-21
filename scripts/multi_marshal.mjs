// scripts/multi_marshal.mjs
//
// Shared helper: discover CPython build toolchains on the host and pack
// per-minor marshal blobs into a multi-version PGMV container.
//
// Runtime (outer stub / stage1 / stage2) scans the container for its own
// sys.version_info and silently exits if no entry matches.
//
// Format:
//   b'PGMV' + <1-byte entry count> +
//       N × (major:1 + minor:1 + len:4LE + marshal_bytes)
//
// marshal_bytes is raw `marshal.dumps(compile(source, filename, 'exec'))`
// for that minor. No nested tag. Audit hooks still observe exactly one
// marshal.loads event per stage on the matching entry's bytes only.

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const BUILD_IR_PATH = path.join(ROOT, 'lib/v5/build_ir.py');

const DEFAULT_MINORS = ['3.9', '3.10', '3.11', '3.12', '3.13', '3.14'];

function probeBin(bin) {
    const r = spawnSync(bin, ['-c', 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'], {
        encoding: 'utf-8',
        timeout: 5_000,
        killSignal: 'SIGKILL',
    });
    if (r.status !== 0) return null;
    const vs = (r.stdout || '').trim();
    const m = vs.match(/^(\d+)\.(\d+)$/);
    if (!m) return null;
    return { bin, major: parseInt(m[1], 10), minor: parseInt(m[2], 10) };
}

export function discoverPythons() {
    const envList = process.env.PYGUARD_PYTHON_BINS;
    const seen = new Map();
    const add = (bin) => {
        const info = probeBin(bin);
        if (!info) return;
        const key = `${info.major}.${info.minor}`;
        if (!seen.has(key)) seen.set(key, info);
    };
    if (envList) {
        for (const b of envList.split(':').filter(Boolean)) add(b);
    } else {
        const candidates = [];
        for (const v of DEFAULT_MINORS) {
            candidates.push(
                `/opt/homebrew/opt/python@${v}/bin/python${v}`,
                `/opt/homebrew/bin/python${v}`,
                `/usr/local/opt/python@${v}/bin/python${v}`,
                `/usr/local/bin/python${v}`,
                `/usr/bin/python${v}`,
                `${process.env.HOME || ''}/.local/bin/python${v}`,
                `python${v}`,
            );
        }
        candidates.push('python3');
        for (const c of candidates) add(c);
    }
    return Array.from(seen.values()).sort((a, b) => {
        if (a.major !== b.major) return a.major - b.major;
        return a.minor - b.minor;
    });
}

function compileAndMarshalOne(pythonBin, source, filename) {
    const r = spawnSync(pythonBin, [BUILD_IR_PATH], {
        input: source,
        encoding: 'utf-8',
        env: {
            PATH: process.env.PATH,
            PYGUARD_MODE: 'marshal',
            PYGUARD_FILENAME: filename || '<pg>',
        },
        maxBuffer: 64 * 1024 * 1024,
        timeout: 45_000,
        killSignal: 'SIGKILL',
    });
    if (r.error && r.error.code === 'ETIMEDOUT') {
        throw new Error('compile_and_marshal subprocess timed out');
    }
    if (r.status !== 0) {
        throw new Error('compile_and_marshal subprocess (' + pythonBin + ') failed: ' + r.stderr);
    }
    const buf = Buffer.from(r.stdout.trim(), 'base64');
    // build_ir outputs b'PGM1' + major + minor + marshal.dumps(code).
    if (buf.length < 6 || buf[0] !== 0x50 || buf[1] !== 0x47 || buf[2] !== 0x4d || buf[3] !== 0x31) {
        throw new Error('compile_and_marshal: missing PGM1 tag from ' + pythonBin);
    }
    return { major: buf[4], minor: buf[5], bytes: Uint8Array.from(buf.subarray(6)) };
}

export function packPGMV(entries) {
    if (entries.length === 0 || entries.length > 255) {
        throw new Error('packPGMV: invalid entry count ' + entries.length);
    }
    let total = 5;
    for (const e of entries) total += 6 + e.bytes.length;
    const out = new Uint8Array(total);
    out[0] = 0x50; out[1] = 0x47; out[2] = 0x4d; out[3] = 0x56; // 'PGMV'
    out[4] = entries.length;
    let off = 5;
    for (const e of entries) {
        out[off] = e.major & 0xff;
        out[off + 1] = e.minor & 0xff;
        const L = e.bytes.length;
        out[off + 2] = L & 0xff;
        out[off + 3] = (L >>> 8) & 0xff;
        out[off + 4] = (L >>> 16) & 0xff;
        out[off + 5] = (L >>> 24) & 0xff;
        off += 6;
        out.set(e.bytes, off);
        off += e.bytes.length;
    }
    return out;
}

// Build a closure that compiles `source` with every discovered Python
// and packs the outputs into PGMV. Reusing one closure across stage1 /
// stage2 / interpreter lets the caller probe Pythons just once.
export function createCompileAndMarshal(pythons) {
    const builds = pythons || discoverPythons();
    if (builds.length === 0) {
        throw new Error('createCompileAndMarshal: no Python toolchains discovered');
    }
    return (source, filename) => {
        const entries = [];
        const seen = new Set();
        for (const b of builds) {
            const entry = compileAndMarshalOne(b.bin, source, filename);
            const key = entry.major + '.' + entry.minor;
            if (seen.has(key)) continue;
            seen.add(key);
            entries.push(entry);
        }
        return packPGMV(entries);
    };
}

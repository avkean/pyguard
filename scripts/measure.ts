import { execFileSync } from "child_process";
import * as zlib from "zlib";
import * as path from "path";
import { INTERPRETER_SRC_B64 } from "../lib/v5/interpreter_src";

const ROOT = path.resolve(".");
const src = zlib.inflateRawSync(Buffer.from(INTERPRETER_SRC_B64, "base64")).toString("utf-8");
console.log("interpreter source bytes:", src.length);

const pythons = [
  '/opt/homebrew/bin/python3.9',
  '/opt/homebrew/bin/python3.10',
  '/Users/avner/.local/bin/python3.11',
  '/opt/anaconda3/bin/python3.12',
  '/opt/homebrew/bin/python3.14',
];

const marshals: Buffer[] = [];
for (const py of pythons) {
  const out = execFileSync(py, [path.join(ROOT, "lib", "v5", "build_ir.py")], {
    input: src,
    encoding: "utf8",
    env: { ...process.env, PYGUARD_MODE: "marshal", PYGUARD_FILENAME: "<pg_interp>" },
    maxBuffer: 64 * 1024 * 1024,
  }).trim();
  const b = Buffer.from(out, "base64").subarray(6);
  console.log(`  ${py.split('/').pop()}: marshal=${b.length}`);
  marshals.push(b);
}

const totalRaw = marshals.reduce((a, b) => a + b.length, 0);
console.log("total raw marshal bytes:", totalRaw);

// Simulate PGMV
let pgmv = Buffer.alloc(5);
pgmv[0] = 0x50; pgmv[1] = 0x47; pgmv[2] = 0x4d; pgmv[3] = 0x56;
pgmv[4] = marshals.length;
for (let i = 0; i < marshals.length; i++) {
  const hdr = Buffer.alloc(6);
  hdr[0] = 3; hdr[1] = 9+i;
  hdr.writeUInt32LE(marshals[i].length, 2);
  pgmv = Buffer.concat([pgmv, hdr, marshals[i]]);
}
console.log("pgmv size:", pgmv.length);

const lzma = execFileSync(pythons[0], ["-c", "import sys, lzma; sys.stdout.buffer.write(lzma.compress(sys.stdin.buffer.read(), preset=9|lzma.PRESET_EXTREME))"], { input: pgmv, maxBuffer: 256*1024*1024 });
console.log("lzma compressed:", lzma.length);
console.log("b85 chars:", Math.ceil(lzma.length * 5 / 4));

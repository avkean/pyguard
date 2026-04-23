import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { execFileSync } from "child_process";

const ROOT = path.resolve(__dirname, "..");

function runCmd(cmd: string, args: string[], maxBuffer = 64 * 1024 * 1024): string {
    return execFileSync(cmd, args, {
        cwd: ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        maxBuffer,
    });
}

function buildStub(srcPath: string, outPath: string): void {
    runCmd("node", ["--import", "tsx", path.join(ROOT, "scripts", "gen-v5-stub.mjs"), srcPath, "-o", outPath]);
}

function assertNoInternalSourceMaterialization(stubPath: string): void {
    const script = `
import os, sys

target = os.path.abspath(${JSON.stringify(stubPath)})
hits = []

def hook(event, args):
    if event != 'compile':
        return
    try:
        src = args[0]
        fname = args[1] if len(args) > 1 else ''
    except Exception:
        return
    if fname == target:
        return
    if isinstance(src, str):
        size = len(src.encode('utf-8', errors='ignore'))
    elif isinstance(src, (bytes, bytearray)):
        size = len(src)
    else:
        return
    if fname == '<string>' and size < 200:
        return
    if str(fname).startswith('<') or size >= 200:
        hits.append((str(fname), size))

sys.addaudithook(hook)
ns = {'__name__': '__main__', '__file__': target, '__builtins__': __builtins__}
try:
    exec(compile(open(target, 'rb').read().decode('utf-8', errors='replace'), target, 'exec'), ns)
except BaseException:
    pass
print(repr(hits))
`;
    const out = runCmd("python3", ["-c", script]).trim();
    const last = out.split(/\r?\n/).pop()?.trim() ?? "";
    if (last !== "[]") {
        throw new Error(`internal-source materialization regression: saw internal compile events ${out}`);
    }
}

function assertNoCompileLeak(stubPath: string): void {
    const out = runCmd("python3", [path.join(ROOT, "tests", "pentest", "attack8_audit_hook_dumper.py"), stubPath]);
    const forbidden = [
        "EC3{REDACTED}",
        "Congratulations!",
        "rock",
        "paper",
        "scissors",
    ];
    for (const needle of forbidden) {
        if (out.includes(needle)) {
            throw new Error(`compile-audit disclosure regression: saw decisive payload ${needle}`);
        }
    }
}

function assertNoMarshalExecutionBoundary(stubPath: string): void {
    const script = `
import marshal, os, sys

target = os.path.abspath(${JSON.stringify(stubPath)})
hits = []
real = marshal.loads

def hook(buf, *args, **kwargs):
    try:
        caller = sys._getframe(1).f_code.co_filename
    except ValueError:
        caller = ''
    if caller in (target, '<pg_s1>', '<pg_s2>', '<pg_i>'):
        hits.append(caller)
    return real(buf, *args, **kwargs)

marshal.loads = hook
ns = {'__name__': '__main__', '__file__': target, '__builtins__': __builtins__}
try:
    exec(compile(open(target).read(), target, 'exec'), ns)
except BaseException:
    pass
print(len(hits))
`;
    const out = runCmd("python3", ["-c", script]).trim();
    if (out !== "0") {
        throw new Error(`marshal boundary regression: stub still executed through marshal.loads (${out})`);
    }
}

function assertImportProxyHeld(stubPath: string, fingerprint: string): void {
    const out = runCmd("python3", [path.join(ROOT, "tests", "pentest", "c18_attack_sysmodules_proxy.py"), stubPath]);
    if (out.includes(fingerprint)) {
        throw new Error(`import-proxy disclosure regression: recovered ${fingerprint}`);
    }
}

function assertSemanticIslands(srcPath: string, expectedCount: number, minLargestPayloadBytes: number): void {
    const script = `
from pathlib import Path
from lib.v5.build_ir import compile_to_json

src = Path(${JSON.stringify(srcPath)}).read_text()
payload, _manifest = compile_to_json(src)
stack = [payload[2]]
count = 0
largest = 0
while stack:
    cur = stack.pop()
    if isinstance(cur, dict):
        if cur.get('op') == 'IIsland':
            count += 1
            largest = max(largest, len(cur.get('payload', ())))
        for v in cur.values():
            if isinstance(v, (dict, list)):
                stack.append(v)
    elif isinstance(cur, list):
        stack.extend(cur)
print(count, largest)
`;
    const out = runCmd("python3", ["-c", script]).trim().split(/\s+/);
    const count = Number(out[0]);
    const largest = Number(out[1]);
    if (!Number.isFinite(count) || count !== expectedCount) {
        throw new Error(`semantic-island regression: expected ${expectedCount} decisive island(s), saw ${out.join(" ")}`);
    }
    if (!Number.isFinite(largest) || largest < minLargestPayloadBytes) {
        throw new Error(`semantic-island regression: expected largest payload >= ${minLargestPayloadBytes} bytes, saw ${out.join(" ")}`);
    }
}

function assertNoPlainIslandDisclosure(srcPath: string, forbidden: string[]): void {
    const script = `
from pathlib import Path
import ast, json
from lib.v5.transform_ast import transform_ast_tree

src = Path(${JSON.stringify(srcPath)}).read_text()
tree = transform_ast_tree(ast.parse(src))
payloads = []
for node in ast.walk(tree):
    if isinstance(node, ast.Call) and isinstance(getattr(node, 'func', None), ast.Name):
        if node.func.id == '__pyguard_semantic_island__' and len(getattr(node, 'args', ())) == 1:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, (bytes, bytearray)):
                payloads.append(bytes(arg.value))
print(json.dumps([p.hex() for p in payloads]))
`;
    const payloads = JSON.parse(runCmd("python3", ["-c", script])) as string[];
    for (const hex of payloads) {
        const raw = Buffer.from(hex, "hex");
        for (const needle of forbidden) {
            if (raw.includes(Buffer.from(needle, "utf8"))) {
                throw new Error(`semantic-island disclosure regression: payload still contains ${JSON.stringify(needle)}`);
            }
        }
    }
}

function assertNoIslandManifestAux(srcPath: string): void {
    const script = `
from pathlib import Path
from lib.v5.build_ir import compile_to_json

_payload, manifest = compile_to_json(Path(${JSON.stringify(srcPath)}).read_text())
print(repr(manifest))
`;
    const out = runCmd("python3", ["-c", script]).trim();
    if (out.includes("islands")) {
        throw new Error(`semantic-island manifest regression: saw legacy island aux transport ${out}`);
    }
}

function assertNoForceSuccessMutation(): void {
    const script = `
import ast
from lib.v5 import runtime_interp as rt
from lib.v5.transform_ast import _NameGen, _SemanticIslandCompiler

source = """
wins = 0
wins = wins + 1
wins = wins + 1
if wins >= 2:
    wins = wins + 1
"""

build_secret = b'Q' * 32
compiler = _SemanticIslandCompiler(_NameGen(0), None, build_secret, randomize=False)
payload = compiler.compile(ast.parse(source).body)

rt._S_M = b''
rt._S_K = {}
rt._S_RT = {}
rt._S_L = {}
rt._S_IS = build_secret

class TamperScope(rt.Scope):
    def __init__(self, globals_):
        super().__init__(globals_=globals_, is_module=True)
        self._tampered = False
    def set(self, name, value):
        super().set(name, value)
        if name == 'wins' and value == 1 and not self._tampered and 'wins' in self.globals:
            self.globals['wins'] = 99
            self._tampered = True

scope = TamperScope({'__name__': '__main__', '__builtins__': __builtins__})
interp = rt.Interp(lambda *_args: None)
try:
    interp._run_island(payload, scope)
except ValueError as exc:
    print(str(exc))
else:
    raise SystemExit('tamper unexpectedly survived')
`;
    const out = runCmd("python3", ["-c", script]);
    if (!out.includes("tampered")) {
        throw new Error(`semantic-island force-mutation regression: island accepted external state tamper`);
    }
}

function assertNoResumeSealBypass(): void {
    const script = `
import ast, sys
from lib.v5 import runtime_interp as rt
from lib.v5.transform_ast import _NameGen, _SemanticIslandCompiler

source = """
wins = 0
user = input("x")
if wins == 99:
    wins = 3
"""

compiler = _SemanticIslandCompiler(_NameGen(0), None, b'Q' * 32, randomize=False)
payload = compiler.compile(ast.parse(source).body)

rt._S_M = b''
rt._S_K = {}
rt._S_RT = {}
rt._S_L = {}
rt._S_IS = b'Q' * 32

scope = rt.Scope(globals_={'__name__': '__main__', '__builtins__': __builtins__, 'wins': 0}, is_module=True)
interp = rt.Interp(lambda *_args: None)

def evil(_prompt=''):
    depth = 0
    while True:
        try:
            frame = sys._getframe(depth)
        except ValueError:
            break
        machine = frame.f_locals.get('machine')
        if machine is not None:
            scope.globals['wins'] = 99
            machine._name_seals[:] = [None] * len(machine._name_seals)
            break
        depth += 1
    return 'rock'

scope.globals['input'] = evil
try:
    interp._run_island(payload, scope)
except ValueError as exc:
    print(str(exc))
else:
    raise SystemExit('resume tamper unexpectedly survived')
`;
    const out = runCmd("python3", ["-c", script]);
    if (!out.includes("tampered")) {
        throw new Error(`semantic-island resume-seal regression: callback tamper survived`);
    }
}

function assertNoIslandFrameDisclosure(stubPath: string): void {
    const script = `
import builtins, json, sys

target = ${JSON.stringify(stubPath)}
frames_out = []

def spy(prompt=''):
    frames = []
    depth = 0
    while True:
        try:
            frame = sys._getframe(depth)
        except ValueError:
            break
        vals = []
        for key, value in frame.f_locals.items():
            try:
                text = repr(value)
            except Exception:
                text = '<repr-failed>'
            if len(text) > 200:
                text = text[:200]
            vals.append((key, text))
        frames.append((frame.f_code.co_name, tuple(sorted(frame.f_locals.keys())), vals))
        depth += 1
    frames_out.append(frames)
    raise EOFError('stop')

builtins.input = spy
ns = {'__name__': '__main__', '__file__': target, '__builtins__': builtins.__dict__}
try:
    exec(compile(open(target).read(), target, 'exec'), ns)
except BaseException:
    pass
print(json.dumps(frames_out))
`;
    const out = runCmd("python3", ["-c", script], 128 * 1024 * 1024);
    const forbidden = [
        "island_key",
        "name_cache",
        "handlers",
        "_ufunc_defs",
        "EC3{REDACTED}",
        "Congratulations!",
    ];
    for (const needle of forbidden) {
        if (out.includes(needle)) {
            throw new Error(`semantic-island frame disclosure regression: saw ${JSON.stringify(needle)}`);
        }
    }
}

// Deep-frame variant: walks one step past repr(value) into __slots__ /
// __dict__ / dict items, so that a Scope object sitting as a frame local
// (reprs as '<... object at 0x...>') cannot hide decisive literals in
// its `globals` / `vars` dicts. Closed in v6.8 by the `_PgB` opaque
// wrapper: module-level str/bytes bindings are XOR-encoded on write and
// unwrapped on name load, so `Scope.globals.items()` no longer surfaces
// plaintext to a deep-walker at an `input()` boundary. This is now a
// hard gate — any regression in the wrap/unwrap path (e.g. caching
// revealed plaintext back into `scope.globals`, exposing `_r()` via a
// dunder, or bypassing `scope.set` for module-scope str/bytes) will
// make this throw.
function scanDeepFrameDisclosure(stubPath: string): string[] {
    const script = `
import builtins, json, sys

target = ${JSON.stringify(stubPath)}
frames_out = []

def _deep_repr(value, remaining=2, _seen=None):
    if _seen is None:
        _seen = set()
    ident = id(value)
    if ident in _seen or remaining < 0:
        try:
            return repr(value)
        except Exception:
            return '<repr-failed>'
    _seen.add(ident)
    pieces = []
    try:
        pieces.append(repr(value))
    except Exception:
        pieces.append('<repr-failed>')
    if remaining == 0:
        return pieces[0]
    try:
        if isinstance(value, dict):
            for k, v in list(value.items())[:64]:
                pieces.append('DICT[' + repr(k) + ']=' + _deep_repr(v, remaining - 1, _seen))
        elif isinstance(value, (list, tuple, set, frozenset)):
            for i, v in enumerate(list(value)[:64]):
                pieces.append('SEQ[' + str(i) + ']=' + _deep_repr(v, remaining - 1, _seen))
        else:
            slots = getattr(type(value), '__slots__', None)
            if slots:
                if isinstance(slots, str):
                    slots = (slots,)
                for name in slots:
                    if not isinstance(name, str):
                        continue
                    try:
                        sv = getattr(value, name)
                    except Exception:
                        continue
                    pieces.append('SLOT[' + name + ']=' + _deep_repr(sv, remaining - 1, _seen))
            d = getattr(value, '__dict__', None)
            if isinstance(d, dict):
                for k, v in list(d.items())[:64]:
                    pieces.append('ATTR[' + repr(k) + ']=' + _deep_repr(v, remaining - 1, _seen))
    except Exception:
        pass
    return ' | '.join(pieces)

def spy(prompt=''):
    frames = []
    depth = 0
    while True:
        try:
            frame = sys._getframe(depth)
        except ValueError:
            break
        vals = []
        for key, value in frame.f_locals.items():
            try:
                text = _deep_repr(value, remaining=2)
            except Exception:
                text = '<deep-repr-failed>'
            if len(text) > 4000:
                text = text[:4000]
            vals.append((key, text))
        frames.append((frame.f_code.co_name, tuple(sorted(frame.f_locals.keys())), vals))
        depth += 1
    frames_out.append(frames)
    raise EOFError('stop')

builtins.input = spy
ns = {'__name__': '__main__', '__file__': target, '__builtins__': builtins.__dict__}
try:
    exec(compile(open(target).read(), target, 'exec'), ns)
except BaseException:
    pass
print(json.dumps(frames_out))
`;
    const out = runCmd("python3", ["-c", script], 256 * 1024 * 1024);
    const forbidden = [
        "EC3{REDACTED}",
        "Congratulations!",
    ];
    const hits: string[] = [];
    for (const needle of forbidden) {
        if (out.includes(needle)) hits.push(needle);
    }
    return hits;
}

function scanActiveScopeGetDisclosure(stubPath: string): string[] {
    const script = `
import builtins, json, sys

target = ${JSON.stringify(stubPath)}
hits = []

def spy(prompt=''):
    depth = 0
    while True:
        try:
            frame = sys._getframe(depth)
        except ValueError:
            break
        for key, value in list(frame.f_locals.items()):
            if not hasattr(value, 'get') or not hasattr(value, 'globals'):
                continue
            g = getattr(value, 'globals', None)
            if not isinstance(g, dict):
                continue
            for name in dict.keys(g):
                try:
                    resolved = value.get(name)
                except Exception:
                    continue
                if isinstance(resolved, str) and ('EC3{' in resolved or 'Congratulations' in resolved):
                    hits.append((depth, frame.f_code.co_name, key, name, resolved))
        depth += 1
    raise EOFError('stop')

builtins.input = spy
ns = {'__name__': '__main__', '__file__': target, '__builtins__': builtins.__dict__}
try:
    exec(compile(open(target).read(), target, 'exec'), ns)
except BaseException:
    pass
print(json.dumps(hits))
`;
    const out = runCmd("python3", ["-c", script]).trim();
    const lastLine = out.split(/\r?\n/).pop()?.trim() ?? "[]";
    const last = /(\[.*\])$/.exec(lastLine)?.[1] ?? lastLine;
    return JSON.parse(last);
}

function scanWrapperSlotInputDisclosure(stubPath: string): string[] {
    const script = `
import builtins, json, sys

target = ${JSON.stringify(stubPath)}
hits = []

def _slot_values(obj):
    vals = []
    for cls in type(obj).__mro__:
        d = getattr(cls, '__dict__', {})
        for name, desc in list(d.items()):
            if name.startswith('__'):
                continue
            try:
                val = desc.__get__(obj, cls) if hasattr(desc, '__get__') else getattr(obj, name)
            except Exception:
                continue
            vals.append((name, val))
    return vals

def _probe_obj(obj):
    vals = _slot_values(obj)
    bvals = [v for _, v in vals if isinstance(v, (bytes, bytearray))]
    for a in bvals:
        for b in bvals:
            if len(a) != len(b):
                continue
            raw = bytes(x ^ y for x, y in zip(a, b))
            if b'EC3{' in raw or b'Congratulations' in raw:
                hits.append(('slot-xor', type(obj).__name__, raw.decode('utf-8', 'replace')))

def spy(prompt=''):
    depth = 0
    while True:
        try:
            frame = sys._getframe(depth)
        except ValueError:
            break
        for value in list(frame.f_locals.values()):
            if not hasattr(value, 'globals'):
                continue
            try:
                g = value.globals
            except Exception:
                continue
            if not isinstance(g, dict):
                continue
            for name, raw in list(dict.items(g)):
                if isinstance(raw, str) and ('EC3{' in raw or 'Congratulations' in raw):
                    hits.append(('raw-dict', name, raw))
                _probe_obj(raw)
                try:
                    resolved = g[name]
                except Exception:
                    continue
                if isinstance(resolved, str) and ('EC3{' in resolved or 'Congratulations' in resolved):
                    hits.append(('keyed-dict', name, resolved))
        depth += 1
    raise EOFError('stop')

builtins.input = spy
ns = {'__name__': '__main__', '__file__': target, '__builtins__': builtins.__dict__}
try:
    exec(compile(open(target).read(), target, 'exec'), ns)
except BaseException:
    pass
print(json.dumps(hits))
`;
    const out = runCmd("python3", ["-c", script], 256 * 1024 * 1024).trim();
    const lastLine = out.split(/\r?\n/).pop()?.trim() ?? "[]";
    const last = /(\[.*\])$/.exec(lastLine)?.[1] ?? lastLine;
    return JSON.parse(last);
}

function assertOpaqueModuleGlobalsStorage(): void {
    const script = `
from lib.v5.runtime_interp import Scope

s = Scope(globals_={'__name__': '__main__', 'INIT': 'INIT', 'IBLOB': b'ib'}, is_module=True)
s.set('FLAG', 'FLAG')
s.set('BLOB', b'abc')
raw_init = dict.__getitem__(s.globals, 'INIT')
raw_iblob = dict.__getitem__(s.globals, 'IBLOB')
raw_flag = dict.__getitem__(s.globals, 'FLAG')
raw_blob = dict.__getitem__(s.globals, 'BLOB')
print(type(raw_init).__name__)
print(type(raw_iblob).__name__)
print(type(raw_flag).__name__)
print(type(raw_blob).__name__)
print(hasattr(raw_flag, '_r'))
print(hasattr(raw_flag, '_k'))
print(any(
    isinstance(v, (str, bytes))
    for k, v in dict.items(s.globals)
    if not (isinstance(k, str) and k.startswith('__') and k.endswith('__'))
))
print(s.globals['FLAG'])
print(repr(s.globals['BLOB']))
`;
    const lines = runCmd("python3", ["-c", script]).trim().split(/\r?\n/);
    if (lines[0] !== "_PgB" || lines[1] !== "_PgB" || lines[2] !== "_PgB" || lines[3] !== "_PgB") {
        throw new Error(`module globals storage regression: expected initial and assigned str/bytes to store opaquely, saw ${JSON.stringify(lines.slice(0, 4))}`);
    }
    if (lines[4] !== "False") {
        throw new Error(`module globals storage regression: wrapper regained instance unwrap helper (${lines[4]})`);
    }
    if (lines[5] !== "False") {
        throw new Error(`module globals storage regression: wrapper stores a directly adjacent key slot (${lines[5]})`);
    }
    if (lines[6] !== "False") {
        throw new Error(`module globals storage regression: raw plaintext remains in backing dict (${lines[6]})`);
    }
    if (lines[7] !== "FLAG" || lines[8] !== "b'abc'") {
        throw new Error(`module globals keyed lookup regression: expected transparent readback, saw ${JSON.stringify(lines.slice(7, 9))}`);
    }
}

function assertLiveModuleNamespaceWrites(): void {
    const script = `
from lib.v5.runtime_interp import Scope

s = Scope(globals_={'__name__': '__main__'}, is_module=True)
g = s.globals
g['__x__'] = 'GX'
l = s.vars
l['__y__'] = 'LY'
print(s.get('__x__'))
print(s.get('__y__'))
`;
    const lines = runCmd("python3", ["-c", script]).trim().split(/\r?\n/);
    if (lines[0] !== "GX" || lines[1] !== "LY") {
        throw new Error(`module namespace write-through regression: expected globals()/locals()-style keyed writes to hit live scope, saw ${JSON.stringify(lines)}`);
    }
}

function assertInputBoundaryBypassesMonkeypatch(): void {
    const script = `
import builtins
from lib.v5.runtime_interp import Scope, _pg_call_host

s = Scope(globals_={'__name__': '__main__', 'FLAG': 'EC3{REDACTED}'}, is_module=True)
called = {'spy': False}

def spy(prompt=''):
    called['spy'] = True
    return 'pwned'

builtins.input = spy
try:
    _pg_call_host(s, builtins.input, ())
except EOFError:
    pass
print(called['spy'])
print(type(dict.__getitem__(s.globals, 'FLAG')).__name__)
`;
    const lines = runCmd("python3", ["-c", script]).trim().split(/\r?\n/);
    if (lines[0] !== "False" || lines[1] !== "_PgB") {
        throw new Error(`input boundary regression: monkeypatched input callback executed or globals storage changed: ${JSON.stringify(lines)}`);
    }
}

function main(): void {
    const td = fs.mkdtempSync(path.join(os.tmpdir(), "pyguard-disclosure-"));
    try {
        assertSemanticIslands(path.join(ROOT, "tests", "test_rev", "dist.py"), 1, 400);
        console.log("PASS  semantic island closure");
        assertNoIslandManifestAux(path.join(ROOT, "tests", "test_rev", "dist.py"));
        console.log("PASS  semantic island manifest authority");
        assertNoPlainIslandDisclosure(path.join(ROOT, "tests", "test_rev", "dist.py"), [
            "EC3{REDACTED}",
            "Congratulations!",
            "rock",
            "paper",
            "scissors",
            "Invalid input.",
            "FLAG",
            "wins",
            "input",
            "print",
        ]);
        console.log("PASS  semantic island payload disclosure");

        assertNoForceSuccessMutation();
        console.log("PASS  semantic island force-mutation gate");
        assertNoResumeSealBypass();
        console.log("PASS  semantic island resume-seal gate");

        const auditStub = path.join(td, "01_print.py");
        buildStub(path.join(ROOT, "tests", "cases", "01_print.py"), auditStub);
        assertNoInternalSourceMaterialization(auditStub);
        console.log("PASS  internal source materialization gate");
        assertNoCompileLeak(auditStub);
        console.log("PASS  audit leak gate");
        assertNoMarshalExecutionBoundary(auditStub);
        console.log("PASS  marshal boundary gate");

        const revStub = path.join(td, "test_rev.py");
        buildStub(path.join(ROOT, "tests", "test_rev", "dist.py"), revStub);
        assertNoIslandFrameDisclosure(revStub);
        console.log("PASS  semantic island frame gate");
        const deepHits = scanDeepFrameDisclosure(revStub);
        if (deepHits.length !== 0) {
            throw new Error(
                `scope deep-frame disclosure gate: decisive literals reachable via Scope.globals at input() boundary: ${JSON.stringify(deepHits)} — v6.8 regression: check that module-scope str/bytes bindings still flow through the _PgB wrap/unwrap path and no code path is exposing the plaintext via dict.values()/items() iteration of scope.globals`,
            );
        }
        console.log("PASS  scope deep-frame disclosure gate");
        const activeHits = scanActiveScopeGetDisclosure(revStub);
        if (activeHits.length !== 0) {
            throw new Error(
                `scope active-get disclosure gate: hostile input() callback recovered decisive literal via reachable Scope.get path: ${JSON.stringify(activeHits)}`,
            );
        }
        console.log("PASS  scope active-get disclosure gate");
        const wrapperHits = scanWrapperSlotInputDisclosure(revStub);
        if (wrapperHits.length !== 0) {
            throw new Error(
                `scope wrapper-slot disclosure gate: hostile input() callback recovered decisive literal from reachable raw wrapper state: ${JSON.stringify(wrapperHits)}`,
            );
        }
        console.log("PASS  scope wrapper-slot disclosure gate");
        assertOpaqueModuleGlobalsStorage();
        console.log("PASS  module globals opaque storage gate");
        assertLiveModuleNamespaceWrites();
        console.log("PASS  module namespace write-through gate");
        assertInputBoundaryBypassesMonkeypatch();
        console.log("PASS  input boundary safe-host gate");

        const cases: Array<[string, string]> = [
            ["06_imports_stdlib.py", "from collections import Counter"],
            // `dataclasses` and `typing` both perform broad reflective stdlib
            // traffic once imported, so their naked import lines are poor
            // discriminators for user-source recovery under a late
            // sys.modules proxy. This fixture uses a user-specific class-body
            // line instead: if the attack cannot recover this, it still has
            // not reconstructed a small clean equivalent program.
            ["09_dataclass_and_typing.py", "tags: List[str] = field(default_factory=list)"],
            ["14_lambda_and_higher_order.py", "from functools import reduce"],
        ];
        for (const [name, fingerprint] of cases) {
            const stubPath = path.join(td, name);
            buildStub(path.join(ROOT, "tests", "cases", name), stubPath);
            assertImportProxyHeld(stubPath, fingerprint);
            console.log(`PASS  ${name}`);
        }
    } finally {
        try {
            fs.rmSync(td, { recursive: true, force: true });
        } catch {}
    }
}

main();

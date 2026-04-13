#!/usr/bin/env node
// scripts/gen-v5-stub.mjs
//
// End-to-end v5 stub generation for local testing.
//
// 1. Shell out to `python3 lib/v5/build_ir.py` to compile user source → IR JSON.
// 2. Run lib/obfuscate.ts (via tsx) with opts.v5IR to produce the stub.
// 3. Write the stub to stdout (or to a file with -o).
//
// Usage:
//   node scripts/gen-v5-stub.mjs tests/cases/01_print.py > out.py
//   node scripts/gen-v5-stub.mjs tests/cases/02_function_calls_function.py -o out.py

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

function randToken(used) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    for (;;) {
        let out = '_';
        for (let i = 0; i < 6; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
        if (!used.has(out)) {
            used.add(out);
            return out;
        }
    }
}

function shuffle(items) {
    const out = items.slice();
    for (let i = out.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        const tmp = out[i];
        out[i] = out[j];
        out[j] = tmp;
    }
    return out;
}

function makeV5Schema() {
    const keys = [
        "annotation","arg","args","asname","attr","bases","body","cause","comparators","consts",
        "context_expr","conversion","decorator_list","defaults","elt","elts","exc","finalbody",
        "format_spec","func","generators","handlers","i","id","idx","instrs","is_async","is_gen",
        "ifs","items","iter","key",
        "keys","keywords","kw_defaults","kwarg","kwonlyargs","left","level","lower","module","name",
        "names","op","op2","operand","ops","optional_vars","orelse","posonlyargs","r","returns",
        "right","simple","slice","step","strings","t","target","targets","test","tree","type","upper",
        "v","value","values","vararg",
    ];
    const tags = [
        "Code",
        "IExpr","IAssign","IAugAssign","IAnnAssign","IReturn","IRaise",
        "IPass","IBreak","IContinue","IDelete","IGlobal","INonlocal",
        "IIf","IWhile","IFor","IAsyncFor","IWith","IAsyncWith",
        "ITry","IHandler","IImport","IImportFrom","IFunctionDef","IClassDef",
        "Module","Expression","Assign","AugAssign","AnnAssign","Expr","Return","Raise","Pass","Break","Continue",
        "If","While","For","AsyncFor","With","AsyncWith","Try","TryStar","ExceptHandler","FunctionDef",
        "AsyncFunctionDef","Lambda","ClassDef","Global","Nonlocal","Delete","Import","ImportFrom","alias",
        "BinOp","UnaryOp","BoolOp","Compare","IfExp","Call","Attribute","Subscript","Slice","Starred",
        "Name","Constant","List","Tuple","Set","Dict","ListComp","SetComp","DictComp","GeneratorExp",
        "comprehension","JoinedStr","FormattedValue","Yield","YieldFrom","Await","NamedExpr","arguments",
        "arg","keyword","withitem","MatchValue","MatchSingleton","MatchSequence","MatchStar","MatchMapping",
        "MatchClass","MatchAs","MatchOr","Match","Add","Sub","Mult","MatMult","Div","Mod","Pow","LShift",
        "RShift","BitOr","BitXor","BitAnd","FloorDiv","And","Or","Invert","Not","UAdd","USub","Eq","NotEq",
        "Lt","LtE","Gt","GtE","Is","IsNot","In","NotIn","Load","Store","Del","none","true","false","int",
        "float","str","bytes","complex","ellipsis","tuple","frozenset",
    ];
    const NODE_LAYOUTS = {
        Code: ["instrs"],
        IExpr: ["value"],
        IAssign: ["targets", "value"],
        IAugAssign: ["target", "op2", "value"],
        IAnnAssign: ["target", "annotation", "value", "simple"],
        IReturn: ["value"],
        IRaise: ["exc", "cause"],
        IPass: [],
        IBreak: [],
        IContinue: [],
        IDelete: ["targets"],
        IGlobal: ["names"],
        INonlocal: ["names"],
        IIf: ["test", "body", "orelse"],
        IWhile: ["test", "body", "orelse"],
        IFor: ["target", "iter", "body", "orelse"],
        IAsyncFor: ["target", "iter", "body", "orelse"],
        IWith: ["items", "body"],
        IAsyncWith: ["items", "body"],
        ITry: ["body", "handlers", "orelse", "finalbody"],
        IHandler: ["type", "name", "body"],
        IImport: ["names"],
        IImportFrom: ["module", "names", "level"],
        IFunctionDef: ["name", "args", "body", "decorator_list", "returns", "is_async", "is_gen"],
        IClassDef: ["name", "bases", "keywords", "body", "decorator_list"],
        Module: ["body"],
        Expr: ["value"],
        Assign: ["targets", "value"],
        AugAssign: ["target", "op2", "value"],
        AnnAssign: ["target", "annotation", "value", "simple"],
        Return: ["value"],
        Raise: ["exc", "cause"],
        Pass: [],
        Break: [],
        Continue: [],
        Delete: ["targets"],
        Global: ["names"],
        Nonlocal: ["names"],
        If: ["test", "body", "orelse"],
        While: ["test", "body", "orelse"],
        For: ["target", "iter", "body", "orelse"],
        AsyncFor: ["target", "iter", "body", "orelse"],
        With: ["items", "body"],
        AsyncWith: ["items", "body"],
        withitem: ["context_expr", "optional_vars"],
        Try: ["body", "handlers", "orelse", "finalbody"],
        ExceptHandler: ["type", "name", "body"],
        Import: ["names"],
        ImportFrom: ["module", "names", "level"],
        alias: ["name", "asname"],
        FunctionDef: ["name", "args", "body", "decorator_list", "returns"],
        AsyncFunctionDef: ["name", "args", "body", "decorator_list", "returns"],
        ClassDef: ["name", "bases", "keywords", "body", "decorator_list"],
        Lambda: ["args", "body"],
        arguments: ["posonlyargs", "args", "vararg", "kwonlyargs", "kw_defaults", "kwarg", "defaults"],
        arg: ["arg", "annotation"],
        keyword: ["arg", "value"],
        Name: ["id", "ctx"],
        Constant: ["idx"],
        BinOp: ["left", "op2", "right"],
        UnaryOp: ["op2", "operand"],
        BoolOp: ["op2", "values"],
        Compare: ["left", "ops", "comparators"],
        IfExp: ["test", "body", "orelse"],
        Call: ["func", "args", "keywords"],
        Attribute: ["value", "attr", "ctx"],
        Subscript: ["value", "slice", "ctx"],
        Slice: ["lower", "upper", "step"],
        Starred: ["value", "ctx"],
        List: ["elts", "ctx"],
        Tuple: ["elts", "ctx"],
        Set: ["elts"],
        Dict: ["keys", "values"],
        ListComp: ["elt", "generators"],
        SetComp: ["elt", "generators"],
        DictComp: ["key", "value", "generators"],
        GeneratorExp: ["elt", "generators"],
        comprehension: ["target", "iter", "ifs", "is_async"],
        JoinedStr: ["values"],
        FormattedValue: ["value", "conversion", "format_spec"],
        Yield: ["value"],
        YieldFrom: ["value"],
        Await: ["value"],
        NamedExpr: ["target", "value"],
    };
    const used = new Set();
    const layouts = {};
    for (const [op, fields] of Object.entries(NODE_LAYOUTS)) {
        layouts[op] = shuffle(fields);
    }
    return {
        keys: Object.fromEntries(keys.map((k) => [k, randToken(used)])),
        tags: Object.fromEntries(tags.map((t) => [t, randToken(used)])),
        mask: Array.from({ length: 16 }, () => Math.floor(Math.random() * 256)),
        layouts,
    };
}

function parseArgs(argv) {
    const args = { src: null, out: null };
    for (let i = 2; i < argv.length; i++) {
        const a = argv[i];
        if (a === '-o' || a === '--out') {
            args.out = argv[++i];
        } else if (a.startsWith('-')) {
            console.error(`unknown flag: ${a}`);
            process.exit(2);
        } else if (!args.src) {
            args.src = a;
        }
    }
    if (!args.src) {
        console.error('usage: gen-v5-stub.mjs <source.py> [-o <out.py>]');
        process.exit(2);
    }
    return args;
}

const args = parseArgs(process.argv);
const userSource = fs.readFileSync(args.src, 'utf-8');
const schema = makeV5Schema();

// Step 1: compile IR via python3 + build_ir.py.
// build_ir's __main__ reads source from stdin and writes base64(zlib(JSON))
// to stdout — the TS obfuscator treats these bytes as an opaque blob.
const py = spawnSync('python3', [path.join(root, 'lib/v5/build_ir.py')], {
    input: userSource,
    encoding: 'utf-8',
    env: { ...process.env, PYGUARD_V5_SCHEMA: JSON.stringify(schema) },
});
if (py.status !== 0) {
    console.error('build_ir.py failed:');
    console.error(py.stderr);
    process.exit(py.status || 1);
}
const irCompressedB64 = py.stdout.trim();

// Step 2: call the TS obfuscator. We use tsx to run the TS directly.
// To avoid process overhead, write a tiny driver script that imports
// obfuscate, calls it, and prints the result.
// Note: static imports of .ts files break under Node 24's native type
// stripping (the re-export graph ends up empty). Dynamic import via tsx
// works correctly, so we use that instead.
const driver = `
const { obfuscatePythonCode } = await import('./lib/obfuscate.ts');
const fs = await import('node:fs');
const userSource = fs.readFileSync(${JSON.stringify(args.src)}, 'utf-8');
const compressed = Uint8Array.from(Buffer.from(${JSON.stringify(irCompressedB64)}, 'base64'));
const stub = obfuscatePythonCode(userSource, { v5IR: { compressed, schema: ${JSON.stringify(schema)} } });
process.stdout.write(stub);
`;

const driverPath = path.join(root, '.v5-driver.mjs');
fs.writeFileSync(driverPath, driver);
try {
    const ts = spawnSync(path.join(root, 'node_modules/.bin/tsx'), [driverPath], {
        cwd: root,
        encoding: 'utf-8',
        maxBuffer: 64 * 1024 * 1024,
    });
    if (ts.status !== 0) {
        console.error('tsx driver failed:');
        console.error(ts.stderr);
        process.exit(ts.status || 1);
    }
    const stub = ts.stdout;
    if (args.out) {
        fs.writeFileSync(args.out, stub);
        console.error(`wrote ${args.out} (${stub.length} chars)`);
    } else {
        process.stdout.write(stub);
    }
} finally {
    try { fs.unlinkSync(driverPath); } catch {}
}

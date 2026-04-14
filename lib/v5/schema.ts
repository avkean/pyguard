export interface V5Schema {
    keys: Record<string, string>;
    tags: Record<string, string>;
    mask: number[];
    layouts: Record<string, string[]>;
    binKey: [number, number];               // 64-bit LCG seed as two 32-bit ints [lo, hi]
    noiseSchedule: [number, number][];      // (position, noise_length) pairs
}

const KEY_NAMES = [
    "annotation", "arg", "args", "asname", "attr", "bases", "body",
    "cause", "comparators", "consts", "context_expr", "conversion",
    "decorator_list", "defaults", "elt", "elts", "exc", "finalbody",
    "format_spec", "func", "generators", "handlers", "i", "id", "idx",
    "instrs", "is_async", "is_gen",
    "ifs", "items", "iter", "key", "keys", "keywords", "kw_defaults",
    "kwarg", "kwonlyargs", "left", "level", "lower", "module", "name",
    "names", "op", "op2", "operand", "ops", "optional_vars", "orelse",
    "posonlyargs", "r", "returns", "right", "simple", "slice", "step",
    "strings", "t", "target", "targets", "test", "tree", "type", "upper",
    "v", "value", "values", "vararg",
];

const TAG_NAMES = [
    "Code",
    "IExpr", "IAssign", "IAugAssign", "IAnnAssign", "IReturn", "IRaise",
    "IPass", "IBreak", "IContinue", "IDelete", "IGlobal", "INonlocal",
    "IIf", "IWhile", "IFor", "IAsyncFor", "IWith", "IAsyncWith",
    "ITry", "IHandler", "IImport", "IImportFrom", "IFunctionDef", "IClassDef",
    "Module", "Expression",
    "Assign", "AugAssign", "AnnAssign",
    "Expr", "Return", "Raise", "Pass", "Break", "Continue",
    "If", "While", "For", "AsyncFor", "With", "AsyncWith",
    "Try", "TryStar", "ExceptHandler",
    "FunctionDef", "AsyncFunctionDef", "Lambda", "ClassDef",
    "Global", "Nonlocal", "Delete",
    "Import", "ImportFrom", "alias",
    "BinOp", "UnaryOp", "BoolOp", "Compare", "IfExp",
    "Call", "Attribute", "Subscript", "Slice", "Starred",
    "Name", "Constant",
    "List", "Tuple", "Set", "Dict",
    "ListComp", "SetComp", "DictComp", "GeneratorExp", "comprehension",
    "JoinedStr", "FormattedValue",
    "Yield", "YieldFrom", "Await",
    "NamedExpr",
    "arguments", "arg", "keyword", "withitem",
    "MatchValue", "MatchSingleton", "MatchSequence", "MatchStar",
    "MatchMapping", "MatchClass", "MatchAs", "MatchOr", "Match",
    "Add", "Sub", "Mult", "MatMult", "Div", "Mod", "Pow",
    "LShift", "RShift", "BitOr", "BitXor", "BitAnd", "FloorDiv",
    "And", "Or",
    "Invert", "Not", "UAdd", "USub",
    "Eq", "NotEq", "Lt", "LtE", "Gt", "GtE", "Is", "IsNot", "In", "NotIn",
    "Load", "Store", "Del",
    "none", "true", "false", "int", "float", "str", "bytes",
    "complex", "ellipsis", "tuple", "frozenset",
];

const NODE_LAYOUTS: Record<string, string[]> = {
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

function randToken(used: Set<string>): string {
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const g: any = typeof globalThis !== "undefined" ? globalThis : {};
    for (;;) {
        let out = "_";
        for (let i = 0; i < 6; i++) {
            const n = g.crypto && typeof g.crypto.getRandomValues === "function"
                ? (() => {
                    const b = new Uint8Array(1);
                    g.crypto.getRandomValues(b);
                    return b[0];
                })()
                : Math.floor(Math.random() * 256);
            out += alphabet[n % alphabet.length];
        }
        if (!used.has(out)) {
            used.add(out);
            return out;
        }
    }
}

function randByte(): number {
    const g: any = typeof globalThis !== "undefined" ? globalThis : {};
    if (g.crypto && typeof g.crypto.getRandomValues === "function") {
        const b = new Uint8Array(1);
        g.crypto.getRandomValues(b);
        return b[0];
    }
    return Math.floor(Math.random() * 256);
}

function shuffle<T>(items: T[]): T[] {
    const out = items.slice();
    for (let i = out.length - 1; i > 0; i--) {
        const j = randByte() % (i + 1);
        const tmp = out[i];
        out[i] = out[j];
        out[j] = tmp;
    }
    return out;
}

export function makeV5Schema(): V5Schema {
    const used = new Set<string>();
    const keys: Record<string, string> = {};
    const tags: Record<string, string> = {};
    for (const k of KEY_NAMES) keys[k] = randToken(used);
    for (const t of TAG_NAMES) tags[t] = randToken(used);
    const layouts: Record<string, string[]> = {};
    for (const [op, fields] of Object.entries(NODE_LAYOUTS)) {
        layouts[op] = shuffle(fields);
    }
    const mask = Array.from({ length: 16 }, () => randByte());

    // Rolling XOR seed: 64-bit value as [lo32, hi32] (JS lacks u64)
    const binKey: [number, number] = [
        (randByte() | (randByte() << 8) | (randByte() << 16) | (randByte() << 24)) >>> 0,
        (randByte() | (randByte() << 8) | (randByte() << 16) | (randByte() << 24)) >>> 0,
    ];

    // Noise schedule: inject random-length noise blobs at random positions.
    // We pick 4-8 noise entries; positions are offsets into the *post-XOR* blob.
    // At build time (Python) we inject; at runtime (Python) we strip.
    const noiseCount = 4 + (randByte() % 5);   // 4..8
    const noiseSchedule: [number, number][] = [];
    for (let i = 0; i < noiseCount; i++) {
        // position: random 16-bit offset (will be taken modulo actual blob length)
        const pos = ((randByte() << 8) | randByte()) >>> 0;
        // length: 2..17 noise bytes
        const len = 2 + (randByte() % 16);
        noiseSchedule.push([pos, len]);
    }

    return { keys, tags, mask, layouts, binKey, noiseSchedule };
}

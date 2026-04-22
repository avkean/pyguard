#!/usr/bin/env python3
"""Build-time source obfuscator for runtime_interp.py.

Reads lib/v5/runtime_interp.py, applies AST-level transformations to make
the interpreter much harder for an attacker (or an LLM) to understand,
and writes obfuscated Python source to stdout.

Transformations:
  1. Rename user-defined identifiers to confusable lIl1O0-style names
  2. XOR-encode string literals as bytes([...]).decode('utf-8')
  3. Insert dead code (unreachable functions/methods)
  4. Scramble method order within classes
  5. Register API-surface names via globals()[encoded] aliasing

Usage: python3 scripts/obfuscate_runtime.py
"""

import ast
import copy
import hashlib
import os
import random
import string
import sys
import textwrap

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
INTERP_PATH = os.path.join(ROOT_DIR, 'lib', 'v5', 'runtime_interp.py')

# Seed for reproducible builds when PYGUARD_OBFUSC_SEED is set, otherwise
# random per invocation.
_seed = os.environ.get('PYGUARD_OBFUSC_SEED', None)
if _seed is not None:
    random.seed(int(hashlib.sha256(_seed.encode()).hexdigest(), 16) % (2**32))
else:
    random.seed()

# Characters for confusable identifier generation.
# Only l, I, 1, O, 0 — no underscore to avoid __ name mangling issues.
_CONFUSE_CHARS = 'lI1O0'

# v9: DRASTICALLY SHRUNK.
#
# Prior rounds registered 16 API names (run_blob, _pg_parse_bin, Interp,
# _decode_const, _pg_text, _pg_tag, _nf, _MISSING, Scope, …) as
# globals()[original] = obfuscated aliases so stage2 + downstream could
# find them by their original names. That set was the foundation of the
# v8 attack: red-team hooked `_pg_parse_bin`, `_decode_const`, `_pg_text`,
# `_pg_tag`, `_nf`, `Interp` by their original names and walked the IR.
#
# Those aliases only existed as a build-time convenience: with one
# exception (`_pg_boot`, which stage2's source literally calls), NONE of
# them are referenced from outside the interpreter module. All internal
# LOAD_GLOBALs resolve against the obfuscated names within the same
# module, which are consistent because the rename pass is atomic.
#
# v9: only `_pg_boot` remains, and even that is registered under a
# RANDOMIZED BYTES KEY (not the literal string "_pg_boot"). An attacker
# who hooks `types.FunctionType` to grab the interpreter's globals now
# finds only obfuscated tokens plus one anonymous bytes-keyed slot.
API_SURFACE_NAMES = {'_pg_boot'}

# v9: the randomized boot export key. Generated fresh every obfuscation
# run. Stage2 needs the same bytes so we emit them on stderr for the
# caller (gen-interpreter-src.mjs) to capture and re-export.
BOOT_EXPORT_KEY = bytes(random.randint(0, 255) for _ in range(12))

# Dunder / magic names that Python calls by protocol -- never rename.
DUNDER_NAMES = {
    '__init__', '__call__', '__get__', '__repr__', '__contains__',
    '__getitem__', '__slots__', '__name__', '__qualname__', '__module__',
    '__doc__', '__annotations__', '__all__', '__func__', '__self__',
    '__main__', '__builtins__', '__package__', '__aiter__', '__anext__',
    '__aenter__', '__aexit__', '__enter__', '__exit__', '__import__',
    '__getattr__', '__setattr__', '__delattr__', '__class__',
    '__pyguard_class__', '__pyguard_self__',
}

# Python builtins and stdlib names -- never rename.
BUILTIN_NAMES = set(dir(__builtins__) if isinstance(__builtins__, dict)
                    else dir(__builtins__)) | {
    'builtins', 'sys', 'None', 'True', 'False', 'Ellipsis',
    'BaseException', 'Exception', 'StopIteration', 'StopAsyncIteration',
    'GeneratorExit', 'ArithmeticError', 'LookupError', 'AssertionError',
    'AttributeError', 'BlockingIOError', 'BrokenPipeError',
    'BufferError', 'BytesWarning', 'ChildProcessError',
    'ConnectionAbortedError', 'ConnectionError', 'ConnectionRefusedError',
    'ConnectionResetError', 'DeprecationWarning', 'EOFError',
    'EnvironmentError', 'FileExistsError', 'FileNotFoundError',
    'FloatingPointError', 'FutureWarning', 'IOError',
    'ImportError', 'ImportWarning', 'IndentationError', 'IndexError',
    'InterruptedError', 'IsADirectoryError', 'KeyError',
    'KeyboardInterrupt', 'MemoryError', 'ModuleNotFoundError',
    'NameError', 'NotADirectoryError', 'NotImplemented',
    'NotImplementedError', 'OSError', 'OverflowError',
    'PendingDeprecationWarning', 'PermissionError', 'ProcessLookupError',
    'RecursionError', 'ReferenceError', 'ResourceWarning',
    'RuntimeError', 'RuntimeWarning', 'StopAsyncIteration',
    'SyntaxError', 'SyntaxWarning', 'SystemError', 'SystemExit',
    'TabError', 'TimeoutError', 'TypeError', 'UnboundLocalError',
    'UnicodeDecodeError', 'UnicodeEncodeError', 'UnicodeError',
    'UnicodeTranslationError', 'UnicodeWarning', 'UserWarning',
    'ValueError', 'Warning', 'ZeroDivisionError',
    # builtins functions
    'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'breakpoint',
    'bytearray', 'bytes', 'callable', 'chr', 'classmethod', 'compile',
    'complex', 'copyright', 'credits', 'delattr', 'dict', 'dir',
    'divmod', 'enumerate', 'eval', 'exec', 'exit', 'filter', 'float',
    'format', 'frozenset', 'getattr', 'globals', 'hasattr', 'hash',
    'help', 'hex', 'id', 'input', 'int', 'isinstance', 'issubclass',
    'iter', 'len', 'license', 'list', 'locals', 'map', 'max',
    'memoryview', 'min', 'next', 'object', 'oct', 'open', 'ord',
    'pow', 'print', 'property', 'quit', 'range', 'repr', 'reversed',
    'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod',
    'str', 'sum', 'super', 'tuple', 'type', 'vars', 'zip',
    '__import__',
    # common method/attr names used dynamically
    'items', 'keys', 'values', 'get', 'set', 'pop', 'update',
    'append', 'extend', 'add', 'remove', 'insert', 'index', 'count',
    'sort', 'reverse', 'copy', 'clear', 'decode', 'encode',
    'split', 'join', 'strip', 'lstrip', 'rstrip', 'replace',
    'startswith', 'endswith', 'find', 'rfind', 'upper', 'lower',
    'format', 'send', 'throw', 'close',
}

# Method names used as dict keys or called dynamically on objects
# within the interpreter -- don't rename these since they appear as
# attribute accesses on external objects.
DYNAMIC_ATTR_NAMES = {
    'items', 'get', 'set', 'delete', 'pop', 'update', 'append',
    'extend', 'add', 'split', 'decode', 'encode', 'startswith',
    'send', 'value', 'close',
}

# The self-test block marker -- everything from here on is stripped.
CUT_MARKER = "# --- self-test entry point"

# ---------------------------------------------------------------------------
# Name generator
# ---------------------------------------------------------------------------

class NameGenerator:
    """Generate short obfuscated identifier names.

    v11: shortened from 7-char `_lI1O0Il` (confusable alphabet) to 3-5
    chars from a 52-letter mixed-case pool. Confusability was a weak
    anti-reading property; the security guarantee is that names carry
    NO SEMANTIC INFORMATION, which holds regardless of length. Stubs
    reference each name many times, so every byte shaved off a name
    cascades into ~O(refs) bytes off the stub.

    Entropy: interpreter has ~800 renameable identifiers. 52^2 = 2704
    two-char bodies, 52^3 = 140k — ample for unique allocation.
    """

    def __init__(self):
        self._used = set()

    def next_name(self):
        body_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        for _ in range(4096):
            n = 2 + random.randint(0, 2)  # 2..4 body chars
            s = '_' + ''.join(random.choice(body_chars) for _ in range(n))
            if s not in self._used:
                self._used.add(s)
                return s
        # Fallback: extremely unlikely with 140k+ 3-char bodies
        raise RuntimeError("NameGenerator: exhausted attempts")


_namegen = NameGenerator()

# ---------------------------------------------------------------------------
# Identifier collection: walk the AST to find all user-defined names
# ---------------------------------------------------------------------------

def _should_rename(name):
    """Return True if this name should be obfuscated."""
    if name.startswith('__') and name.endswith('__'):
        return False
    if name in BUILTIN_NAMES:
        return False
    if name in DUNDER_NAMES:
        return False
    return True


def collect_defined_names(tree):
    """Walk the AST and collect all user-defined identifier names."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            names.add(node.name)
            # Parameters
            for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                names.add(arg.arg)
            if node.args.vararg:
                names.add(node.args.vararg.arg)
            if node.args.kwarg:
                names.add(node.args.kwarg.arg)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Global):
            for n in node.names:
                names.add(n)
        elif isinstance(node, ast.Nonlocal):
            for n in node.names:
                names.add(n)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.asname:
                    names.add(alias.asname)
                else:
                    names.add(alias.name)
    return names


def collect_class_method_names(tree):
    """Collect names of methods defined inside class bodies (FunctionDef inside ClassDef)."""
    method_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_names.add(item.name)
    return method_names


def build_rename_map(tree):
    """Build a mapping from original name -> obfuscated name."""
    all_names = collect_defined_names(tree)
    rename_map = {}
    for name in sorted(all_names):  # sort for determinism
        if _should_rename(name):
            rename_map[name] = _namegen.next_name()
    return rename_map


# ---------------------------------------------------------------------------
# AST transformer: rename identifiers
# ---------------------------------------------------------------------------

class IdentifierRenamer(ast.NodeTransformer):
    """Rename user-defined identifiers throughout the AST."""

    def __init__(self, rename_map, class_method_names=None):
        self.rename_map = rename_map
        self._class_method_names = class_method_names or set()

    def _r(self, name):
        return self.rename_map.get(name, name)

    def visit_FunctionDef(self, node):
        node.name = self._r(node.name)
        self._rename_args(node.args)
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        node.body = [self.visit(s) for s in node.body]
        if node.returns:
            node.returns = self.visit(node.returns)
        return node

    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)

    def visit_ClassDef(self, node):
        node.name = self._r(node.name)
        node.bases = [self.visit(b) for b in node.bases]
        node.keywords = [self.visit(k) for k in node.keywords]
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        # Don't rename __slots__ strings since we don't rename attributes
        node.body = [self.visit(s) for s in node.body]
        return node

    def visit_Name(self, node):
        node.id = self._r(node.id)
        return node

    def visit_Attribute(self, node):
        node.value = self.visit(node.value)
        # Only rename attributes that are internal class method names.
        # Data attributes (value, body, parent, etc.) are left alone since
        # we can't distinguish self.value from si.value (StopIteration)
        # without type information.
        if node.attr in self._class_method_names and node.attr in self.rename_map:
            node.attr = self.rename_map[node.attr]
        return node

    def visit_Global(self, node):
        node.names = [self._r(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._r(n) for n in node.names]
        return node

    def visit_arg(self, node):
        node.arg = self._r(node.arg)
        if node.annotation:
            node.annotation = self.visit(node.annotation)
        return node

    def _rename_args(self, args):
        for a in args.args:
            self.visit_arg(a)
        for a in args.posonlyargs:
            self.visit_arg(a)
        for a in args.kwonlyargs:
            self.visit_arg(a)
        if args.vararg:
            self.visit_arg(args.vararg)
        if args.kwarg:
            self.visit_arg(args.kwarg)
        args.defaults = [self.visit(d) for d in args.defaults]
        args.kw_defaults = [self.visit(d) if d else d for d in args.kw_defaults]

    def visit_ExceptHandler(self, node):
        # except ... as name: — name is a plain string, not an ast.Name node.
        if node.name and node.name in self.rename_map:
            node.name = self.rename_map[node.name]
        if node.type:
            node.type = self.visit(node.type)
        node.body = [self.visit(s) for s in node.body]
        return node

    def visit_keyword(self, node):
        # Rename keyword arg names that match user-defined parameter names.
        # External kwargs (e.g., end=, sep=, file=) aren't in the rename map
        # so they're safely skipped.
        if node.arg and node.arg in self.rename_map:
            node.arg = self.rename_map[node.arg]
        node.value = self.visit(node.value)
        return node

    def visit_Import(self, node):
        # Don't rename module names (they're runtime-looked-up) but DO
        # rename the `asname` — `import hashlib as _h` binds `_h` in the
        # enclosing scope, and usages of `_h` elsewhere are renamed, so
        # the alias itself must be renamed in lockstep. Otherwise every
        # call to hashlib turns into a NameError on the renamed alias.
        for alias in node.names:
            if alias.asname and alias.asname in self.rename_map:
                alias.asname = self.rename_map[alias.asname]
        return node

    def visit_ImportFrom(self, node):
        # Same treatment as Import: preserve the imported module/member
        # name but rename the alias if one is present. For bare
        # `from mod import foo` (no asname), `alias.name` becomes the
        # binding in the enclosing scope, but rewriting it would break
        # the import itself — so those are left untouched and the
        # collect/rename pass excludes them already by pattern.
        for alias in node.names:
            if alias.asname and alias.asname in self.rename_map:
                alias.asname = self.rename_map[alias.asname]
        return node

    def generic_visit(self, node):
        return super().generic_visit(node)


# ---------------------------------------------------------------------------
# AST transformer: XOR-encode string literals
# ---------------------------------------------------------------------------

# The name for the shared XOR-decode helper function inserted at the top of
# the obfuscated module. Generated once per run.
# IMPORTANT: Must not start with '__' to avoid Python's class-body name mangling.
_BODY_CHARS = 'lI1O0'
_XOR_DECODE_FUNC_NAME = '_' + ''.join(random.choices(_BODY_CHARS, k=8))


def _make_xor_decode_func(used_names=None):
    """Return AST nodes for the shared XOR decode helper with caching.

    Generates a cache dict and a decode function that memoizes results
    to avoid repeated computation and reduce call stack depth in deep
    recursion scenarios.

    `used_names`: set of identifiers already consumed by the rename pass —
    we avoid regenerating any of those to prevent the cache dict name
    from colliding with a renamed class or function. (Previously this
    was a silent statistical bug: when a collision hit, the cache dict
    got rebound to a class object and `in`-tests raised TypeError.)
    """
    used_names = used_names if used_names is not None else set()

    def fresh(width):
        while True:
            cand = '_' + ''.join(random.choices(_BODY_CHARS, k=width))
            if cand not in used_names:
                used_names.add(cand)
                return cand

    pd = fresh(5)
    pk = fresh(5)
    pi = fresh(5)
    pc = fresh(6)      # cache dict name
    pkey = fresh(5)

    func_src = f'''
{pc} = {{}}
def {_XOR_DECODE_FUNC_NAME}({pd}, {pk}):
    {pkey} = (bytes({pd}), bytes({pk}))
    if {pkey} in {pc}:
        return {pc}[{pkey}]
    {pc}[{pkey}] = bytes(({pd}[{pi}] ^ {pk}[{pi} % len({pk})] for {pi} in range(len({pd})))).decode('utf-8')
    return {pc}[{pkey}]
'''
    return ast.parse(func_src.strip()).body


def _xor_encode_string(s):
    """Return an AST Call node: _decode_func(bytes([xored...]), bytes([key...]))."""
    raw = s.encode('utf-8')
    if len(raw) == 0:
        return ast.Constant(value='')

    # Generate random XOR key (1-8 bytes)
    key_len = random.randint(1, min(8, len(raw)))
    key = bytes(random.randint(1, 255) for _ in range(key_len))
    xored = bytes(b ^ key[i % key_len] for i, b in enumerate(raw))

    # O1: emit bytes LITERALS (b'\xHH\xHH...'), not bytes([int,int,...]).
    # ast.unparse renders bytes constants as b'...' escape form, roughly
    # 3 + 4n chars vs ~4n + 8 for the bytes([...]) form. Saves ~5 chars
    # per short string plus defeats trivially-greppable `bytes([` patterns
    # in static analysis (the interpreter goes from hundreds of those per
    # module to zero).
    # Build: _decode_func(b'...xored...', b'...key...')
    return ast.Call(
        func=ast.Name(id=_XOR_DECODE_FUNC_NAME, ctx=ast.Load()),
        args=[
            ast.Constant(value=xored),
            ast.Constant(value=key),
        ],
        keywords=[],
    )


# Strings that should NOT be encoded (they are part of Python/runtime protocol)
_NO_ENCODE_STRINGS = {
    'utf-8', 'utf8', 'ascii', 'latin-1',
    '__main__', '__name__', '__builtins__', '__doc__', '__annotations__',
    '__package__', '__all__', '__pyguard_class__', '__pyguard_self__',
    'yield', 'await', 'return',
    # format spec conversions
    '', ' ', '\n', '\t', '\r',
    # Single characters used as tags in binary parser
    'n', 't', 'f', 'i', 'r', 's', 'l', 'm',
    # Type names accessed by convention
    'metaclass',
}

# String values that are node-tag names (they appear as dict keys in _NODE_POS
# and as op== comparisons). These get transformed differently.
_NODE_TAG_STRINGS = {
    'Code', 'IExpr', 'IAssign', 'IAugAssign', 'IAnnAssign', 'IReturn',
    'IRaise', 'IPass', 'IBreak', 'IContinue', 'IDelete', 'IGlobal',
    'INonlocal', 'IIf', 'IWhile', 'IFor', 'IAsyncFor', 'IWith',
    'IAsyncWith', 'ITry', 'IHandler', 'IImport', 'IImportFrom',
    'IFunctionDef', 'IClassDef', 'Module', 'Expr', 'Assign', 'AugAssign',
    'AnnAssign', 'Return', 'Raise', 'Pass', 'Break', 'Continue', 'Delete',
    'Global', 'Nonlocal', 'If', 'While', 'For', 'AsyncFor', 'With',
    'AsyncWith', 'withitem', 'Try', 'ExceptHandler', 'Import', 'ImportFrom',
    'alias', 'FunctionDef', 'AsyncFunctionDef', 'ClassDef', 'Lambda',
    'arguments', 'arg', 'keyword', 'Name', 'Constant', 'BinOp', 'UnaryOp',
    'BoolOp', 'Compare', 'IfExp', 'Call', 'Attribute', 'Subscript', 'Slice',
    'Starred', 'List', 'Tuple', 'Set', 'Dict', 'ListComp', 'SetComp',
    'DictComp', 'GeneratorExp', 'comprehension', 'JoinedStr',
    'FormattedValue', 'Yield', 'YieldFrom', 'Await', 'NamedExpr',
    # Operator names
    'Add', 'Sub', 'Mult', 'MatMult', 'Div', 'Mod', 'Pow', 'LShift',
    'RShift', 'BitOr', 'BitXor', 'BitAnd', 'FloorDiv',
    'Invert', 'Not', 'UAdd', 'USub',
    'Eq', 'NotEq', 'Lt', 'LtE', 'Gt', 'GtE', 'Is', 'IsNot', 'In', 'NotIn',
    'And', 'Or',
}

# Field names used in _NODE_POS values -- these are internal to the interpreter
# and passed through _pg_key, so they should be encoded.
_NODE_FIELD_STRINGS = {
    'instrs', 'value', 'targets', 'op2', 'target', 'annotation', 'simple',
    'test', 'body', 'orelse', 'iter', 'items', 'handlers', 'type', 'name',
    'module', 'names', 'level', 'args', 'decorator_list', 'returns',
    'is_async', 'is_gen', 'bases', 'keywords', 'id', 'ctx', 'idx', 'left',
    'right', 'operand', 'values', 'ops', 'comparators', 'func', 'attr',
    'slice', 'lower', 'upper', 'step', 'elts', 'keys', 'elt', 'generators',
    'key', 'conversion', 'format_spec', 'context_expr', 'optional_vars',
    'ifs', 'is_async', 'posonlyargs', 'vararg', 'kwonlyargs', 'kw_defaults',
    'kwarg', 'defaults', 'arg', 'asname', 'cause', 'exc', 'finalbody',
}


class StringEncoder(ast.NodeTransformer):
    """Replace string literals with XOR-encoded byte expressions."""

    def __init__(self):
        self._in_node_pos = False
        self._in_op_table = False

    def visit_Assign(self, node):
        # Check if this is the _NODE_POS assignment or op table assignment
        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id in ('_NODE_POS',):
                    # Don't encode _NODE_POS keys -- they go through _pg_tag
                    # at runtime anyway. But DO encode them for confusion.
                    pass
        self.generic_visit(node)
        return node

    def visit_Constant(self, node):
        if not isinstance(node.value, str):
            return node
        s = node.value
        # Don't encode certain protocol strings
        if s in _NO_ENCODE_STRINGS:
            return node
        if len(s) <= 1:
            return node
        # Don't encode format strings or very short strings
        if len(s) > 200:
            return node
        return _xor_encode_string(s)


# ---------------------------------------------------------------------------
# Dead code generator
# ---------------------------------------------------------------------------

_dead_code_name_counter = 0

def _rand_confuse_name():
    """Generate a unique confusable name for dead code."""
    global _dead_code_name_counter
    _dead_code_name_counter += 1
    # Use the counter to guarantee uniqueness, then pad with random chars
    body_chars = 'lI1O0'
    base = len(body_chars)
    n = _dead_code_name_counter
    parts = []
    while n > 0:
        parts.append(body_chars[n % base])
        n //= base
    # Pad to 8+ chars
    while len(parts) < 8:
        parts.append(body_chars[random.randint(0, base - 1)])
    random.shuffle(parts)
    return '_' + ''.join(parts)


def _make_dead_function():
    """Generate a plausible-looking but unreachable function definition."""
    templates = [
        # Template 1: fake node walker
        '''
def {name}({p1}, {p2}, {p3}=None):
    if not isinstance({p1}, tuple) or not {p1}:
        return {p3}
    {v1} = {p1}[0]
    {v2} = {{}}
    for {v3} in range(1, len({p1})):
        {v2}[{v3}] = {p1}[{v3}]
    if {p2} in {v2}:
        return {v2}[{p2}]
    return {p3}
''',
        # Template 2: fake hash combiner
        '''
def {name}({p1}, {p2}=0x9E3779B9):
    {v1} = 0
    for {v2} in range(len({p1})):
        {v1} = (({v1} << 5) | ({v1} >> 27)) ^ (({p1}[{v2}] if isinstance({p1}, (bytes, bytearray, list, tuple)) else ord({p1}[{v2}])) * {p2})
        {v1} &= 0xFFFFFFFF
    return {v1}
''',
        # Template 3: fake scope resolver
        '''
def {name}({p1}, {p2}):
    {v1} = {p1}
    while {v1} is not None:
        if hasattr({v1}, 'vars') and {p2} in {v1}.vars:
            return {v1}.vars[{p2}]
        {v1} = getattr({v1}, 'parent', None)
    return None
''',
        # Template 4: fake dispatch table builder
        '''
def {name}({p1}):
    {v1} = {{}}
    for {v2}, {v3} in enumerate({p1}):
        if isinstance({v3}, tuple) and len({v3}) >= 2:
            {v1}[{v3}[0]] = {v3}[1]
        else:
            {v1}[{v2}] = {v3}
    return {v1}
''',
        # Template 5: fake binary unpacker
        '''
def {name}({p1}, {p2}=0):
    if {p2} + 4 > len({p1}):
        return 0, {p2}
    {v1} = {p1}[{p2}] | ({p1}[{p2}+1] << 8) | ({p1}[{p2}+2] << 16) | ({p1}[{p2}+3] << 24)
    return {v1}, {p2} + 4
''',
        # Template 6: fake constant decoder
        '''
def {name}({p1}, {p2}=None):
    if {p1} is None:
        return {p2}
    if isinstance({p1}, (int, float, bool)):
        return {p1}
    if isinstance({p1}, (list, tuple)):
        return type({p1})({name}({v1}, {p2}) for {v1} in {p1})
    return {p1}
''',
        # Template 7: fake XOR mask applier
        '''
def {name}({p1}, {p2}):
    if not {p2}:
        return {p1}
    {v1} = bytearray(len({p1}))
    for {v2} in range(len({p1})):
        {v1}[{v2}] = {p1}[{v2}] ^ {p2}[{v2} % len({p2})]
    return bytes({v1})
''',
        # Template 8: fake string pool lookup
        '''
def {name}({p1}, {p2}, {p3}=None):
    if {p2} is None or {p2} < 0:
        return {p3}
    if {p2} >= len({p1}):
        return {p3}
    {v1} = {p1}[{p2}]
    if isinstance({v1}, str):
        return {v1}
    if isinstance({v1}, (list, tuple)):
        return ''.join(chr({v2}) for {v2} in {v1})
    return str({v1})
''',
        # Template 9: fake tag normalizer
        '''
def {name}({p1}, {p2}=None):
    if {p2} is not None:
        {v1} = {p2}.get({p1}, {p1})
        return {v1}
    return {p1}
''',
        # Template 10: fake iteration helper
        '''
def {name}({p1}, {p2}, {p3}=False):
    {v1} = []
    for {v2} in {p1}:
        if isinstance({v2}, tuple) and {v2}:
            {v1}.append({v2})
        elif {p3}:
            {v1}.append(({p2}, {v2}))
    return {v1}
''',
    ]

    template = random.choice(templates)
    params = {
        'name': _rand_confuse_name(),
        'p1': _rand_confuse_name(),
        'p2': _rand_confuse_name(),
        'p3': _rand_confuse_name(),
        'v1': _rand_confuse_name(),
        'v2': _rand_confuse_name(),
        'v3': _rand_confuse_name(),
    }
    code = template.format(**params)
    return ast.parse(textwrap.dedent(code)).body[0]


def _make_dead_method():
    """Generate a plausible method for insertion into a class body."""
    templates = [
        # fake step method
        '''
def {name}(self, {p1}, {p2}):
    if False:
        yield
    if not isinstance({p1}, tuple) or not {p1}:
        return
    {v1} = {p1}[0]
    if {v1} not in {p2}:
        return
    for {v2} in {p1}[1:]:
        if isinstance({v2}, tuple):
            yield from self.{name}({v2}, {p2})
''',
        # fake eval helper
        '''
def {name}(self, {p1}, {p2}):
    if False:
        yield
    {v1} = None
    if isinstance({p1}, (list, tuple)):
        {v1} = []
        for {v2} in {p1}:
            {v3} = yield from self.{name}({v2}, {p2})
            {v1}.append({v3})
        return tuple({v1})
    return {v1}
''',
        # fake scope walker
        '''
def {name}(self, {p1}, {p2}):
    {v1} = {p1}
    while {v1} is not None:
        if {p2} in getattr({v1}, 'vars', {{}}):
            return getattr({v1}, 'vars')[{p2}]
        {v1} = getattr({v1}, 'parent', None)
    return None
''',
        # fake node validator
        '''
def {name}(self, {p1}):
    if not isinstance({p1}, tuple):
        return False
    if len({p1}) < 1:
        return False
    {v1} = {p1}[0]
    return isinstance({v1}, str) and len({v1}) > 0
''',
    ]

    template = random.choice(templates)
    params = {
        'name': _rand_confuse_name(),
        'p1': _rand_confuse_name(),
        'p2': _rand_confuse_name(),
        'v1': _rand_confuse_name(),
        'v2': _rand_confuse_name(),
        'v3': _rand_confuse_name(),
    }
    code = textwrap.dedent(template.strip())
    code_formatted = code.format(**params)
    # Parse as class body
    wrapper = "class _T:\n" + textwrap.indent(code_formatted, "    ")
    parsed = ast.parse(wrapper)
    return parsed.body[0].body[0]


# ---------------------------------------------------------------------------
# Method scrambler: shuffle method order in classes
# ---------------------------------------------------------------------------

def scramble_class_methods(tree):
    """Shuffle the order of method definitions within each class."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Separate __init__ (must stay first-ish for readability is
            # irrelevant -- we're obfuscating! But we should keep __slots__
            # assignments before methods for correctness).
            slots_stmts = []
            init_method = None
            other_stmts = []
            other_methods = []

            for stmt in node.body:
                if (isinstance(stmt, ast.Assign) and
                    any(isinstance(t, ast.Name) and t.id == '__slots__'
                        for t in stmt.targets)):
                    slots_stmts.append(stmt)
                elif (isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and stmt.name == '__init__'):
                    init_method = stmt
                elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    other_methods.append(stmt)
                else:
                    other_stmts.append(stmt)

            random.shuffle(other_methods)

            new_body = slots_stmts + other_stmts
            if init_method:
                new_body.append(init_method)
            new_body.extend(other_methods)
            node.body = new_body


# ---------------------------------------------------------------------------
# Dead code insertion
# ---------------------------------------------------------------------------

def insert_dead_code(tree, n_funcs=12, n_methods_per_class=3):
    """Insert dead code: unreachable functions at module level and methods
    in classes."""
    # Module-level dead functions
    dead_funcs = [_make_dead_function() for _ in range(n_funcs)]

    # Insert at random positions among the existing module body
    body = list(tree.body)
    # Find valid insertion points (after imports but throughout)
    insert_positions = list(range(2, len(body)))  # skip first 2 (imports)
    random.shuffle(insert_positions)

    for func in dead_funcs:
        if insert_positions:
            pos = insert_positions.pop()
            body.insert(pos, func)
        else:
            body.append(func)

    tree.body = body

    # Methods in classes
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            dead_methods = [_make_dead_method() for _ in range(n_methods_per_class)]
            class_body = list(node.body)
            for method in dead_methods:
                pos = random.randint(0, len(class_body))
                class_body.insert(pos, method)
            node.body = class_body


# ---------------------------------------------------------------------------
# Globals registration: API surface names get aliased via globals()
# ---------------------------------------------------------------------------

def make_globals_registration(rename_map):
    """Stage2 calls the renamed _pg_boot directly after module init.

    Older rounds ended the module body with an inline globals()-based
    boot fetch. The current stage2 path performs module initialization
    first, then resolves the renamed `_pg_boot` from the module globals
    and calls it externally. That removes the pre-boot provider object
    from interpreter globals and keeps this pass as a no-op.
    """
    return []


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def strip_self_test(src):
    """Remove the self-test __main__ block."""
    cut = src.find(CUT_MARKER)
    if cut >= 0:
        return src[:cut].rstrip() + '\n'
    return src


def strip_docstrings(tree):
    """Remove all docstrings from the AST."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, 'body', [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                # Only remove if the body has more than one statement
                if len(body) > 1:
                    node.body = body[1:]


def obfuscate(src):
    """Apply obfuscation passes and return the transformed source.

    Size-conscious pipeline (v6.6 cleanup). Prior rounds ran CFF +
    StringEncoder + 12 dead functions + MBA on the interpreter source
    before marshaling. Measured (2026-04-20) each of those adds bytes
    to the marshaled, multi-version-packed, lzma-compressed blob while
    the attack surface it defends lives at the post-crypto, post-
    marshal.loads, disassembly level — by which point a professional
    reverser reads past those layers regardless. Per CLAUDE.md's
    "no cosmetic bloat" rule we keep ONLY:

      - strip_docstrings       : zero-cost, removes __doc__ from marshal
      - identifier rename      : free (marshal string-table dedup), hides
                                 semantic names like `Scope`, `Interp`,
                                 `run_blob`, `_pg_boot` from dis output
      - bootkey registration   : prevents `_pg_boot` from appearing under
                                 its literal name in interpreter globals
      - method-order scramble  : free, makes vtable-style analysis harder

    Dropped (measured 5-ver lzma cost per build on 2026-04-20):
      - StringEncoder + XOR helper : +19 KB  (encodes error strings /
                                              stdlib method names that
                                              bytecode references anyway)
      - transform_ast_tree CFF     :  +8 KB  (interpreter's own control
                                              flow; attacker reading dis
                                              output walks past CFF)
      - insert_dead_code           :  +2 KB  (pure visual clutter)

    Total saved: ~29 KB lzma × base85 5/4 ≈ 37 KB per stub.
    """
    tree = ast.parse(src)

    strip_docstrings(tree)

    rename_map = build_rename_map(tree)
    class_methods = collect_class_method_names(tree)
    renamer = IdentifierRenamer(rename_map, class_methods)
    tree = renamer.visit(tree)

    scramble_class_methods(tree)

    reg_stmts = make_globals_registration(rename_map)
    tree.body.extend(reg_stmts)

    ast.fix_missing_locations(tree)
    return ast.unparse(tree), rename_map.get('_pg_boot', '_pg_boot')


def main():
    src = open(INTERP_PATH, 'r').read()
    src = strip_self_test(src)
    result, boot_func_name = obfuscate(src)
    sys.stdout.write(result)
    sys.stdout.write('\n')
    # v9: emit the boot export key to stderr as a hex line so
    # gen-interpreter-src.mjs can capture it and export it alongside
    # INTERPRETER_SRC_B64 for stage2 to use.
    sys.stderr.write('PYG_BOOT_KEY_HEX=' + BOOT_EXPORT_KEY.hex() + '\n')
    sys.stderr.write('PYG_BOOT_FUNC_NAME=' + boot_func_name + '\n')
    sys.stderr.flush()


if __name__ == '__main__':
    main()

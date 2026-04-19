"""PyGuard v5 build-time IR compiler.

Runs INSIDE Pyodide in the browser at build time. Takes user Python source,
parses it via Python's stdlib `ast` module, and walks the AST to emit a
custom IR tree. The IR is then JSON-serialised and handed back to TS for
encryption + bundling into the stub.

The output IR is structurally similar to a Python AST but uses opaque
numeric op tags (per-build randomised on the TS side, not here) and
flattens identifier strings into a separate string pool.

This file is loaded as a Python source string by the TS layer and exec'd
in Pyodide. It exposes a `compile_to_ir(source: str) -> dict` function.
"""

import ast
import json
import os


# IR op names. The TS side replaces these with random numeric tags
# per build, so the names below never appear in the runtime stub.
OPS = (
    'Module', 'Expression',
    'Assign', 'AugAssign', 'AnnAssign',
    'Expr', 'Return', 'Raise', 'Pass', 'Break', 'Continue',
    'If', 'While', 'For', 'AsyncFor', 'With', 'AsyncWith',
    'Try', 'TryStar', 'ExceptHandler',
    'FunctionDef', 'AsyncFunctionDef', 'Lambda', 'ClassDef',
    'Global', 'Nonlocal', 'Delete',
    'Import', 'ImportFrom', 'alias',
    'BinOp', 'UnaryOp', 'BoolOp', 'Compare', 'IfExp',
    'Call', 'Attribute', 'Subscript', 'Slice', 'Starred',
    'Name', 'Constant',
    'List', 'Tuple', 'Set', 'Dict',
    'ListComp', 'SetComp', 'DictComp', 'GeneratorExp', 'comprehension',
    'JoinedStr', 'FormattedValue',
    'Yield', 'YieldFrom', 'Await',
    'NamedExpr',
    'arguments', 'arg', 'keyword', 'withitem',
    'MatchValue', 'MatchSingleton', 'MatchSequence', 'MatchStar',
    'MatchMapping', 'MatchClass', 'MatchAs', 'MatchOr', 'Match',
    # Operator tags (subset)
    'Add', 'Sub', 'Mult', 'MatMult', 'Div', 'Mod', 'Pow',
    'LShift', 'RShift', 'BitOr', 'BitXor', 'BitAnd', 'FloorDiv',
    'And', 'Or',
    'Invert', 'Not', 'UAdd', 'USub',
    'Eq', 'NotEq', 'Lt', 'LtE', 'Gt', 'GtE', 'Is', 'IsNot', 'In', 'NotIn',
    'Load', 'Store', 'Del',
)

# Operator class names → OP names
_OP_BIN = {
    'Add': 'Add', 'Sub': 'Sub', 'Mult': 'Mult', 'MatMult': 'MatMult',
    'Div': 'Div', 'Mod': 'Mod', 'Pow': 'Pow',
    'LShift': 'LShift', 'RShift': 'RShift',
    'BitOr': 'BitOr', 'BitXor': 'BitXor', 'BitAnd': 'BitAnd',
    'FloorDiv': 'FloorDiv',
}
_OP_UNARY = {'Invert': 'Invert', 'Not': 'Not', 'UAdd': 'UAdd', 'USub': 'USub'}
_OP_BOOL = {'And': 'And', 'Or': 'Or'}
_OP_CMP = {
    'Eq': 'Eq', 'NotEq': 'NotEq', 'Lt': 'Lt', 'LtE': 'LtE',
    'Gt': 'Gt', 'GtE': 'GtE', 'Is': 'Is', 'IsNot': 'IsNot',
    'In': 'In', 'NotIn': 'NotIn',
}


class _Lifter:
    def __init__(self):
        self.strings = []
        self.string_idx = {}
        self.consts = []
        self.const_idx = {}

    def s(self, value):
        """Intern a string into the string pool, return its index."""
        if value is None:
            return -1
        if value in self.string_idx:
            return self.string_idx[value]
        i = len(self.strings)
        self.string_idx[value] = i
        self.strings.append(value)
        return i

    def c(self, value):
        """Intern a constant value into the const pool, return its index."""
        # Use repr+type to disambiguate (1 vs True etc).
        key = (type(value).__name__, repr(value))
        if key in self.const_idx:
            return self.const_idx[key]
        i = len(self.consts)
        self.const_idx[key] = i
        self.consts.append(value)
        return i

    def op_name(self, node):
        cls = type(node).__name__
        if cls in _OP_BIN:
            return _OP_BIN[cls]
        if cls in _OP_UNARY:
            return _OP_UNARY[cls]
        if cls in _OP_BOOL:
            return _OP_BOOL[cls]
        if cls in _OP_CMP:
            return _OP_CMP[cls]
        raise ValueError(f"unknown operator: {cls}")

    def _drop_docstring(self, body):
        """v6.5 / C16 — strip the leading Expr(Constant(str)) statement
        from Module / FunctionDef / ClassDef bodies.

        Docstrings survived every prior round of source concealment
        (pre-IR string XOR-split doesn't touch them because they're
        standalone expression statements, and the const pool stores them
        verbatim after marshal.dumps). An attacker who defeats the
        crypto — or exfiltrates the const pool via any future pivot —
        recovers the docstring byte-for-byte, which often contains API
        signatures, class purpose, and usage examples. Stripping them
        at lift time makes that leak impossible regardless of where
        crypto ends up. Honest limit: does NOT preserve `__doc__` at
        runtime; callers relying on `obj.__doc__` get None.
        """
        if not body:
            return body
        first = body[0]
        if type(first).__name__ != 'Expr':
            return body
        v = getattr(first, 'value', None)
        if v is None or type(v).__name__ != 'Constant':
            return body
        val = getattr(v, 'value', None)
        if isinstance(val, str):
            return body[1:]
        return body

    def lift(self, node):
        """Recursively lift an AST node to an IR dict."""
        if node is None:
            return None
        if isinstance(node, list):
            return [self.lift(x) for x in node]

        cls = type(node).__name__

        # ---- Module / top-level ----
        if cls == 'Module':
            return {'op': 'Module', 'body': self.lift(self._drop_docstring(node.body))}

        # ---- Statements ----
        if cls == 'Expr':
            return {'op': 'Expr', 'value': self.lift(node.value)}
        if cls == 'Assign':
            return {
                'op': 'Assign',
                'targets': self.lift(node.targets),
                'value': self.lift(node.value),
            }
        if cls == 'AugAssign':
            return {
                'op': 'AugAssign',
                'target': self.lift(node.target),
                'op2': self.op_name(node.op),
                'value': self.lift(node.value),
            }
        if cls == 'AnnAssign':
            return {
                'op': 'AnnAssign',
                'target': self.lift(node.target),
                'annotation': self.lift(node.annotation),
                'value': self.lift(node.value),
                'simple': node.simple,
            }
        if cls == 'Return':
            return {'op': 'Return', 'value': self.lift(node.value)}
        if cls == 'Raise':
            return {'op': 'Raise', 'exc': self.lift(node.exc), 'cause': self.lift(node.cause)}
        if cls == 'Pass':
            return {'op': 'Pass'}
        if cls == 'Break':
            return {'op': 'Break'}
        if cls == 'Continue':
            return {'op': 'Continue'}
        if cls == 'Delete':
            return {'op': 'Delete', 'targets': self.lift(node.targets)}
        if cls == 'Global':
            return {'op': 'Global', 'names': [self.s(n) for n in node.names]}
        if cls == 'Nonlocal':
            return {'op': 'Nonlocal', 'names': [self.s(n) for n in node.names]}

        if cls == 'If':
            return {
                'op': 'If',
                'test': self.lift(node.test),
                'body': self.lift(node.body),
                'orelse': self.lift(node.orelse),
            }
        if cls == 'While':
            return {
                'op': 'While',
                'test': self.lift(node.test),
                'body': self.lift(node.body),
                'orelse': self.lift(node.orelse),
            }
        if cls == 'For':
            return {
                'op': 'For',
                'target': self.lift(node.target),
                'iter': self.lift(node.iter),
                'body': self.lift(node.body),
                'orelse': self.lift(node.orelse),
            }
        if cls == 'AsyncFor':
            return {
                'op': 'AsyncFor',
                'target': self.lift(node.target),
                'iter': self.lift(node.iter),
                'body': self.lift(node.body),
                'orelse': self.lift(node.orelse),
            }
        if cls == 'With':
            return {
                'op': 'With',
                'items': self.lift(node.items),
                'body': self.lift(node.body),
            }
        if cls == 'AsyncWith':
            return {
                'op': 'AsyncWith',
                'items': self.lift(node.items),
                'body': self.lift(node.body),
            }
        if cls == 'withitem':
            return {
                'op': 'withitem',
                'context_expr': self.lift(node.context_expr),
                'optional_vars': self.lift(node.optional_vars),
            }
        if cls == 'Try':
            return {
                'op': 'Try',
                'body': self.lift(node.body),
                'handlers': self.lift(node.handlers),
                'orelse': self.lift(node.orelse),
                'finalbody': self.lift(node.finalbody),
            }
        if cls == 'ExceptHandler':
            return {
                'op': 'ExceptHandler',
                'type': self.lift(node.type),
                'name': self.s(node.name),
                'body': self.lift(node.body),
            }

        # ---- Imports ----
        if cls == 'Import':
            return {'op': 'Import', 'names': self.lift(node.names)}
        if cls == 'ImportFrom':
            return {
                'op': 'ImportFrom',
                'module': self.s(node.module),
                'names': self.lift(node.names),
                'level': node.level,
            }
        if cls == 'alias':
            return {
                'op': 'alias',
                'name': self.s(node.name),
                'asname': self.s(node.asname),
            }

        # ---- Function / class defs ----
        if cls == 'FunctionDef':
            return {
                'op': 'FunctionDef',
                'name': self.s(node.name),
                'args': self.lift(node.args),
                'body': self.lift(self._drop_docstring(node.body)),
                'decorator_list': self.lift(node.decorator_list),
                'returns': self.lift(node.returns),
            }
        if cls == 'AsyncFunctionDef':
            return {
                'op': 'AsyncFunctionDef',
                'name': self.s(node.name),
                'args': self.lift(node.args),
                'body': self.lift(self._drop_docstring(node.body)),
                'decorator_list': self.lift(node.decorator_list),
                'returns': self.lift(node.returns),
            }
        if cls == 'Lambda':
            return {
                'op': 'Lambda',
                'args': self.lift(node.args),
                'body': self.lift(node.body),
            }
        if cls == 'ClassDef':
            return {
                'op': 'ClassDef',
                'name': self.s(node.name),
                'bases': self.lift(node.bases),
                'keywords': self.lift(node.keywords),
                'body': self.lift(self._drop_docstring(node.body)),
                'decorator_list': self.lift(node.decorator_list),
            }
        if cls == 'arguments':
            return {
                'op': 'arguments',
                'posonlyargs': self.lift(node.posonlyargs),
                'args': self.lift(node.args),
                'vararg': self.lift(node.vararg),
                'kwonlyargs': self.lift(node.kwonlyargs),
                'kw_defaults': self.lift(node.kw_defaults),
                'kwarg': self.lift(node.kwarg),
                'defaults': self.lift(node.defaults),
            }
        if cls == 'arg':
            return {
                'op': 'arg',
                'arg': self.s(node.arg),
                'annotation': self.lift(node.annotation),
            }
        if cls == 'keyword':
            return {
                'op': 'keyword',
                'arg': self.s(node.arg),
                'value': self.lift(node.value),
            }

        # ---- Expressions ----
        if cls == 'BinOp':
            return {
                'op': 'BinOp',
                'left': self.lift(node.left),
                'op2': self.op_name(node.op),
                'right': self.lift(node.right),
            }
        if cls == 'UnaryOp':
            return {
                'op': 'UnaryOp',
                'op2': self.op_name(node.op),
                'operand': self.lift(node.operand),
            }
        if cls == 'BoolOp':
            return {
                'op': 'BoolOp',
                'op2': self.op_name(node.op),
                'values': self.lift(node.values),
            }
        if cls == 'Compare':
            return {
                'op': 'Compare',
                'left': self.lift(node.left),
                'ops': [self.op_name(o) for o in node.ops],
                'comparators': self.lift(node.comparators),
            }
        if cls == 'IfExp':
            return {
                'op': 'IfExp',
                'test': self.lift(node.test),
                'body': self.lift(node.body),
                'orelse': self.lift(node.orelse),
            }
        if cls == 'Call':
            return {
                'op': 'Call',
                'func': self.lift(node.func),
                'args': self.lift(node.args),
                'keywords': self.lift(node.keywords),
            }
        if cls == 'Attribute':
            return {
                'op': 'Attribute',
                'value': self.lift(node.value),
                'attr': self.s(node.attr),
                'ctx': type(node.ctx).__name__,
            }
        if cls == 'Subscript':
            return {
                'op': 'Subscript',
                'value': self.lift(node.value),
                'slice': self.lift(node.slice),
                'ctx': type(node.ctx).__name__,
            }
        if cls == 'Slice':
            return {
                'op': 'Slice',
                'lower': self.lift(node.lower),
                'upper': self.lift(node.upper),
                'step': self.lift(node.step),
            }
        if cls == 'Starred':
            return {
                'op': 'Starred',
                'value': self.lift(node.value),
                'ctx': type(node.ctx).__name__,
            }
        if cls == 'Name':
            return {
                'op': 'Name',
                'id': self.s(node.id),
                'ctx': type(node.ctx).__name__,
            }
        if cls == 'Constant':
            return {'op': 'Constant', 'idx': self.c(node.value)}
        if cls == 'List':
            return {
                'op': 'List',
                'elts': self.lift(node.elts),
                'ctx': type(node.ctx).__name__,
            }
        if cls == 'Tuple':
            return {
                'op': 'Tuple',
                'elts': self.lift(node.elts),
                'ctx': type(node.ctx).__name__,
            }
        if cls == 'Set':
            return {'op': 'Set', 'elts': self.lift(node.elts)}
        if cls == 'Dict':
            return {
                'op': 'Dict',
                'keys': self.lift(node.keys),
                'values': self.lift(node.values),
            }

        if cls == 'ListComp':
            return {
                'op': 'ListComp',
                'elt': self.lift(node.elt),
                'generators': self.lift(node.generators),
            }
        if cls == 'SetComp':
            return {
                'op': 'SetComp',
                'elt': self.lift(node.elt),
                'generators': self.lift(node.generators),
            }
        if cls == 'DictComp':
            return {
                'op': 'DictComp',
                'key': self.lift(node.key),
                'value': self.lift(node.value),
                'generators': self.lift(node.generators),
            }
        if cls == 'GeneratorExp':
            return {
                'op': 'GeneratorExp',
                'elt': self.lift(node.elt),
                'generators': self.lift(node.generators),
            }
        if cls == 'comprehension':
            return {
                'op': 'comprehension',
                'target': self.lift(node.target),
                'iter': self.lift(node.iter),
                'ifs': self.lift(node.ifs),
                'is_async': node.is_async,
            }

        if cls == 'JoinedStr':
            return {'op': 'JoinedStr', 'values': self.lift(node.values)}
        if cls == 'FormattedValue':
            return {
                'op': 'FormattedValue',
                'value': self.lift(node.value),
                'conversion': node.conversion,
                'format_spec': self.lift(node.format_spec),
            }

        if cls == 'Yield':
            return {'op': 'Yield', 'value': self.lift(node.value)}
        if cls == 'YieldFrom':
            return {'op': 'YieldFrom', 'value': self.lift(node.value)}
        if cls == 'Await':
            return {'op': 'Await', 'value': self.lift(node.value)}

        if cls == 'NamedExpr':
            return {
                'op': 'NamedExpr',
                'target': self.lift(node.target),
                'value': self.lift(node.value),
            }

        raise NotImplementedError(f"v5 lifter: unsupported AST node {cls}")


class _ImportManifestBuilder:
    def __init__(self):
        self.entries = []
        self._by_pair = {}
        self._used_ids = set()
        self._counter = 0

    def _next_id(self):
        while True:
            try:
                ident = int.from_bytes(os.urandom(4), 'little')
            except Exception:
                self._counter += 1
                ident = ((self._counter * 0x9E3779B1) ^ 0xA5A5A5A5) & 0xFFFFFFFF
            if ident not in self._used_ids:
                return ident

    def add(self, module_path, attr):
        key = (module_path, attr)
        if key in self._by_pair:
            return self._by_pair[key]
        ident = self._next_id()
        self._by_pair[key] = ident
        self._used_ids.add(ident)
        self.entries.append((ident, module_path, attr))
        return ident


def compile_to_ir(source):
    """Parse user Python source and emit a v5 IR dict.

    Returns:
        dict with keys:
          'tree'    — the lifted AST
          'strings' — list of all interned identifiers and string keys
          'consts'  — list of all interned constant values (Python objects)
    """
    tree = ast.parse(source, mode='exec')

    # v6 hardening: apply AST-level obfuscation transforms BEFORE lifting.
    # This converts control flow into state machines, decomposes expressions,
    # injects opaque predicates with dead code, unfolds constants into
    # arithmetic, and obfuscates string literals. The resulting AST is
    # semantically equivalent but structurally alien — the IR no longer maps
    # 1:1 back to the original Python.
    try:
        from transform_ast import transform_ast_tree
        tree = transform_ast_tree(tree)
    except ImportError:
        try:
            from lib.v5.transform_ast import transform_ast_tree
            tree = transform_ast_tree(tree)
        except ImportError:
            pass  # transforms not available (e.g. Pyodide without the module)

    lifter = _Lifter()
    lifted = lifter.lift(tree)
    return {
        'tree': lifted,
        'strings': lifter.strings,
        'consts': lifter.consts,
    }


def compile_to_json(source):
    """Return `(payload, manifest)` for the build pipeline.

    v5.2 shape change: the top-level container is a list, not a dict.
    Attack 12 (tests/pentest/attack12_v5_frame_walk.py) fingerprints the
    v5.1 IR shape by checking

        isinstance(v, dict) and {'tree','strings','consts'} <= v.keys()

    on every value in every `frame.f_locals` dict at every `return`
    event. Encoding the IR as a JSON list makes that `isinstance(dict)`
    check fail, so attack 12 can't capture the top-level container at
    all. (Individual AST nodes are still dicts with an 'op' key — a
    smarter attack could walk those, which is what the v5.2-era attack
    13 pentest does; see the README security section.)

    Constants that aren't naturally JSON-serialisable (bytes, complex,
    frozenset, ellipsis) get tagged so the runtime can rebuild them.
    The static-import manifest is returned alongside the payload so stage2
    can resolve imports into opaque `(id, value)` pairs before the
    interpreter marshal.loads event fires, without retaining plaintext
    module/attr names after stage2 completes.
    """
    ir = compile_to_ir(source)
    lowered_tree, manifest = _lower_to_code(ir['tree'], ir['strings'])
    # v8: consts now emitted positionally as lists, not dicts. Previous
    # `{'t': type, 'v': value}` shape gave attackers a stable structural
    # fingerprint they could match on every const wrapper. Positional
    # `[type, value]` collides with the shape of every other list in the
    # IR (AST-node argument lists, expression-tuple elements, etc.) so
    # there's nothing distinguishable at parse time.
    encoded_consts = []
    for v in ir['consts']:
        if v is None:
            encoded_consts.append(['none'])
        elif v is True:
            encoded_consts.append(['true'])
        elif v is False:
            encoded_consts.append(['false'])
        elif isinstance(v, int):
            encoded_consts.append(['int', str(v)])
        elif isinstance(v, float):
            encoded_consts.append(['float', repr(v)])
        elif isinstance(v, str):
            encoded_consts.append(['str', v])
        elif isinstance(v, bytes):
            encoded_consts.append(['bytes', list(v)])
        elif isinstance(v, complex):
            encoded_consts.append(['complex', repr(v.real), repr(v.imag)])
        elif v is Ellipsis:
            encoded_consts.append(['ellipsis'])
        elif isinstance(v, tuple):
            encoded_consts.append(['tuple', [_enc(x) for x in v]])
        elif isinstance(v, frozenset):
            encoded_consts.append(['frozenset', [_enc(x) for x in v]])
        else:
            raise NotImplementedError(f"unsupported constant type: {type(v).__name__}")
    return [ir['strings'], encoded_consts, lowered_tree], manifest


def _lower_to_code(module_node, strings):
    if not isinstance(module_node, dict) or module_node.get('op') != 'Module':
        raise ValueError('expected Module root')
    manifest = _ImportManifestBuilder()
    instrs = []
    for stmt in module_node['body']:
        instrs.extend(_lower_stmt_list(stmt, manifest, strings))
    return {'op': 'Code', 'instrs': instrs}, manifest.entries


def _lower_stmt_list(node, manifest, strings):
    op = node['op']
    if op == 'Expr':
        return [{'op': 'IExpr', 'value': node['value']}]
    if op == 'Assign':
        return [{'op': 'IAssign', 'targets': node['targets'], 'value': node['value']}]
    if op == 'AugAssign':
        return [{'op': 'IAugAssign', 'target': node['target'], 'op2': node['op2'], 'value': node['value']}]
    if op == 'AnnAssign':
        return [{
            'op': 'IAnnAssign',
            'target': node['target'],
            'annotation': node['annotation'],
            'value': node['value'],
            'simple': node['simple'],
        }]
    if op == 'Return':
        return [{'op': 'IReturn', 'value': node['value']}]
    if op == 'Raise':
        return [{'op': 'IRaise', 'exc': node['exc'], 'cause': node['cause']}]
    if op == 'Pass':
        return [{'op': 'IPass'}]
    if op == 'Break':
        return [{'op': 'IBreak'}]
    if op == 'Continue':
        return [{'op': 'IContinue'}]
    if op == 'Delete':
        return [{'op': 'IDelete', 'targets': node['targets']}]
    if op == 'Global':
        return [{'op': 'IGlobal', 'names': node['names']}]
    if op == 'Nonlocal':
        return [{'op': 'INonlocal', 'names': node['names']}]
    if op == 'If':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        orelse = []
        for stmt in node['orelse']:
            orelse.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'IIf',
            'test': node['test'],
            'body': {'op': 'Code', 'instrs': body},
            'orelse': {'op': 'Code', 'instrs': orelse},
        }]
    if op == 'While':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        orelse = []
        for stmt in node['orelse']:
            orelse.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'IWhile',
            'test': node['test'],
            'body': {'op': 'Code', 'instrs': body},
            'orelse': {'op': 'Code', 'instrs': orelse},
        }]
    if op == 'For':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        orelse = []
        for stmt in node['orelse']:
            orelse.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'IFor',
            'target': node['target'],
            'iter': node['iter'],
            'body': {'op': 'Code', 'instrs': body},
            'orelse': {'op': 'Code', 'instrs': orelse},
        }]
    if op == 'AsyncFor':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        orelse = []
        for stmt in node['orelse']:
            orelse.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'IAsyncFor',
            'target': node['target'],
            'iter': node['iter'],
            'body': {'op': 'Code', 'instrs': body},
            'orelse': {'op': 'Code', 'instrs': orelse},
        }]
    if op == 'With':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'IWith',
            'items': node['items'],
            'body': {'op': 'Code', 'instrs': body},
        }]
    if op == 'AsyncWith':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'IAsyncWith',
            'items': node['items'],
            'body': {'op': 'Code', 'instrs': body},
        }]
    if op == 'Try':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        orelse = []
        for stmt in node['orelse']:
            orelse.extend(_lower_stmt_list(stmt, manifest, strings))
        finalbody = []
        for stmt in node['finalbody']:
            finalbody.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'ITry',
            'body': {'op': 'Code', 'instrs': body},
            'handlers': [_lower_handler(h, manifest, strings) for h in node['handlers']],
            'orelse': {'op': 'Code', 'instrs': orelse},
            'finalbody': {'op': 'Code', 'instrs': finalbody},
        }]
    if op == 'Import':
        binds = []
        ids = []
        fallback = []
        for alias in node['names']:
            name = alias['name']
            asname = alias['asname']
            mod_name = None if name is None or name < 0 else strings[name]
            bind_name = asname if asname is not None and asname >= 0 else name
            if mod_name and ('.' not in mod_name or (asname is not None and asname >= 0)):
                binds.append(bind_name)
                ids.append(manifest.add(mod_name, None))
            else:
                fallback.append(alias)
        out = []
        if binds:
            out.append({'op': 'IImportLookup', 'binds': binds, 'ids': ids})
        if fallback:
            out.append({'op': 'IImport', 'names': fallback})
        return out
    if op == 'ImportFrom':
        module = node['module']
        module_name = None if module is None or module < 0 else strings[module]
        level = node['level']
        if level or not module_name or any(
            (alias['name'] is None or alias['name'] < 0 or strings[alias['name']] == '*')
            for alias in node['names']
        ):
            return [{
                'op': 'IImportFrom',
                'module': node['module'],
                'names': node['names'],
                'level': node['level'],
            }]
        binds = []
        ids = []
        for alias in node['names']:
            name = strings[alias['name']]
            bind = alias['asname'] if alias['asname'] is not None and alias['asname'] >= 0 else alias['name']
            binds.append(bind)
            ids.append(manifest.add(module_name, name))
        return [{'op': 'IImportLookup', 'binds': binds, 'ids': ids}]
    if op == 'FunctionDef':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'IFunctionDef',
            'name': node['name'],
            'args': node['args'],
            'body': {'op': 'Code', 'instrs': body},
            'decorator_list': node['decorator_list'],
            'returns': node['returns'],
            'is_async': False,
            'is_gen': _contains_yield_tree(node['body']),
        }]
    if op == 'AsyncFunctionDef':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'IFunctionDef',
            'name': node['name'],
            'args': node['args'],
            'body': {'op': 'Code', 'instrs': body},
            'decorator_list': node['decorator_list'],
            'returns': node['returns'],
            'is_async': True,
            'is_gen': False,
        }]
    if op == 'ClassDef':
        body = []
        for stmt in node['body']:
            body.extend(_lower_stmt_list(stmt, manifest, strings))
        return [{
            'op': 'IClassDef',
            'name': node['name'],
            'bases': node['bases'],
            'keywords': node['keywords'],
            'body': {'op': 'Code', 'instrs': body},
            'decorator_list': node['decorator_list'],
        }]
    raise NotImplementedError(f"statement lowering unsupported: {op}")


def _lower_handler(node, manifest, strings):
    body = []
    for stmt in node['body']:
        body.extend(_lower_stmt_list(stmt, manifest, strings))
    return {
        'op': 'IHandler',
        'type': node['type'],
        'name': node['name'],
        'body': {'op': 'Code', 'instrs': body},
    }


def _contains_yield_tree(node):
    if isinstance(node, list):
        for x in node:
            if _contains_yield_tree(x):
                return True
        return False
    if not isinstance(node, dict):
        return False
    op = node.get('op')
    if op in ('FunctionDef', 'AsyncFunctionDef', 'Lambda', 'ClassDef', 'IFunctionDef', 'IClassDef'):
        return False
    if op in ('Yield', 'YieldFrom'):
        return True
    for k, v in node.items():
        if k == 'op':
            continue
        if _contains_yield_tree(v):
            return True
    return False


_CONST_TAGS = frozenset((
    'none', 'true', 'false', 'int', 'float', 'str',
    'bytes', 'complex', 'ellipsis', 'tuple', 'frozenset',
))


def _apply_schema(obj, key_map, tag_map):
    if isinstance(obj, list):
        # v8: const wrappers are now positional lists `[tag, *values]` (was
        # dicts with 't' key). Tag-map the leading element when it looks
        # like a const tag. The check `obj[0] in _CONST_TAGS` is safe — no
        # other list at this build stage starts with one of those strings
        # (AST nodes are still dicts; the IR is _to_positional'd later).
        if obj and isinstance(obj[0], str) and obj[0] in _CONST_TAGS:
            new_tag = tag_map.get(obj[0], obj[0])
            return [new_tag] + [_apply_schema(x, key_map, tag_map) for x in obj[1:]]
        return [_apply_schema(x, key_map, tag_map) for x in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nk = key_map.get(k, k)
            nv = _apply_schema(v, key_map, tag_map)
            if k in ('op', 'op2', 'ctx') and isinstance(nv, str):
                nv = tag_map.get(nv, nv)
            out[nk] = nv
        return out
    return obj


def _schema_parts(schema_json):
    if not schema_json:
        return {}, {}, None, {}
    if isinstance(schema_json, str):
        schema = json.loads(schema_json)
    else:
        schema = schema_json
    return (
        dict(schema.get('keys', {})),
        dict(schema.get('tags', {})),
        schema.get('mask'),
        dict(schema.get('layouts', {})),
    )


def _schema_bin_parts(schema_json):
    """Extract binKey (as a 64-bit int) and noiseSchedule from the schema."""
    if not schema_json:
        return None, []
    if isinstance(schema_json, str):
        schema = json.loads(schema_json)
    else:
        schema = schema_json
    bin_key_pair = schema.get('binKey')
    if bin_key_pair is not None:
        lo, hi = bin_key_pair
        bin_key = (lo & 0xFFFFFFFF) | ((hi & 0xFFFFFFFF) << 32)
    else:
        bin_key = None
    noise_schedule = schema.get('noiseSchedule', [])
    return bin_key, noise_schedule


def _mask_text(s, mask):
    if not mask:
        return s
    b = s.encode('utf-8')
    return [(x ^ mask[i % len(mask)]) for i, x in enumerate(b)]


def _mask_payload(payload, mask):
    if not mask:
        return payload
    strings, consts, tree = payload

    def _mask_const(c):
        # v8: consts are positional lists `[tag, *values]`. When tag == 'str',
        # the value at index 1 is a Python str — mask its bytes. Otherwise
        # recurse into nested const lists (tuple/frozenset wrappers).
        if isinstance(c, list):
            if c and c[0] == 'str' and len(c) >= 2 and isinstance(c[1], str):
                return [c[0], _mask_text(c[1], mask)] + [_mask_const(x) for x in c[2:]]
            return [_mask_const(x) for x in c]
        return c

    return [[_mask_text(s, mask) for s in strings], [_mask_const(c) for c in consts], tree]


def _pack_u32(n):
    return bytes((
        n & 0xFF,
        (n >> 8) & 0xFF,
        (n >> 16) & 0xFF,
        (n >> 24) & 0xFF,
    ))


def _pack_obj(obj):
    if obj is None:
        return b'n'
    if obj is True:
        return b't'
    if obj is False:
        return b'f'
    if isinstance(obj, int):
        b = str(obj).encode('utf-8')
        return b'i' + _pack_u32(len(b)) + b
    if isinstance(obj, float):
        b = repr(obj).encode('utf-8')
        return b'r' + _pack_u32(len(b)) + b
    if isinstance(obj, str):
        b = obj.encode('utf-8')
        return b's' + _pack_u32(len(b)) + b
    if isinstance(obj, (list, tuple)):
        parts = [b'l', _pack_u32(len(obj))]
        for x in obj:
            parts.append(_pack_obj(x))
        return b''.join(parts)
    if isinstance(obj, dict):
        parts = [b'm', _pack_u32(len(obj))]
        for k, v in obj.items():
            kb = k.encode('utf-8')
            parts.append(_pack_u32(len(kb)))
            parts.append(kb)
            parts.append(_pack_obj(v))
        return b''.join(parts)
    raise NotImplementedError(f"unsupported packed type: {type(obj).__name__}")


_NODE_LAYOUTS = {
    'Code': ('instrs',),
    'IExpr': ('value',),
    'IAssign': ('targets', 'value'),
    'IAugAssign': ('target', 'op2', 'value'),
    'IAnnAssign': ('target', 'annotation', 'value', 'simple'),
    'IReturn': ('value',),
    'IRaise': ('exc', 'cause'),
    'IPass': (),
    'IBreak': (),
    'IContinue': (),
    'IDelete': ('targets',),
    'IGlobal': ('names',),
    'INonlocal': ('names',),
    'IIf': ('test', 'body', 'orelse'),
    'IWhile': ('test', 'body', 'orelse'),
    'IFor': ('target', 'iter', 'body', 'orelse'),
    'IAsyncFor': ('target', 'iter', 'body', 'orelse'),
    'IWith': ('items', 'body'),
    'IAsyncWith': ('items', 'body'),
    'ITry': ('body', 'handlers', 'orelse', 'finalbody'),
    'IHandler': ('type', 'name', 'body'),
    'IImportLookup': ('binds', 'ids'),
    'IImport': ('names',),
    'IImportFrom': ('module', 'names', 'level'),
    'IFunctionDef': ('name', 'args', 'body', 'decorator_list', 'returns', 'is_async', 'is_gen'),
    'IClassDef': ('name', 'bases', 'keywords', 'body', 'decorator_list'),
    'Module': ('body',),
    'Expr': ('value',),
    'Assign': ('targets', 'value'),
    'AugAssign': ('target', 'op2', 'value'),
    'AnnAssign': ('target', 'annotation', 'value', 'simple'),
    'Return': ('value',),
    'Raise': ('exc', 'cause'),
    'Pass': (),
    'Break': (),
    'Continue': (),
    'Delete': ('targets',),
    'Global': ('names',),
    'Nonlocal': ('names',),
    'If': ('test', 'body', 'orelse'),
    'While': ('test', 'body', 'orelse'),
    'For': ('target', 'iter', 'body', 'orelse'),
    'AsyncFor': ('target', 'iter', 'body', 'orelse'),
    'With': ('items', 'body'),
    'AsyncWith': ('items', 'body'),
    'withitem': ('context_expr', 'optional_vars'),
    'Try': ('body', 'handlers', 'orelse', 'finalbody'),
    'ExceptHandler': ('type', 'name', 'body'),
    'Import': ('names',),
    'ImportFrom': ('module', 'names', 'level'),
    'alias': ('name', 'asname'),
    'FunctionDef': ('name', 'args', 'body', 'decorator_list', 'returns'),
    'AsyncFunctionDef': ('name', 'args', 'body', 'decorator_list', 'returns'),
    'ClassDef': ('name', 'bases', 'keywords', 'body', 'decorator_list'),
    'Lambda': ('args', 'body'),
    'arguments': ('posonlyargs', 'args', 'vararg', 'kwonlyargs', 'kw_defaults', 'kwarg', 'defaults'),
    'arg': ('arg', 'annotation'),
    'keyword': ('arg', 'value'),
    'Name': ('id', 'ctx'),
    'Constant': ('idx',),
    'BinOp': ('left', 'op2', 'right'),
    'UnaryOp': ('op2', 'operand'),
    'BoolOp': ('op2', 'values'),
    'Compare': ('left', 'ops', 'comparators'),
    'IfExp': ('test', 'body', 'orelse'),
    'Call': ('func', 'args', 'keywords'),
    'Attribute': ('value', 'attr', 'ctx'),
    'Subscript': ('value', 'slice', 'ctx'),
    'Slice': ('lower', 'upper', 'step'),
    'Starred': ('value', 'ctx'),
    'List': ('elts', 'ctx'),
    'Tuple': ('elts', 'ctx'),
    'Set': ('elts',),
    'Dict': ('keys', 'values'),
    'ListComp': ('elt', 'generators'),
    'SetComp': ('elt', 'generators'),
    'DictComp': ('key', 'value', 'generators'),
    'GeneratorExp': ('elt', 'generators'),
    'comprehension': ('target', 'iter', 'ifs', 'is_async'),
    'JoinedStr': ('values',),
    'FormattedValue': ('value', 'conversion', 'format_spec'),
    'Yield': ('value',),
    'YieldFrom': ('value',),
    'Await': ('value',),
    'NamedExpr': ('target', 'value'),
}


def _to_positional(obj, key_map, rev_tag_map, layouts=None):
    layouts = layouts or {}
    if isinstance(obj, list):
        return [_to_positional(x, key_map, rev_tag_map, layouts) for x in obj]
    if isinstance(obj, dict):
        op_key = key_map.get('op', 'op')
        if op_key in obj:
            op_val = obj[op_key]
            canon_op = rev_tag_map.get(op_val, op_val)
            layout = tuple(layouts.get(canon_op, _NODE_LAYOUTS.get(canon_op, ())))
            if layout is not None:
                return tuple([op_val] + [
                    _to_positional(obj[key_map.get(field, field)], key_map, rev_tag_map, layouts)
                    for field in layout
                ])
        return {
            k: _to_positional(v, key_map, rev_tag_map, layouts)
            for k, v in obj.items()
        }
    return obj


def _rolling_xor(data, seed):
    """Apply rolling XOR using an LCG-derived byte stream. Self-inverse."""
    _MULT = 6364136223846793005
    _INC = 1442695040888963407
    _MASK64 = (1 << 64) - 1
    out = bytearray(len(data))
    key = seed & _MASK64
    for i in range(len(data)):
        key = (key * _MULT + _INC) & _MASK64
        out[i] = data[i] ^ ((key >> 32) & 0xFF)
    return bytes(out)


def _inject_noise(data, noise_schedule):
    """Insert random noise bytes at positions derived from the noise schedule.

    Each entry in *noise_schedule* is ``(position, length)``. The *position*
    is taken modulo ``(len(data) + 1)`` so it always falls within range.
    Entries are processed in order; each insertion shifts subsequent positions
    so the schedule is applied left-to-right on the growing buffer.
    """
    import os as _nos
    buf = bytearray(data)
    offset = 0                          # cumulative shift from earlier insertions
    for pos, length in noise_schedule:
        actual = (pos % (len(buf) + 1))  # clamp into current buffer length
        noise = _nos.urandom(length)
        buf[actual:actual] = noise
        offset += length
    return bytes(buf)


def compile_to_compressed_bytes(source, schema_json=None):
    """Return the IR as zlib-deflated (raw, -15 wbits) JSON bytes.

    This is the form the TS obfuscator encrypts. Compressing here saves
    a JS-side zlib dependency: Python (Pyodide or subprocess) always has
    zlib in the stdlib, and the TS layer treats the bytes as opaque.

    The encoded IR uses a small custom binary container rather than JSON.
    That removes readable structure from the decrypted payload and avoids
    handing attackers a plaintext AST-ish blob if they intercept it.

    v5.4 hardening: the packed binary blob is encrypted with a rolling XOR
    (LCG-derived keystream) and then has random noise bytes injected at
    positions determined by the schema's noise schedule. The XOR seed and
    noise schedule are embedded in the encrypted schema, so an attacker
    must first decrypt the schema to learn them.
    """
    import zlib
    payload, _manifest = compile_to_json(source)
    key_map, tag_map, mask, layouts = _schema_parts(schema_json)
    payload = _mask_payload(payload, mask)
    if key_map or tag_map:
        payload = _apply_schema(payload, key_map, tag_map)
    payload = _to_positional(payload, key_map, {v: k for k, v in tag_map.items()}, layouts)
    packed = _pack_obj(payload)

    # --- rolling XOR + noise injection (v5.4) ---
    bin_key, noise_schedule = _schema_bin_parts(schema_json)
    if bin_key is not None:
        packed = _rolling_xor(packed, bin_key)
    if noise_schedule:
        packed = _inject_noise(packed, noise_schedule)

    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(packed) + co.flush()


def _pack_manifest(entries):
    buf = bytearray()
    buf.extend(len(entries).to_bytes(4, 'little'))
    for ident, module_path, attr in entries:
        mb = module_path.encode('utf-8')
        if len(mb) > 0xFFFF:
            raise ValueError('manifest module path too long')
        buf.extend((ident & 0xFFFFFFFF).to_bytes(4, 'little'))
        buf.extend(len(mb).to_bytes(2, 'little'))
        buf.extend(mb)
        if attr is None:
            buf.extend((0xFFFF).to_bytes(2, 'little'))
        else:
            ab = attr.encode('utf-8')
            if len(ab) > 0xFFFF:
                raise ValueError('manifest attr too long')
            buf.extend(len(ab).to_bytes(2, 'little'))
            buf.extend(ab)
    return bytes(buf)


def compile_to_artifacts(source, schema_json=None):
    import zlib

    payload, manifest = compile_to_json(source)
    key_map, tag_map, mask, layouts = _schema_parts(schema_json)
    payload = _mask_payload(payload, mask)
    if key_map or tag_map:
        payload = _apply_schema(payload, key_map, tag_map)
    payload = _to_positional(payload, key_map, {v: k for k, v in tag_map.items()}, layouts)
    packed = _pack_obj(payload)

    bin_key, noise_schedule = _schema_bin_parts(schema_json)
    if bin_key is not None:
        packed = _rolling_xor(packed, bin_key)
    if noise_schedule:
        packed = _inject_noise(packed, noise_schedule)

    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    compressed = co.compress(packed) + co.flush()

    mo = zlib.compressobj(9, zlib.DEFLATED, -15)
    manifest_bytes = _pack_manifest(manifest)
    manifest_compressed = mo.compress(manifest_bytes) + mo.flush()
    return {
        'compressed': compressed,
        'manifest': manifest_compressed,
    }


def _enc(v):
    """Inline encoder for nested constants inside tuples/frozensets.

    v8: positional list form (matches outer encoder in compile_to_json).
    """
    if v is None: return ['none']
    if v is True: return ['true']
    if v is False: return ['false']
    if isinstance(v, int): return ['int', str(v)]
    if isinstance(v, float): return ['float', repr(v)]
    if isinstance(v, str): return ['str', v]
    if isinstance(v, bytes): return ['bytes', list(v)]
    if v is Ellipsis: return ['ellipsis']
    if isinstance(v, tuple): return ['tuple', [_enc(x) for x in v]]
    if isinstance(v, frozenset): return ['frozenset', [_enc(x) for x in v]]
    raise NotImplementedError(f"unsupported nested constant: {type(v).__name__}")


_MARSHAL_TAG = b'PGM1'


def compile_and_marshal(source, filename='<pg>'):
    import marshal
    import sys

    code = compile(source, filename, 'exec')
    tag = _MARSHAL_TAG + bytes([
        sys.version_info.major & 0xFF,
        sys.version_info.minor & 0xFF,
    ])
    return tag + marshal.dumps(code)


# Self-test entry point — used by the build drivers.
#
# Default mode reads Python source from stdin and writes the zlib-compressed
# IR artifacts to stdout as JSON so the TS layer can pipe them straight into
# encryption. `PYGUARD_MODE=marshal` instead emits a tagged marshal blob for
# stage1 / stage2 / interpreter packaging. The 6-byte header lets the runtime
# fail closed on Python-version mismatch before calling marshal.loads.
if __name__ == '__main__':
    import base64
    import sys

    src = sys.stdin.read()
    mode = os.environ.get('PYGUARD_MODE', 'ir')
    if mode == 'marshal':
        blob = compile_and_marshal(src, os.environ.get('PYGUARD_FILENAME', '<pg>'))
        sys.stdout.write(base64.b64encode(blob).decode('ascii'))
    else:
        arts = compile_to_artifacts(src, os.environ.get('PYGUARD_V5_SCHEMA'))
        sys.stdout.write(json.dumps({
            'compressed': base64.b64encode(arts['compressed']).decode('ascii'),
            'manifest': base64.b64encode(arts['manifest']).decode('ascii'),
        }))

"""PyGuard v5 runtime AST-walking interpreter.

Embedded into v5 obfuscated stubs. Takes a v5 IR dict (tree + strings + consts)
and executes the program WITHOUT ever calling compile() or exec() on user code.

This is the only architecture that defends against PEP 578 audit-hook attacks
on a pure-Python self-decoding obfuscator: there is never a moment at which
user source materializes as a code object or a string fed to compile().

Stdlib-only. Compatible with Python 3.8+.
"""

import builtins
import sys


# --- sentinel exceptions used for control flow ---------------------------

class _Return(BaseException):
    __slots__ = ('value',)
    def __init__(self, value=None):
        self.value = value


class _Break(BaseException):
    pass


class _Continue(BaseException):
    pass


_MISSING = object()

# Internal schema storage — populated by run_blob(), not accessible as
# _PG_* globals (those are wiped after copying to prevent frame-walk extraction).
_S_K = {}   # keys mapping
_S_RT = {}  # reverse tags
_S_M = b''  # XOR mask
_S_L = {}   # field layouts


def _pg_key(key):
    return _S_K.get(key, key)


def _pg_tag(tag):
    return _S_RT.get(tag, tag)


def _pg_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        mask = _S_M
        if not mask:
            return ''.join(chr(x) for x in value)
        buf = bytearray(len(value))
        for i, b in enumerate(value):
            buf[i] = b ^ mask[i % len(mask)]
        return bytes(buf).decode('utf-8')
    return value


_NODE_POS = {
    'Code': {'instrs': 1},
    'IExpr': {'value': 1},
    'IAssign': {'targets': 1, 'value': 2},
    'IAugAssign': {'target': 1, 'op2': 2, 'value': 3},
    'IAnnAssign': {'target': 1, 'annotation': 2, 'value': 3, 'simple': 4},
    'IReturn': {'value': 1},
    'IRaise': {'exc': 1, 'cause': 2},
    'IPass': {},
    'IBreak': {},
    'IContinue': {},
    'IDelete': {'targets': 1},
    'IGlobal': {'names': 1},
    'INonlocal': {'names': 1},
    'IIf': {'test': 1, 'body': 2, 'orelse': 3},
    'IWhile': {'test': 1, 'body': 2, 'orelse': 3},
    'IFor': {'target': 1, 'iter': 2, 'body': 3, 'orelse': 4},
    'IAsyncFor': {'target': 1, 'iter': 2, 'body': 3, 'orelse': 4},
    'IWith': {'items': 1, 'body': 2},
    'IAsyncWith': {'items': 1, 'body': 2},
    'ITry': {'body': 1, 'handlers': 2, 'orelse': 3, 'finalbody': 4},
    'IHandler': {'type': 1, 'name': 2, 'body': 3},
    'IImport': {'names': 1},
    'IImportFrom': {'module': 1, 'names': 2, 'level': 3},
    'IFunctionDef': {'name': 1, 'args': 2, 'body': 3, 'decorator_list': 4, 'returns': 5, 'is_async': 6, 'is_gen': 7},
    'IClassDef': {'name': 1, 'bases': 2, 'keywords': 3, 'body': 4, 'decorator_list': 5},
    'Module': {'body': 1},
    'Expr': {'value': 1},
    'Assign': {'targets': 1, 'value': 2},
    'AugAssign': {'target': 1, 'op2': 2, 'value': 3},
    'AnnAssign': {'target': 1, 'annotation': 2, 'value': 3, 'simple': 4},
    'Return': {'value': 1},
    'Raise': {'exc': 1, 'cause': 2},
    'Pass': {},
    'Break': {},
    'Continue': {},
    'Delete': {'targets': 1},
    'Global': {'names': 1},
    'Nonlocal': {'names': 1},
    'If': {'test': 1, 'body': 2, 'orelse': 3},
    'While': {'test': 1, 'body': 2, 'orelse': 3},
    'For': {'target': 1, 'iter': 2, 'body': 3, 'orelse': 4},
    'AsyncFor': {'target': 1, 'iter': 2, 'body': 3, 'orelse': 4},
    'With': {'items': 1, 'body': 2},
    'AsyncWith': {'items': 1, 'body': 2},
    'withitem': {'context_expr': 1, 'optional_vars': 2},
    'Try': {'body': 1, 'handlers': 2, 'orelse': 3, 'finalbody': 4},
    'ExceptHandler': {'type': 1, 'name': 2, 'body': 3},
    'Import': {'names': 1},
    'ImportFrom': {'module': 1, 'names': 2, 'level': 3},
    'alias': {'name': 1, 'asname': 2},
    'FunctionDef': {'name': 1, 'args': 2, 'body': 3, 'decorator_list': 4, 'returns': 5},
    'AsyncFunctionDef': {'name': 1, 'args': 2, 'body': 3, 'decorator_list': 4, 'returns': 5},
    'ClassDef': {'name': 1, 'bases': 2, 'keywords': 3, 'body': 4, 'decorator_list': 5},
    'Lambda': {'args': 1, 'body': 2},
    'arguments': {'posonlyargs': 1, 'args': 2, 'vararg': 3, 'kwonlyargs': 4, 'kw_defaults': 5, 'kwarg': 6, 'defaults': 7},
    'arg': {'arg': 1, 'annotation': 2},
    'keyword': {'arg': 1, 'value': 2},
    'Name': {'id': 1, 'ctx': 2},
    'Constant': {'idx': 1},
    'BinOp': {'left': 1, 'op2': 2, 'right': 3},
    'UnaryOp': {'op2': 1, 'operand': 2},
    'BoolOp': {'op2': 1, 'values': 2},
    'Compare': {'left': 1, 'ops': 2, 'comparators': 3},
    'IfExp': {'test': 1, 'body': 2, 'orelse': 3},
    'Call': {'func': 1, 'args': 2, 'keywords': 3},
    'Attribute': {'value': 1, 'attr': 2, 'ctx': 3},
    'Subscript': {'value': 1, 'slice': 2, 'ctx': 3},
    'Slice': {'lower': 1, 'upper': 2, 'step': 3},
    'Starred': {'value': 1, 'ctx': 2},
    'List': {'elts': 1, 'ctx': 2},
    'Tuple': {'elts': 1, 'ctx': 2},
    'Set': {'elts': 1},
    'Dict': {'keys': 1, 'values': 2},
    'ListComp': {'elt': 1, 'generators': 2},
    'SetComp': {'elt': 1, 'generators': 2},
    'DictComp': {'key': 1, 'value': 2, 'generators': 3},
    'GeneratorExp': {'elt': 1, 'generators': 2},
    'comprehension': {'target': 1, 'iter': 2, 'ifs': 3, 'is_async': 4},
    'JoinedStr': {'values': 1},
    'FormattedValue': {'value': 1, 'conversion': 2, 'format_spec': 3},
    'Yield': {'value': 1},
    'YieldFrom': {'value': 1},
    'Await': {'value': 1},
    'NamedExpr': {'target': 1, 'value': 2},
}


def _nf(node, field, default=_MISSING):
    if not isinstance(node, tuple) or not node:
        if default is not _MISSING:
            return default
        raise KeyError(field)
    canon_op = _pg_tag(node[0])
    pos = _S_L.get(canon_op, {}).get(field, _MISSING)
    if pos is _MISSING:
        pos = _NODE_POS.get(canon_op, {}).get(field, _MISSING)
    if pos is _MISSING:
        if default is not _MISSING:
            return default
        raise KeyError(field)
    if pos >= len(node):
        if default is not _MISSING:
            return default
        raise KeyError(field)
    return node[pos]


# No _PGMap wrapper class: a class with __slots__ == ('_k', '_v') would
# be a single unique fingerprint an attacker could locate and patch to
# dump every materialized map (schema, layouts, IR map-nodes, const
# wrappers, …). Call sites construct dict(items) inline; the const wire
# format is positional (t, v) tuples (see _decode_const), so the only
# dict that exists at parse time is the transient schema map, and even
# that is replaced in step D by a positional binary schema parser inside
# _pg_boot's frame (no dict ever materializes).


# --- operator dispatch ---------------------------------------------------
#
# Op dispatch is inlined at each call site. Module-level dicts would
# centralize a hook point (`runtime_interp._CMP_OPS['Eq'] = sniff` would
# intercept every compare in one line); with the tables gone, each of the
# five call sites performs its own if/elif chain on the op tag. No single
# observable symbol intercepts every compare or every binary op.


# --- scope ---------------------------------------------------------------

class Scope:
    """Lexical scope. Chains via parent. Module scope has vars==globals."""

    __slots__ = ('vars', 'parent', 'globals', 'global_names',
                 'nonlocal_names', 'is_module')

    def __init__(self, parent=None, globals_=None, is_module=False):
        self.parent = parent
        if globals_ is not None:
            self.globals = globals_
        elif parent is not None:
            self.globals = parent.globals
        else:
            self.globals = {}
        if is_module:
            self.vars = self.globals
        else:
            self.vars = {}
        self.global_names = set()
        self.nonlocal_names = set()
        self.is_module = is_module

    def get(self, name):
        if name in self.global_names:
            if name in self.globals:
                return self.globals[name]
            try:
                return getattr(builtins, name)
            except AttributeError:
                raise NameError(name)
        if name in self.nonlocal_names:
            p = self.parent
            while p is not None:
                if not p.is_module and name in p.vars:
                    return p.vars[name]
                p = p.parent
            raise NameError(name)
        if name in self.vars:
            return self.vars[name]
        p = self.parent
        while p is not None:
            if name in p.vars:
                return p.vars[name]
            p = p.parent
        if name in self.globals:
            return self.globals[name]
        try:
            return getattr(builtins, name)
        except AttributeError:
            raise NameError(name)

    def set(self, name, value):
        if name in self.global_names:
            self.globals[name] = value
            return
        if name in self.nonlocal_names:
            p = self.parent
            while p is not None:
                if not p.is_module and name in p.vars:
                    p.vars[name] = value
                    return
                p = p.parent
            raise NameError(name)
        self.vars[name] = value

    def delete(self, name):
        if name in self.global_names:
            del self.globals[name]
            return
        if name in self.vars:
            del self.vars[name]
            return
        raise NameError(name)


# --- user function -------------------------------------------------------

class _UFunction:
    """A user-defined function. Acts as a regular Python callable."""

    def __init__(self, interp, name, args_def, body, defining_scope,
                 is_gen, is_async, defaults, kw_defaults):
        self._interp = interp
        self.__name__ = name
        self.__qualname__ = name
        self.__module__ = '__main__'
        self.__doc__ = None
        self.__annotations__ = {}
        self.args_def = args_def
        self.body = body
        self.defining_scope = defining_scope
        self.is_gen = is_gen
        self.is_async = is_async
        self.defaults = defaults
        self.kw_defaults = kw_defaults
        self.defining_class = None  # patched after class build for super()

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return _BoundMethod(self, instance)

    def __call__(self, *args, **kwargs):
        return self._interp.call_user_function(self, args, kwargs)

    def __repr__(self):
        return "<function {} at 0x{:x}>".format(self.__name__, id(self))


class _BoundMethod:
    __slots__ = ('__func__', '__self__')

    def __init__(self, func, instance):
        self.__func__ = func
        self.__self__ = instance

    def __call__(self, *args, **kwargs):
        return self.__func__(self.__self__, *args, **kwargs)

    def __getattr__(self, item):
        return getattr(self.__func__, item)

    def __repr__(self):
        return "<bound method {} of {!r}>".format(
            self.__func__.__name__, self.__self__)


# --- driver helpers ------------------------------------------------------

def _drive_sync(gen):
    """Drive a step-generator that should not yield events (sync context)."""
    try:
        evt = next(gen)
    except StopIteration as si:
        return si.value
    raise RuntimeError("yield/await outside generator/coroutine: " + repr(evt))


# --- interpreter ---------------------------------------------------------

class Interp:
    """Holds an opaque accessor closure instead of plain strings/consts
    tuples. Callers build `(_a)` where `_a(kind, idx)` is a closure holding
    the encrypted/masked tables. The strings/consts never live as instance
    attributes — only inside the closure cells of `_a`, which are not
    addressable without first locating `_a` itself (and `_a` is a vanilla
    function with no stable name across builds).
    """

    def __init__(self, *_args):
        # Vararg signature: `co_argcount == 1` (self), indistinguishable
        # from dozens of other methods. A fixed-arity signature like
        # `__init__(self, _a, _decoy_a=None, _decoy_b=None, _decoy_c=None)`
        # gives `co_argcount == 5` — a structural fingerprint that locates
        # the Interp class regardless of name obfuscation.
        #
        # `_args[0]` MUST be the accessor closure `_a`. Remaining entries
        # are decoys (ignored).
        if not _args:
            raise TypeError("Interp: missing accessor")
        # `_a(0, idx)` returns raw (possibly mask-encoded) strings table entry.
        # `_a(1, idx)` returns the decoded const table entry.
        self._a = _args[0]
        self._str_cache = {}

    def s(self, idx):
        if idx is None or idx < 0:
            return None
        if idx in self._str_cache:
            return self._str_cache[idx]
        v = _pg_text(self._a(0, idx))
        self._str_cache[idx] = v
        return v

    def k(self, idx):
        return self._a(1, idx)

    # ---- entry point ----

    def run(self, tree, module_name='__main__'):
        # Each user call goes through several Python frames in our step
        # generators, so the host limit must be raised proportionally.
        try:
            cur = sys.getrecursionlimit()
            if cur < 50000:
                sys.setrecursionlimit(50000)
        except Exception:
            pass
        glob = {
            '__name__': module_name,
            '__builtins__': builtins,
            '__doc__': None,
            '__annotations__': {},
            '__package__': None,
        }
        scope = Scope(globals_=glob, is_module=True)
        try:
            if isinstance(tree, tuple) and tree and _pg_tag(tree[0]) == 'Code':
                _drive_sync(self.exec_code(tree, scope))
            else:
                _drive_sync(self.step_block(_nf(tree, 'body'), scope))
        except _Return:
            pass

    # ---- statement stepper (generator-of-events) ----

    def step_block(self, body, scope):
        if False:
            yield  # mark as generator
        for stmt in body:
            yield from self.step_stmt(stmt, scope)

    def exec_code(self, code, scope):
        if False:
            yield
        if isinstance(code, tuple) and code and _pg_tag(code[0]) == 'Code':
            for inst in _nf(code, 'instrs'):
                yield from self.step_inst(inst, scope)
            return
        yield from self.step_block(code, scope)

    def _exec_body(self, body, scope):
        if False:
            yield
        if isinstance(body, tuple) and body and _pg_tag(body[0]) == 'Code':
            yield from self.exec_code(body, scope)
            return
        yield from self.step_block(body, scope)

    def step_inst(self, node, scope):
        if False:
            yield
        op = _pg_tag(node[0])

        if op == 'IPass':
            return

        if op == 'IExpr':
            yield from self.step_expr(_nf(node, 'value'), scope)
            return

        if op == 'IReturn':
            v = None
            value = _nf(node, 'value')
            if value is not None:
                v = yield from self.step_expr(value, scope)
            raise _Return(v)

        if op == 'IRaise':
            exc = None
            cause = None
            exc_node = _nf(node, 'exc')
            cause_node = _nf(node, 'cause')
            if exc_node is not None:
                exc = yield from self.step_expr(exc_node, scope)
            if cause_node is not None:
                cause = yield from self.step_expr(cause_node, scope)
            if exc is None:
                raise
            if cause is not None:
                raise exc from cause
            raise exc

        if op == 'IBreak':
            raise _Break()

        if op == 'IContinue':
            raise _Continue()

        if op == 'IDelete':
            for tgt in _nf(node, 'targets'):
                yield from self._delete(tgt, scope)
            return

        if op == 'IGlobal':
            for n in _nf(node, 'names'):
                scope.global_names.add(self.s(n))
            return

        if op == 'INonlocal':
            for n in _nf(node, 'names'):
                scope.nonlocal_names.add(self.s(n))
            return

        if op == 'IAssign':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            for tgt in _nf(node, 'targets'):
                yield from self._assign(tgt, v, scope)
            return

        if op == 'IAugAssign':
            tgt = _nf(node, 'target')
            cur = yield from self._load_target(tgt, scope)
            inc = yield from self.step_expr(_nf(node, 'value'), scope)
            _ot = _pg_tag(_nf(node, 'op2'))
            if   _ot == 'Add':      new_v = cur + inc
            elif _ot == 'Sub':      new_v = cur - inc
            elif _ot == 'Mult':     new_v = cur * inc
            elif _ot == 'FloorDiv': new_v = cur // inc
            elif _ot == 'Div':      new_v = cur / inc
            elif _ot == 'Mod':      new_v = cur % inc
            elif _ot == 'Pow':      new_v = cur ** inc
            elif _ot == 'BitOr':    new_v = cur | inc
            elif _ot == 'BitXor':   new_v = cur ^ inc
            elif _ot == 'BitAnd':   new_v = cur & inc
            elif _ot == 'LShift':   new_v = cur << inc
            elif _ot == 'RShift':   new_v = cur >> inc
            elif _ot == 'MatMult':  new_v = cur @ inc
            else: raise ValueError(_ot)
            yield from self._assign(tgt, new_v, scope)
            return

        if op == 'IAnnAssign':
            ann_v = yield from self.step_expr(_nf(node, 'annotation'), scope)
            value = _nf(node, 'value')
            target = _nf(node, 'target')
            if value is not None:
                v = yield from self.step_expr(value, scope)
                yield from self._assign(target, v, scope)
            if _nf(node, 'simple', False) and _pg_tag(target[0]) == 'Name':
                name = self.s(_nf(target, 'id'))
                if '__annotations__' in scope.vars:
                    scope.vars['__annotations__'][name] = ann_v
            return

        if op == 'IIf':
            test = yield from self.step_expr(_nf(node, 'test'), scope)
            yield from self._exec_body(
                _nf(node, 'body') if test else _nf(node, 'orelse'), scope)
            return

        if op == 'IWhile':
            broke = False
            while True:
                test = yield from self.step_expr(_nf(node, 'test'), scope)
                if not test:
                    break
                try:
                    yield from self._exec_body(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self._exec_body(_nf(node, 'orelse'), scope)
            return

        if op == 'IFor':
            iter_val = yield from self.step_expr(_nf(node, 'iter'), scope)
            broke = False
            for item in iter_val:
                yield from self._assign(_nf(node, 'target'), item, scope)
                try:
                    yield from self._exec_body(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self._exec_body(_nf(node, 'orelse'), scope)
            return

        if op == 'IAsyncFor':
            ait_val = yield from self.step_expr(_nf(node, 'iter'), scope)
            ait = ait_val.__aiter__()
            broke = False
            while True:
                try:
                    item = yield ('await', ait.__anext__())
                except StopAsyncIteration:
                    break
                yield from self._assign(_nf(node, 'target'), item, scope)
                try:
                    yield from self._exec_body(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self._exec_body(_nf(node, 'orelse'), scope)
            return

        if op == 'IWith':
            yield from self._do_with(_nf(node, 'items'), 0, _nf(node, 'body'), scope, False)
            return

        if op == 'IAsyncWith':
            yield from self._do_with(_nf(node, 'items'), 0, _nf(node, 'body'), scope, True)
            return

        if op == 'ITry':
            yield from self._do_try(node, scope)
            return

        if op == 'IImport':
            for alias in _nf(node, 'names'):
                name = self.s(_nf(alias, 'name'))
                asname = self.s(_nf(alias, 'asname'))
                mod = __import__(name, scope.globals, None, (), 0)
                if asname is not None:
                    target = mod
                    for p in name.split('.')[1:]:
                        target = getattr(target, p)
                    scope.set(asname, target)
                else:
                    scope.set(name.split('.')[0], mod)
            return

        if op == 'IImportFrom':
            module = self.s(_nf(node, 'module')) or ''
            level = _nf(node, 'level')
            fromlist = tuple(self.s(_nf(a, 'name')) for a in _nf(node, 'names'))
            mod = __import__(module, scope.globals, None, fromlist, level)
            for alias in _nf(node, 'names'):
                name = self.s(_nf(alias, 'name'))
                asname = self.s(_nf(alias, 'asname'))
                bind = asname if asname is not None else name
                if name == '*':
                    if hasattr(mod, '__all__'):
                        for k in mod.__all__:
                            scope.set(k, getattr(mod, k))
                    else:
                        for k in dir(mod):
                            if not k.startswith('_'):
                                scope.set(k, getattr(mod, k))
                else:
                    scope.set(bind, getattr(mod, name))
            return

        if op == 'IFunctionDef':
            yield from self._define_function(node, scope, _nf(node, 'is_async', False))
            return

        if op == 'IClassDef':
            yield from self._define_class(node, scope)
            return

        yield from self.step_stmt(node, scope)

    def step_stmt(self, node, scope):
        if False:
            yield
        op = _pg_tag(node[0])

        if op == 'Pass':
            return

        if op == 'Expr':
            yield from self.step_expr(_nf(node, 'value'), scope)
            return

        if op == 'Return':
            v = None
            value = _nf(node, 'value')
            if value is not None:
                v = yield from self.step_expr(value, scope)
            raise _Return(v)

        if op == 'Raise':
            exc = None
            cause = None
            exc_node = _nf(node, 'exc')
            cause_node = _nf(node, 'cause')
            if exc_node is not None:
                exc = yield from self.step_expr(exc_node, scope)
            if cause_node is not None:
                cause = yield from self.step_expr(cause_node, scope)
            if exc is None:
                raise
            if cause is not None:
                raise exc from cause
            raise exc

        if op == 'Break':
            raise _Break()

        if op == 'Continue':
            raise _Continue()

        if op == 'Delete':
            for tgt in _nf(node, 'targets'):
                yield from self._delete(tgt, scope)
            return

        if op == 'Global':
            for n in _nf(node, 'names'):
                scope.global_names.add(self.s(n))
            return

        if op == 'Nonlocal':
            for n in _nf(node, 'names'):
                scope.nonlocal_names.add(self.s(n))
            return

        if op == 'Assign':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            for tgt in _nf(node, 'targets'):
                yield from self._assign(tgt, v, scope)
            return

        if op == 'AugAssign':
            tgt = _nf(node, 'target')
            cur = yield from self._load_target(tgt, scope)
            inc = yield from self.step_expr(_nf(node, 'value'), scope)
            _ot = _pg_tag(_nf(node, 'op2'))
            if   _ot == 'Add':      new_v = cur + inc
            elif _ot == 'Sub':      new_v = cur - inc
            elif _ot == 'Mult':     new_v = cur * inc
            elif _ot == 'FloorDiv': new_v = cur // inc
            elif _ot == 'Div':      new_v = cur / inc
            elif _ot == 'Mod':      new_v = cur % inc
            elif _ot == 'Pow':      new_v = cur ** inc
            elif _ot == 'BitOr':    new_v = cur | inc
            elif _ot == 'BitXor':   new_v = cur ^ inc
            elif _ot == 'BitAnd':   new_v = cur & inc
            elif _ot == 'LShift':   new_v = cur << inc
            elif _ot == 'RShift':   new_v = cur >> inc
            elif _ot == 'MatMult':  new_v = cur @ inc
            else: raise ValueError(_ot)
            yield from self._assign(tgt, new_v, scope)
            return

        if op == 'AnnAssign':
            ann_v = yield from self.step_expr(_nf(node, 'annotation'), scope)
            value = _nf(node, 'value')
            target = _nf(node, 'target')
            if value is not None:
                v = yield from self.step_expr(value, scope)
                yield from self._assign(target, v, scope)
            if _nf(node, 'simple', False) and _pg_tag(target[0]) == 'Name':
                name = self.s(_nf(target, 'id'))
                if '__annotations__' in scope.vars:
                    scope.vars['__annotations__'][name] = ann_v
            return

        if op == 'If':
            test = yield from self.step_expr(_nf(node, 'test'), scope)
            yield from self.step_block(
                _nf(node, 'body') if test else _nf(node, 'orelse'), scope)
            return

        if op == 'While':
            broke = False
            while True:
                test = yield from self.step_expr(_nf(node, 'test'), scope)
                if not test:
                    break
                try:
                    yield from self.step_block(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self.step_block(_nf(node, 'orelse'), scope)
            return

        if op == 'For':
            iter_val = yield from self.step_expr(_nf(node, 'iter'), scope)
            broke = False
            for item in iter_val:
                yield from self._assign(_nf(node, 'target'), item, scope)
                try:
                    yield from self.step_block(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self.step_block(_nf(node, 'orelse'), scope)
            return

        if op == 'AsyncFor':
            ait_val = yield from self.step_expr(_nf(node, 'iter'), scope)
            ait = ait_val.__aiter__()
            broke = False
            while True:
                try:
                    item = yield ('await', ait.__anext__())
                except StopAsyncIteration:
                    break
                yield from self._assign(_nf(node, 'target'), item, scope)
                try:
                    yield from self.step_block(_nf(node, 'body'), scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self.step_block(_nf(node, 'orelse'), scope)
            return

        if op == 'With':
            yield from self._do_with(_nf(node, 'items'), 0, _nf(node, 'body'), scope, False)
            return

        if op == 'AsyncWith':
            yield from self._do_with(_nf(node, 'items'), 0, _nf(node, 'body'), scope, True)
            return

        if op == 'Try':
            yield from self._do_try(node, scope)
            return

        if op == 'Import':
            for alias in _nf(node, 'names'):
                name = self.s(_nf(alias, 'name'))
                asname = self.s(_nf(alias, 'asname'))
                mod = __import__(name, scope.globals, None, (), 0)
                if asname is not None:
                    # for "import a.b as c", bind c=a.b
                    target = mod
                    for p in name.split('.')[1:]:
                        target = getattr(target, p)
                    scope.set(asname, target)
                else:
                    scope.set(name.split('.')[0], mod)
            return

        if op == 'ImportFrom':
            module = self.s(_nf(node, 'module')) or ''
            level = _nf(node, 'level')
            fromlist = tuple(self.s(_nf(a, 'name')) for a in _nf(node, 'names'))
            mod = __import__(module, scope.globals, None, fromlist, level)
            for alias in _nf(node, 'names'):
                name = self.s(_nf(alias, 'name'))
                asname = self.s(_nf(alias, 'asname'))
                bind = asname if asname is not None else name
                if name == '*':
                    if hasattr(mod, '__all__'):
                        for k in mod.__all__:
                            scope.set(k, getattr(mod, k))
                    else:
                        for k in dir(mod):
                            if not k.startswith('_'):
                                scope.set(k, getattr(mod, k))
                else:
                    scope.set(bind, getattr(mod, name))
            return

        if op == 'FunctionDef' or op == 'AsyncFunctionDef':
            yield from self._define_function(node, scope, op == 'AsyncFunctionDef')
            return

        if op == 'ClassDef':
            yield from self._define_class(node, scope)
            return

        raise NotImplementedError("step_stmt: " + op)

    # ---- expression stepper ----

    def step_expr(self, node, scope):
        if False:
            yield
        op = _pg_tag(node[0])

        if op == 'Constant':
            return self.k(_nf(node, 'idx'))

        if op == 'Name':
            return scope.get(self.s(_nf(node, 'id')))

        if op == 'BinOp':
            l = yield from self.step_expr(_nf(node, 'left'), scope)
            r = yield from self.step_expr(_nf(node, 'right'), scope)
            _ot = _pg_tag(_nf(node, 'op2'))
            if   _ot == 'Add':      return l + r
            elif _ot == 'Sub':      return l - r
            elif _ot == 'Mult':     return l * r
            elif _ot == 'FloorDiv': return l // r
            elif _ot == 'Div':      return l / r
            elif _ot == 'Mod':      return l % r
            elif _ot == 'Pow':      return l ** r
            elif _ot == 'BitOr':    return l | r
            elif _ot == 'BitXor':   return l ^ r
            elif _ot == 'BitAnd':   return l & r
            elif _ot == 'LShift':   return l << r
            elif _ot == 'RShift':   return l >> r
            elif _ot == 'MatMult':  return l @ r
            raise ValueError(_ot)

        if op == 'UnaryOp':
            v = yield from self.step_expr(_nf(node, 'operand'), scope)
            _ot = _pg_tag(_nf(node, 'op2'))
            if   _ot == 'USub':   return -v
            elif _ot == 'UAdd':   return +v
            elif _ot == 'Not':    return not v
            elif _ot == 'Invert': return ~v
            raise ValueError(_ot)

        if op == 'BoolOp':
            if _pg_tag(_nf(node, 'op2')) == 'And':
                last = True
                for vn in _nf(node, 'values'):
                    last = yield from self.step_expr(vn, scope)
                    if not last:
                        return last
                return last
            else:
                last = False
                for vn in _nf(node, 'values'):
                    last = yield from self.step_expr(vn, scope)
                    if last:
                        return last
                return last

        if op == 'Compare':
            left = yield from self.step_expr(_nf(node, 'left'), scope)
            for cmp_op, cn in zip(_nf(node, 'ops'), _nf(node, 'comparators')):
                right = yield from self.step_expr(cn, scope)
                _ot = _pg_tag(cmp_op)
                if   _ot == 'Eq':    ok = left == right
                elif _ot == 'NotEq': ok = left != right
                elif _ot == 'Lt':    ok = left < right
                elif _ot == 'LtE':   ok = left <= right
                elif _ot == 'Gt':    ok = left > right
                elif _ot == 'GtE':   ok = left >= right
                elif _ot == 'In':    ok = left in right
                elif _ot == 'NotIn': ok = left not in right
                elif _ot == 'Is':    ok = left is right
                elif _ot == 'IsNot': ok = left is not right
                else: raise ValueError(_ot)
                if not ok:
                    return False
                left = right
            return True

        if op == 'IfExp':
            test = yield from self.step_expr(_nf(node, 'test'), scope)
            if test:
                v = yield from self.step_expr(_nf(node, 'body'), scope)
            else:
                v = yield from self.step_expr(_nf(node, 'orelse'), scope)
            return v

        if op == 'Call':
            func = yield from self.step_expr(_nf(node, 'func'), scope)
            # Intercept zero-arg super() so it works without the magic cell.
            if (func is builtins.super
                    and not _nf(node, 'args') and not _nf(node, 'keywords')):
                cls_v = self._lookup_magic(scope, '__pyguard_class__')
                self_v = self._lookup_magic(scope, '__pyguard_self__')
                if cls_v is not None and self_v is not None:
                    return builtins.super(cls_v, self_v)
                return builtins.super()
            args = []
            for a in _nf(node, 'args'):
                if _pg_tag(a[0]) == 'Starred':
                    sv = yield from self.step_expr(_nf(a, 'value'), scope)
                    args.extend(sv)
                else:
                    av = yield from self.step_expr(a, scope)
                    args.append(av)
            kwargs = {}
            for kw in _nf(node, 'keywords'):
                arg_idx = _nf(kw, 'arg')
                if arg_idx is None or arg_idx < 0:
                    kv = yield from self.step_expr(_nf(kw, 'value'), scope)
                    kwargs.update(kv)
                else:
                    kv = yield from self.step_expr(_nf(kw, 'value'), scope)
                    kwargs[self.s(arg_idx)] = kv
            return func(*args, **kwargs)

        if op == 'Attribute':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            return getattr(v, self.s(_nf(node, 'attr')))

        if op == 'Subscript':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            sl = yield from self._eval_slice(_nf(node, 'slice'), scope)
            return v[sl]

        if op == 'Slice':
            return (yield from self._eval_slice(node, scope))

        if op == 'List':
            elts = []
            for e in _nf(node, 'elts'):
                if _pg_tag(e[0]) == 'Starred':
                    sv = yield from self.step_expr(_nf(e, 'value'), scope)
                    elts.extend(sv)
                else:
                    ev = yield from self.step_expr(e, scope)
                    elts.append(ev)
            return elts

        if op == 'Tuple':
            elts = []
            for e in _nf(node, 'elts'):
                if _pg_tag(e[0]) == 'Starred':
                    sv = yield from self.step_expr(_nf(e, 'value'), scope)
                    elts.extend(sv)
                else:
                    ev = yield from self.step_expr(e, scope)
                    elts.append(ev)
            return tuple(elts)

        if op == 'Set':
            out = set()
            for e in _nf(node, 'elts'):
                if _pg_tag(e[0]) == 'Starred':
                    sv = yield from self.step_expr(_nf(e, 'value'), scope)
                    out.update(sv)
                else:
                    ev = yield from self.step_expr(e, scope)
                    out.add(ev)
            return out

        if op == 'Dict':
            d = {}
            for kn, vn in zip(_nf(node, 'keys'), _nf(node, 'values')):
                if kn is None:
                    vv = yield from self.step_expr(vn, scope)
                    d.update(vv)
                else:
                    kv = yield from self.step_expr(kn, scope)
                    vv = yield from self.step_expr(vn, scope)
                    d[kv] = vv
            return d

        if op == 'Lambda':
            # Pre-evaluate defaults
            args_def = _nf(node, 'args')
            defaults = []
            for d in _nf(args_def, 'defaults'):
                dv = yield from self.step_expr(d, scope)
                defaults.append(dv)
            kw_defaults = []
            for kd in _nf(args_def, 'kw_defaults'):
                if kd is None:
                    kw_defaults.append(_MISSING)
                else:
                    kdv = yield from self.step_expr(kd, scope)
                    kw_defaults.append(kdv)
            # Wrap body as Return statement so the function path works
            wrapped = (('Return', _nf(node, 'body')),)
            return _UFunction(self, '<lambda>', args_def, wrapped,
                              scope, False, False, defaults, kw_defaults)

        if op == 'ListComp':
            return (yield from self._eval_comp('list', node, scope))
        if op == 'SetComp':
            return (yield from self._eval_comp('set', node, scope))
        if op == 'DictComp':
            return (yield from self._eval_comp('dict', node, scope))
        if op == 'GeneratorExp':
            return (yield from self._eval_genexp(node, scope))

        if op == 'JoinedStr':
            parts = []
            for vn in _nf(node, 'values'):
                v = yield from self.step_expr(vn, scope)
                parts.append(v if isinstance(v, str) else str(v))
            return ''.join(parts)

        if op == 'FormattedValue':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            conv = _nf(node, 'conversion')
            if conv == 115:
                v = str(v)
            elif conv == 114:
                v = repr(v)
            elif conv == 97:
                v = ascii(v)
            spec = ''
            if _nf(node, 'format_spec') is not None:
                spec = yield from self.step_expr(_nf(node, 'format_spec'), scope)
            return format(v, spec)

        if op == 'Yield':
            v = None
            if _nf(node, 'value') is not None:
                v = yield from self.step_expr(_nf(node, 'value'), scope)
            sent = yield ('yield', v)
            return sent

        if op == 'YieldFrom':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            it = iter(v)
            result = None
            while True:
                try:
                    item = next(it)
                except StopIteration as si:
                    result = si.value
                    break
                yield ('yield', item)
            return result

        if op == 'Await':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            r = yield ('await', v)
            return r

        if op == 'NamedExpr':
            v = yield from self.step_expr(_nf(node, 'value'), scope)
            yield from self._assign(_nf(node, 'target'), v, scope)
            return v

        if op == 'Starred':
            return (yield from self.step_expr(_nf(node, 'value'), scope))

        raise NotImplementedError("step_expr: " + op)

    # ---- assignment / lvalue helpers ----

    def _assign(self, target, value, scope):
        if False:
            yield
        op = _pg_tag(target[0])
        if op == 'Name':
            scope.set(self.s(_nf(target, 'id')), value)
            return
        if op == 'Tuple' or op == 'List':
            elts = _nf(target, 'elts')
            star_idx = None
            for i, e in enumerate(elts):
                if _pg_tag(e[0]) == 'Starred':
                    star_idx = i
                    break
            if star_idx is None:
                vlist = list(value)
                if len(vlist) != len(elts):
                    raise ValueError(
                        "expected {} values, got {}".format(
                            len(elts), len(vlist)))
                for e, v in zip(elts, vlist):
                    yield from self._assign(e, v, scope)
            else:
                vlist = list(value)
                n_before = star_idx
                n_after = len(elts) - star_idx - 1
                if len(vlist) < n_before + n_after:
                    raise ValueError("not enough values to unpack")
                for i in range(n_before):
                    yield from self._assign(elts[i], vlist[i], scope)
                star_count = len(vlist) - n_before - n_after
                yield from self._assign(
                    _nf(elts[star_idx], 'value'),
                    vlist[n_before:n_before + star_count],
                    scope)
                for j in range(n_after):
                    yield from self._assign(
                        elts[star_idx + 1 + j],
                        vlist[n_before + star_count + j],
                        scope)
            return
        if op == 'Attribute':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            setattr(obj, self.s(_nf(target, 'attr')), value)
            return
        if op == 'Subscript':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            sl = yield from self._eval_slice(_nf(target, 'slice'), scope)
            obj[sl] = value
            return
        if op == 'Starred':
            yield from self._assign(_nf(target, 'value'), value, scope)
            return
        raise NotImplementedError("_assign: " + op)

    def _delete(self, target, scope):
        if False:
            yield
        op = _pg_tag(target[0])
        if op == 'Name':
            scope.delete(self.s(_nf(target, 'id')))
            return
        if op == 'Attribute':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            delattr(obj, self.s(_nf(target, 'attr')))
            return
        if op == 'Subscript':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            sl = yield from self._eval_slice(_nf(target, 'slice'), scope)
            del obj[sl]
            return
        if op == 'Tuple' or op == 'List':
            for e in _nf(target, 'elts'):
                yield from self._delete(e, scope)
            return
        raise NotImplementedError("_delete: " + op)

    def _load_target(self, target, scope):
        if False:
            yield
        op = _pg_tag(target[0])
        if op == 'Name':
            return scope.get(self.s(_nf(target, 'id')))
        if op == 'Attribute':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            return getattr(obj, self.s(_nf(target, 'attr')))
        if op == 'Subscript':
            obj = yield from self.step_expr(_nf(target, 'value'), scope)
            sl = yield from self._eval_slice(_nf(target, 'slice'), scope)
            return obj[sl]
        raise NotImplementedError("_load_target: " + op)

    def _eval_slice(self, node, scope):
        if False:
            yield
        if _pg_tag(node[0]) == 'Slice':
            l = None
            u = None
            s = None
            if _nf(node, 'lower') is not None:
                l = yield from self.step_expr(_nf(node, 'lower'), scope)
            if _nf(node, 'upper') is not None:
                u = yield from self.step_expr(_nf(node, 'upper'), scope)
            if _nf(node, 'step') is not None:
                s = yield from self.step_expr(_nf(node, 'step'), scope)
            return slice(l, u, s)
        if _pg_tag(node[0]) == 'Tuple':
            elts = []
            for e in _nf(node, 'elts'):
                if _pg_tag(e[0]) == 'Slice':
                    elts.append((yield from self._eval_slice(e, scope)))
                else:
                    elts.append((yield from self.step_expr(e, scope)))
            return tuple(elts)
        return (yield from self.step_expr(node, scope))

    # ---- function / class definition ----

    def _define_function(self, node, scope, is_async):
        if False:
            yield
        if is_async is None:
            is_async = _nf(node, 'is_async', False)
        is_gen = _nf(node, 'is_gen', None)
        if is_gen is None:
            is_gen = self._contains_yield(_nf(node, 'body'))
        # Async generators (PEP 525) are not supported in this version.
        if is_async:
            is_gen = False  # treat any yield in async def as syntax-irrelevant
        args_def = _nf(node, 'args')
        defaults = []
        for d in _nf(args_def, 'defaults'):
            dv = yield from self.step_expr(d, scope)
            defaults.append(dv)
        kw_defaults = []
        for kd in _nf(args_def, 'kw_defaults'):
            if kd is None:
                kw_defaults.append(_MISSING)
            else:
                kdv = yield from self.step_expr(kd, scope)
                kw_defaults.append(kdv)
        func = _UFunction(
            self, self.s(_nf(node, 'name')), args_def, _nf(node, 'body'),
            scope, is_gen, is_async, defaults, kw_defaults)
        # Evaluate annotations
        ann = {}
        for a in (_nf(args_def, 'posonlyargs') + _nf(args_def, 'args')
                  + _nf(args_def, 'kwonlyargs')):
            if _nf(a, 'annotation') is not None:
                ann[self.s(_nf(a, 'arg'))] = (
                    yield from self.step_expr(_nf(a, 'annotation'), scope))
        vararg = _nf(args_def, 'vararg')
        if vararg is not None and _nf(vararg, 'annotation') is not None:
            ann[self.s(_nf(vararg, 'arg'))] = (
                yield from self.step_expr(_nf(vararg, 'annotation'), scope))
        kwarg = _nf(args_def, 'kwarg')
        if kwarg is not None and _nf(kwarg, 'annotation') is not None:
            ann[self.s(_nf(kwarg, 'arg'))] = (
                yield from self.step_expr(_nf(kwarg, 'annotation'), scope))
        if _nf(node, 'returns') is not None:
            ann['return'] = yield from self.step_expr(_nf(node, 'returns'), scope)
        func.__annotations__ = ann
        # Decorators
        decos = []
        for d in _nf(node, 'decorator_list'):
            dv = yield from self.step_expr(d, scope)
            decos.append(dv)
        decorated = func
        for d in reversed(decos):
            decorated = d(decorated)
        scope.set(self.s(_nf(node, 'name')), decorated)

    def _define_class(self, node, scope):
        if False:
            yield
        name = self.s(_nf(node, 'name'))
        bases = []
        for b in _nf(node, 'bases'):
            bv = yield from self.step_expr(b, scope)
            bases.append(bv)
        kw = {}
        for k in _nf(node, 'keywords'):
            kv = yield from self.step_expr(_nf(k, 'value'), scope)
            arg_idx = _nf(k, 'arg')
            if arg_idx is None or arg_idx < 0:
                kw.update(kv)
            else:
                kw[self.s(arg_idx)] = kv
        metaclass = kw.pop('metaclass', None)
        if metaclass is None:
            metaclass = type(bases[0]) if bases else type
        # Class body in its own scope
        cls_scope = Scope(parent=scope)
        cls_scope.vars['__annotations__'] = {}
        cls_scope.vars['__name__'] = name
        cls_scope.vars['__qualname__'] = name
        cls_scope.vars['__module__'] = scope.globals.get('__name__', '__main__')
        yield from self._exec_body(_nf(node, 'body'), cls_scope)
        ns = dict(cls_scope.vars)
        cls = metaclass(name, tuple(bases), ns, **kw)
        # Patch defining_class onto user functions for super()
        for v in ns.values():
            if isinstance(v, _UFunction):
                v.defining_class = cls
            elif isinstance(v, (staticmethod, classmethod)):
                inner = v.__func__
                if isinstance(inner, _UFunction):
                    inner.defining_class = cls
        # Decorators
        decos = []
        for d in _nf(node, 'decorator_list'):
            dv = yield from self.step_expr(d, scope)
            decos.append(dv)
        for d in reversed(decos):
            cls = d(cls)
        scope.set(name, cls)

    # ---- function call binding ----

    def call_user_function(self, func, args, kwargs):
        local = Scope(parent=func.defining_scope)
        self._bind_args(func, args, kwargs, local)
        if func.defining_class is not None:
            local.vars['__pyguard_class__'] = func.defining_class
            if args:
                local.vars['__pyguard_self__'] = args[0]
        if func.is_gen:
            return self._make_host_generator(func, local)
        if func.is_async:
            return self._make_host_coroutine(func, local)
        try:
            _drive_sync(self._exec_body(func.body, local))
        except _Return as r:
            return r.value
        return None

    def _bind_args(self, func, args, kwargs, local):
        a = func.args_def
        posonly = _nf(a, 'posonlyargs')
        pos = _nf(a, 'args')
        kwonly = _nf(a, 'kwonlyargs')
        vararg = _nf(a, 'vararg')
        kwarg = _nf(a, 'kwarg')

        all_pos = posonly + pos
        n_pos = len(all_pos)
        defaults = func.defaults
        n_defaults = len(defaults)

        bound = {}
        kwargs = dict(kwargs)
        n_args = len(args)

        # 1. positional → posonly+pos
        for i in range(min(n_args, n_pos)):
            bound[self.s(_nf(all_pos[i], 'arg'))] = args[i]

        # 2. extra positional → vararg (or error)
        if n_args > n_pos:
            if vararg is not None:
                bound[self.s(_nf(vararg, 'arg'))] = tuple(args[n_pos:])
            else:
                raise TypeError(
                    "{}() takes {} positional arguments but {} were given".format(
                        func.__name__, n_pos, n_args))
        elif vararg is not None:
            bound[self.s(_nf(vararg, 'arg'))] = ()

        # 3. keyword → pos (excluding posonly) and kwonly
        pos_names = {self.s(_nf(p, 'arg')) for p in pos}
        kwonly_names = [self.s(_nf(p, 'arg')) for p in kwonly]
        for k in list(kwargs):
            if k in pos_names:
                if k in bound:
                    raise TypeError(
                        "{}() got multiple values for argument {!r}".format(
                            func.__name__, k))
                bound[k] = kwargs.pop(k)
            elif k in kwonly_names:
                bound[k] = kwargs.pop(k)

        # 4. defaults for unfilled positional
        for i, p in enumerate(all_pos):
            name = self.s(_nf(p, 'arg'))
            if name in bound:
                continue
            di = i - (n_pos - n_defaults)
            if di >= 0:
                bound[name] = defaults[di]
            else:
                raise TypeError(
                    "{}() missing required argument: {!r}".format(
                        func.__name__, name))

        # 5. defaults for unfilled kwonly
        for i, name in enumerate(kwonly_names):
            if name in bound:
                continue
            kd = func.kw_defaults[i]
            if kd is not _MISSING:
                bound[name] = kd
            else:
                raise TypeError(
                    "{}() missing required keyword argument: {!r}".format(
                        func.__name__, name))

        # 6. leftover keyword → **kwarg
        if kwarg is not None:
            bound[self.s(_nf(kwarg, 'arg'))] = dict(kwargs)
        elif kwargs:
            raise TypeError(
                "{}() got unexpected keyword arguments: {}".format(
                    func.__name__, list(kwargs)))

        local.vars.update(bound)

    # ---- generator / coroutine host wrappers ----

    def _make_host_generator(self, func, local):
        inner = self._exec_body(func.body, local)
        def host():
            sent = None
            try:
                while True:
                    try:
                        if sent is None:
                            evt = next(inner)
                        else:
                            evt = inner.send(sent)
                            sent = None
                    except StopIteration:
                        return
                    if evt[0] == 'yield':
                        sent = (yield evt[1])
                    else:
                        raise RuntimeError(
                            "await event in non-async generator")
            except _Return:
                return
        return host()

    def _make_host_coroutine(self, func, local):
        inner = self._exec_body(func.body, local)
        async def host():
            sent = None
            try:
                while True:
                    try:
                        if sent is None:
                            evt = next(inner)
                        else:
                            evt = inner.send(sent)
                            sent = None
                    except StopIteration:
                        return None
                    if evt[0] == 'await':
                        sent = await evt[1]
                    else:
                        raise RuntimeError(
                            "yield event in coroutine")
            except _Return as r:
                return r.value
        return host()

    # ---- with-statement ----

    def _do_with(self, items, idx, body, scope, is_async):
        if False:
            yield
        if idx >= len(items):
            yield from self._exec_body(body, scope)
            return
        item = items[idx]
        ctx = yield from self.step_expr(_nf(item, 'context_expr'), scope)
        if is_async:
            entered = yield ('await', ctx.__aenter__())
            if _nf(item, 'optional_vars') is not None:
                yield from self._assign(_nf(item, 'optional_vars'), entered, scope)
            try:
                yield from self._do_with(items, idx + 1, body, scope, is_async)
            except BaseException:
                exc_info = sys.exc_info()
                suppress = yield ('await',
                                  ctx.__aexit__(exc_info[0], exc_info[1], exc_info[2]))
                if not suppress:
                    raise
            else:
                yield ('await', ctx.__aexit__(None, None, None))
        else:
            entered = ctx.__enter__()
            if _nf(item, 'optional_vars') is not None:
                yield from self._assign(_nf(item, 'optional_vars'), entered, scope)
            try:
                yield from self._do_with(items, idx + 1, body, scope, is_async)
            except BaseException:
                exc_info = sys.exc_info()
                suppress = ctx.__exit__(exc_info[0], exc_info[1], exc_info[2])
                if not suppress:
                    raise
            else:
                ctx.__exit__(None, None, None)

    # ---- try/except/finally ----

    def _do_try(self, node, scope):
        if False:
            yield
        pending_exc = None
        pending_ctrl = None
        try:
            try:
                yield from self._exec_body(_nf(node, 'body'), scope)
            except (_Return, _Break, _Continue) as ctrl:
                pending_ctrl = ctrl
            except BaseException as e:
                handled = False
                for handler in _nf(node, 'handlers'):
                    htype = None
                    if _nf(handler, 'type') is not None:
                        htype = yield from self.step_expr(
                            _nf(handler, 'type'), scope)
                    if htype is None or isinstance(e, htype):
                        handled = True
                        name_idx = _nf(handler, 'name')
                        name = self.s(name_idx) if name_idx is not None and name_idx >= 0 else None
                        if name is not None:
                            scope.set(name, e)
                        try:
                            try:
                                yield from self._exec_body(
                                    _nf(handler, 'body'), scope)
                            except (_Return, _Break, _Continue) as ctrl:
                                pending_ctrl = ctrl
                            except BaseException as e2:
                                pending_exc = e2
                        finally:
                            if name is not None and name in scope.vars:
                                del scope.vars[name]
                        break
                if not handled:
                    pending_exc = e
            else:
                try:
                    yield from self._exec_body(_nf(node, 'orelse'), scope)
                except (_Return, _Break, _Continue) as ctrl:
                    pending_ctrl = ctrl
                except BaseException as e:
                    pending_exc = e
        finally:
            try:
                yield from self._exec_body(_nf(node, 'finalbody'), scope)
            except (_Return, _Break, _Continue) as ctrl:
                pending_ctrl = ctrl
                pending_exc = None
            except BaseException as e:
                pending_exc = e
                pending_ctrl = None
        if pending_exc is not None:
            raise pending_exc
        if pending_ctrl is not None:
            raise pending_ctrl

    # ---- comprehensions ----

    def _eval_comp(self, kind, node, scope):
        if False:
            yield
        if kind == 'list':
            result = []
        elif kind == 'set':
            result = set()
        else:
            result = {}
        first_iter = yield from self.step_expr(
            _nf(_nf(node, 'generators')[0], 'iter'), scope)
        comp_scope = Scope(parent=scope)
        yield from self._comp_loop(node, 0, comp_scope, kind, result, first_iter)
        return result

    def _comp_loop(self, node, gi, comp_scope, kind, result, first_iter):
        if False:
            yield
        generators = _nf(node, 'generators')
        gen = generators[gi]
        if gi == 0:
            iter_val = first_iter
        else:
            iter_val = yield from self.step_expr(_nf(gen, 'iter'), comp_scope)
        for item in iter_val:
            yield from self._assign(_nf(gen, 'target'), item, comp_scope)
            skip = False
            for cond in _nf(gen, 'ifs'):
                cv = yield from self.step_expr(cond, comp_scope)
                if not cv:
                    skip = True
                    break
            if skip:
                continue
            if gi + 1 < len(generators):
                yield from self._comp_loop(
                    node, gi + 1, comp_scope, kind, result, None)
            else:
                if kind == 'list':
                    v = yield from self.step_expr(_nf(node, 'elt'), comp_scope)
                    result.append(v)
                elif kind == 'set':
                    v = yield from self.step_expr(_nf(node, 'elt'), comp_scope)
                    result.add(v)
                else:
                    kv = yield from self.step_expr(_nf(node, 'key'), comp_scope)
                    vv = yield from self.step_expr(_nf(node, 'value'), comp_scope)
                    result[kv] = vv

    def _eval_genexp(self, node, scope):
        if False:
            yield
        # Eager (build a list, return iter). Adequate for our test surface.
        result = []
        first_iter = yield from self.step_expr(
            _nf(_nf(node, 'generators')[0], 'iter'), scope)
        comp_scope = Scope(parent=scope)
        yield from self._comp_loop(node, 0, comp_scope, 'list', result, first_iter)
        return iter(result)

    # ---- helpers ----

    def _lookup_magic(self, scope, name):
        s = scope
        while s is not None:
            if name in s.vars:
                return s.vars[name]
            s = s.parent
        return None

    def _contains_yield(self, body):
        return self._walk_for_yield(body)

    def _walk_for_yield(self, node):
        if isinstance(node, tuple) and node and _pg_tag(node[0]) in _NODE_POS:
            op = _pg_tag(node[0])
            if op in ('FunctionDef', 'AsyncFunctionDef', 'Lambda', 'ClassDef', 'IFunctionDef', 'IClassDef'):
                return False
            if op in ('Yield', 'YieldFrom'):
                return True
            for v in node[1:]:
                if self._walk_for_yield(v):
                    return True
            return False
        if isinstance(node, (list, tuple)):
            for x in node:
                if self._walk_for_yield(x):
                    return True
            return False
        if not isinstance(node, dict):
            return False
        for _, v in node.items():
            if self._walk_for_yield(v):
                return True
        return False


# --- entry points --------------------------------------------------------

def _decode_const(c):
    """Decode a positional const wrapper produced by build_ir.compile_to_json.

    v8: const wire format is a positional list/tuple `(tag, *values)`. The
    previous `{'t': tag, 'v': value, ...}` dict shape was a unique structural
    fingerprint by which an attacker could find every const wrapper materialized
    during parse — replaced here with positional access so const wrappers
    look indistinguishable from any other tuple in the IR stream.
    """
    t = _pg_tag(c[0])
    if t == 'none':     return None
    if t == 'true':     return True
    if t == 'false':    return False
    if t == 'int':      return int(c[1])
    if t == 'float':    return float(c[1])
    if t == 'str':      return _pg_text(c[1])
    if t == 'bytes':    return bytes(c[1])
    if t == 'complex':  return complex(float(c[1]), float(c[2]))
    if t == 'ellipsis': return Ellipsis
    if t == 'tuple':    return tuple(_decode_const(x) for x in c[1])
    if t == 'frozenset': return frozenset(_decode_const(x) for x in c[1])
    raise ValueError("unknown const tag: " + t)


def _build_accessor(strings, consts):
    """Construct the opaque (kind, idx) -> entry accessor passed to Interp.

    `strings` is the raw strings tuple (entries may be plain str or mask-
    encoded byte lists; Interp.s() applies _pg_text on each access).
    `consts` is the already-decoded consts tuple of Python objects.

    Both are captured in this function's closure cells. They are never
    exposed as attributes on Interp; the only handle on them is the
    returned closure, which has no stable name across builds.
    """
    def _a(kind, idx):
        if kind == 0:
            return strings[idx]
        if kind == 1:
            return consts[idx]
        # Unknown kind probe — return a sentinel that doesn't leak data
        # but isn't None (a hooked _a returning None on probe is a tamper
        # signal a future hardening round can verify).
        raise LookupError(kind)
    return _a


def run_blob(blob, module_name='__main__'):
    """Parse packed binary IR and execute it.

    Strips noise bytes and reverses rolling XOR before parsing. The
    seed and noise schedule are injected as globals by stage2.
    """
    global _S_K, _S_RT, _S_M, _S_L
    g = globals()
    # Internalize schema from _PG_* globals → private module vars, then wipe.
    # This prevents frame-walk attacks from extracting schema by known names.
    _S_K = dict(g.pop('_PG_KEYS', {}))
    _S_RT = dict(g.pop('_PG_RTAGS', {}))
    _S_M = bytes(g.pop('_PG_MASK', ()))
    _S_L = dict(g.pop('_PG_LAYOUTS', {}))
    g.pop('_PG_TAGS', None)
    # --- undo noise injection + rolling XOR ---
    _ns = g.pop('_PG_NOISE_SCHEDULE', None)
    if _ns:
        blob = _strip_noise(blob, _ns)
    _bk = g.pop('_PG_BIN_KEY', None)
    if _bk is not None:
        blob = _rolling_xor(blob, _bk)
    del _ns, _bk
    # ------------------------------------------------
    loaded = _pg_parse_bin(blob)
    consts = tuple(_decode_const(c) for c in loaded[1])
    interp = Interp(_build_accessor(loaded[0], consts))
    tree = loaded[2]
    del loaded, blob, consts
    interp.run(tree, module_name)


def _pg_boot(*_a):
    """PyGuard interpreter entry point.

    Signature (9 or 10 inert-bytes positional args, no callables):
      schema_ct, schema_label, ir_ct, ir_label, seed,
      interp_hash, env_hash, pep, profile[, module_name='__main__']

    All stage2-supplied "config" is inert bytes: a 32-byte `pep` pepper,
    and a 15-byte `profile` struct (rounds, rot_mod, sbx_nudge,
    rk_label[4], rot_label[4], sbx_label[4]). The cipher algorithm is
    implemented inline here via the _k_derive / _c_dec helpers above.
    An attacker hooking `types.FunctionType` finds only inert bytes in
    the boot-args tuple — no callable to replace with a logging wrapper.

    `co_argcount == 0` (vararg-only) defeats any structural fingerprint
    keyed on argument count.
    """
    if len(_a) == 9:
        (schema_ct, schema_label, ir_ct, ir_label, seed,
         interp_hash, env_hash, pep, profile) = _a
        module_name = '__main__'
    elif len(_a) == 10:
        (schema_ct, schema_label, ir_ct, ir_label, seed,
         interp_hash, env_hash, pep, profile, module_name) = _a
    else:
        raise TypeError("_pg_boot: expected 9 or 10 args, got " + str(len(_a)))
    del _a

    # Unpack the 15-byte profile struct (layout must match TS emission
    # in lib/obfuscate.ts / lib/v5/assemble.ts).
    _rounds = profile[0]
    _rot_mod = profile[1]
    _sbx_nudge = profile[2]
    _rk_label = bytes(profile[3:7])
    _rot_label = bytes(profile[7:11])
    _sbx_label = bytes(profile[11:15])

    global _S_K, _S_RT, _S_M, _S_L
    import hashlib as _h
    import zlib as _z

    # --- decrypt schema (v8: positional binary, not JSON) ---
    _schema_seed_pre = _h.sha256(seed + schema_label).digest()
    _schema_seed = bytes(a ^ b ^ c for a, b, c in zip(
        _schema_seed_pre, interp_hash, env_hash))
    _schema_p = _k_derive(_schema_seed, pep, _rounds, _rk_label,
                          _rot_label, _sbx_label, _rot_mod, _sbx_nudge)
    _sb = _c_dec(schema_ct, _schema_p[0], _schema_p[1], _schema_p[2])
    del _schema_seed, _schema_seed_pre, _schema_p

    _o = 0
    # mask
    _ml = _sb[_o]; _o += 1
    _S_M = bytes(_sb[_o:_o + _ml]); _o += _ml
    # bin_key
    _bk_lo = _sb[_o] | (_sb[_o+1] << 8) | (_sb[_o+2] << 16) | (_sb[_o+3] << 24); _o += 4
    _bk_hi = _sb[_o] | (_sb[_o+1] << 8) | (_sb[_o+2] << 16) | (_sb[_o+3] << 24); _o += 4
    _bin_key = _bk_lo | (_bk_hi << 32)
    # noise schedule
    _nc = _sb[_o]; _o += 1
    _noise = []
    for _ in range(_nc):
        _pos = _sb[_o] | (_sb[_o+1] << 8); _o += 2
        _ln = _sb[_o]; _o += 1
        _noise.append((_pos, _ln))
    # keys
    _kc = _sb[_o] | (_sb[_o+1] << 8); _o += 2
    _S_K = {}
    for _ in range(_kc):
        _kl = _sb[_o]; _o += 1
        _k = _sb[_o:_o + _kl].decode('utf-8'); _o += _kl
        _vl = _sb[_o]; _o += 1
        _v = _sb[_o:_o + _vl].decode('utf-8'); _o += _vl
        _S_K[_k] = _v
    # tags (read straight into reverse-tag map; forward map never exists)
    _tc = _sb[_o] | (_sb[_o+1] << 8); _o += 2
    _S_RT = {}
    for _ in range(_tc):
        _kl = _sb[_o]; _o += 1
        _k = _sb[_o:_o + _kl].decode('utf-8'); _o += _kl
        _vl = _sb[_o]; _o += 1
        _v = _sb[_o:_o + _vl].decode('utf-8'); _o += _vl
        _S_RT[_v] = _k
    # layouts (name → {field: index+1})
    _lc = _sb[_o] | (_sb[_o+1] << 8); _o += 2
    _S_L = {}
    for _ in range(_lc):
        _tl = _sb[_o]; _o += 1
        _tag = _sb[_o:_o + _tl].decode('utf-8'); _o += _tl
        _fc = _sb[_o]; _o += 1
        _fmap = {}
        for _j in range(_fc):
            _fl = _sb[_o]; _o += 1
            _fn = _sb[_o:_o + _fl].decode('utf-8'); _o += _fl
            _fmap[_fn] = _j + 1
        _S_L[_tag] = _fmap
    del _sb, _o, _ml, _bk_lo, _bk_hi, _nc
    try:
        del _pos, _ln, _kc, _kl, _k, _vl, _v, _tc, _lc, _tl, _tag, _fc, _fmap, _fl, _fn, _j
    except NameError:
        pass

    # --- decrypt IR bytes ---
    _ir_seed_pre = _h.sha256(seed + ir_label).digest()
    _ir_seed = bytes(a ^ b ^ c for a, b, c in zip(
        _ir_seed_pre, interp_hash, env_hash))
    _ir_p = _k_derive(_ir_seed, pep, _rounds, _rk_label,
                      _rot_label, _sbx_label, _rot_mod, _sbx_nudge)
    blob = _z.decompress(_c_dec(ir_ct, _ir_p[0], _ir_p[1], _ir_p[2]), -15)
    del _ir_seed, _ir_seed_pre, _ir_p, schema_ct, ir_ct, seed, pep, profile
    del _rounds, _rot_mod, _sbx_nudge, _rk_label, _rot_label, _sbx_label

    # --- strip noise + rolling XOR ---
    if _noise:
        blob = _strip_noise(blob, _noise)
    if _bin_key is not None:
        blob = _rolling_xor(blob, _bin_key)
    del _noise, _bin_key

    # --- parse + run ---
    loaded = _pg_parse_bin(blob)
    _consts = tuple(_decode_const(c) for c in loaded[1])
    # Build accessor closure here. The strings tuple (loaded[0]) and the
    # decoded consts are captured in `_a`'s closure cells. They are not
    # stored as Interp instance attributes, so a class-init hook on
    # Interp captures only `_a` (an opaque function), not the underlying
    # tables.
    interp = Interp(_build_accessor(loaded[0], _consts))
    tree = loaded[2]
    del loaded, blob, _consts
    interp.run(tree, module_name)


def _k_derive(input_seed, pep, rounds, rk_label, rot_label, sbx_label, rot_mod, sbx_nudge):
    """Inline key-derivation — mirror of stage1's _kd.

    Derivation runs INSIDE the interpreter. Profile parameters (rounds,
    labels, rot_mod, sbx_nudge) travel as inert bytes in the boot-args
    tuple; there is no Python callable to wrap. An attacker who captures
    the args has only raw bytes and must reimplement this derivation
    offline to make use of them.

    Algorithm must match lib/obfuscate.ts `kdf()` exactly — the stage1
    encryption side used the same math and any drift breaks compat.
    """
    import hashlib as _h2
    peppered = bytes(a ^ b for a, b in zip(input_seed, pep))
    rks = []
    h = peppered
    for _ in range(rounds):
        h = _h2.sha256(h + rk_label).digest()
        rks.append(h)
    rot_seed = _h2.sha256(peppered + rot_label).digest()
    rotk = [(rot_seed[i] % rot_mod) + 1 for i in range(rounds)]
    sbx_seed = _h2.sha256(peppered + sbx_label).digest()
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + sbx_seed[i % 32] + sbx_nudge) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    inv = [0] * 256
    for i in range(256):
        inv[sbox[i]] = i
    return rks, rotk, inv


def _c_dec(ct, rks, rotk, inv):
    """Inline cipher decrypt — canonical (unflattened) version of the
    state machine stage1 generates as source. Equivalent semantics,
    ~20x less code. Stage1's flattened version is retained for its own
    use (where extraction resistance matters); the interpreter's copy
    runs after FunctionType has already latched the code object, so
    flattening buys no additional protection here.
    """
    N = len(rks)
    out = bytearray(len(ct))
    prev = 0
    for i in range(len(ct)):
        b = ct[i]
        for r in range(N - 1, -1, -1):
            k = rotk[r]
            b = ((b >> k) | (b << (8 - k))) & 0xFF
            b = inv[b]
            b ^= rks[r][i % 32]
        b ^= prev
        out[i] = b
        prev = ct[i]
    return bytes(out)


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


def _strip_noise(data, noise_schedule):
    """Remove noise bytes previously injected by _inject_noise.

    Reverses the schedule in reverse order so that position accounting
    is consistent with the forward injection pass.
    """
    buf = bytearray(data)
    # Replay in reverse to undo the cumulative offset correctly
    for pos, length in reversed(noise_schedule):
        # During injection, actual = pos % (len(buf_at_that_time) + 1).
        # We need to reconstruct the same actual position.  When stripping
        # in reverse, buf is at the same length it was *after* that particular
        # injection, so actual = pos % (len(buf) - length + 1) ... but the
        # injection used len(buf_before)+1 = len(buf)-length+1.  Since we
        # are undoing the *last* injection first, the current buf is exactly
        # the state right after that injection.
        before_len = len(buf) - length
        actual = pos % (before_len + 1)
        del buf[actual:actual + length]
    return bytes(buf)


def _pg_parse_bin(blob):
    idx = [0]
    n = len(blob)

    def _u32():
        i = idx[0]
        if i + 4 > n:
            raise ValueError("short u32")
        idx[0] = i + 4
        return blob[i] | (blob[i + 1] << 8) | (blob[i + 2] << 16) | (blob[i + 3] << 24)

    def _take(m):
        i = idx[0]
        if i + m > n:
            raise ValueError("short read")
        idx[0] = i + m
        return blob[i:i + m]

    def _parse():
        tag = _take(1)
        if tag == b'n':
            return None
        if tag == b't':
            return True
        if tag == b'f':
            return False
        if tag == b'i':
            return int(_take(_u32()).decode('utf-8'))
        if tag == b'r':
            return float(_take(_u32()).decode('utf-8'))
        if tag == b's':
            return _take(_u32()).decode('utf-8')
        if tag == b'l':
            out = []
            for _ in range(_u32()):
                out.append(_parse())
            return tuple(out)
        if tag == b'm':
            # v8: legacy `m` (map) tag retained only so old packed blobs
            # parse — current build_ir.py emits const wrappers as positional
            # tuples (`l` tag) per step B, so the only `m` payloads in v8
            # streams are absent. Returning a plain dict keeps backward-compat
            # without re-introducing a unique-class fingerprint.
            items = []
            for _ in range(_u32()):
                k = _take(_u32()).decode('utf-8')
                items.append((k, _parse()))
            return dict(items)
        raise ValueError("bad tag: " + repr(tag))

    out = _parse()
    if idx[0] != n:
        raise ValueError("trailing packed data")
    return out


# --- self-test entry point ----------------------------------------------
if __name__ == '__main__':
    import json
    import os

    # Smoke test: read source from argv[1], compile via the real packed
    # binary path (compile_to_compressed_bytes + run_blob) so this exercises
    # the same code that production stubs use.
    import zlib

    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import build_ir as _bi  # noqa

    if len(sys.argv) < 2:
        print("usage: runtime_interp.py <source.py>")
        sys.exit(2)
    with open(sys.argv[1]) as f:
        src = f.read()
    schema_json = os.environ.get('PYGUARD_V5_SCHEMA')
    compressed = _bi.compile_to_compressed_bytes(src, schema_json)
    blob = zlib.decompress(compressed, -15)
    if schema_json:
        schema = json.loads(schema_json)
        globals()['_PG_KEYS'] = dict(schema.get('keys', {}).items())
        tags = dict(schema.get('tags', {}).items())
        globals()['_PG_TAGS'] = tags
        globals()['_PG_RTAGS'] = {v: k for k, v in tags.items()}
        globals()['_PG_MASK'] = bytes(schema.get('mask', []))
        globals()['_PG_LAYOUTS'] = {
            k: {name: i + 1 for i, name in enumerate(v)}
            for k, v in dict(schema.get('layouts', {}).items()).items()
        }
        # rolling XOR + noise injection globals
        bin_key_pair = schema.get('binKey')
        if bin_key_pair is not None:
            lo, hi = bin_key_pair
            globals()['_PG_BIN_KEY'] = (lo & 0xFFFFFFFF) | ((hi & 0xFFFFFFFF) << 32)
        globals()['_PG_NOISE_SCHEDULE'] = schema.get('noiseSchedule', [])
    run_blob(blob)

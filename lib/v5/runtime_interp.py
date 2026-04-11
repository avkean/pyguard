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


# --- operator dispatch tables --------------------------------------------

_BIN_OPS = {
    'Add':       lambda a, b: a + b,
    'Sub':       lambda a, b: a - b,
    'Mult':      lambda a, b: a * b,
    'MatMult':   lambda a, b: a @ b,
    'Div':       lambda a, b: a / b,
    'Mod':       lambda a, b: a % b,
    'Pow':       lambda a, b: a ** b,
    'LShift':    lambda a, b: a << b,
    'RShift':    lambda a, b: a >> b,
    'BitOr':     lambda a, b: a | b,
    'BitXor':    lambda a, b: a ^ b,
    'BitAnd':    lambda a, b: a & b,
    'FloorDiv':  lambda a, b: a // b,
}

_UNARY_OPS = {
    'Invert':  lambda x: ~x,
    'Not':     lambda x: not x,
    'UAdd':    lambda x: +x,
    'USub':    lambda x: -x,
}

_CMP_OPS = {
    'Eq':     lambda a, b: a == b,
    'NotEq':  lambda a, b: a != b,
    'Lt':     lambda a, b: a < b,
    'LtE':    lambda a, b: a <= b,
    'Gt':     lambda a, b: a > b,
    'GtE':    lambda a, b: a >= b,
    'Is':     lambda a, b: a is b,
    'IsNot':  lambda a, b: a is not b,
    'In':     lambda a, b: a in b,
    'NotIn':  lambda a, b: a not in b,
}


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
    def __init__(self, strings, consts):
        self.strings = strings
        self.consts = consts

    def s(self, idx):
        if idx is None or idx < 0:
            return None
        return self.strings[idx]

    def k(self, idx):
        return self.consts[idx]

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
            _drive_sync(self.step_block(tree['body'], scope))
        except _Return:
            pass

    # ---- statement stepper (generator-of-events) ----

    def step_block(self, body, scope):
        if False:
            yield  # mark as generator
        for stmt in body:
            yield from self.step_stmt(stmt, scope)

    def step_stmt(self, node, scope):
        if False:
            yield
        op = node['op']

        if op == 'Pass':
            return

        if op == 'Expr':
            yield from self.step_expr(node['value'], scope)
            return

        if op == 'Return':
            v = None
            if node['value'] is not None:
                v = yield from self.step_expr(node['value'], scope)
            raise _Return(v)

        if op == 'Raise':
            exc = None
            cause = None
            if node['exc'] is not None:
                exc = yield from self.step_expr(node['exc'], scope)
            if node['cause'] is not None:
                cause = yield from self.step_expr(node['cause'], scope)
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
            for tgt in node['targets']:
                yield from self._delete(tgt, scope)
            return

        if op == 'Global':
            for n in node['names']:
                scope.global_names.add(self.s(n))
            return

        if op == 'Nonlocal':
            for n in node['names']:
                scope.nonlocal_names.add(self.s(n))
            return

        if op == 'Assign':
            v = yield from self.step_expr(node['value'], scope)
            for tgt in node['targets']:
                yield from self._assign(tgt, v, scope)
            return

        if op == 'AugAssign':
            tgt = node['target']
            cur = yield from self._load_target(tgt, scope)
            inc = yield from self.step_expr(node['value'], scope)
            new_v = _BIN_OPS[node['op2']](cur, inc)
            yield from self._assign(tgt, new_v, scope)
            return

        if op == 'AnnAssign':
            ann_v = yield from self.step_expr(node['annotation'], scope)
            if node['value'] is not None:
                v = yield from self.step_expr(node['value'], scope)
                yield from self._assign(node['target'], v, scope)
            if node.get('simple') and node['target']['op'] == 'Name':
                name = self.s(node['target']['id'])
                if '__annotations__' in scope.vars:
                    scope.vars['__annotations__'][name] = ann_v
            return

        if op == 'If':
            test = yield from self.step_expr(node['test'], scope)
            yield from self.step_block(
                node['body'] if test else node['orelse'], scope)
            return

        if op == 'While':
            broke = False
            while True:
                test = yield from self.step_expr(node['test'], scope)
                if not test:
                    break
                try:
                    yield from self.step_block(node['body'], scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self.step_block(node['orelse'], scope)
            return

        if op == 'For':
            iter_val = yield from self.step_expr(node['iter'], scope)
            broke = False
            for item in iter_val:
                yield from self._assign(node['target'], item, scope)
                try:
                    yield from self.step_block(node['body'], scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self.step_block(node['orelse'], scope)
            return

        if op == 'AsyncFor':
            ait_val = yield from self.step_expr(node['iter'], scope)
            ait = ait_val.__aiter__()
            broke = False
            while True:
                try:
                    item = yield ('await', ait.__anext__())
                except StopAsyncIteration:
                    break
                yield from self._assign(node['target'], item, scope)
                try:
                    yield from self.step_block(node['body'], scope)
                except _Continue:
                    continue
                except _Break:
                    broke = True
                    break
            if not broke:
                yield from self.step_block(node['orelse'], scope)
            return

        if op == 'With':
            yield from self._do_with(node['items'], 0, node['body'], scope, False)
            return

        if op == 'AsyncWith':
            yield from self._do_with(node['items'], 0, node['body'], scope, True)
            return

        if op == 'Try':
            yield from self._do_try(node, scope)
            return

        if op == 'Import':
            for alias in node['names']:
                name = self.s(alias['name'])
                asname = self.s(alias['asname'])
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
            module = self.s(node['module']) or ''
            level = node['level']
            fromlist = tuple(self.s(a['name']) for a in node['names'])
            mod = __import__(module, scope.globals, None, fromlist, level)
            for alias in node['names']:
                name = self.s(alias['name'])
                asname = self.s(alias['asname'])
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
        op = node['op']

        if op == 'Constant':
            return self.k(node['idx'])

        if op == 'Name':
            return scope.get(self.s(node['id']))

        if op == 'BinOp':
            l = yield from self.step_expr(node['left'], scope)
            r = yield from self.step_expr(node['right'], scope)
            return _BIN_OPS[node['op2']](l, r)

        if op == 'UnaryOp':
            v = yield from self.step_expr(node['operand'], scope)
            return _UNARY_OPS[node['op2']](v)

        if op == 'BoolOp':
            if node['op2'] == 'And':
                last = True
                for vn in node['values']:
                    last = yield from self.step_expr(vn, scope)
                    if not last:
                        return last
                return last
            else:
                last = False
                for vn in node['values']:
                    last = yield from self.step_expr(vn, scope)
                    if last:
                        return last
                return last

        if op == 'Compare':
            left = yield from self.step_expr(node['left'], scope)
            for cmp_op, cn in zip(node['ops'], node['comparators']):
                right = yield from self.step_expr(cn, scope)
                if not _CMP_OPS[cmp_op](left, right):
                    return False
                left = right
            return True

        if op == 'IfExp':
            test = yield from self.step_expr(node['test'], scope)
            if test:
                v = yield from self.step_expr(node['body'], scope)
            else:
                v = yield from self.step_expr(node['orelse'], scope)
            return v

        if op == 'Call':
            func = yield from self.step_expr(node['func'], scope)
            # Intercept zero-arg super() so it works without the magic cell.
            if (func is builtins.super
                    and not node['args'] and not node['keywords']):
                cls_v = self._lookup_magic(scope, '__pyguard_class__')
                self_v = self._lookup_magic(scope, '__pyguard_self__')
                if cls_v is not None and self_v is not None:
                    return builtins.super(cls_v, self_v)
                return builtins.super()
            args = []
            for a in node['args']:
                if a['op'] == 'Starred':
                    sv = yield from self.step_expr(a['value'], scope)
                    args.extend(sv)
                else:
                    av = yield from self.step_expr(a, scope)
                    args.append(av)
            kwargs = {}
            for kw in node['keywords']:
                arg_idx = kw['arg']
                if arg_idx is None or arg_idx < 0:
                    kv = yield from self.step_expr(kw['value'], scope)
                    kwargs.update(kv)
                else:
                    kv = yield from self.step_expr(kw['value'], scope)
                    kwargs[self.s(arg_idx)] = kv
            return func(*args, **kwargs)

        if op == 'Attribute':
            v = yield from self.step_expr(node['value'], scope)
            return getattr(v, self.s(node['attr']))

        if op == 'Subscript':
            v = yield from self.step_expr(node['value'], scope)
            sl = yield from self._eval_slice(node['slice'], scope)
            return v[sl]

        if op == 'Slice':
            return (yield from self._eval_slice(node, scope))

        if op == 'List':
            elts = []
            for e in node['elts']:
                if e['op'] == 'Starred':
                    sv = yield from self.step_expr(e['value'], scope)
                    elts.extend(sv)
                else:
                    ev = yield from self.step_expr(e, scope)
                    elts.append(ev)
            return elts

        if op == 'Tuple':
            elts = []
            for e in node['elts']:
                if e['op'] == 'Starred':
                    sv = yield from self.step_expr(e['value'], scope)
                    elts.extend(sv)
                else:
                    ev = yield from self.step_expr(e, scope)
                    elts.append(ev)
            return tuple(elts)

        if op == 'Set':
            out = set()
            for e in node['elts']:
                if e['op'] == 'Starred':
                    sv = yield from self.step_expr(e['value'], scope)
                    out.update(sv)
                else:
                    ev = yield from self.step_expr(e, scope)
                    out.add(ev)
            return out

        if op == 'Dict':
            d = {}
            for kn, vn in zip(node['keys'], node['values']):
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
            args_def = node['args']
            defaults = []
            for d in args_def['defaults']:
                dv = yield from self.step_expr(d, scope)
                defaults.append(dv)
            kw_defaults = []
            for kd in args_def['kw_defaults']:
                if kd is None:
                    kw_defaults.append(_MISSING)
                else:
                    kdv = yield from self.step_expr(kd, scope)
                    kw_defaults.append(kdv)
            # Wrap body as Return statement so the function path works
            wrapped = [{'op': 'Return', 'value': node['body']}]
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
            for vn in node['values']:
                v = yield from self.step_expr(vn, scope)
                parts.append(v if isinstance(v, str) else str(v))
            return ''.join(parts)

        if op == 'FormattedValue':
            v = yield from self.step_expr(node['value'], scope)
            conv = node['conversion']
            if conv == 115:
                v = str(v)
            elif conv == 114:
                v = repr(v)
            elif conv == 97:
                v = ascii(v)
            spec = ''
            if node['format_spec'] is not None:
                spec = yield from self.step_expr(node['format_spec'], scope)
            return format(v, spec)

        if op == 'Yield':
            v = None
            if node['value'] is not None:
                v = yield from self.step_expr(node['value'], scope)
            sent = yield ('yield', v)
            return sent

        if op == 'YieldFrom':
            v = yield from self.step_expr(node['value'], scope)
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
            v = yield from self.step_expr(node['value'], scope)
            r = yield ('await', v)
            return r

        if op == 'NamedExpr':
            v = yield from self.step_expr(node['value'], scope)
            yield from self._assign(node['target'], v, scope)
            return v

        if op == 'Starred':
            return (yield from self.step_expr(node['value'], scope))

        raise NotImplementedError("step_expr: " + op)

    # ---- assignment / lvalue helpers ----

    def _assign(self, target, value, scope):
        if False:
            yield
        op = target['op']
        if op == 'Name':
            scope.set(self.s(target['id']), value)
            return
        if op == 'Tuple' or op == 'List':
            elts = target['elts']
            star_idx = None
            for i, e in enumerate(elts):
                if e['op'] == 'Starred':
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
                    elts[star_idx]['value'],
                    vlist[n_before:n_before + star_count],
                    scope)
                for j in range(n_after):
                    yield from self._assign(
                        elts[star_idx + 1 + j],
                        vlist[n_before + star_count + j],
                        scope)
            return
        if op == 'Attribute':
            obj = yield from self.step_expr(target['value'], scope)
            setattr(obj, self.s(target['attr']), value)
            return
        if op == 'Subscript':
            obj = yield from self.step_expr(target['value'], scope)
            sl = yield from self._eval_slice(target['slice'], scope)
            obj[sl] = value
            return
        if op == 'Starred':
            yield from self._assign(target['value'], value, scope)
            return
        raise NotImplementedError("_assign: " + op)

    def _delete(self, target, scope):
        if False:
            yield
        op = target['op']
        if op == 'Name':
            scope.delete(self.s(target['id']))
            return
        if op == 'Attribute':
            obj = yield from self.step_expr(target['value'], scope)
            delattr(obj, self.s(target['attr']))
            return
        if op == 'Subscript':
            obj = yield from self.step_expr(target['value'], scope)
            sl = yield from self._eval_slice(target['slice'], scope)
            del obj[sl]
            return
        if op == 'Tuple' or op == 'List':
            for e in target['elts']:
                yield from self._delete(e, scope)
            return
        raise NotImplementedError("_delete: " + op)

    def _load_target(self, target, scope):
        if False:
            yield
        op = target['op']
        if op == 'Name':
            return scope.get(self.s(target['id']))
        if op == 'Attribute':
            obj = yield from self.step_expr(target['value'], scope)
            return getattr(obj, self.s(target['attr']))
        if op == 'Subscript':
            obj = yield from self.step_expr(target['value'], scope)
            sl = yield from self._eval_slice(target['slice'], scope)
            return obj[sl]
        raise NotImplementedError("_load_target: " + op)

    def _eval_slice(self, node, scope):
        if False:
            yield
        if node['op'] == 'Slice':
            l = None
            u = None
            s = None
            if node['lower'] is not None:
                l = yield from self.step_expr(node['lower'], scope)
            if node['upper'] is not None:
                u = yield from self.step_expr(node['upper'], scope)
            if node['step'] is not None:
                s = yield from self.step_expr(node['step'], scope)
            return slice(l, u, s)
        if node['op'] == 'Tuple':
            elts = []
            for e in node['elts']:
                if e['op'] == 'Slice':
                    elts.append((yield from self._eval_slice(e, scope)))
                else:
                    elts.append((yield from self.step_expr(e, scope)))
            return tuple(elts)
        return (yield from self.step_expr(node, scope))

    # ---- function / class definition ----

    def _define_function(self, node, scope, is_async):
        if False:
            yield
        is_gen = self._contains_yield(node['body'])
        # Async generators (PEP 525) are not supported in this version.
        if is_async:
            is_gen = False  # treat any yield in async def as syntax-irrelevant
        args_def = node['args']
        defaults = []
        for d in args_def['defaults']:
            dv = yield from self.step_expr(d, scope)
            defaults.append(dv)
        kw_defaults = []
        for kd in args_def['kw_defaults']:
            if kd is None:
                kw_defaults.append(_MISSING)
            else:
                kdv = yield from self.step_expr(kd, scope)
                kw_defaults.append(kdv)
        func = _UFunction(
            self, self.s(node['name']), args_def, node['body'],
            scope, is_gen, is_async, defaults, kw_defaults)
        # Evaluate annotations
        ann = {}
        for a in (args_def['posonlyargs'] + args_def['args']
                  + args_def['kwonlyargs']):
            if a['annotation'] is not None:
                ann[self.s(a['arg'])] = (
                    yield from self.step_expr(a['annotation'], scope))
        if args_def['vararg'] is not None and args_def['vararg']['annotation'] is not None:
            ann[self.s(args_def['vararg']['arg'])] = (
                yield from self.step_expr(args_def['vararg']['annotation'], scope))
        if args_def['kwarg'] is not None and args_def['kwarg']['annotation'] is not None:
            ann[self.s(args_def['kwarg']['arg'])] = (
                yield from self.step_expr(args_def['kwarg']['annotation'], scope))
        if node['returns'] is not None:
            ann['return'] = yield from self.step_expr(node['returns'], scope)
        func.__annotations__ = ann
        # Decorators
        decos = []
        for d in node['decorator_list']:
            dv = yield from self.step_expr(d, scope)
            decos.append(dv)
        decorated = func
        for d in reversed(decos):
            decorated = d(decorated)
        scope.set(self.s(node['name']), decorated)

    def _define_class(self, node, scope):
        if False:
            yield
        name = self.s(node['name'])
        bases = []
        for b in node['bases']:
            bv = yield from self.step_expr(b, scope)
            bases.append(bv)
        kw = {}
        for k in node['keywords']:
            kv = yield from self.step_expr(k['value'], scope)
            arg_idx = k['arg']
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
        yield from self.step_block(node['body'], cls_scope)
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
        for d in node['decorator_list']:
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
            _drive_sync(self.step_block(func.body, local))
        except _Return as r:
            return r.value
        return None

    def _bind_args(self, func, args, kwargs, local):
        a = func.args_def
        posonly = a['posonlyargs']
        pos = a['args']
        kwonly = a['kwonlyargs']
        vararg = a['vararg']
        kwarg = a['kwarg']

        all_pos = posonly + pos
        n_pos = len(all_pos)
        defaults = func.defaults
        n_defaults = len(defaults)

        bound = {}
        kwargs = dict(kwargs)
        n_args = len(args)

        # 1. positional → posonly+pos
        for i in range(min(n_args, n_pos)):
            bound[self.s(all_pos[i]['arg'])] = args[i]

        # 2. extra positional → vararg (or error)
        if n_args > n_pos:
            if vararg is not None:
                bound[self.s(vararg['arg'])] = tuple(args[n_pos:])
            else:
                raise TypeError(
                    "{}() takes {} positional arguments but {} were given".format(
                        func.__name__, n_pos, n_args))
        elif vararg is not None:
            bound[self.s(vararg['arg'])] = ()

        # 3. keyword → pos (excluding posonly) and kwonly
        pos_names = {self.s(p['arg']) for p in pos}
        kwonly_names = [self.s(p['arg']) for p in kwonly]
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
            name = self.s(p['arg'])
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
            bound[self.s(kwarg['arg'])] = dict(kwargs)
        elif kwargs:
            raise TypeError(
                "{}() got unexpected keyword arguments: {}".format(
                    func.__name__, list(kwargs)))

        local.vars.update(bound)

    # ---- generator / coroutine host wrappers ----

    def _make_host_generator(self, func, local):
        inner = self.step_block(func.body, local)
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
        inner = self.step_block(func.body, local)
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
            yield from self.step_block(body, scope)
            return
        item = items[idx]
        ctx = yield from self.step_expr(item['context_expr'], scope)
        if is_async:
            entered = yield ('await', ctx.__aenter__())
            if item['optional_vars'] is not None:
                yield from self._assign(item['optional_vars'], entered, scope)
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
            if item['optional_vars'] is not None:
                yield from self._assign(item['optional_vars'], entered, scope)
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
                yield from self.step_block(node['body'], scope)
            except (_Return, _Break, _Continue) as ctrl:
                pending_ctrl = ctrl
            except BaseException as e:
                handled = False
                for handler in node['handlers']:
                    htype = None
                    if handler['type'] is not None:
                        htype = yield from self.step_expr(
                            handler['type'], scope)
                    if htype is None or isinstance(e, htype):
                        handled = True
                        name_idx = handler['name']
                        name = self.s(name_idx) if name_idx is not None and name_idx >= 0 else None
                        if name is not None:
                            scope.set(name, e)
                        try:
                            try:
                                yield from self.step_block(
                                    handler['body'], scope)
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
                    yield from self.step_block(node['orelse'], scope)
                except (_Return, _Break, _Continue) as ctrl:
                    pending_ctrl = ctrl
                except BaseException as e:
                    pending_exc = e
        finally:
            try:
                yield from self.step_block(node['finalbody'], scope)
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
            node['generators'][0]['iter'], scope)
        comp_scope = Scope(parent=scope)
        yield from self._comp_loop(node, 0, comp_scope, kind, result, first_iter)
        return result

    def _comp_loop(self, node, gi, comp_scope, kind, result, first_iter):
        if False:
            yield
        gen = node['generators'][gi]
        if gi == 0:
            iter_val = first_iter
        else:
            iter_val = yield from self.step_expr(gen['iter'], comp_scope)
        for item in iter_val:
            yield from self._assign(gen['target'], item, comp_scope)
            skip = False
            for cond in gen['ifs']:
                cv = yield from self.step_expr(cond, comp_scope)
                if not cv:
                    skip = True
                    break
            if skip:
                continue
            if gi + 1 < len(node['generators']):
                yield from self._comp_loop(
                    node, gi + 1, comp_scope, kind, result, None)
            else:
                if kind == 'list':
                    v = yield from self.step_expr(node['elt'], comp_scope)
                    result.append(v)
                elif kind == 'set':
                    v = yield from self.step_expr(node['elt'], comp_scope)
                    result.add(v)
                else:
                    kv = yield from self.step_expr(node['key'], comp_scope)
                    vv = yield from self.step_expr(node['value'], comp_scope)
                    result[kv] = vv

    def _eval_genexp(self, node, scope):
        if False:
            yield
        # Eager (build a list, return iter). Adequate for our test surface.
        result = []
        first_iter = yield from self.step_expr(
            node['generators'][0]['iter'], scope)
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
        if isinstance(node, list):
            for x in node:
                if self._walk_for_yield(x):
                    return True
            return False
        if not isinstance(node, dict):
            return False
        op = node.get('op')
        if op in ('FunctionDef', 'AsyncFunctionDef', 'Lambda', 'ClassDef'):
            return False
        if op in ('Yield', 'YieldFrom'):
            return True
        for k, v in node.items():
            if k == 'op':
                continue
            if self._walk_for_yield(v):
                return True
        return False


# --- entry points --------------------------------------------------------

def _decode_const(c):
    """Decode a JSON-encoded constant from build_ir.compile_to_json."""
    t = c['t']
    if t == 'none':     return None
    if t == 'true':     return True
    if t == 'false':    return False
    if t == 'int':      return int(c['v'])
    if t == 'float':    return float(c['v'])
    if t == 'str':      return c['v']
    if t == 'bytes':    return bytes(c['v'])
    if t == 'complex':  return complex(float(c['r']), float(c['i']))
    if t == 'ellipsis': return Ellipsis
    if t == 'tuple':    return tuple(_decode_const(x) for x in c['v'])
    if t == 'frozenset': return frozenset(_decode_const(x) for x in c['v'])
    raise ValueError("unknown const tag: " + t)


def run_ir(ir, module_name='__main__'):
    """Run a v5 IR dict (already-decoded form: consts are Python objects)."""
    interp = Interp(ir['strings'], ir['consts'])
    interp.run(ir['tree'], module_name)


def run_json_ir(jir, module_name='__main__'):
    """Run a JSON-form IR dict (consts are tagged dicts)."""
    consts = [_decode_const(c) for c in jir['consts']]
    interp = Interp(jir['strings'], consts)
    interp.run(jir['tree'], module_name)


# --- inline JSON parser -------------------------------------------------
#
# v5.1 hardening: stage2 loads the decrypted IR via this hand-rolled
# recursive-descent parser instead of `json.loads`. The motivating attack
# (attack 11) was a one-line `json.loads` monkey-patch that captured the
# IR dict the moment stage2 decoded it. Using a local parser with a
# per-build randomized entry-point name forces an attacker to either
#   (a) frame-walk during interpretation and dump locals of Interp.run
#       (attack 12), or
#   (b) statically locate and patch this function inside the stub
#       (defeated by the outer encryption — by the time this function
#       exists as bytecode, the stub has already decrypted it).
#
# This parser is NOT a fully general JSON implementation — it only
# handles the subset the IR uses: objects, arrays, strings (including
# \uXXXX and \\ \/ \" \b \f \n \r \t escapes), integers, floats,
# true/false/null. It intentionally does not allocate temporary strings
# for keys beyond what the dict needs, to limit the set of observable
# string-pool events an attacker could listen to.

def _pg_parse_json(src):
    """Parse a JSON string into Python dict/list/str/int/float/None.

    Same subset of JSON that compile_to_json emits in build_ir.py.
    Runs in O(n), single-pass, no regex, no stdlib json import.
    """
    idx = [0]
    n = len(src)

    def _skip_ws():
        i = idx[0]
        while i < n:
            c = src[i]
            if c == ' ' or c == '\t' or c == '\n' or c == '\r':
                i += 1
            else:
                break
        idx[0] = i

    def _parse_string():
        i = idx[0]
        if src[i] != '"':
            raise ValueError("expected string at " + str(i))
        i += 1
        out = []
        while i < n:
            c = src[i]
            if c == '"':
                idx[0] = i + 1
                return ''.join(out)
            if c == '\\':
                i += 1
                if i >= n:
                    raise ValueError("bad escape at EOF")
                e = src[i]
                if e == '"' or e == '\\' or e == '/':
                    out.append(e); i += 1
                elif e == 'n':
                    out.append('\n'); i += 1
                elif e == 't':
                    out.append('\t'); i += 1
                elif e == 'r':
                    out.append('\r'); i += 1
                elif e == 'b':
                    out.append('\b'); i += 1
                elif e == 'f':
                    out.append('\f'); i += 1
                elif e == 'u':
                    if i + 5 > n:
                        raise ValueError("short \\u escape")
                    hex4 = src[i+1:i+5]
                    cp = int(hex4, 16)
                    # Handle UTF-16 surrogate pair.
                    if 0xD800 <= cp <= 0xDBFF and i + 11 <= n and src[i+5:i+7] == '\\u':
                        hi = cp
                        lo = int(src[i+7:i+11], 16)
                        cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                        out.append(chr(cp))
                        i += 11
                    else:
                        out.append(chr(cp))
                        i += 5
                else:
                    raise ValueError("bad escape \\" + e)
            else:
                out.append(c)
                i += 1
        raise ValueError("unterminated string")

    def _parse_number():
        i = idx[0]
        start = i
        if src[i] == '-':
            i += 1
        while i < n:
            c = src[i]
            if ('0' <= c <= '9') or c == '.' or c == 'e' or c == 'E' or c == '+' or c == '-':
                i += 1
            else:
                break
        frag = src[start:i]
        idx[0] = i
        if '.' in frag or 'e' in frag or 'E' in frag:
            return float(frag)
        return int(frag)

    def _parse_value():
        _skip_ws()
        i = idx[0]
        if i >= n:
            raise ValueError("unexpected EOF")
        c = src[i]
        if c == '{':
            idx[0] = i + 1
            d = {}
            _skip_ws()
            if idx[0] < n and src[idx[0]] == '}':
                idx[0] += 1
                return d
            while True:
                _skip_ws()
                k = _parse_string()
                _skip_ws()
                if idx[0] >= n or src[idx[0]] != ':':
                    raise ValueError("expected ':'")
                idx[0] += 1
                v = _parse_value()
                d[k] = v
                _skip_ws()
                if idx[0] >= n:
                    raise ValueError("unterminated object")
                if src[idx[0]] == ',':
                    idx[0] += 1
                    continue
                if src[idx[0]] == '}':
                    idx[0] += 1
                    return d
                raise ValueError("expected ',' or '}'")
        if c == '[':
            idx[0] = i + 1
            lst = []
            _skip_ws()
            if idx[0] < n and src[idx[0]] == ']':
                idx[0] += 1
                return lst
            while True:
                lst.append(_parse_value())
                _skip_ws()
                if idx[0] >= n:
                    raise ValueError("unterminated array")
                if src[idx[0]] == ',':
                    idx[0] += 1
                    continue
                if src[idx[0]] == ']':
                    idx[0] += 1
                    return lst
                raise ValueError("expected ',' or ']'")
        if c == '"':
            return _parse_string()
        if c == 't':
            if src[i:i+4] == 'true':
                idx[0] = i + 4
                return True
            raise ValueError("bad literal at " + str(i))
        if c == 'f':
            if src[i:i+5] == 'false':
                idx[0] = i + 5
                return False
            raise ValueError("bad literal at " + str(i))
        if c == 'n':
            if src[i:i+4] == 'null':
                idx[0] = i + 4
                return None
            raise ValueError("bad literal at " + str(i))
        if c == '-' or ('0' <= c <= '9'):
            return _parse_number()
        raise ValueError("unexpected char " + repr(c) + " at " + str(i))

    result = _parse_value()
    _skip_ws()
    if idx[0] != n:
        raise ValueError("trailing data at " + str(idx[0]))
    return result


# --- self-test entry point ----------------------------------------------
if __name__ == '__main__':
    import json
    import os
    import io

    # Smoke test: read source from argv[1], compile via build_ir, run.
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import build_ir as _bi  # noqa

    if len(sys.argv) < 2:
        print("usage: runtime_interp.py <source.py>")
        sys.exit(2)
    with open(sys.argv[1]) as f:
        src = f.read()
    ir = _bi.compile_to_ir(src)
    run_ir(ir)

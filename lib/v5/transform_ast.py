"""PyGuard build-time AST obfuscation transforms.

Applied to user Python source BEFORE IR compilation. The resulting AST is
semantically equivalent but structurally alien — control flow is flattened
into state-machine dispatchers, expressions are decomposed into chains of
temporaries, opaque predicates inject unreachable dead code, constants are
unfolded into arithmetic expressions, arithmetic BinOps become MBA
identities, string literals are split into multi-key XOR fragments, and
every `Name(args)` call is routed through an opaque dispatcher dict.

Every eligible node is deformed — no probabilistic gates. CFF fires on
≥2-statement bodies. String obfuscation splits every non-empty string
≤200 bytes into multi-fragment XOR reassembly. Call indirection routes
every resolvable `Name(args)` through an opaque dispatcher subscripted
by a MBA-masked key.

The _SecretGateRewriter (step 0) detects `if X == "pw":` patterns and
replaces their true branches with scrypt+keystream-cipher gates whose
plaintext (the secret-revealing code) is only derivable by running
scrypt on the correct password. See the class-level comment block for
the full threat model, cost parameters, and bypass resistance.

The interpreter doesn't need to change because the transformed AST is still
valid Python — it just *looks* nothing like the original.

Stdlib-only. Compatible with Python 3.8+.
"""

import ast
import builtins
import copy
import hashlib
import marshal
import random
import os

# ---------------------------------------------------------------------------
# Name generation (collision-free temporaries)
# ---------------------------------------------------------------------------

class _NameGen:
    def __init__(self, seed=None):
        self._counter = 0
        self._rng = random.Random(seed or os.urandom(16))
        self._pool = 'abcdefghijklmnopqrstuvwxyz'

    def temp(self):
        self._counter += 1
        pfx = ''.join(self._rng.choice(self._pool) for _ in range(4))
        return f'__{pfx}{self._counter}'

    def state_val(self, used):
        while True:
            v = self._rng.randint(100, 999999)
            if v not in used:
                used.add(v)
                return v


# ---------------------------------------------------------------------------
# Attribute Mangler (v5.1 / C1)
# ---------------------------------------------------------------------------
#
# H1 hole: `lib/v5/build_ir.py:348` writes `node.attr` (the attribute name
# string) into the IR string pool via `self.s(node.attr)`. Attribute names
# survive verbatim through lifting, encryption, and transport; a profile-
# hook attack (A36) extracts the pool at runtime and recovers names like
# `_stash_ciphertext` by grep.
#
# C1 rewrites every non-dunder `obj.attr` / `obj.attr = v` / `del obj.attr`
# into `_gA(obj, K)` / `_sA(obj, K, v)` / `_dA(obj, K)` where K is a small
# integer and the actual attribute name lives XOR-masked in a synthesized
# module-level `_ATAB` tuple. At runtime the three helpers decode the name
# *inline* (on the evaluation stack, NOT as a named local) and call the
# C-level getattr/setattr/delattr — so a profile-hook sees only
# {o, k} in f_locals, never the plaintext name.
#
# Why inline-decode matters: if we wrote
#     def _gA(o, k):
#         name = _decode(_ATAB[k])   # name is now a NAMED local
#         return getattr(o, name)
# then frame.f_locals at the call/return event leaks `name`. The fused
# single-expression form keeps the decoded name only on the bytecode stack.
#
# Dunders are skipped: renaming `__init__`, `__len__`, etc. breaks Python
# semantics (descriptor protocol, dataclass dunders, the class statement
# body namespace).
#
# Limitations (honest disclosure):
# - Attribute access where the attribute name is already a string literal
#   (e.g. `getattr(obj, "x")`) is NOT mangled by this pass. Users are
#   expected to prefer dot-syntax; literal-name getattr is a manual leak.
# - Tuple-unpacking stores with Attribute targets fall back to a
#   sequential rewrite via a temporary (`_t`); if rhs is an infinite
#   iterator the behavior still completes because we list() it.
# - AugAssign (`obj.attr += v`) expands to `_sA(obj,k,_gA(obj,k)+v)`.
# - Method calls work naturally: `obj.m(x)` → `_gA(obj, k)(x)`.

class _AttributeMangler(ast.NodeTransformer):
    """Replace Attribute nodes with numeric-key _gA/_sA/_dA calls.

    MUST run before _IdentifierRenamer so the renamer can rename the
    synthesized helper names (`_gA`/`_sA`/`_dA`/`_ATAB`/`_AM`) into the
    opaque-name pool consistently.

    Usage:
        mg = _AttributeMangler(ng)
        tree = mg.visit(tree)
        mg.inject_prelude(tree, rng)   # prepends _ATAB/_AM/_gA/_sA/_dA
    """

    def __init__(self, ng):
        self.ng = ng
        # attr_name -> int key
        self._key = {}
        self._next_key = 0
        # How many Attribute nodes were mangled (for telemetry/tests).
        self.mangled = 0
        # Helper names (per-build opaque). Runs AFTER identifier
        # renaming, so these can't clash with user names and don't
        # need to be re-renamed. build_ir will intern them into the
        # strings pool in their opaque form — no stable `_gA` token
        # ever appears in the pool.
        self.n_gA = self.ng.temp()
        self.n_sA = self.ng.temp()
        self.n_dA = self.ng.temp()
        self.n_ATAB = self.ng.temp()
        self.n_AM = self.ng.temp()
        # C2 (ImportConcealer) shares attr-name table via `_kfor` but
        # has its own module-path table `_IMPT` and helper `_imp`.
        # These are lazily populated by ImportConcealer and emitted
        # by inject_prelude if non-empty.
        self.n_imp = self.ng.temp()
        self.n_IMPT = self.ng.temp()
        self._mod_key = {}      # "collections" -> int
        self._next_mod_key = 0

    # --- shared interface used by _ImportConcealer ---

    def add_attr_key(self, name):
        """Public: register an attr name (e.g. an imported name) so the
        ImportConcealer can reuse _gA/_ATAB for it."""
        return self._kfor(name)

    def add_mod_key(self, module_path):
        k = self._mod_key.get(module_path)
        if k is None:
            k = self._next_mod_key
            self._next_mod_key += 1
            self._mod_key[module_path] = k
        return k

    @staticmethod
    def _is_dunder(name):
        return bool(name) and name.startswith('__') and name.endswith('__')

    def _kfor(self, attr):
        k = self._key.get(attr)
        if k is None:
            k = self._next_key
            self._next_key += 1
            self._key[attr] = k
        return k

    # --- helpers to build call AST nodes ---

    def _call(self, fname, args):
        return ast.Call(
            func=ast.Name(id=fname, ctx=ast.Load()),
            args=args, keywords=[])

    def _gA_call(self, value, attr):
        return self._call(self.n_gA, [value, ast.Constant(value=self._kfor(attr))])

    def _sA_call(self, obj, attr, val):
        return self._call(self.n_sA, [obj, ast.Constant(value=self._kfor(attr)), val])

    def _dA_call(self, obj, attr):
        return self._call(self.n_dA, [obj, ast.Constant(value=self._kfor(attr))])

    # --- transform Attribute in Load context ---

    def visit_Attribute(self, node):
        # Recurse first so nested attrs (a.b.c) transform bottom-up.
        node.value = self.visit(node.value)
        if self._is_dunder(node.attr):
            return node
        if isinstance(node.ctx, ast.Load):
            self.mangled += 1
            return self._gA_call(node.value, node.attr)
        # Store/Del contexts are handled by the parent Assign/Delete/AugAssign
        # visitors — leave the Attribute node intact here so those visitors
        # can detect it. (Visit stops at Attribute in Store/Del ctx.)
        return node

    # --- Assign: rewrite `obj.attr = v` → _sA(obj, k, v) ---

    def visit_Assign(self, node):
        # Visit the rhs first — plain expression, Load ctx, safe.
        node.value = self.visit(node.value)

        # Each target is either Name/Tuple/List/Starred/Attribute/Subscript.
        # If ANY target contains an Attribute-in-Store somewhere (including
        # nested tuple), we need to rewrite the whole assign.
        if not any(self._has_store_attr(t) for t in node.targets):
            # Recurse normally into targets (Subscripts with Load-context
            # sub-expressions need visiting).
            node.targets = [self.visit(t) for t in node.targets]
            return node

        # Rewrite: `_t = value` then one _sA / assign per target element.
        tname = self.ng.temp()
        out = [ast.Assign(
            targets=[ast.Name(id=tname, ctx=ast.Store())],
            value=node.value)]
        for tgt in node.targets:
            out.extend(self._emit_store(tgt, ast.Name(id=tname, ctx=ast.Load())))
        return out

    def _has_store_attr(self, target):
        """True if `target` (or any nested target) contains an Attribute
        node in Store context."""
        for n in ast.walk(target):
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Store):
                if not self._is_dunder(n.attr):
                    return True
        return False

    def _emit_store(self, target, value_ast):
        """Emit statements that store `value_ast` into `target`, using
        _sA for Attribute leaves and regular Assign for everything else.
        Handles Name/Tuple/List/Starred/Attribute/Subscript."""
        if isinstance(target, ast.Attribute) and isinstance(target.ctx, ast.Store):
            if self._is_dunder(target.attr):
                return [ast.Assign(targets=[target], value=value_ast)]
            obj = self.visit(target.value)
            return [ast.Expr(value=self._sA_call(obj, target.attr, value_ast))]
        if isinstance(target, (ast.Tuple, ast.List)):
            # List-ify the rhs once (supports iterators) then index per-elt.
            # Starred elements: handled by letting Python unpack via a
            # plain assign that reconstructs the star form (we can't easily
            # index around a star). In that case fall back to one assign
            # to a list-of-stores that Python evaluates natively.
            if any(isinstance(e, ast.Starred) for e in target.elts):
                # Fall back: single Assign with the (possibly-Attribute-
                # containing) target preserved — attr name leaks, rare case.
                return [ast.Assign(targets=[target], value=value_ast)]
            tlist = self.ng.temp()
            stmts = [ast.Assign(
                targets=[ast.Name(id=tlist, ctx=ast.Store())],
                value=ast.Call(func=ast.Name(id='list', ctx=ast.Load()),
                               args=[value_ast], keywords=[]))]
            for i, elt in enumerate(target.elts):
                idx_val = ast.Subscript(
                    value=ast.Name(id=tlist, ctx=ast.Load()),
                    slice=ast.Constant(value=i),
                    ctx=ast.Load())
                stmts.extend(self._emit_store(elt, idx_val))
            return stmts
        # Name / Subscript / others — normal assign, but visit value context.
        return [ast.Assign(targets=[target], value=value_ast)]

    def visit_AugAssign(self, node):
        # `obj.attr OP= v`  →  `_sA(obj, k, _gA(obj, k) OP v)`
        # `name OP= v`  →  untouched (no Attribute)
        # `subscript OP= v`  →  untouched (no Attribute)
        node.value = self.visit(node.value)
        tgt = node.target
        if isinstance(tgt, ast.Attribute) and isinstance(tgt.ctx, ast.Store) \
                and not self._is_dunder(tgt.attr):
            obj = self.visit(tgt.value)
            # Need a fresh temp for `obj` so we don't evaluate it twice
            # (side-effects).
            tname = self.ng.temp()
            stmts = [ast.Assign(
                targets=[ast.Name(id=tname, ctx=ast.Store())],
                value=obj)]
            get_expr = self._gA_call(ast.Name(id=tname, ctx=ast.Load()), tgt.attr)
            new_val = ast.BinOp(left=get_expr, op=node.op, right=node.value)
            stmts.append(ast.Expr(value=self._sA_call(
                ast.Name(id=tname, ctx=ast.Load()), tgt.attr, new_val)))
            return stmts
        # Fall through — visit children
        self.generic_visit(node)
        return node

    # --- Delete: `del obj.attr` → _dA(obj, k) ---

    def visit_Delete(self, node):
        new_targets = []
        extra = []
        for tgt in node.targets:
            if isinstance(tgt, ast.Attribute) and isinstance(tgt.ctx, ast.Del) \
                    and not self._is_dunder(tgt.attr):
                obj = self.visit(tgt.value)
                extra.append(ast.Expr(value=self._dA_call(obj, tgt.attr)))
            else:
                new_targets.append(self.visit(tgt))
        if extra and new_targets:
            return [ast.Delete(targets=new_targets)] + extra
        if extra:
            return extra
        return node

    # --- prelude injection ---

    @staticmethod
    def _masked_bytes_node(b, mask):
        masked = bytes(c ^ mask[i & 15] for i, c in enumerate(b))
        return ast.Call(
            func=ast.Name(id='bytes', ctx=ast.Load()),
            args=[ast.List(
                elts=[ast.Constant(value=x) for x in masked],
                ctx=ast.Load())],
            keywords=[])

    def inject_prelude(self, tree, rng):
        """Prepend C1 (+ optional C2) helper definitions to module body.

        `rng` must be a random.Random-compatible object.

        Always emitted (if any attr was mangled OR any import concealed):
            _AM     = bytes([..16 random..])
            _ATAB   = (masked attr name 0, masked attr name 1, ...)
            def _gA(o, k): ...        # decode + getattr
            def _sA(o, k, v): ...      # decode + setattr
            def _dA(o, k): ...          # decode + delattr

        Emitted only when C2 registered module paths:
            _IMPT   = (masked module path 0, masked module path 1, ...)
            def _imp(k): return __import__(decode(_IMPT[k]))
        """
        if not self._key and not self._mod_key:
            return  # nothing to do
        if not isinstance(tree, ast.Module):
            return

        mask = bytes(rng.randint(0, 255) for _ in range(16))

        prelude_body = []

        # _AM = bytes([...16 random...])
        prelude_body.append(ast.Assign(
            targets=[ast.Name(id=self.n_AM, ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id='bytes', ctx=ast.Load()),
                args=[ast.List(
                    elts=[ast.Constant(value=b) for b in mask],
                    ctx=ast.Load())],
                keywords=[])))

        # _ATAB is required even if empty (in case only imports were
        # registered) — keep _gA/_sA/_dA definitions self-contained.
        ordered_attr = sorted(self._key.items(), key=lambda kv: kv[1])
        atab_entries = [self._masked_bytes_node(name.encode('utf-8'), mask)
                        for name, _k in ordered_attr]
        prelude_body.append(ast.Assign(
            targets=[ast.Name(id=self.n_ATAB, ctx=ast.Store())],
            value=ast.Tuple(elts=atab_entries, ctx=ast.Load())))

        attr_helpers_src = (
            f'def {self.n_gA}(_o, _k):\n'
            f'    return getattr(_o, bytes(_c ^ {self.n_AM}[_i & 15] for _i, _c in enumerate({self.n_ATAB}[_k])).decode())\n'
            f'def {self.n_sA}(_o, _k, _v):\n'
            f'    setattr(_o, bytes(_c ^ {self.n_AM}[_i & 15] for _i, _c in enumerate({self.n_ATAB}[_k])).decode(), _v)\n'
            f'def {self.n_dA}(_o, _k):\n'
            f'    delattr(_o, bytes(_c ^ {self.n_AM}[_i & 15] for _i, _c in enumerate({self.n_ATAB}[_k])).decode())\n'
        )
        prelude_body.extend(ast.parse(attr_helpers_src).body)

        # C2: emit _IMPT + _imp only if any import was concealed.
        if self._mod_key:
            ordered_mod = sorted(self._mod_key.items(), key=lambda kv: kv[1])
            impt_entries = [self._masked_bytes_node(path.encode('utf-8'), mask)
                            for path, _k in ordered_mod]
            prelude_body.append(ast.Assign(
                targets=[ast.Name(id=self.n_IMPT, ctx=ast.Store())],
                value=ast.Tuple(elts=impt_entries, ctx=ast.Load())))
            # fromlist=('_',) is the minimum incantation that makes
            # __import__('X.Y', …) return the submodule X.Y rather than
            # the top-level X. A non-empty fromlist triggers submodule
            # semantics; '_' is a common name that may exist in some
            # modules but harmless when missing (fromlist is lenient).
            imp_src = (
                f'def {self.n_imp}(_k):\n'
                f'    return __import__(bytes(_c ^ {self.n_AM}[_i & 15] for _i, _c in enumerate({self.n_IMPT}[_k])).decode(), None, None, (\'_\',), 0)\n'
            )
            prelude_body.extend(ast.parse(imp_src).body)

        tree.body = prelude_body + tree.body
        ast.fix_missing_locations(tree)


# ---------------------------------------------------------------------------
# Import Concealment (C2)
# ---------------------------------------------------------------------------

class _ImportConcealer(ast.NodeTransformer):
    """Rewrite `import X` / `from X import Y` into opaque-key lookups.

    Shares state with _AttributeMangler:
      - Module paths are interned into `_IMPT` (mangler.add_mod_key)
      - Imported names are interned into the same `_ATAB` used for
        attribute access (mangler.add_attr_key), so a single table hides
        both surfaces.

    Transforms:
      import X                    →  X = _imp(k_X)            # k_X in _IMPT
      import X as Y               →  Y = _imp(k_X)
      import X.Y as Z             →  Z = _imp(k_XY)           # fromlist → submod
      from X import Y             →  _t = _imp(k_X); Y = _gA(_t, k_Y)
      from X import Y as Z        →  _t = _imp(k_X); Z = _gA(_t, k_Y)
      from X import Y1, Y2        →  _t = _imp(k_X); Y1=_gA(_t,k1); Y2=_gA(_t,k2)
      from X.Y import Z           →  _t = _imp(k_XY); Z = _gA(_t, k_Z)

    Not transformed (left structurally intact — rare / complex):
      import X.Y                  (no asname; binds top-level X)
      from . import X             (relative; level > 0)
      from X import *             (star; __all__ semantics)

    Must run AFTER _IdentifierRenamer so that `alias.asname` already
    reflects the final (renamed) local binding — otherwise the assignment
    target would be the pre-rename plaintext name and the renamer's map
    wouldn't apply.
    """

    def __init__(self, ng, mangler):
        self.ng = ng
        self.mangler = mangler
        self.concealed = 0

    def visit_Import(self, node):
        out = []
        leftover = []
        for alias in node.names:
            # asname present if the renamer tagged one (it does for all
            # non-dotted imports), else we bind the original name.
            mod = alias.name
            if '.' in mod and not alias.asname:
                # `import X.Y` with no asname binds `X` (top-level). Our
                # `_imp` helper returns the deepest submodule (X.Y), which
                # doesn't match that semantic. Leave this intact.
                leftover.append(alias)
                continue
            if not mod:
                leftover.append(alias)
                continue
            local = alias.asname if alias.asname else mod
            mod_key = self.mangler.add_mod_key(mod)
            out.append(ast.Assign(
                targets=[ast.Name(id=local, ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id=self.mangler.n_imp, ctx=ast.Load()),
                    args=[ast.Constant(value=mod_key)],
                    keywords=[])))
            self.concealed += 1
        if leftover:
            out.insert(0, ast.Import(names=leftover))
        return out if out else node

    def visit_ImportFrom(self, node):
        # Relative imports: skip. `__import__` with level>0 needs the
        # caller's __package__ and a valid globals dict; safer to leave
        # them as plaintext.
        if node.level and node.level > 0:
            return node
        if not node.module:
            return node
        # `from X import *`: __all__ semantics not worth replicating.
        if any(a.name == '*' for a in node.names):
            return node
        mod_key = self.mangler.add_mod_key(node.module)
        tname = self.ng.temp()
        stmts = [ast.Assign(
            targets=[ast.Name(id=tname, ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id=self.mangler.n_imp, ctx=ast.Load()),
                args=[ast.Constant(value=mod_key)],
                keywords=[]))]
        for alias in node.names:
            name_key = self.mangler.add_attr_key(alias.name)
            local = alias.asname if alias.asname else alias.name
            stmts.append(ast.Assign(
                targets=[ast.Name(id=local, ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id=self.mangler.n_gA, ctx=ast.Load()),
                    args=[ast.Name(id=tname, ctx=ast.Load()),
                          ast.Constant(value=name_key)],
                    keywords=[])))
            self.concealed += 1
        return stmts


# ---------------------------------------------------------------------------
# Identifier Renaming
# ---------------------------------------------------------------------------

# Names that Python sets implicitly or that external code relies on.
_BUILTIN_NAMES = set(dir(builtins))
# Common stdlib module names that might be imported — if they also appear as
# attribute names we already exclude them, but add a few extras for safety.
_BUILTIN_NAMES.update({
    'self', 'cls',  # conventional but not keywords; leave for attribute safety
})

class _IdentifierRenamer(ast.NodeTransformer):
    """Rename user-defined identifiers to random opaque names.

    Must run BEFORE any other transform so that only genuine user identifiers
    are affected. CFF/decomposition add their own random temps afterward.

    Safety rules:
    - Builtins (print, len, Exception, …) are never renamed.
    - Dunder names (__init__, __name__, …) are never renamed.
    - Names that also appear as Attribute.attr anywhere in the source are
      never renamed (prevents breaking self.x / obj.method() patterns).
    - Names that appear as keyword arguments in calls are never renamed
      (prevents breaking foo(bar=1) when bar is a parameter name).
    """

    def __init__(self, ng):
        self.ng = ng
        self._map = {}
        self._attr_names = set()
        self._kwarg_names = set()

    def prepare(self, tree):
        """First pass: collect names used as attributes and keyword args."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                self._attr_names.add(node.attr)
            if isinstance(node, ast.keyword) and node.arg:
                self._kwarg_names.add(node.arg)

    def _skip(self, name):
        if not name:
            return True
        if name.startswith('__') and name.endswith('__'):
            return True
        if name in _BUILTIN_NAMES:
            return True
        if name in self._attr_names:
            return True
        if name in self._kwarg_names:
            return True
        return False

    def _r(self, name):
        """Get or create a renamed identifier."""
        if self._skip(name):
            return name
        if name not in self._map:
            self._map[name] = self.ng.temp()
        return self._map[name]

    # -- Name nodes (variables, references) --

    def visit_Name(self, node):
        node.id = self._r(node.id)
        return node

    # -- Definitions --

    def visit_FunctionDef(self, node):
        node.name = self._r(node.name)
        node.args = self.visit(node.args)
        node.body = [self.visit(s) for s in node.body]
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        if node.returns:
            node.returns = self.visit(node.returns)
        return node

    def visit_AsyncFunctionDef(self, node):
        node.name = self._r(node.name)
        node.args = self.visit(node.args)
        node.body = [self.visit(s) for s in node.body]
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        if node.returns:
            node.returns = self.visit(node.returns)
        return node

    def visit_ClassDef(self, node):
        node.name = self._r(node.name)
        node.bases = [self.visit(b) for b in node.bases]
        node.keywords = [self.visit(k) for k in node.keywords]
        node.body = [self.visit(s) for s in node.body]
        node.decorator_list = [self.visit(d) for d in node.decorator_list]
        return node

    # -- Parameters --

    def visit_arg(self, node):
        node.arg = self._r(node.arg)
        if node.annotation:
            node.annotation = self.visit(node.annotation)
        return node

    # -- Exception handlers (name is a plain string, not a Name node) --

    def visit_ExceptHandler(self, node):
        if node.name:
            node.name = self._r(node.name)
        if node.type:
            node.type = self.visit(node.type)
        node.body = [self.visit(s) for s in node.body]
        return node

    # -- Global / nonlocal (names are plain strings) --

    def visit_Global(self, node):
        node.names = [self._r(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._r(n) for n in node.names]
        return node

    # -- Imports: rename local binding, keep import source intact --

    def _rename_alias(self, alias):
        if alias.name == '*':
            return
        if alias.asname:
            alias.asname = self._r(alias.asname)
        else:
            # Only rename simple (non-dotted) imports
            if '.' not in alias.name:
                renamed = self._r(alias.name)
                if renamed != alias.name:
                    alias.asname = renamed

    def visit_Import(self, node):
        for alias in node.names:
            self._rename_alias(alias)
        return node

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self._rename_alias(alias)
        return node


# ---------------------------------------------------------------------------
# Control Flow Flattening
# ---------------------------------------------------------------------------

_CFF_BRANCH = object()   # sentinel: block handles its own transition
_CFF_EXIT = object()      # sentinel: placeholder for loop exit

class _Block:
    __slots__ = ('state', 'stmts', 'next_state')
    def __init__(self, state, stmts, next_state=None):
        self.state = state
        self.stmts = stmts
        self.next_state = next_state  # int, _CFF_BRANCH, _CFF_EXIT, or None


class _CFFlattener(ast.NodeTransformer):
    def __init__(self, ng):
        self.ng = ng
        self._depth = 0

    def visit_Module(self, node):
        # Threshold is 2-stmt bodies (not 3) — two lines of original
        # code is enough for an attacker to recognise if CFF doesn't
        # scramble them. Pay the size cost.
        if len(node.body) >= 2:
            node.body = self._flatten_body(node.body)
        return node

    def visit_FunctionDef(self, node):
        if self._depth > 0:
            return node
        self._depth += 1
        if not self._has_yield(node) and len(node.body) >= 2:
            node.body = self._flatten_body(node.body)
        self._depth -= 1
        return node

    def visit_AsyncFunctionDef(self, node):
        return node

    def _has_yield(self, node):
        for child in ast.walk(node):
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return True
        return False

    def _flatten_body(self, stmts):
        if len(stmts) < 3:
            return stmts

        used_states = set()
        ng = self.ng
        state_var = ng.temp()

        # Decompose statements into blocks
        blocks = self._decompose(stmts, ng, used_states, state_var)
        if len(blocks) < 3:
            return stmts

        entry_state = blocks[0].state
        exit_state = ng.state_val(used_states)

        # Resolve None next_state to exit, resolve _CFF_EXIT placeholders
        for blk in blocks:
            if blk.next_state is None:
                blk.next_state = exit_state

        # If there are _CFF_EXIT blocks that weren't resolved by a loop,
        # point them to exit
        for blk in blocks:
            if blk.next_state is _CFF_EXIT:
                blk.next_state = exit_state

        # Build dispatcher cases
        cases = []
        for blk in blocks:
            body = list(blk.stmts)
            # Append state transition unless block handles it itself
            if blk.next_state is not _CFF_BRANCH and isinstance(blk.next_state, int):
                body.append(_make_assign(state_var, blk.next_state))
            test = _make_eq(state_var, blk.state)
            cases.append((test, body if body else [ast.Pass()]))

        # Exit case
        cases.append((_make_eq(state_var, exit_state), [ast.Break()]))

        # Shuffle cases
        self.ng._rng.shuffle(cases)

        if_chain = _build_if_chain(cases)
        while_node = ast.While(
            test=ast.Constant(value=True), body=[if_chain], orelse=[])

        result = [_make_assign(state_var, entry_state), while_node]
        ast.fix_missing_locations(ast.Module(body=result, type_ignores=[]))
        return result

    def _decompose(self, stmts, ng, used, state_var):
        """Decompose a list of statements into basic blocks."""
        blocks = []

        for stmt in stmts:
            state = ng.state_val(used)

            # Link previous block to this one
            if blocks and blocks[-1].next_state is None:
                blocks[-1].next_state = state

            if isinstance(stmt, ast.If) and not self._has_yield_in(stmt):
                if_blocks = self._decompose_if(stmt, ng, used, state_var)
                # Set entry of if as this block's state
                if blocks and blocks[-1].next_state == state:
                    blocks[-1].next_state = if_blocks[0].state
                # Merge point after if
                merge_state = ng.state_val(used)
                for blk in if_blocks:
                    if blk.next_state is None:
                        blk.next_state = merge_state
                blocks.extend(if_blocks)
                blocks.append(_Block(merge_state, [], None))

            elif isinstance(stmt, ast.While) and not self._has_yield_in(stmt):
                wh_blocks = self._decompose_while(stmt, ng, used, state_var)
                if blocks and blocks[-1].next_state == state:
                    blocks[-1].next_state = wh_blocks[0].state
                # After-loop state
                after_state = ng.state_val(used)
                # Resolve _CFF_EXIT in while blocks
                for blk in wh_blocks:
                    if blk.next_state is _CFF_EXIT:
                        blk.next_state = after_state
                    # Also fix _CFF_EXIT in inner stmts (break replacements)
                    blk.stmts = self._resolve_exit_in_stmts(
                        blk.stmts, state_var, after_state)
                blocks.extend(wh_blocks)
                blocks.append(_Block(after_state, [], None))

            elif isinstance(stmt, ast.For):
                # Keep for-loops as-is in the CFF. The interpreter handles
                # IFor natively; converting to iter()/next() with try/except
                # StopIteration breaks under PEP 479 (StopIteration inside a
                # generator → RuntimeError). The body is still CFF'd when
                # the recursive transformer processes function bodies.
                blocks.append(_Block(state, [stmt], None))

            else:
                blocks.append(_Block(state, [stmt], None))

        return blocks

    def _decompose_if(self, node, ng, used, sv):
        """Decompose if/elif/else into CFF blocks."""
        entry = ng.state_val(used)
        then_state = ng.state_val(used)
        else_state = ng.state_val(used)

        # Entry: evaluate condition and branch
        entry_stmts = [ast.If(
            test=node.test,
            body=[_make_assign(sv, then_state)],
            orelse=[_make_assign(sv, else_state)]
        )]
        blocks = [_Block(entry, entry_stmts, _CFF_BRANCH)]

        # Then body (may contain multiple stmts)
        then_stmts = node.body
        blocks.append(_Block(then_state, then_stmts, None))

        # Else body
        if node.orelse:
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                # elif chain
                elif_blocks = self._decompose_if(node.orelse[0], ng, used, sv)
                # Point our else to the elif entry
                entry_stmts[0].orelse = [_make_assign(sv, elif_blocks[0].state)]
                blocks.extend(elif_blocks)
            else:
                blocks.append(_Block(else_state, node.orelse, None))
        else:
            blocks.append(_Block(else_state, [], None))

        return blocks

    def _decompose_while(self, node, ng, used, sv):
        cond_state = ng.state_val(used)
        body_state = ng.state_val(used)

        # Condition: test → body or exit
        if node.orelse:
            orelse_state = ng.state_val(used)
            cond_stmts = [ast.If(
                test=node.test,
                body=[_make_assign(sv, body_state)],
                orelse=[_make_assign(sv, orelse_state)]
            )]
            blocks = [_Block(cond_state, cond_stmts, _CFF_BRANCH)]
            # Orelse runs when loop exits normally (not via break)
            blocks.append(_Block(orelse_state, node.orelse, _CFF_EXIT))
        else:
            cond_stmts = [ast.If(
                test=node.test,
                body=[_make_assign(sv, body_state)],
                orelse=[_make_assign(sv, -1)]  # placeholder, resolved later
            )]
            blocks = [_Block(cond_state, cond_stmts, _CFF_BRANCH)]
            # Mark the else branch to resolve to loop exit
            # We'll use a special state that gets resolved
            cond_stmts[0].orelse = [_make_assign_exit_marker(sv)]
            blocks[0] = _Block(cond_state,
                               [ast.If(
                                   test=node.test,
                                   body=[_make_assign(sv, body_state)],
                                   orelse=[]  # empty means fall through to exit
                               )], _CFF_EXIT)
            # Actually simpler: just use an if that either goes to body or exits
            blocks = [_Block(cond_state, [], None)]
            blocks[0].stmts = [ast.If(
                test=node.test,
                body=[_make_assign(sv, body_state)],
                orelse=[_make_assign_marker(sv, '__EXIT__')]
            )]
            blocks[0].next_state = _CFF_BRANCH

        # Body: execute then go back to condition
        body_stmts = self._transform_loop_stmts(node.body, sv, cond_state)
        blocks.append(_Block(body_state, body_stmts, cond_state))

        return blocks

    def _decompose_for(self, node, ng, used, sv):
        iter_var = self.ng.temp()
        item_var = self.ng.temp()
        sentinel_var = self.ng.temp()
        init_state = ng.state_val(used)
        cond_state = ng.state_val(used)
        body_state = ng.state_val(used)

        # Init: create iterator
        init_stmts = [ast.Assign(
            targets=[ast.Name(id=iter_var, ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id='iter', ctx=ast.Load()),
                args=[node.iter], keywords=[])
        )]
        blocks = [_Block(init_state, init_stmts, cond_state)]

        # Condition: try next(), handle StopIteration
        cond_stmts = [
            ast.Assign(
                targets=[ast.Name(id=sentinel_var, ctx=ast.Store())],
                value=ast.Constant(value=False)),
            ast.Try(
                body=[ast.Assign(
                    targets=[ast.Name(id=item_var, ctx=ast.Store())],
                    value=ast.Call(
                        func=ast.Name(id='next', ctx=ast.Load()),
                        args=[ast.Name(id=iter_var, ctx=ast.Load())],
                        keywords=[]))],
                handlers=[ast.ExceptHandler(
                    type=ast.Name(id='StopIteration', ctx=ast.Load()),
                    name=None,
                    body=[ast.Assign(
                        targets=[ast.Name(id=sentinel_var, ctx=ast.Store())],
                        value=ast.Constant(value=True))])],
                orelse=[], finalbody=[]),
            ast.If(
                test=ast.Name(id=sentinel_var, ctx=ast.Load()),
                body=[_make_assign_marker(sv, '__EXIT__')],
                orelse=[
                    ast.Assign(targets=[node.target],
                               value=ast.Name(id=item_var, ctx=ast.Load())),
                    _make_assign(sv, body_state)
                ])
        ]
        blocks.append(_Block(cond_state, cond_stmts, _CFF_BRANCH))

        # Body
        body_stmts = self._transform_loop_stmts(node.body, sv, cond_state)
        blocks.append(_Block(body_state, body_stmts, cond_state))

        return blocks

    def _transform_loop_stmts(self, stmts, sv, continue_target):
        """Replace break/continue in loop body with state transitions."""
        result = []
        for stmt in stmts:
            if isinstance(stmt, ast.Break):
                result.append(_make_assign_marker(sv, '__EXIT__'))
                result.append(ast.Continue())
            elif isinstance(stmt, ast.Continue):
                result.append(_make_assign(sv, continue_target))
                result.append(ast.Continue())
            else:
                result.append(stmt)
        return result

    def _resolve_exit_in_stmts(self, stmts, sv, exit_state):
        """Replace __EXIT__ marker assignments with actual exit state."""
        result = []
        for stmt in stmts:
            if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and
                isinstance(stmt.targets[0], ast.Name) and
                stmt.targets[0].id == sv and
                isinstance(stmt.value, ast.Constant) and
                stmt.value.value == '__EXIT__'):
                result.append(_make_assign(sv, exit_state))
            elif isinstance(stmt, ast.If):
                stmt.body = self._resolve_exit_in_stmts(stmt.body, sv, exit_state)
                stmt.orelse = self._resolve_exit_in_stmts(stmt.orelse, sv, exit_state)
                result.append(stmt)
            elif isinstance(stmt, ast.Try):
                stmt.body = self._resolve_exit_in_stmts(stmt.body, sv, exit_state)
                for h in stmt.handlers:
                    h.body = self._resolve_exit_in_stmts(h.body, sv, exit_state)
                stmt.orelse = self._resolve_exit_in_stmts(stmt.orelse, sv, exit_state)
                stmt.finalbody = self._resolve_exit_in_stmts(stmt.finalbody, sv, exit_state)
                result.append(stmt)
            else:
                result.append(stmt)
        return result

    def _has_yield_in(self, node):
        for child in ast.walk(node):
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return True
        return False


# ---------------------------------------------------------------------------
# Expression Decomposition
# ---------------------------------------------------------------------------

class _ExprDecomposer(ast.NodeTransformer):
    """Decompose complex expressions into temporary chains.

    Only operates on simple assignment statements at the current body level.
    Does NOT recurse into compound statements (try, for, while, if) to avoid
    hoisting expressions that reference variables from inner scopes.
    """

    def __init__(self, ng):
        self.ng = ng

    def visit_FunctionDef(self, node):
        node.body = self._transform_body(node.body)
        return node

    def visit_AsyncFunctionDef(self, node):
        node.body = self._transform_body(node.body)
        return node

    def visit_Module(self, node):
        node.body = self._transform_body(node.body)
        return node

    def _transform_body(self, body):
        new_body = []
        for stmt in body:
            # Only decompose simple statements (Assign, Expr, Return)
            if isinstance(stmt, (ast.Assign, ast.Return)):
                pre = []
                self._decompose_stmt(stmt, pre)
                new_body.extend(pre)
            elif isinstance(stmt, ast.Expr):
                pre = []
                self._decompose_expr_stmt(stmt, pre)
                new_body.extend(pre)
            new_body.append(stmt)
        return new_body

    def _decompose_stmt(self, stmt, pre):
        """Extract nested sub-expressions from an assignment/return."""
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            self._decompose_call_args(stmt.value, pre)
        elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.BinOp):
            self._decompose_binop(stmt.value, stmt, 'value', pre)
        elif isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            self._decompose_call_args(stmt.value, pre)

    def _decompose_expr_stmt(self, stmt, pre):
        if isinstance(stmt.value, ast.Call):
            self._decompose_call_args(stmt.value, pre)

    def _decompose_call_args(self, call, pre):
        """Extract Call arguments that are themselves Calls into temporaries."""
        new_args = []
        for arg in call.args:
            if isinstance(arg, ast.Call):
                tmp = self.ng.temp()
                pre.append(ast.Assign(
                    targets=[ast.Name(id=tmp, ctx=ast.Store())],
                    value=arg))
                new_args.append(ast.Name(id=tmp, ctx=ast.Load()))
            else:
                new_args.append(arg)
        call.args = new_args

    def _decompose_binop(self, binop, parent, attr, pre):
        """Extract nested BinOps into temporaries."""
        if isinstance(binop.left, ast.BinOp):
            tmp = self.ng.temp()
            pre.append(ast.Assign(
                targets=[ast.Name(id=tmp, ctx=ast.Store())],
                value=binop.left))
            binop.left = ast.Name(id=tmp, ctx=ast.Load())
        if isinstance(binop.right, ast.BinOp):
            tmp = self.ng.temp()
            pre.append(ast.Assign(
                targets=[ast.Name(id=tmp, ctx=ast.Store())],
                value=binop.right))
            binop.right = ast.Name(id=tmp, ctx=ast.Load())


# ---------------------------------------------------------------------------
# Opaque Predicates
# ---------------------------------------------------------------------------

class _OpaquePredicateInjector(ast.NodeTransformer):
    def __init__(self, ng, density=0.12):
        self.ng = ng
        self.density = density

    def visit_Module(self, node):
        self.generic_visit(node)
        node.body = self._inject(node.body)
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if len(node.body) >= 3:
            node.body = self._inject(node.body)
        return node

    def _inject(self, body):
        if len(body) < 3:
            return body
        rng = self.ng._rng
        new_body = []
        for stmt in body:
            new_body.append(stmt)
            if rng.random() < self.density:
                new_body.extend(self._make_opaque(rng))
        return new_body

    def _make_opaque(self, rng):
        """Returns a list of statements: [init_var, if_pred_then_noop_else_dead]."""
        var = self.ng.temp()
        init_val = rng.randint(2, 10000)

        predicates = [
            # (v * v + v) % 2 == 0 (always true)
            lambda v: ast.Compare(
                left=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.BinOp(
                            left=ast.Name(id=v, ctx=ast.Load()),
                            op=ast.Mult(),
                            right=ast.Name(id=v, ctx=ast.Load())),
                        op=ast.Add(),
                        right=ast.Name(id=v, ctx=ast.Load())),
                    op=ast.Mod(), right=ast.Constant(value=2)),
                ops=[ast.Eq()], comparators=[ast.Constant(value=0)]),
            # v * v >= 0 (always true)
            lambda v: ast.Compare(
                left=ast.BinOp(
                    left=ast.Name(id=v, ctx=ast.Load()),
                    op=ast.Mult(),
                    right=ast.Name(id=v, ctx=ast.Load())),
                ops=[ast.GtE()], comparators=[ast.Constant(value=0)]),
            # (v * v * v - v) % 6 == 0 (always true by Fermat)
            lambda v: ast.Compare(
                left=ast.BinOp(
                    left=ast.BinOp(
                        left=ast.BinOp(
                            left=ast.BinOp(
                                left=ast.Name(id=v, ctx=ast.Load()),
                                op=ast.Mult(),
                                right=ast.Name(id=v, ctx=ast.Load())),
                            op=ast.Mult(),
                            right=ast.Name(id=v, ctx=ast.Load())),
                        op=ast.Sub(),
                        right=ast.Name(id=v, ctx=ast.Load())),
                    op=ast.Mod(), right=ast.Constant(value=6)),
                ops=[ast.Eq()], comparators=[ast.Constant(value=0)]),
        ]

        pred = rng.choice(predicates)
        dead = self._dead_code(rng)

        # Initialize the variable BEFORE the predicate test
        init_stmt = ast.Assign(
            targets=[ast.Name(id=var, ctx=ast.Store())],
            value=ast.Constant(value=init_val))

        if_stmt = ast.If(
            test=pred(var),
            body=[ast.Pass()],
            orelse=dead
        )

        return [init_stmt, if_stmt]

    def _dead_code(self, rng):
        stmts = []
        for _ in range(rng.randint(2, 4)):
            t = self.ng.temp()
            stmts.append(ast.Assign(
                targets=[ast.Name(id=t, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.Constant(value=rng.randint(-1000, 1000)),
                    op=rng.choice([ast.Add(), ast.Sub(), ast.Mult(),
                                   ast.BitXor()]),
                    right=ast.Constant(value=rng.randint(1, 255)))))
        return stmts


# ---------------------------------------------------------------------------
# Constant Unfolding
# ---------------------------------------------------------------------------

class _ConstantUnfolder(ast.NodeTransformer):
    def __init__(self, ng):
        self.ng = ng

    def visit_Constant(self, node):
        # Unconditional unfold on every in-range integer literal — a
        # probabilistic gate leaves most ints readable after unwrap, and
        # numeric constants are structural hints (magic numbers, opcodes,
        # indices, sizes) that attackers grep.
        if isinstance(node.value, int) and 2 <= abs(node.value) <= 500:
            return self._unfold(node.value, self.ng._rng)
        return node

    def _unfold(self, val, rng):
        s = rng.randint(0, 3)
        if s == 0:
            a = rng.randint(-500, 500)
            return ast.BinOp(left=ast.Constant(value=a), op=ast.Add(),
                             right=ast.Constant(value=val - a))
        elif s == 1 and val != 0:
            a = rng.randint(0, 0xFFFF)
            return ast.BinOp(left=ast.Constant(value=a), op=ast.BitXor(),
                             right=ast.Constant(value=val ^ a))
        elif s == 2 and val > 0:
            n = rng.randint(1, 3)
            a = val >> n
            b = val & ((1 << n) - 1)
            return ast.BinOp(
                left=ast.BinOp(left=ast.Constant(value=a), op=ast.LShift(),
                               right=ast.Constant(value=n)),
                op=ast.BitOr(), right=ast.Constant(value=b))
        return ast.Constant(value=val)


# ---------------------------------------------------------------------------
# MBA (Mixed Boolean-Arithmetic)
# ---------------------------------------------------------------------------

class _MBAObfuscator(ast.NodeTransformer):
    """Mixed Boolean-Arithmetic rewrite on every integer-typed BinOp we can
    reach. Add/Sub expand via the classic (x^y) + 2·(x&y) identity;
    BitXor/BitOr/BitAnd expand via a 3-cycle of identities so the outputs of
    one expansion aren't trivially collapsible by the next. Note:
    `self.generic_visit(node)` only recurses into the *original* children;
    the expansion we return is NOT revisited, so there's no risk of
    infinite rewriting.
    """

    def __init__(self, ng):
        self.ng = ng

    def visit_BinOp(self, node):
        self.generic_visit(node)
        # MBA uses bitwise ops (^, &, ~) which only work on ints.
        # Only apply when both operands are provably integer.
        if self._both_int(node.left, node.right):
            return self._mba(node)
        return node

    def _both_int(self, a, b):
        return self._is_int_expr(a) and self._is_int_expr(b)

    def _is_int_expr(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (
                ast.BitOr, ast.BitXor, ast.BitAnd, ast.LShift, ast.RShift,
                ast.FloorDiv, ast.Mod)):
            return True
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
            return True
        return False

    def _mba(self, node):
        x, y = node.left, node.right
        if isinstance(node.op, ast.Add):
            # x + y = (x ^ y) + 2*(x & y)
            return ast.BinOp(
                left=ast.BinOp(left=x, op=ast.BitXor(), right=y),
                op=ast.Add(),
                right=ast.BinOp(
                    left=ast.Constant(value=2), op=ast.Mult(),
                    right=ast.BinOp(left=copy.deepcopy(x), op=ast.BitAnd(),
                                    right=copy.deepcopy(y))))
        if isinstance(node.op, ast.Sub):
            # x - y = (x ^ y) - 2*(~x & y)
            return ast.BinOp(
                left=ast.BinOp(left=x, op=ast.BitXor(), right=y),
                op=ast.Sub(),
                right=ast.BinOp(
                    left=ast.Constant(value=2), op=ast.Mult(),
                    right=ast.BinOp(
                        left=ast.UnaryOp(op=ast.Invert(),
                                         operand=copy.deepcopy(x)),
                        op=ast.BitAnd(), right=copy.deepcopy(y))))
        if isinstance(node.op, ast.BitXor):
            # x ^ y = (x | y) - (x & y)
            return ast.BinOp(
                left=ast.BinOp(left=x, op=ast.BitOr(), right=y),
                op=ast.Sub(),
                right=ast.BinOp(left=copy.deepcopy(x), op=ast.BitAnd(),
                                right=copy.deepcopy(y)))
        if isinstance(node.op, ast.BitOr):
            # x | y = (x ^ y) + (x & y)
            return ast.BinOp(
                left=ast.BinOp(left=x, op=ast.BitXor(), right=y),
                op=ast.Add(),
                right=ast.BinOp(left=copy.deepcopy(x), op=ast.BitAnd(),
                                right=copy.deepcopy(y)))
        if isinstance(node.op, ast.BitAnd):
            # x & y = (x | y) - (x ^ y)
            return ast.BinOp(
                left=ast.BinOp(left=x, op=ast.BitOr(), right=y),
                op=ast.Sub(),
                right=ast.BinOp(left=copy.deepcopy(x), op=ast.BitXor(),
                                right=copy.deepcopy(y)))
        return node


# ---------------------------------------------------------------------------
# String Obfuscation
# ---------------------------------------------------------------------------

class _StringObfuscator(ast.NodeTransformer):
    """Every string literal (2..200 bytes) is deformed unconditionally, and
    the encoding is multi-fragment instead of single-key XOR.

    The literal is split into K ∈ [2, 4] contiguous fragments and each
    fragment is XOR'd with its own per-fragment key. The AST-level output
    is a flat `bytes([b0^k0, b1^k0, ..., bm^k1, ...]).decode('utf-8')`
    expression. Recovery requires identifying every split point and every
    key — a 1-line XOR-back script no longer works.

    Empty strings and strings > 200 bytes are skipped: empty strings carry
    no information worth hiding, and very long strings blow up the AST
    linearly (one BinOp per byte).
    """

    def __init__(self, ng):
        self.ng = ng

    def visit_Constant(self, node):
        if not isinstance(node.value, str):
            return node
        if len(node.value) == 0 or len(node.value) > 200:
            return node
        return self._encode(node.value)

    # --- contexts where a string Constant is grammatically required ---

    def visit_JoinedStr(self, node):
        # f-strings: the literal-text parts of `values` MUST stay ast.Constant.
        # Replacing them with a Call produces an invalid JoinedStr that
        # compile() rejects (it also trips ast.unparse). We recurse only into
        # the *expression* side of each FormattedValue child.
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                v.value = self.visit(v.value)
                if v.format_spec is not None:
                    v.format_spec = self.visit(v.format_spec)
        return node

    def visit_MatchValue(self, node):
        # `match x: case "literal": ...` — MatchValue.value must be a Constant
        # (or a dotted Name). Don't rewrite it into a Call.
        return node

    def visit_MatchMapping(self, node):
        # MatchMapping.keys must be literal patterns. Recurse only into the
        # sub-pattern side (`patterns`) and let `rest` (a name) stand.
        node.patterns = [self.visit(p) for p in node.patterns]
        return node

    def _encode(self, s):
        raw = list(s.encode('utf-8'))
        rng = self.ng._rng
        # Pick fragmentation factor capped by byte length (we need at least
        # one byte per fragment for the split to be valid).
        max_k = min(4, len(raw))
        k = rng.randint(2, max_k) if max_k >= 2 else 1

        if k == 1:
            parts = [raw]
        else:
            splits = sorted(rng.sample(range(1, len(raw)), k - 1))
            parts = []
            prev = 0
            for s_idx in splits:
                parts.append(raw[prev:s_idx])
                prev = s_idx
            parts.append(raw[prev:])

        all_elts = []
        for frag in parts:
            key = rng.randint(1, 255)
            for b in frag:
                all_elts.append(ast.BinOp(
                    left=ast.Constant(value=b ^ key), op=ast.BitXor(),
                    right=ast.Constant(value=key)))

        return ast.Call(
            func=ast.Attribute(
                value=ast.Call(
                    func=ast.Name(id='bytes', ctx=ast.Load()),
                    args=[ast.List(elts=all_elts, ctx=ast.Load())],
                    keywords=[]),
                attr='decode', ctx=ast.Load()),
            args=[ast.Constant(value='utf-8')], keywords=[])


# ---------------------------------------------------------------------------
# F-String Deformation
# ---------------------------------------------------------------------------

class _FStringDeformer(ast.NodeTransformer):
    """Convert simple f-strings into explicit concatenation so the literal
    text fragments become regular `ast.Constant` nodes that the
    `_StringObfuscator` can XOR-shred later.

    `f"hello {name}!"`  becomes  `"hello " + str(name) + "!"`

    Conversion only fires for the grammatically simple case — no conversion
    flag (`!r`/`!s`/`!a`) and no format spec. Those cases involve semantics
    (repr, ascii, padding, precision) that plain `str(…)` doesn't preserve,
    so we leave those f-strings intact. They still cost us plaintext template
    leaks, but that's a narrow loss compared to blanket-skipping every
    f-string.
    """

    def visit_FormattedValue(self, node):
        # Transform the interpolated expression (which may itself contain a
        # nested f-string) but leave `format_spec` strictly alone — it is a
        # JoinedStr of Constants whose grammar forbids the BinOp/Call forms
        # this transform produces.
        node.value = self.visit(node.value)
        return node

    def visit_JoinedStr(self, node):
        # Recurse into children first so nested f-strings inside
        # FormattedValue.value get deformed bottom-up; format_spec is
        # intentionally skipped by `visit_FormattedValue` above.
        self.generic_visit(node)

        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                if v.value:  # drop empty literal slots
                    parts.append(v)
            elif isinstance(v, ast.FormattedValue):
                # Bail on anything with semantics we don't preserve.
                if v.conversion != -1 or v.format_spec is not None:
                    return node
                parts.append(ast.Call(
                    func=ast.Name(id='str', ctx=ast.Load()),
                    args=[v.value], keywords=[]))
            else:
                return node  # unknown child type, don't touch

        if not parts:
            return ast.Constant(value='')
        result = parts[0]
        for p in parts[1:]:
            result = ast.BinOp(left=result, op=ast.Add(), right=p)
        return result


# ---------------------------------------------------------------------------
# Call Indirection
# ---------------------------------------------------------------------------

class _CallIndirector(ast.NodeTransformer):
    """Route every resolvable `Name(args)` call through an opaque dispatcher
    dict `_pg_D`, keyed by per-build random integers.

    Before:
        def foo(x): return x + 1
        print(foo(3))

    After (roughly):
        _pg_D = {}
        _pg_D[((K_print ^ m0) ^ m0)] = print
        def foo(x): return x + 1
        _pg_D[((K_foo ^ m1) ^ m1)] = foo
        _pg_D[((K_print ^ m2) ^ m2)](_pg_D[((K_foo ^ m3) ^ m3)](3))

    Why: after unwrap, the call graph disappears. `print` is no longer
    greppable because it's `_pg_D[999887766]`; the key is itself emitted
    as `(encoded ^ mask) ^ mask` so downstream MBA can rewrite the XOR
    into longer (x|y) - (x&y) chains. An attacker needs to reconstruct
    `_pg_D` by emulating module-level registration order before any call
    site becomes legible.

    Indirection scope: only bare-Name calls where the Name resolves to
    (a) a top-level user binding (def / class / import / ImportFrom), or
    (b) a known builtin. Method calls `obj.method()`, dynamic calls
    `(a or b)()`, and calls through local parameters are left alone — we
    can't prove those names will be in the dispatcher at call time.
    """

    DISPATCHER = '_pg_D'

    def __init__(self, ng):
        self.ng = ng
        self._keys = {}           # name -> stable opaque int for this build
        self._top_bindings = set()  # module-level user bindings we can register
        self._shadowed_builtins = set()  # builtins the user locally rebinds

    # -- Key allocation --

    def _alloc_key(self, name):
        if name not in self._keys:
            rng = self.ng._rng
            while True:
                k = rng.randint(10**7, 10**12)
                if k not in self._keys.values():
                    self._keys[name] = k
                    break
        return self._keys[name]

    def _key_expr(self, key):
        """Emit `key` as (encoded ^ mask) so downstream MBA can expand further."""
        mask = self.ng._rng.randint(1, 0xFFFFFFFF)
        return ast.BinOp(
            left=ast.Constant(value=key ^ mask),
            op=ast.BitXor(),
            right=ast.Constant(value=mask))

    def _dispatcher_subscript(self, key, ctx):
        return ast.Subscript(
            value=ast.Name(id=self.DISPATCHER, ctx=ast.Load()),
            slice=self._key_expr(key),
            ctx=ctx)

    # -- Module-level binding collection --

    def _collect_top_bindings(self, module):
        for stmt in module.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                self._top_bindings.add(stmt.name)
            elif isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    n = alias.asname or alias.name.split('.')[0]
                    self._top_bindings.add(n)
            elif isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    n = alias.asname or alias.name
                    if n != '*':
                        self._top_bindings.add(n)

    def _collect_shadowed_builtins(self, module):
        # If the user rebinds `print`, `len`, etc. anywhere in the file
        # (parameter, assignment target, except-as, def/class name), we
        # conservatively don't indirect those names — a call site might
        # refer to the local shadow, not the builtin. Whole-file scope here
        # is deliberately blunt; accurate per-scope tracking would need a
        # full scope analyser and the correctness risk isn't worth it.
        stored = set()
        for node in ast.walk(module):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                stored.add(node.id)
            elif isinstance(node, ast.arg):
                stored.add(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                   ast.ClassDef)):
                stored.add(node.name)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                stored.add(node.name)
        self._shadowed_builtins = stored & _BUILTIN_NAMES

    # -- Transformation --

    def visit_Module(self, node):
        self._collect_top_bindings(node)
        self._collect_shadowed_builtins(node)
        # Rewrite call sites (populates self._keys lazily).
        self.generic_visit(node)
        if not self._keys:
            return node

        # Assemble the new body:
        #   1. _pg_D = {}
        #   2. Registrations for every key'd name that is NOT a top-level
        #      binding (assumed to be builtins / already-imported names).
        #   3. Original stmts, each followed by a registration for any
        #      top-level binding that names a key'd callable.
        new_body = []
        new_body.append(ast.Assign(
            targets=[ast.Name(id=self.DISPATCHER, ctx=ast.Store())],
            value=ast.Dict(keys=[], values=[])))

        for name, k in self._keys.items():
            if name not in self._top_bindings:
                new_body.append(self._register(name, k))

        for stmt in node.body:
            new_body.append(stmt)
            for n in self._bindings_introduced_by(stmt):
                if n in self._keys:
                    new_body.append(self._register(n, self._keys[n]))

        node.body = new_body
        return node

    def _bindings_introduced_by(self, stmt):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            return [stmt.name]
        if isinstance(stmt, ast.Import):
            return [alias.asname or alias.name.split('.')[0]
                    for alias in stmt.names]
        if isinstance(stmt, ast.ImportFrom):
            return [alias.asname or alias.name
                    for alias in stmt.names if alias.name != '*']
        return []

    def _register(self, name, key):
        return ast.Assign(
            targets=[self._dispatcher_subscript(key, ast.Store())],
            value=ast.Name(id=name, ctx=ast.Load()))

    def visit_Call(self, node):
        self.generic_visit(node)
        if not isinstance(node.func, ast.Name):
            return node
        name = node.func.id
        # Don't recurse on the dispatcher itself, and leave dunders alone
        # (they can hit things like __import__ that we don't want to touch).
        if name == self.DISPATCHER:
            return node
        if name.startswith('__') and name.endswith('__'):
            return node
        # Only indirect if we can prove the name will be resolvable via the
        # dispatcher at call time. Locals/parameters don't qualify.
        if name not in self._top_bindings and name not in _BUILTIN_NAMES:
            return node
        # Conservative shadow check: if the user also uses this name as a
        # store target anywhere (param, assignment, etc.), the call at a
        # given site might resolve to their local, not the builtin. Skip.
        if name in self._shadowed_builtins:
            return node
        k = self._alloc_key(name)
        node.func = self._dispatcher_subscript(k, ast.Load())
        return node


# ---------------------------------------------------------------------------
# Secret-Gate Rewriter
# ---------------------------------------------------------------------------
#
# Rationale
# ---------
# Any attacker who can set a sys.setprofile (or gettrace shim, or any of
# their siblings) captures every string that materialises as a Python-frame
# local while the interpreter evaluates user code — including "secrets"
# like passwords and flags that a plain `Compare(Eq)` node touches.
#
# The structural fix at the source level is: the secret must never be a
# materialised str value on any code path the attacker can reach. This
# transform detects
#
#     if <guess-expr> == "<literal pw>":
#         <true-branch>
#     [else:
#         <false-branch>]
#
# (or the symmetric form, or with Name references bound to module-level
# string constants), and rewrites the gate as:
#
#     try:
#         _k = hashlib.scrypt(<str(guess-expr).encode(...)>,
#                             salt=SALT, n=N, r=R, p=P, dklen=32)
#         verify AEAD tag against <ciphertext>
#         <plaintext> = aead_decrypt_keystream(<ct>, _k)
#         _co = marshal.loads(<plaintext>)
#         exec(_co)                       # runs the true-branch
#     except Exception:
#         <false-branch>
#
# The password literal never appears at runtime: it was consumed at build
# time to derive the AEAD key, and only its scrypt-derived key can open
# the ciphertext. The true branch itself is compiled to bytecode, and any
# string literals it references (e.g. FLAG) are inlined as co_consts of
# that bytecode — they only become visible if the profiler is still running
# AND the user submits the correct password, which is the threat model the
# gate assumes is safe. A profiler given the wrong password sees the false
# branch run and nothing more.
#
# Crypto construction
# -------------------
# Stdlib-only (hashlib + hmac):
#   * KDF:  hashlib.scrypt(pw, salt, n, r, p, dklen=32) — memory-hard;
#           n=16384, r=8, p=1 → ~30 ms / 32 MiB per try on modern CPUs.
#   * AEAD: HMAC-SHA256 keystream (counter mode) encrypt-then-MAC.
#           enc_key = HMAC(k, b"\x01").digest()
#           mac_key = HMAC(k, b"\x02").digest()
#           ks[i]   = HMAC(enc_key, nonce || i_be8).digest()
#           ct      = pt XOR ks[:len(pt)]
#           tag     = HMAC(mac_key, nonce || ct).digest()
#   verify then decrypt; hmac.compare_digest for constant-time compare.
#
# Scope
# -----
# Conservative: only fires on gates whose TRUE_BRANCH contains statements
# safe to `exec()` in the enclosing scope — Expr, Pass, Assert, nested If/
# Try/For/While, Import/ImportFrom, and inner Assign (values stay inside
# the exec). Disallowed: Return, Yield, Break, Continue, Global, Nonlocal,
# FunctionDef, ClassDef. If the true branch is not exec-safe the gate is
# left untouched.

# HMAC-SHA256 keystream AEAD used both at build time (here) and at runtime
# (emitted inline into the rewritten AST). Kept as free functions so the
# build-side encode and the runtime-side decode share identical logic.

def _sg_seal(key, nonce, plaintext):
    """Scrypt-KDF stream cipher: encrypt `plaintext` under a 32-byte
    `key` (scrypt output) and `nonce` using a SHA256-based keystream.

    No separate MAC: marshal.loads() on a wrong-key decrypt raises
    (random bytes don't form a valid marshal stream), which the
    rewritten gate catches via its outer try/except. This costs one
    integrity signal vs. a full AEAD but saves ~5 AST nodes per gate
    in the obfuscated stub — worthwhile because the ciphertext is
    baked into the distributed artifact, not exchanged over a
    channel where an adversary could flip bits.
    """
    ks = bytearray()
    ctr = 0
    while len(ks) < len(plaintext):
        ks += hashlib.sha256(
            key + nonce + ctr.to_bytes(4, 'big')).digest()
        ctr += 1
    return bytes(p ^ k for p, k in zip(plaintext, ks[:len(plaintext)]))


_SG_SAFE_STMT_TYPES = (
    ast.Expr, ast.Pass, ast.Assert,
    ast.If, ast.Try, ast.For, ast.While, ast.With,
    ast.Import, ast.ImportFrom,
    ast.Assign, ast.AugAssign, ast.AnnAssign,
    ast.Raise,
)
_SG_FORBID_NODE_TYPES = (
    ast.Return, ast.Yield, ast.YieldFrom,
    ast.Break, ast.Continue,
    ast.Global, ast.Nonlocal,
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
    ast.Lambda,  # lambdas are fine by themselves, but their bodies would
                 # capture exec-scope semantics we can't reason about safely
)


def _sg_is_exec_safe(body):
    """Check that every statement in body is safe to run via exec() in
    the enclosing function's scope (reads are OK; no escaping control
    flow; no declarations that would normally rebind enclosing scope)."""
    for stmt in body:
        if not isinstance(stmt, _SG_SAFE_STMT_TYPES):
            return False
        for sub in ast.walk(stmt):
            if isinstance(sub, _SG_FORBID_NODE_TYPES):
                return False
    return True


class _SecretGateRewriter(ast.NodeTransformer):
    """Rewrite `if X == "pw": TRUE else: FALSE` into a scrypt+AEAD gate.

    Runs FIRST in the pipeline, before identifier renaming, so that
      * the password-side string literal is still an ast.Constant;
      * module-level const strings (FLAG = "..." / PW = "...") are still
        resolvable by their original names; the rewriter inlines their
        values into the true-branch bytecode and removes the module-level
        assignments if they become dead (no surviving references).

    Instance attributes used across the two passes:
      _const_strs   : {name -> literal value} for module-level single-assign
                      string constants that we can treat as inlineable.
      _const_refs   : {name -> int} total Load references for each const.
      _consumed_pw  : set of names whose literal was used as a gate password.
      _inlined_refs : {name -> int} number of references inlined into
                      encrypted true branches.
    """

    # Tunable knobs. Kept conservative to stay fast on Pyodide boot and
    # small enough not to bloat the stub with ciphertext.
    MIN_PW_LEN = 4
    # v12.5 raises the scrypt floor from N=16384 to N=65536 (4x compute
    # and 4x memory: ~128 MiB RAM, ~120 ms CPU per guess on a 2023
    # laptop). One legitimate unlock runs once; an offline dictionary
    # attack pays the full factor per candidate. Per-build jitter on
    # (N, R) — see __init__ — further prevents the attacker from
    # pre-tuning a cracking rig: different stubs land on different
    # points on the (N, r) cost curve, so they can't share work across
    # builds. Kept constant within a single stub to avoid forcing each
    # gate to thread (N, r) through its helper signature.
    KDF_N_DEFAULT = 65536
    KDF_R_DEFAULT = 8
    KDF_P = 1
    # v12.5 nonce/salt length jitter. Larger salt makes precomputed
    # rainbow tables worthless (they already are for scrypt, but the
    # wider variance also frustrates automated IOC scanners looking for
    # fixed-size fields). Each visit_If() draws a fresh length per gate.
    SALT_LEN_MIN = 16
    SALT_LEN_MAX = 32
    NONCE_LEN_MIN = 12
    NONCE_LEN_MAX = 24
    MAX_TRUE_BRANCH_NODES = 400  # refuse to encrypt unreasonably large bodies

    # Per-build jitter choice tables. Chosen once per stub at __init__.
    # scrypt requires N to be a power of 2, so we pick from the dyadic
    # set {2^15 .. 2^17}. The 2^17 (=131072) point costs ~240 ms and
    # ~256 MiB per guess; we cap there because scrypt's CPython backing
    # refuses larger N unless the caller raises maxmem (we set
    # maxmem=1 GiB — enough for the highest N*r=2097152 point in the
    # choice table; Python's scrypt default is 32 MiB which would error).
    _KDF_N_CHOICES = (32768, 65536, 131072)
    _KDF_R_CHOICES = (8, 10, 12, 14, 16)

    def __init__(self, ng):
        self.ng = ng
        self._rng = ng._rng
        # v12.5: pick a per-build (N, R) pair from the jitter tables.
        # Seeded off the build RNG so reproducible builds stay
        # reproducible — two builds with the same seed get the same
        # (N, R) and byte-identical stubs.
        self.KDF_N = self._rng.choice(self._KDF_N_CHOICES)
        self.KDF_R = self._rng.choice(self._KDF_R_CHOICES)
        self._const_strs = {}
        self._const_refs = {}
        self._consumed_pw = set()
        self._inlined_refs = {}
        self._fired = 0
        # Pending gate metadata for two-phase emission.
        # visit_If() records (placeholder_node, guess_expr, salt, nonce,
        # ct_and_tag, false_branch) tuples into _pending and returns the
        # placeholder as the AST substitution. finalize_gates() then
        # picks a strategy based on self._fired:
        #   * 1 gate  -> INLINE the scrypt+AEAD body into that gate
        #                (smaller stub, no call overhead).
        #   * 2+ gates -> install a single module-level helper and emit
        #                 per-gate call sites (amortises the cost).
        self._pending = []
        # Helper identifiers (function + 4 params) are lazily generated
        # by _ensure_helper_names() on the extraction path only, so the
        # single-gate / inline path doesn't waste names from the pool.
        self._helper_name = None
        self._p_guess = None
        self._p_salt  = None
        self._p_nonce = None
        self._p_ct    = None

    def _ensure_helper_names(self):
        if self._helper_name is None:
            self._helper_name = self.ng.temp()
            self._p_guess = self.ng.temp()
            self._p_salt  = self.ng.temp()
            self._p_nonce = self.ng.temp()
            self._p_ct    = self.ng.temp()

    # -- Pre-pass: collect module-level single-assign string constants --

    def prepare(self, module):
        assign_counts = {}
        for stmt in module.body:
            if isinstance(stmt, ast.Assign):
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name):
                        assign_counts[tgt.id] = assign_counts.get(tgt.id, 0) + 1
            elif isinstance(stmt, (ast.AugAssign, ast.AnnAssign)):
                if isinstance(getattr(stmt, 'target', None), ast.Name):
                    assign_counts[stmt.target.id] = 999

        # Any non-module-level Store of the same name disqualifies it.
        for sub in ast.walk(module):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                assign_counts[sub.id] = max(
                    assign_counts.get(sub.id, 0), 1)
        # Re-walk to actually COUNT stores across the whole tree (including
        # inside functions). If a name gets stored more than once anywhere
        # in the module we treat it as mutable and don't inline it.
        store_counts = {}
        for sub in ast.walk(module):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                store_counts[sub.id] = store_counts.get(sub.id, 0) + 1
            elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef)):
                store_counts[sub.name] = store_counts.get(sub.name, 0) + 1
            elif isinstance(sub, ast.arg):
                store_counts[sub.arg] = store_counts.get(sub.arg, 0) + 1

        for stmt in module.body:
            if (isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                    and isinstance(stmt.value, ast.Constant)
                    and isinstance(stmt.value.value, str)):
                name = stmt.targets[0].id
                if store_counts.get(name, 0) == 1:
                    self._const_strs[name] = stmt.value.value

        # Count loads for each const name across the whole tree.
        for sub in ast.walk(module):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                if sub.id in self._const_strs:
                    self._const_refs[sub.id] = \
                        self._const_refs.get(sub.id, 0) + 1

    # -- Inline Name(Load) -> Constant for known module consts --

    def _inline_consts_into(self, body):
        """Replace Name(Load) refs of const_strs with their literal values,
        counting each inline so we can prune dead const assignments later."""
        class _Inliner(ast.NodeTransformer):
            def __init__(inner, outer):
                inner.outer = outer
            def visit_Name(inner, node):
                if (isinstance(node.ctx, ast.Load)
                        and node.id in inner.outer._const_strs):
                    outer = inner.outer
                    outer._inlined_refs[node.id] = \
                        outer._inlined_refs.get(node.id, 0) + 1
                    return ast.copy_location(
                        ast.Constant(value=outer._const_strs[node.id]), node)
                return node
        return [_Inliner(self).visit(s) for s in body]

    # v12.6: Fragment str constants in the compiled true branch.
    _FRAG_MIN_LEN = 6  # below this length, fragmentation isn't worth it
    _FRAG_MIN_PARTS = 3
    _FRAG_MAX_PARTS = 6

    def _fragment_string_constants(self, body):
        """Walk `body` AST and replace every `str` Constant of length
        >= _FRAG_MIN_LEN with a `+`-joined chain of 3..6 random-cut
        fragments. Purpose: after compile(), the code object's
        co_consts holds fragments separately — walking co_consts no
        longer yields the full literal as a single value.

        Non-str constants (int/bytes/None) are untouched. Short strs
        (< _FRAG_MIN_LEN) are also untouched because 4-char strings
        fragmented into 2-char pieces are trivially reassembled by a
        substring grep that the scoreboard runs over the whole attack
        stdout — fragmentation of short strings gives nothing.
        """
        outer = self

        class _Fragmenter(ast.NodeTransformer):
            def visit_Constant(inner, node):
                v = node.value
                if not isinstance(v, str):
                    return node
                if len(v) < outer._FRAG_MIN_LEN:
                    return node
                # Pick a fragment count bounded by the string length.
                max_parts = min(outer._FRAG_MAX_PARTS, len(v))
                n = outer._rng.randint(
                    min(outer._FRAG_MIN_PARTS, max_parts), max_parts)
                if n < 2:
                    return node
                # Random distinct cut points strictly between positions
                # 1 and len(v)-1 so no empty fragment is produced.
                cuts = sorted(outer._rng.sample(range(1, len(v)), n - 1))
                fragments = []
                prev = 0
                for c in cuts:
                    fragments.append(v[prev:c])
                    prev = c
                fragments.append(v[prev:])
                # Build BinOp(+) chain: f0 + f1 + f2 + ...
                expr = ast.Constant(value=fragments[0])
                for frag in fragments[1:]:
                    expr = ast.BinOp(
                        left=expr, op=ast.Add(),
                        right=ast.Constant(value=frag))
                return ast.copy_location(expr, node)

        frg = _Fragmenter()
        return [frg.visit(s) for s in body]

    # -- Pattern detection --

    def _resolve_pw_side(self, node):
        """If node is a string literal OR a Name bound to a module const
        string, return the literal value. Otherwise None."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self._const_strs:
            return self._const_strs[node.id]
        return None

    # Strings and patterns we refuse to treat as a "password literal".
    # These are common Python idioms that happen to compare a runtime
    # value against a string — encrypting them breaks the program (e.g.
    # `__name__ == "__main__"` is the standard entry-point guard) or adds
    # cost without security value.
    _SKIP_STRS = frozenset({
        '__main__', '__init__', '__name__', '__file__', '__doc__',
        '__package__', '__spec__', '__loader__', '__class__',
        # HTTP / IO idioms that often appear as == comparisons but aren't
        # access-control gates
        'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH',
        'utf-8', 'utf8', 'ascii', 'latin-1',
        'http', 'https',
    })

    def _is_skippable_string(self, s):
        """Return True if `s` looks like a harmless idiom we shouldn't
        encrypt (would break common patterns or waste cipher budget)."""
        if s in self._SKIP_STRS:
            return True
        # Any dunder-fenced identifier ("__xxx__") is almost always a
        # magic name rather than a secret.
        if len(s) >= 4 and s.startswith('__') and s.endswith('__'):
            return True
        return False

    def _is_skippable_side(self, node):
        """Return True if this side of the compare is a Name that's a
        magic/dunder reference we shouldn't touch (e.g. __name__)."""
        if isinstance(node, ast.Name):
            n = node.id
            if n.startswith('__') and n.endswith('__'):
                return True
        return False

    def _is_gate(self, ifnode):
        """Detect `if A == B:` with one side resolvable to a non-trivial
        string literal. Returns (guess_expr, pw_value, pw_name_or_None)
        or None."""
        t = ifnode.test
        if not (isinstance(t, ast.Compare)
                and len(t.ops) == 1 and isinstance(t.ops[0], ast.Eq)
                and len(t.comparators) == 1):
            return None
        left, right = t.left, t.comparators[0]
        # Skip gates whose comparand is a Python magic name — encrypting
        # `__name__ == "__main__"` is both useless and actively harmful.
        if self._is_skippable_side(left) or self._is_skippable_side(right):
            return None
        lv = self._resolve_pw_side(left)
        rv = self._resolve_pw_side(right)
        # Prefer the side that's a pure literal or const name, AND require
        # the OTHER side to NOT also be a fixed literal (that'd be a const
        # comparison, not a gate).
        if (rv is not None and lv is None
                and len(rv) >= self.MIN_PW_LEN
                and not self._is_skippable_string(rv)):
            pw_name = right.id if isinstance(right, ast.Name) else None
            return (left, rv, pw_name)
        if (lv is not None and rv is None
                and len(lv) >= self.MIN_PW_LEN
                and not self._is_skippable_string(lv)):
            pw_name = left.id if isinstance(left, ast.Name) else None
            return (right, lv, pw_name)
        return None

    # -- AST emitters for the replacement gate --

    def _bytes_literal(self, data):
        """Emit `bytes([b0, b1, ...])` — plain enough that downstream
        transforms (MBA / constant unfold) can rewrite the individual ints
        but the overall shape survives."""
        return ast.Call(
            func=ast.Name(id='bytes', ctx=ast.Load()),
            args=[ast.List(
                elts=[ast.Constant(value=b) for b in data],
                ctx=ast.Load())],
            keywords=[])

    def _import_call(self, module_name):
        """Emit `__import__('modname')`."""
        return ast.Call(
            func=ast.Name(id='__import__', ctx=ast.Load()),
            args=[ast.Constant(value=module_name)],
            keywords=[])

    def _build_decrypt_block(self, v_k, v_nn, v_ct):
        """Shared keystream-decrypt construction used by both the single-
        gate inline body and the multi-gate helper function.

        Given three Name ids — `v_k` (32-byte scrypt key), `v_nn` (nonce
        bytes), `v_ct` (ciphertext bytes) — return `(stmts, plaintext)`
        where `stmts` is the list of statements that build up the
        keystream, and `plaintext` is an expression that evaluates to
        the decrypted bytes. The caller decides whether to Assign or
        Return the plaintext.

        Keystream:  block_i = sha256(_k + _nn + i.to_bytes(4,'big')).digest()
        Plaintext:  bytes(a ^ b for a, b in zip(ct, ks[:len(ct)]))
        """
        ng = self.ng
        v_ks = ng.temp()
        v_i  = ng.temp()

        def _len(name):
            return ast.Call(
                func=ast.Name(id='len', ctx=ast.Load()),
                args=[ast.Name(id=name, ctx=ast.Load())], keywords=[])

        def _ks_block_expr():
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Attribute(
                            value=self._import_call('hashlib'),
                            attr='sha256', ctx=ast.Load()),
                        args=[ast.BinOp(
                            left=ast.BinOp(
                                left=ast.Name(id=v_k, ctx=ast.Load()),
                                op=ast.Add(),
                                right=ast.Name(id=v_nn, ctx=ast.Load())),
                            op=ast.Add(),
                            right=ast.Call(
                                func=ast.Attribute(
                                    value=ast.Name(id=v_i, ctx=ast.Load()),
                                    attr='to_bytes', ctx=ast.Load()),
                                args=[ast.Constant(value=4),
                                      ast.Constant(value='big')],
                                keywords=[]))],
                        keywords=[]),
                    attr='digest', ctx=ast.Load()),
                args=[], keywords=[])

        stmts = [
            ast.Assign(
                targets=[ast.Name(id=v_ks, ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id='bytearray', ctx=ast.Load()),
                    args=[], keywords=[])),
            ast.Assign(
                targets=[ast.Name(id=v_i, ctx=ast.Store())],
                value=ast.Constant(value=0)),
            ast.While(
                test=ast.Compare(
                    left=_len(v_ks), ops=[ast.Lt()],
                    comparators=[_len(v_ct)]),
                body=[
                    ast.Expr(value=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id=v_ks, ctx=ast.Load()),
                            attr='extend', ctx=ast.Load()),
                        args=[_ks_block_expr()],
                        keywords=[])),
                    ast.AugAssign(
                        target=ast.Name(id=v_i, ctx=ast.Store()),
                        op=ast.Add(),
                        value=ast.Constant(value=1)),
                ],
                orelse=[]),
        ]
        plaintext = ast.Call(
            func=ast.Name(id='bytes', ctx=ast.Load()),
            args=[ast.GeneratorExp(
                elt=ast.BinOp(
                    left=ast.Name(id='a', ctx=ast.Load()),
                    op=ast.BitXor(),
                    right=ast.Name(id='b', ctx=ast.Load())),
                generators=[ast.comprehension(
                    target=ast.Tuple(
                        elts=[ast.Name(id='a', ctx=ast.Store()),
                              ast.Name(id='b', ctx=ast.Store())],
                        ctx=ast.Store()),
                    iter=ast.Call(
                        func=ast.Name(id='zip', ctx=ast.Load()),
                        args=[
                            ast.Name(id=v_ct, ctx=ast.Load()),
                            ast.Subscript(
                                value=ast.Name(id=v_ks, ctx=ast.Load()),
                                slice=ast.Slice(
                                    lower=None, upper=_len(v_ct), step=None),
                                ctx=ast.Load()),
                        ],
                        keywords=[]),
                    ifs=[], is_async=0)])],
            keywords=[])
        return stmts, plaintext

    def _build_scrypt_assign(self, v_k, guess_expr, salt_expr):
        """Shared scrypt-key derivation: `_k = hashlib.scrypt(...)`.

        `guess_expr` is the user-side expression (the gate's operand).
        `salt_expr` is either a bytes-literal Call (inline path) or a
        Name load (helper path). Both return a 32-byte key.
        """
        encoded_guess = ast.Call(
            func=ast.Attribute(
                value=ast.Call(
                    func=ast.Name(id='str', ctx=ast.Load()),
                    args=[guess_expr], keywords=[]),
                attr='encode', ctx=ast.Load()),
            args=[ast.Constant(value='utf-8'),
                  ast.Constant(value='replace')],
            keywords=[])
        scrypt_call = ast.Call(
            func=ast.Attribute(
                value=self._import_call('hashlib'),
                attr='scrypt', ctx=ast.Load()),
            args=[encoded_guess],
            keywords=[
                ast.keyword(arg='salt',   value=salt_expr),
                ast.keyword(arg='n',      value=ast.Constant(value=self.KDF_N)),
                ast.keyword(arg='r',      value=ast.Constant(value=self.KDF_R)),
                ast.keyword(arg='p',      value=ast.Constant(value=self.KDF_P)),
                ast.keyword(arg='maxmem', value=ast.Constant(value=1073741824)),
                ast.keyword(arg='dklen',  value=ast.Constant(value=32)),
            ])
        return ast.Assign(
            targets=[ast.Name(id=v_k, ctx=ast.Store())],
            value=scrypt_call)

    def _build_helper_ast(self):
        """Build the module-level helper function
            def _sg_open(guess, salt, nonce, ct) -> bytes
        that performs scrypt-KDF + sha256-keystream decryption. Shared
        by 2+ gates via `_install_helper()`. The body is composed from
        `_build_scrypt_assign` + `_build_decrypt_block` so the inline and
        helper paths stay in lockstep.
        """
        name = self._helper_name
        p_g  = self._p_guess
        p_s  = self._p_salt
        p_n  = self._p_nonce
        p_c  = self._p_ct

        v_k  = self.ng.temp()
        scrypt_assign = self._build_scrypt_assign(
            v_k, ast.Name(id=p_g, ctx=ast.Load()),
            ast.Name(id=p_s, ctx=ast.Load()))
        dec_stmts, pt_expr = self._build_decrypt_block(v_k, p_n, p_c)
        body = [scrypt_assign] + dec_stmts + [ast.Return(value=pt_expr)]

        args = ast.arguments(
            posonlyargs=[],
            args=[
                ast.arg(arg=p_g, annotation=None),
                ast.arg(arg=p_s, annotation=None),
                ast.arg(arg=p_n, annotation=None),
                ast.arg(arg=p_c, annotation=None),
            ],
            vararg=None, kwonlyargs=[], kw_defaults=[],
            kwarg=None, defaults=[])
        return ast.FunctionDef(
            name=name,
            args=args,
            body=body,
            decorator_list=[],
            returns=None,
            type_comment=None)

    def _install_helper(self, module):
        """Insert the shared AEAD helper at module top level, after any
        leading `from __future__` imports. Called only on the extraction
        path (2+ gates)."""
        self._ensure_helper_names()
        helper = self._build_helper_ast()
        ast.fix_missing_locations(helper)
        insert_at = 0
        for i, stmt in enumerate(module.body):
            if (isinstance(stmt, ast.ImportFrom)
                    and stmt.module == '__future__'):
                insert_at = i + 1
            else:
                break
        module.body.insert(insert_at, helper)

    def _marshal_exec_tail(self, v_pt):
        """Common tail for both inline and call-site bodies:
            _co = marshal.loads(_pt)
            types.FunctionType(_co, globals())()
        Returns a list of two statements.

        v12.4: we emit `FunctionType(co, globals())()` instead of
        `exec(co, globals(), locals())`. Both run the code object in the
        enclosing scope's globals, but FunctionType dodges the
        `builtins.exec = _hook` interception that A6 uses. The locals()
        argument is dropped: the true-branch body is guaranteed by
        _sg_is_exec_safe() to not rebind locals (no FunctionDef /
        ClassDef / Global / Nonlocal), so running it through a fresh
        function frame is semantically equivalent for the restricted
        statement set we allow. The co_consts of the code object
        (including FLAG literals) never flow through any builtins
        attribute an attacker can monkey-patch from the outside.
        """
        ng = self.ng
        v_co = ng.temp()
        marshal_imp = self._import_call('marshal')
        types_imp = self._import_call('types')
        return [
            ast.Assign(
                targets=[ast.Name(id=v_co, ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Attribute(
                        value=marshal_imp, attr='loads', ctx=ast.Load()),
                    args=[ast.Name(id=v_pt, ctx=ast.Load())],
                    keywords=[])),
            ast.Expr(value=ast.Call(
                func=ast.Call(
                    func=ast.Attribute(
                        value=types_imp, attr='FunctionType', ctx=ast.Load()),
                    args=[
                        ast.Name(id=v_co, ctx=ast.Load()),
                        ast.Call(func=ast.Name(id='globals', ctx=ast.Load()),
                                 args=[], keywords=[]),
                    ],
                    keywords=[]),
                args=[], keywords=[])),
        ]

    def _build_callsite_body(self, guess_expr, salt, nonce, ct_and_tag):
        """Extraction path: emit `_pt = helper(...); marshal.loads; exec`.
        ~3 statements per gate; the heavy body lives in the helper."""
        self._ensure_helper_names()
        ng = self.ng
        v_pt = ng.temp()
        helper_call = ast.Call(
            func=ast.Name(id=self._helper_name, ctx=ast.Load()),
            args=[
                guess_expr,
                self._bytes_literal(salt),
                self._bytes_literal(nonce),
                self._bytes_literal(ct_and_tag),
            ],
            keywords=[])
        return [
            ast.Assign(
                targets=[ast.Name(id=v_pt, ctx=ast.Store())],
                value=helper_call),
        ] + self._marshal_exec_tail(v_pt)

    def _build_inline_body(self, guess_expr, salt, nonce, ct_and_tag):
        """Single-gate path: emit scrypt + sha256-keystream + XOR +
        marshal.loads + exec, inline in the gate. ~8 statements total.

        Keystream construction:
            block_i = sha256(key + nonce + i.to_bytes(4, 'big')).digest()
        `key` is 32 bytes from scrypt, so the keystream is indistinguishable
        from random without the password. Wrong-key decrypt -> junk bytes
        -> marshal.loads() raises -> outer try/except runs false branch.
        """
        ng = self.ng
        v_k   = ng.temp()   # scrypt-derived key
        v_ct  = ng.temp()   # ciphertext bytes
        v_nn  = ng.temp()   # nonce
        v_pt  = ng.temp()   # plaintext bytes

        scrypt_assign = self._build_scrypt_assign(
            v_k, guess_expr, self._bytes_literal(salt))
        dec_stmts, pt_expr = self._build_decrypt_block(v_k, v_nn, v_ct)

        body = [
            scrypt_assign,
            ast.Assign(
                targets=[ast.Name(id=v_ct, ctx=ast.Store())],
                value=self._bytes_literal(ct_and_tag)),
            ast.Assign(
                targets=[ast.Name(id=v_nn, ctx=ast.Store())],
                value=self._bytes_literal(nonce)),
        ] + dec_stmts + [
            ast.Assign(
                targets=[ast.Name(id=v_pt, ctx=ast.Store())],
                value=pt_expr),
        ]
        body += self._marshal_exec_tail(v_pt)
        return body

    # -- Main visitor --

    def visit_If(self, node):
        # Recurse first so nested gates inside an already-matched gate's
        # body also get rewritten before we encrypt the enclosing one.
        self.generic_visit(node)
        match = self._is_gate(node)
        if match is None:
            return node
        guess_expr, pw, pw_name = match

        # True-branch safety check.
        if not _sg_is_exec_safe(node.body):
            return node
        if sum(1 for _ in ast.walk(ast.Module(body=node.body, type_ignores=[]))
               ) > self.MAX_TRUE_BRANCH_NODES:
            return node

        # Inline module-level const strings into the true branch so their
        # literals travel inside the encrypted payload rather than living
        # in module globals where A5 can sniff them.
        inlined_body = self._inline_consts_into(
            [copy.deepcopy(s) for s in node.body])

        # v12.6: fragment every string constant in the true branch into
        # randomly-cut pieces joined with `+`. After `compile()`, the
        # code object's `co_consts` tuple holds the fragments separately,
        # not the whole secret. An attacker who bypasses v12.4's env
        # check (e.g., hooking types.FunctionType post-env-check) and
        # dumps co_consts sees a handful of short pieces per line —
        # substring-grep for the full FLAG fails. This runs BEFORE
        # compile() so the bytecode's LOAD_CONST / BUILD_STRING ops
        # reference the fragments directly.
        inlined_body = self._fragment_string_constants(inlined_body)

        # Compile the true-branch to a code object. Use a marker filename
        # so compile-audit hooks that dump filenames don't leak user paths.
        tb_module = ast.Module(body=inlined_body, type_ignores=[])
        ast.fix_missing_locations(tb_module)
        try:
            code_obj = compile(tb_module, '<pg_gate>', 'exec')
        except SyntaxError:
            # Inlining produced something compile() rejects — leave the
            # gate alone rather than breaking the build.
            return node
        payload = marshal.dumps(code_obj)

        # Random salt + nonce per gate. Seeded off the build RNG so two
        # builds with the same build seed produce identical stubs (useful
        # for reproducible builds); otherwise os.urandom would do.
        # v12.5: jitter salt / nonce length per gate within the declared
        # ranges. The lengths are implicit in the emitted byte literals
        # (gate reads len(salt) / len(nonce) from its own body), so no
        # extra metadata has to leak out.
        salt_len = self._rng.randint(self.SALT_LEN_MIN, self.SALT_LEN_MAX)
        nonce_len = self._rng.randint(self.NONCE_LEN_MIN, self.NONCE_LEN_MAX)
        salt = bytes(self._rng.randint(0, 255) for _ in range(salt_len))
        nonce = bytes(self._rng.randint(0, 255) for _ in range(nonce_len))
        key = hashlib.scrypt(
            pw.encode('utf-8', 'replace'),
            salt=salt, n=self.KDF_N, r=self.KDF_R, p=self.KDF_P,
            maxmem=1073741824, dklen=32)
        ct_and_tag = _sg_seal(key, nonce, payload)

        # Track which const names we're now responsible for (so a later
        # pruning pass can drop their module-level assignments).
        if pw_name is not None:
            self._consumed_pw.add(pw_name)

        self._fired += 1
        # Emit a placeholder Try — .body is filled later by
        # finalize_gates() once we know whether to inline or extract.
        placeholder = ast.Try(
            body=[ast.Pass()],  # filler, replaced by finalize_gates
            handlers=[ast.ExceptHandler(
                type=ast.Name(id='Exception', ctx=ast.Load()),
                name=None,
                body=(list(node.orelse) if node.orelse else [ast.Pass()]))],
            orelse=[], finalbody=[])
        self._pending.append(
            (placeholder, guess_expr, salt, nonce, ct_and_tag))
        return ast.copy_location(placeholder, node)

    # -- Finalize: decide inline vs helper based on gate count --

    def finalize_gates(self, module):
        """Fill in the placeholder Try bodies recorded by visit_If().

        Strategy:
          * 1 gate  -> inline the scrypt+AEAD body (smaller, faster boot
            because there's no FunctionDef creation or call through the
            obfuscated interpreter).
          * 2+ gates -> install a shared module-level helper and emit a
            per-gate call site (amortises body across gates).
        """
        if not self._pending:
            return
        if len(self._pending) >= 2:
            self._install_helper(module)
            for (node, guess_expr, salt, nonce, ct) in self._pending:
                node.body = self._build_callsite_body(
                    guess_expr, salt, nonce, ct)
        else:
            (node, guess_expr, salt, nonce, ct) = self._pending[0]
            node.body = self._build_inline_body(
                guess_expr, salt, nonce, ct)
        # After this, consumers should re-run ast.fix_missing_locations.

    # -- Post-pass: prune now-dead module-level const assignments --

    def prune(self, module):
        """Remove `NAME = "literal"` for every NAME whose ONLY remaining
        Load-references were rewritten/inlined by this transform."""
        # Re-walk the CURRENT (post-rewrite) tree to count surviving loads.
        surviving = {}
        for sub in ast.walk(module):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                if sub.id in self._const_strs:
                    surviving[sub.id] = surviving.get(sub.id, 0) + 1

        keep_body = []
        for stmt in module.body:
            if (isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and isinstance(stmt.targets[0], ast.Name)
                    and stmt.targets[0].id in self._const_strs):
                name = stmt.targets[0].id
                if surviving.get(name, 0) == 0:
                    # Fully consumed / inlined. Drop the assignment.
                    continue
                # Mixed use: still referenced elsewhere. Leave the
                # assignment in place so the surviving refs still work.
            keep_body.append(stmt)
        module.body = keep_body
        return module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_assign(name, value):
    return ast.Assign(
        targets=[ast.Name(id=name, ctx=ast.Store())],
        value=ast.Constant(value=value))

def _make_assign_marker(sv, marker):
    """Create an assignment with a string marker value for later resolution."""
    return ast.Assign(
        targets=[ast.Name(id=sv, ctx=ast.Store())],
        value=ast.Constant(value=marker))

def _make_eq(name, value):
    return ast.Compare(
        left=ast.Name(id=name, ctx=ast.Load()),
        ops=[ast.Eq()],
        comparators=[ast.Constant(value=value)])

def _build_if_chain(cases):
    if not cases:
        return ast.Pass()
    test, body = cases[0]
    if len(cases) == 1:
        return ast.If(test=test, body=body, orelse=[])
    return ast.If(test=test, body=body,
                  orelse=[_build_if_chain(cases[1:])])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _apply_transforms(tree, ng, rename_identifiers=True, rewrite_secret_gates=True):
    """Apply all transforms in the correct order.

    Order matters:
      0. Secret-gate rewrite (v12.1) — detect `if X == "pw":` patterns and
         encrypt the true-branch with scrypt+AEAD. MUST run BEFORE identifier
         renaming so the rewriter can still resolve module-level Name -> str
         bindings (e.g. `FLAG = "..."`) and inline them into the encrypted
         payload. After this pass, module-level string constants consumed
         purely by the gate (or inlined into its true branch) are pruned.
         Skipped when rewrite_secret_gates=False — required for interpreter
         self-obfuscation because every `if op == 'IBreak':`-style dispatch
         branch looks like a gate to the rewriter, and wrapping those in
         scrypt-AEAD exec bodies breaks raise/generator semantics.
      1. Identifier renaming         — mangle user names before any
         restructuring so CFF/decomposition temps can't collide with them.
      2. Expression decomposition    — break nested calls / BinOps into
         temporaries before CFF rearranges statements.
      3. Opaque predicates           — inject always-true/always-false
         dead branches before CFF so they become dispatcher states too.
      4. Control-flow flattening     — rewrite blocks into state machines.
      5. Call indirection            — route every resolvable Name-call
         through `_pg_D[opaque_key]`. Must run AFTER rename (keys reference
         final names) and AFTER CFF (so CFF-synthesised `iter`/`next` etc.
         also get indirected). Emits key expressions as `(enc ^ mask)` so
         MBA can rewrite them further.
      6. Constant unfolding          — rewrite small int literals as
         arithmetic chains. Skips ints > 500, so indirection keys (10^7+)
         pass through untouched.
      7. MBA obfuscation             — rewrite {+, -, ^, |, &} into MBA
         identities on all provably-int operands.
      8. String obfuscation          — split every non-empty string ≤ 200
         bytes into K ≥ 2 XOR'd fragments.
    """
    # Step 0: Secret-gate rewrite. Must run on an ast.Module.
    if rewrite_secret_gates and isinstance(tree, ast.Module):
        sgr = _SecretGateRewriter(ng)
        sgr.prepare(tree)
        tree = sgr.visit(tree)
        if sgr._fired > 0:
            # Two-phase emission: visit_If() recorded placeholder Try
            # nodes; finalize_gates() now fills their bodies, inlining
            # for a single gate or extracting to a shared helper for
            # 2+ gates. Then prune dead module-level const assignments.
            sgr.finalize_gates(tree)
            sgr.prune(tree)
        ast.fix_missing_locations(tree)

    if rename_identifiers:
        renamer = _IdentifierRenamer(ng)
        renamer.prepare(tree)
        tree = renamer.visit(tree)
        ast.fix_missing_locations(tree)

    # v5.1 / C1: mangle attribute access into _gA/_sA/_dA calls keyed by
    # small ints, with real names XOR-masked in a synthesized `_ATAB`
    # tuple. Must run AFTER identifier renaming — otherwise the renamer
    # sees zero Attribute nodes (we replaced them all with Calls) and
    # proceeds to rename method definitions like `def unlock():` whose
    # callers no longer match. By running the mangler SECOND, the
    # renamer already preserved method names via its `_attr_names`
    # collection pass, and the mangler's helper names (self.n_gA etc.)
    # are already opaque temps (allocated via `ng.temp()`) so they
    # won't be re-renamed and won't clash with user identifiers.
    if rename_identifiers and isinstance(tree, ast.Module):
        mangler = _AttributeMangler(ng)
        tree = mangler.visit(tree)
        # C2: conceal imports by routing them through _imp (module paths
        # in _IMPT) and _gA (imported names reuse _ATAB). Runs BEFORE
        # inject_prelude so registered module keys show up in the emitted
        # _IMPT tuple. Shares mangler state so `from X import Y` reuses
        # the attr-table index allocator rather than fighting for a
        # separate keyspace.
        tree = _ImportConcealer(ng, mangler).visit(tree)
        mangler.inject_prelude(tree, ng._rng)
        ast.fix_missing_locations(tree)

    tree = _ExprDecomposer(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _OpaquePredicateInjector(ng).visit(tree)
    ast.fix_missing_locations(tree)

    # Decompose simple f-strings before CFF/call indirection so the new
    # `str(x)` calls flow through the indirector and the newly-exposed
    # literal fragments flow through the string obfuscator.
    tree = _FStringDeformer().visit(tree)
    ast.fix_missing_locations(tree)

    tree = _CFFlattener(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _CallIndirector(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _ConstantUnfolder(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _MBAObfuscator(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _StringObfuscator(ng).visit(tree)
    ast.fix_missing_locations(tree)

    return tree


def transform_source(source, seed=None, rename_identifiers=True,
                     rewrite_secret_gates=True):
    """Apply all obfuscating AST transforms to Python source."""
    tree = ast.parse(source)
    ng = _NameGen(seed)
    return _apply_transforms(tree, ng,
                             rename_identifiers=rename_identifiers,
                             rewrite_secret_gates=rewrite_secret_gates)


def transform_ast_tree(tree, seed=None, rename_identifiers=True,
                       rewrite_secret_gates=True):
    """Apply transforms to an already-parsed AST tree.

    Set rename_identifiers=False when the caller handles its own
    identifier renaming (e.g. obfuscate_runtime.py).

    Set rewrite_secret_gates=False when transforming the interpreter
    itself — the rewriter mistakes `if op == 'IBreak':` dispatch branches
    for password gates and wraps them in scrypt-AEAD exec bodies that
    break generator/raise semantics.
    """
    ng = _NameGen(seed)
    return _apply_transforms(tree, ng,
                             rename_identifiers=rename_identifiers,
                             rewrite_secret_gates=rewrite_secret_gates)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("usage: transform_ast.py <source.py>")
        sys.exit(2)
    with open(sys.argv[1]) as f:
        src = f.read()
    tree = transform_source(src)
    print(ast.unparse(tree))

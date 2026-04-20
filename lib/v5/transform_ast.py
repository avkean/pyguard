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


_SEM_ISLAND_SENTINEL = '__pyguard_semantic_island__'
_LAST_SEMANTIC_ISLAND_AUX = []

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


# v6.5 / C17 — emit a bytes-constructor call that does NOT resolve through
# the `bytes` Name at runtime. Instead we build `(b'').__class__(...)`:
#   Constant(b'')       -> real bytes literal (no Name lookup)
#   .__class__          -> C-slot Py_TYPE read on object header, returns
#                          real bytes type even if builtins.bytes has been
#                          replaced with a sitecustomize-planted subclass
#   Call([...])         -> invokes real bytes constructor
# The emitted AST never hits `getattr(builtins, 'bytes')`, so a `_SpyBytes`
# subclass installed via `builtins.bytes = _SpyBytes` cannot intercept the
# literal reconstruction path (string-pool decode, attr-name decode, etc).
def _bytes_ctor(args_list):
    return ast.Call(
        func=ast.Attribute(
            value=ast.Constant(value=b''),
            attr='__class__', ctx=ast.Load()),
        args=[args_list], keywords=[])


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
        return _bytes_ctor(ast.List(
            elts=[ast.Constant(value=x) for x in masked],
            ctx=ast.Load()))

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
            value=_bytes_ctor(ast.List(
                elts=[ast.Constant(value=b) for b in mask],
                ctx=ast.Load()))))

        # _ATAB is required even if empty (in case only imports were
        # registered) — keep _gA/_sA/_dA definitions self-contained.
        ordered_attr = sorted(self._key.items(), key=lambda kv: kv[1])
        atab_entries = [self._masked_bytes_node(name.encode('utf-8'), mask)
                        for name, _k in ordered_attr]
        prelude_body.append(ast.Assign(
            targets=[ast.Name(id=self.n_ATAB, ctx=ast.Store())],
            value=ast.Tuple(elts=atab_entries, ctx=ast.Load())))

        # v6.5 / C17 — use `(b'').__class__(...)` instead of `bytes(...)` so
        # the attr-name decode path cannot be intercepted by a sitecustomize
        # `builtins.bytes = _SpyBytes` hook. `b''.__class__` is a C-slot read
        # on the bytes literal's object header and returns the real bytes type
        # regardless of the builtins-module binding.
        attr_helpers_src = (
            f'def {self.n_gA}(_o, _k):\n'
            f'    return getattr(_o, (b\'\').__class__(_c ^ {self.n_AM}[_i & 15] for _i, _c in enumerate({self.n_ATAB}[_k])).decode())\n'
            f'def {self.n_sA}(_o, _k, _v):\n'
            f'    setattr(_o, (b\'\').__class__(_c ^ {self.n_AM}[_i & 15] for _i, _c in enumerate({self.n_ATAB}[_k])).decode(), _v)\n'
            f'def {self.n_dA}(_o, _k):\n'
            f'    delattr(_o, (b\'\').__class__(_c ^ {self.n_AM}[_i & 15] for _i, _c in enumerate({self.n_ATAB}[_k])).decode())\n'
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
                f'    return __import__((b\'\').__class__(_c ^ {self.n_AM}[_i & 15] for _i, _c in enumerate({self.n_IMPT}[_k])).decode(), None, None, (\'_\',), 0)\n'
            )
            prelude_body.extend(ast.parse(imp_src).body)

        tree.body = prelude_body + tree.body
        ast.fix_missing_locations(tree)


# ---------------------------------------------------------------------------
# Import Concealment (C2)
# ---------------------------------------------------------------------------

class _ImportConcealer(ast.NodeTransformer):
    """Rewrite only residual import shapes into opaque-key lookups.

    Shares state with _AttributeMangler:
      - Module paths are interned into `_IMPT` (mangler.add_mod_key)
      - Imported names are interned into the same `_ATAB` used for
        attribute access (mangler.add_attr_key), so a single table hides
        both surfaces.

    v6.6 / C20: common static absolute imports are now left intact so the
    build-IR layer can lift them into encrypted manifest-backed lookup ops.
    That closes the `sys.modules` proxy leak at the runtime IR layer instead
    of routing normal imports through `_imp(...)` / `_gA(...)` forever.

    Still transformed here (residual / harder-to-freeze cases):
      import X.Y as Z             →  Z = _imp(k_XY)           # fromlist → submod

    Left structurally intact for downstream lowering / fallback:
      import X
      import X as Y
      from X import Y
      from X import Y as Z
      from X import Y1, Y2
      from X.Y import Z
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
            mod = alias.name
            if not mod:
                leftover.append(alias)
                continue
            if '.' not in mod:
                leftover.append(alias)
                continue
            if not alias.asname:
                # `import X.Y` with no asname binds `X` (top-level). Our
                # `_imp` helper returns the deepest submodule (X.Y), which
                # doesn't match that semantic. Leave this intact.
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
        return node


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
            blocks = [_Block(cond_state, [ast.If(
                test=node.test,
                body=[_make_assign(sv, body_state)],
                orelse=[_make_assign_marker(sv, '__EXIT__')]
            )], _CFF_BRANCH)]

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
                value=_bytes_ctor(ast.List(elts=all_elts, ctx=ast.Load())),
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
# Local Slot Lifting (v6.0 / C6.B)
# ---------------------------------------------------------------------------
#
# Rationale
# ---------
# Even after C1 attribute mangling and identifier renaming, each function's
# locals still land in the IR string pool as distinct identifiers (renamed
# to opaque tokens, but one token per variable). The IR tree also marks
# every variable access as a Name node, which is a 1-to-1 proxy for "this
# is variable X of function F." An analyst reading the IR can still
# partition local-variable nodes per function and infer data flow.
#
# This pass collapses all locals of a function into a single list `_s`
# indexed by small integers. Every Load/Store/Del of a local becomes a
# Subscript(Name('_s'), Constant(idx)) node. The IR string pool no longer
# carries per-variable names (only the single `_s` name per build-random
# token); the IR node type for every variable access is uniformly
# Subscript, not Name. Per-function variable identity dissolves into
# positional slot references.
#
# Applied per-FunctionDef, before fusion (so fused branches each carry
# their own slot table allocation and the fusion parameter-binding
# prologue still works through the parameter-name bindings).
#
# Eligibility (conservative):
#   - No yield / yield from     (slotting across yield is legal, but we
#                                skip to keep the first implementation
#                                small; can revisit)
#   - No nested FunctionDef / AsyncFunctionDef / ClassDef / Lambda in body
#                               (nested scopes read closures by name, and
#                                lifting the outer's locals would break
#                                the Inner's cell-variable binding)
#   - No `nonlocal` declaration (same reason — the parent's slotted
#                                local would not be visible as a cell)
#   - No `del LOCAL_NAME`       (del on a list subscript shifts indices)
#   - Exception handler's `except ... as NAME` where NAME is local:
#                                left un-slotted (rewriting ExceptHandler
#                                name attr to a subscript is invalid AST).
#                                These names remain plain locals; they
#                                don't leak anything meaningful.

class _LocalSlotLifter(ast.NodeTransformer):
    """Per-function: replace local Name references with `_s[idx]` subscripts."""

    def __init__(self, ng):
        self.ng = ng
        # Per-build name for the slot list. ONE name used in every function.
        # Rationale: using one name keeps the string pool pressure constant
        # regardless of function count — all slot accesses share the token.
        self._slot = ng.temp()
        self.lifted_count = 0

    def visit_Module(self, node):
        self.generic_visit(node)
        return node

    def _is_eligible(self, fn):
        # Reject generators
        for n in ast.walk(fn):
            if isinstance(n, (ast.Yield, ast.YieldFrom)):
                return False
        # Scan body (without descending into nested scopes) for hard cases
        stack = list(fn.body)
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef, ast.Lambda)):
                return False
            if isinstance(n, ast.Nonlocal):
                return False
            if isinstance(n, ast.Delete):
                # If any target is a Name that would become a slot, reject.
                # (Subscript targets, attr targets are fine.)
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        return False
            stack.extend(ast.iter_child_nodes(n))
        return True

    def _collect_locals(self, fn):
        """Return (slot_map, except_names) for this function.

        - slot_map: {local_name: slot_index} for names we will rewrite.
        - except_names: set of names used by `except ... as NAME:` — these
          stay un-slotted (NAME is a string attr, not a Name node).
        """
        # Globals/nonlocals declared (excluded from slotting)
        excluded = set()
        # Parameter names (always local)
        param_names = set()
        for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs:
            param_names.add(a.arg)
        if fn.args.vararg:
            param_names.add(fn.args.vararg.arg)
        if fn.args.kwarg:
            param_names.add(fn.args.kwarg.arg)

        # Scan body, no nested-scope descent
        stored = set()
        except_names = set()
        stack = list(fn.body)
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef, ast.Lambda)):
                continue  # opaque
            if isinstance(n, ast.Global):
                excluded.update(n.names)
            elif isinstance(n, ast.Nonlocal):
                excluded.update(n.names)
            elif isinstance(n, ast.Name) and isinstance(n.ctx,
                                                        (ast.Store, ast.Del)):
                stored.add(n.id)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                except_names.add(n.name)
            elif isinstance(n, ast.arg):
                # (nested arg objects — defensive)
                param_names.add(n.arg)
            stack.extend(ast.iter_child_nodes(n))

        locals_ = (param_names | stored) - excluded - except_names
        if not locals_:
            return {}, except_names
        # Deterministic-but-shuffled slot assignment per build.
        ordered = sorted(locals_)
        self.ng._rng.shuffle(ordered)
        return {name: i for i, name in enumerate(ordered)}, except_names

    def _sub(self, idx, ctx):
        return ast.Subscript(
            value=ast.Name(id=self._slot, ctx=ast.Load()),
            slice=ast.Constant(value=idx),
            ctx=ctx)

    def _rewrite_body(self, body, slot_map, except_names):
        """Walk `body` without descending into nested scopes; rewrite Name
        references for slotted locals to Subscript(_s, idx)."""
        slot_name = self._slot

        class _Rewriter(ast.NodeTransformer):
            def visit_FunctionDef(_self, node):
                return node  # don't recurse
            def visit_AsyncFunctionDef(_self, node):
                return node
            def visit_ClassDef(_self, node):
                return node
            def visit_Lambda(_self, node):
                return node
            def visit_Name(_self, node):
                if node.id in slot_map:
                    return ast.Subscript(
                        value=ast.Name(id=slot_name, ctx=ast.Load()),
                        slice=ast.Constant(value=slot_map[node.id]),
                        ctx=node.ctx)
                return node
            def visit_Global(_self, node):
                # Don't touch — names are strings; they reference module-scope.
                return node
            def visit_Nonlocal(_self, node):
                return node

        r = _Rewriter()
        return [r.visit(s) for s in body]

    def visit_FunctionDef(self, node):
        # Don't recurse into nested functions from here — we still visit
        # them separately via Module's generic_visit; but if THIS function
        # is eligible, its body must not contain nested scopes (enforced
        # by _is_eligible), so no inner rewriting needed.
        if not self._is_eligible(node):
            # Recurse so nested eligible fns get processed.
            self.generic_visit(node)
            return node

        slot_map, except_names = self._collect_locals(node)
        if len(slot_map) < 1:
            return node
        # Note: threshold = 1, not 2. Lifting trivial single-local functions
        # too keeps the IR shape uniform across all eligible functions
        # (every local access is a Subscript node). Non-uniformity would
        # leak a discriminator: functions with >=2 locals slotted, <2 not.

        new_body = self._rewrite_body(node.body, slot_map, except_names)

        # Prologue: allocate _s and copy params into their slots.
        prologue = []
        prologue.append(ast.Assign(
            targets=[ast.Name(id=self._slot, ctx=ast.Store())],
            value=ast.List(elts=[ast.Constant(value=None)] * len(slot_map),
                           ctx=ast.Load())))
        # Copy parameters into their slots. Parameter references inside the
        # body have been rewritten to subscripts, so we must also *seed*
        # those slots from the Python-level parameter bindings.
        all_params = list(node.args.posonlyargs) + list(node.args.args) + \
                     list(node.args.kwonlyargs)
        if node.args.vararg:
            all_params.append(node.args.vararg)
        if node.args.kwarg:
            all_params.append(node.args.kwarg)
        for a in all_params:
            if a.arg in slot_map:
                prologue.append(ast.Assign(
                    targets=[self._sub(slot_map[a.arg], ast.Store())],
                    value=ast.Name(id=a.arg, ctx=ast.Load())))

        node.body = prologue + new_body
        self.lifted_count += 1
        return node

    def visit_AsyncFunctionDef(self, node):
        # Treat the same as FunctionDef for eligibility — but we skip async
        # entirely (safer; async adds await scope).
        self.generic_visit(node)
        return node


class _SemanticIslandCompiler:
    """Compile a closure-sized statement region into a bespoke VM payload."""

    _UNARY = {
        ast.Not: 'NOT',
        ast.UAdd: 'UADD',
        ast.USub: 'USUB',
        ast.Invert: 'INVERT',
    }
    _BINARY = {
        ast.Add: 'ADD',
        ast.Sub: 'SUB',
        ast.Mult: 'MULT',
        ast.Div: 'DIV',
        ast.FloorDiv: 'FLOORDIV',
        ast.Mod: 'MOD',
        ast.Pow: 'POW',
        ast.BitOr: 'BITOR',
        ast.BitXor: 'BITXOR',
        ast.BitAnd: 'BITAND',
        ast.LShift: 'LSHIFT',
        ast.RShift: 'RSHIFT',
        ast.MatMult: 'MATMULT',
    }
    _COMPARE = {
        ast.Eq: 'EQ',
        ast.NotEq: 'NE',
        ast.Lt: 'LT',
        ast.LtE: 'LE',
        ast.Gt: 'GT',
        ast.GtE: 'GE',
        ast.Is: 'IS',
        ast.IsNot: 'ISNOT',
        ast.In: 'IN',
        ast.NotIn: 'NOTIN',
    }
    _LOGICAL_OPS = (
        'LOAD_CONST', 'LOAD_NAME', 'LOAD_SLOT',
        'STORE_NAME', 'STORE_SLOT',
        'LOAD_SUBSCR',
        'BUILD_LIST', 'BUILD_TUPLE',
        'POP', 'CALL',
        'UNARY', 'BINARY', 'COMPARE',
        'JUMP', 'JUMP_IF_FALSE', 'JUMP_IF_TRUE',
        'RETURN', 'BREAK', 'CONTINUE', 'RAISE',
    )
    _UNARY_LOGICAL = ('NOT', 'UADD', 'USUB', 'INVERT')
    _BINARY_LOGICAL = (
        'ADD', 'SUB', 'MULT', 'DIV', 'FLOORDIV', 'MOD', 'POW',
        'BITOR', 'BITXOR', 'BITAND', 'LSHIFT', 'RSHIFT', 'MATMULT',
    )
    _COMPARE_LOGICAL = (
        'EQ', 'NE', 'LT', 'LE', 'GT', 'GE', 'IS', 'ISNOT', 'IN', 'NOTIN',
    )

    def __init__(self, ng, slot_name, randomize=True):
        self.ng = ng
        self.slot_name = slot_name
        self._uses_slot = False
        self._used_slots = set()
        self._names = []
        self._name_idx = {}
        self._consts = []
        self._const_idx = {}
        self._insts = []
        self._labels = {}
        self._loop_stack = []
        rng = ng._rng if randomize else random.Random(0)
        self._island_id = rng.getrandbits(32) or 1
        self._aux_key = bytes(rng.getrandbits(8) for _ in range(32))
        code_pool = list(range(1, 256))
        rng.shuffle(code_pool)
        self._opcodes = {
            name: code_pool[i] for i, name in enumerate(self._LOGICAL_OPS)
        }
        unary_pool = list(range(1, 256))
        binary_pool = list(range(1, 256))
        compare_pool = list(range(1, 256))
        rng.shuffle(unary_pool)
        rng.shuffle(binary_pool)
        rng.shuffle(compare_pool)
        self._unary_codes = {
            name: unary_pool[i] for i, name in enumerate(self._UNARY_LOGICAL)
        }
        self._binary_codes = {
            name: binary_pool[i] for i, name in enumerate(self._BINARY_LOGICAL)
        }
        self._compare_codes = {
            name: compare_pool[i] for i, name in enumerate(self._COMPARE_LOGICAL)
        }
        self._flags = {
            'reverse_stack': bool(rng.getrandbits(1)),
            'relative_jumps': bool(rng.getrandbits(1)),
            'callee_last': bool(rng.getrandbits(1)),
            'dispatch_mode': rng.randint(0, 1),
        }
        state_slots = [0, 1, 2, 3]
        rng.shuffle(state_slots)
        self._state_layout = {
            'pc': state_slots[0],
            'stack': state_slots[1],
            'slot': state_slots[2],
            'scratch': state_slots[3],
        }
        self._u8_keys = {
            'count': (rng.randint(0, 255), rng.randint(0, 255)),
            'unaryop': (rng.randint(0, 255), rng.randint(0, 255)),
            'binaryop': (rng.randint(0, 255), rng.randint(0, 255)),
            'compareop': (rng.randint(0, 255), rng.randint(0, 255)),
        }
        self._u16_keys = {
            'name': (rng.randint(0, 0xFFFF), rng.randint(0, 0xFFFF)),
            'const': (rng.randint(0, 0xFFFF), rng.randint(0, 0xFFFF)),
            'slot': (rng.randint(0, 0xFFFF), rng.randint(0, 0xFFFF)),
            'jump': (rng.randint(0, 0xFFFF), rng.randint(0, 0xFFFF)),
        }

    @property
    def island_id(self):
        return self._island_id

    @property
    def aux_key(self):
        return self._aux_key

    def _key_for_const(self, value):
        t = type(value)
        if t is list:
            return ('list', tuple(self._key_for_const(x) for x in value))
        if t is tuple:
            return ('tuple', tuple(self._key_for_const(x) for x in value))
        if t is bytes:
            return ('bytes', bytes(value))
        return (t.__name__, repr(value))

    def _const(self, value):
        key = self._key_for_const(value)
        idx = self._const_idx.get(key)
        if idx is None:
            idx = len(self._consts)
            self._const_idx[key] = idx
            self._consts.append(value)
        return idx

    def _name(self, value):
        idx = self._name_idx.get(value)
        if idx is None:
            idx = len(self._names)
            self._name_idx[value] = idx
            self._names.append(value)
        return idx

    def _emit(self, opname, *operands):
        self._insts.append({'op': opname, 'operands': list(operands)})

    def _label(self, name):
        self._labels[name] = len(self._insts)

    def _new_label(self):
        return self.ng.temp()

    def _slot_index(self, node):
        if not isinstance(node, ast.Subscript):
            return None
        if not isinstance(node.value, ast.Name) or node.value.id != self.slot_name:
            return None
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, int):
            return sl.value
        return None

    def _enc_u8(self, value, kind):
        add, xor = self._u8_keys[kind]
        return (((value & 0xFF) + add) & 0xFF) ^ xor

    def _enc_u16(self, value, kind):
        add, xor = self._u16_keys[kind]
        return ((((value & 0xFFFF) + add) & 0xFFFF) ^ xor) & 0xFFFF

    def _expr_supported(self, node, allow_bool):
        slot_idx = self._slot_index(node)
        if slot_idx is not None:
            return True
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, (ast.List, ast.Tuple)):
            return len(node.elts) <= 255 and all(
                self._expr_supported(elt, allow_bool=False) for elt in node.elts
            )
        if isinstance(node, ast.Subscript):
            return self._expr_supported(node.value, allow_bool=False) and \
                self._expr_supported(node.slice, allow_bool=False)
        if isinstance(node, ast.Call):
            if node.keywords or len(node.args) > 255:
                return False
            if not self._expr_supported(node.func, allow_bool=False):
                return False
            return all(self._expr_supported(a, allow_bool=False) for a in node.args)
        if isinstance(node, ast.UnaryOp):
            if type(node.op) not in self._UNARY:
                return False
            return self._expr_supported(node.operand, allow_bool=allow_bool)
        if isinstance(node, ast.BinOp):
            if type(node.op) not in self._BINARY:
                return False
            return self._expr_supported(node.left, False) and \
                self._expr_supported(node.right, False)
        if isinstance(node, ast.Compare):
            if len(node.ops) != 1 or len(node.comparators) != 1:
                return False
            if type(node.ops[0]) not in self._COMPARE:
                return False
            return self._expr_supported(node.left, False) and \
                self._expr_supported(node.comparators[0], False)
        if allow_bool and isinstance(node, ast.BoolOp):
            return all(self._expr_supported(v, allow_bool=True) for v in node.values)
        return False

    def _target_supported(self, node):
        return self._slot_index(node) is not None or isinstance(node, ast.Name)

    def _stmt_supported(self, stmt):
        if isinstance(stmt, ast.If):
            if not self._expr_supported(stmt.test, allow_bool=True):
                return False
            return all(self._stmt_supported(s) for s in stmt.body) and \
                all(self._stmt_supported(s) for s in stmt.orelse)
        if isinstance(stmt, ast.While):
            if stmt.orelse:
                return False
            if not self._expr_supported(stmt.test, allow_bool=True):
                return False
            return all(self._stmt_supported(s) for s in stmt.body)
        if isinstance(stmt, ast.Expr):
            return self._expr_supported(stmt.value, allow_bool=False)
        if isinstance(stmt, ast.Assign):
            return len(stmt.targets) == 1 and \
                self._target_supported(stmt.targets[0]) and \
                self._expr_supported(stmt.value, allow_bool=False)
        if isinstance(stmt, ast.AugAssign):
            return self._target_supported(stmt.target) and \
                type(stmt.op) in self._BINARY and \
                self._expr_supported(stmt.value, allow_bool=False)
        if isinstance(stmt, ast.Return):
            return stmt.value is None or self._expr_supported(stmt.value, allow_bool=False)
        if isinstance(stmt, ast.Raise):
            return stmt.cause is None and stmt.exc is not None and \
                self._expr_supported(stmt.exc, allow_bool=False)
        return isinstance(stmt, (ast.Pass, ast.Break, ast.Continue))

    def supports(self, node):
        if isinstance(node, list):
            return all(self._stmt_supported(stmt) for stmt in node)
        return self._stmt_supported(node)

    def _compile_expr(self, node, allow_bool=False):
        slot_idx = self._slot_index(node)
        if slot_idx is not None:
            self._uses_slot = True
            self._used_slots.add(slot_idx)
            self._emit('LOAD_SLOT', ('slot', slot_idx))
            return
        if isinstance(node, ast.Constant):
            self._emit('LOAD_CONST', ('const', self._const(node.value)))
            return
        if isinstance(node, ast.Name):
            self._emit('LOAD_NAME', ('name', self._name(node.id)))
            return
        if isinstance(node, ast.List):
            for elt in node.elts:
                self._compile_expr(elt, allow_bool=False)
            self._emit('BUILD_LIST', ('count', len(node.elts)))
            return
        if isinstance(node, ast.Tuple):
            for elt in node.elts:
                self._compile_expr(elt, allow_bool=False)
            self._emit('BUILD_TUPLE', ('count', len(node.elts)))
            return
        if isinstance(node, ast.Subscript):
            self._compile_expr(node.value, allow_bool=False)
            self._compile_expr(node.slice, allow_bool=False)
            self._emit('LOAD_SUBSCR')
            return
        if isinstance(node, ast.Call):
            if self._flags['callee_last']:
                for arg in node.args:
                    self._compile_expr(arg, allow_bool=False)
                self._compile_expr(node.func, allow_bool=False)
            else:
                self._compile_expr(node.func, allow_bool=False)
                for arg in node.args:
                    self._compile_expr(arg, allow_bool=False)
            self._emit('CALL', ('count', len(node.args)))
            return
        if isinstance(node, ast.UnaryOp):
            self._compile_expr(node.operand, allow_bool=allow_bool)
            self._emit('UNARY', ('unaryop', self._UNARY[type(node.op)]))
            return
        if isinstance(node, ast.BinOp):
            self._compile_expr(node.left, allow_bool=False)
            self._compile_expr(node.right, allow_bool=False)
            self._emit('BINARY', ('binaryop', self._BINARY[type(node.op)]))
            return
        if isinstance(node, ast.Compare):
            self._compile_expr(node.left, allow_bool=False)
            self._compile_expr(node.comparators[0], allow_bool=False)
            self._emit('COMPARE', ('compareop', self._COMPARE[type(node.ops[0])]))
            return
        if allow_bool and isinstance(node, ast.BoolOp):
            l_false = self._new_label()
            l_end = self._new_label()
            self._compile_test_jump_false(node, l_false)
            self._emit('LOAD_CONST', ('const', self._const(True)))
            self._emit('JUMP', ('label', l_end))
            self._label(l_false)
            self._emit('LOAD_CONST', ('const', self._const(False)))
            self._label(l_end)
            return
        raise ValueError('unsupported expr')

    def _compile_store(self, target):
        slot_idx = self._slot_index(target)
        if slot_idx is not None:
            self._uses_slot = True
            self._used_slots.add(slot_idx)
            self._emit('STORE_SLOT', ('slot', slot_idx))
            return
        if isinstance(target, ast.Name):
            self._emit('STORE_NAME', ('name', self._name(target.id)))
            return
        raise ValueError('unsupported store target')

    def _compile_test_jump_false(self, node, false_label):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            for value in node.values:
                self._compile_test_jump_false(value, false_label)
            return
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            done_label = self._new_label()
            for value in node.values[:-1]:
                self._compile_expr(value, allow_bool=True)
                self._emit('JUMP_IF_TRUE', ('label', done_label))
            self._compile_test_jump_false(node.values[-1], false_label)
            self._label(done_label)
            return
        self._compile_expr(node, allow_bool=True)
        self._emit('JUMP_IF_FALSE', ('label', false_label))

    def _compile_stmt(self, stmt):
        if isinstance(stmt, ast.If):
            l_else = self._new_label()
            l_end = self._new_label()
            self._compile_test_jump_false(stmt.test, l_else)
            for sub in stmt.body:
                self._compile_stmt(sub)
            self._emit('JUMP', ('label', l_end))
            self._label(l_else)
            for sub in stmt.orelse:
                self._compile_stmt(sub)
            self._label(l_end)
            return
        if isinstance(stmt, ast.While):
            l_test = self._new_label()
            l_end = self._new_label()
            self._label(l_test)
            self._compile_test_jump_false(stmt.test, l_end)
            self._loop_stack.append((l_end, l_test))
            for sub in stmt.body:
                self._compile_stmt(sub)
            self._loop_stack.pop()
            self._emit('JUMP', ('label', l_test))
            self._label(l_end)
            return
        if isinstance(stmt, ast.Expr):
            self._compile_expr(stmt.value, allow_bool=False)
            self._emit('POP')
            return
        if isinstance(stmt, ast.Assign):
            self._compile_expr(stmt.value, allow_bool=False)
            self._compile_store(stmt.targets[0])
            return
        if isinstance(stmt, ast.AugAssign):
            self._compile_expr(stmt.target, allow_bool=False)
            self._compile_expr(stmt.value, allow_bool=False)
            self._emit('BINARY', ('binaryop', self._BINARY[type(stmt.op)]))
            self._compile_store(stmt.target)
            return
        if isinstance(stmt, ast.Return):
            if stmt.value is None:
                self._emit('LOAD_CONST', ('const', self._const(None)))
            else:
                self._compile_expr(stmt.value, allow_bool=False)
            self._emit('RETURN')
            return
        if isinstance(stmt, ast.Raise):
            self._compile_expr(stmt.exc, allow_bool=False)
            self._emit('RAISE')
            return
        if isinstance(stmt, ast.Pass):
            return
        if isinstance(stmt, ast.Break):
            if self._loop_stack:
                self._emit('JUMP', ('label', self._loop_stack[-1][0]))
            else:
                self._emit('BREAK')
            return
        if isinstance(stmt, ast.Continue):
            if self._loop_stack:
                self._emit('JUMP', ('label', self._loop_stack[-1][1]))
            else:
                self._emit('CONTINUE')
            return
        raise ValueError('unsupported stmt')

    def _fragment_bytes(self, raw):
        if not raw:
            return [(0, b'')]
        rng = self.ng._rng
        max_parts = min(4, len(raw))
        part_count = rng.randint(2, max_parts) if max_parts >= 2 and len(raw) >= 4 else 1
        if part_count == 1:
            parts = [raw]
        else:
            cuts = sorted(rng.sample(range(1, len(raw)), part_count - 1))
            parts = []
            start = 0
            for end in cuts:
                parts.append(raw[start:end])
                start = end
            parts.append(raw[start:])
        out = []
        for frag in parts:
            key = rng.randint(1, 255)
            out.append((key, bytes((b ^ key) for b in frag)))
        return out

    def _guard_stream(self, salt, n):
        key = self._aux_key
        state = 0x9E3779B9
        seed = key + salt
        for idx, b in enumerate(seed):
            state ^= (b + ((idx + 1) * 0x45D9F3B)) & 0xFFFFFFFF
            state = ((state << 7) | (state >> 25)) & 0xFFFFFFFF
            state = (state * 0x85EBCA6B + 0xC2B2AE35) & 0xFFFFFFFF
        out = bytearray(n)
        sl = len(salt)
        kl = len(key)
        for i in range(n):
            state ^= (key[i % kl] << 8) ^ salt[i % sl] ^ ((i + 1) * 0x27D4EB2D)
            state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
            out[i] = ((state >> 16) ^ key[(i * 5 + 3) % kl] ^ salt[(i * 7 + 1) % sl]) & 0xFF
        return bytes(out)

    def _pack_guarded_blob(self, tag, raw):
        salt = bytes(self.ng._rng.getrandbits(8) for _ in range(8))
        stream = self._guard_stream(salt, len(raw))
        mixed = bytes((b ^ stream[i]) for i, b in enumerate(raw))
        frags = self._fragment_bytes(mixed)
        parts = [bytes([tag]), salt, bytes([len(frags)])]
        for key, frag in frags:
            parts.append(bytes([key]))
            parts.append(len(frag).to_bytes(2, 'little'))
            parts.append(frag)
        return b''.join(parts)

    def _pack_const(self, value):
        t = type(value)
        if value is None:
            return b'\x00'
        if value is True:
            return b'\x01'
        if value is False:
            return b'\x02'
        if t is int:
            n = (value.bit_length() // 8) + 1
            b = value.to_bytes(n, 'little', signed=True)
            return b'\x03' + len(b).to_bytes(2, 'little') + b
        if t is float:
            raw = repr(value).encode('utf-8')
            return b'\x04' + len(raw).to_bytes(2, 'little') + raw
        if t is str:
            raw = value.encode('utf-8')
            if raw:
                return self._pack_guarded_blob(0x09, raw)
            return b'\x05\x00'
        if t is bytes:
            if value:
                return self._pack_guarded_blob(0x0A, value)
            return b'\x06\x00'
        if t is tuple:
            parts = b''.join(self._pack_const(x) for x in value)
            return b'\x07' + len(value).to_bytes(2, 'little') + parts
        if t is list:
            parts = b''.join(self._pack_const(x) for x in value)
            return b'\x08' + len(value).to_bytes(2, 'little') + parts
        raise TypeError('unsupported const ' + t.__name__)

    def _mask_stream(self, seed, n):
        out = bytearray(n)
        state = seed & 0xFFFFFFFF
        for i in range(n):
            state = ((1103515245 * state) + 12345) & 0xFFFFFFFF
            out[i] = (state >> 16) & 0xFF
        return bytes(out)

    def _inst_size(self, inst):
        size = 1
        for kind, _value in inst['operands']:
            if kind in ('count', 'unaryop', 'binaryop', 'compareop'):
                size += 1
            elif kind in ('name', 'const', 'slot', 'label'):
                size += 2
            else:
                raise ValueError(kind)
        return size

    def _assemble(self):
        rng = self.ng._rng
        name_order = list(range(len(self._names)))
        const_order = list(range(len(self._consts)))
        slot_order = sorted(self._used_slots)
        rng.shuffle(name_order)
        rng.shuffle(const_order)
        rng.shuffle(slot_order)
        name_map = {old: new for new, old in enumerate(name_order)}
        const_map = {old: new for new, old in enumerate(const_order)}
        slot_map = {old: new for new, old in enumerate(slot_order)}
        names = [self._names[idx] for idx in name_order]
        consts = [self._consts[idx] for idx in const_order]

        pcs = []
        pc = 0
        for inst in self._insts:
            pcs.append(pc)
            pc += self._inst_size(inst)
        total_len = pc
        label_pc = {}
        for name, inst_idx in self._labels.items():
            label_pc[name] = total_len if inst_idx >= len(pcs) else pcs[inst_idx]

        code = bytearray()
        for idx, inst in enumerate(self._insts):
            cur_pc = pcs[idx]
            code.append(self._opcodes[inst['op']])
            for kind, value in inst['operands']:
                if kind == 'count':
                    code.append(self._enc_u8(value, 'count'))
                elif kind == 'unaryop':
                    code.append(self._enc_u8(self._unary_codes[value], 'unaryop'))
                elif kind == 'binaryop':
                    code.append(self._enc_u8(self._binary_codes[value], 'binaryop'))
                elif kind == 'compareop':
                    code.append(self._enc_u8(self._compare_codes[value], 'compareop'))
                elif kind == 'name':
                    enc = self._enc_u16(name_map[value], 'name')
                    code.extend((enc & 0xFF, (enc >> 8) & 0xFF))
                elif kind == 'const':
                    enc = self._enc_u16(const_map[value], 'const')
                    code.extend((enc & 0xFF, (enc >> 8) & 0xFF))
                elif kind == 'slot':
                    enc = self._enc_u16(slot_map[value], 'slot')
                    code.extend((enc & 0xFF, (enc >> 8) & 0xFF))
                elif kind == 'label':
                    target = label_pc[value]
                    if self._flags['relative_jumps']:
                        base = cur_pc + self._inst_size(inst)
                        target = (target - base) & 0xFFFF
                    enc = self._enc_u16(target, 'jump')
                    code.extend((enc & 0xFF, (enc >> 8) & 0xFF))
                else:
                    raise ValueError(kind)
        return names, consts, slot_order, bytes(code)

    def compile(self, node):
        if isinstance(node, list):
            for stmt in node:
                self._compile_stmt(stmt)
        else:
            self._compile_stmt(node)
        names, consts, slot_order, code_plain = self._assemble()
        seed = self.ng._rng.getrandbits(32)
        mask = self._mask_stream(seed, len(code_plain))
        code = bytes((code_plain[i] ^ mask[i]) for i in range(len(code_plain)))
        parts = [b'PGSI2']
        parts.append((self._island_id & 0xFFFFFFFF).to_bytes(4, 'little'))
        flags = 0
        if self._flags['reverse_stack']:
            flags |= 1
        if self._flags['relative_jumps']:
            flags |= 2
        if self._flags['callee_last']:
            flags |= 4
        if self._flags['dispatch_mode']:
            flags |= 8
        parts.append(bytes([flags]))
        parts.append(bytes([
            self._state_layout['pc'],
            self._state_layout['stack'],
            self._state_layout['slot'],
            self._state_layout['scratch'],
        ]))
        if self.slot_name is None or not self._uses_slot:
            parts.append((0xFFFF).to_bytes(2, 'little'))
        else:
            raw = self.slot_name.encode('utf-8')
            parts.append(len(raw).to_bytes(2, 'little'))
            parts.append(raw)
        parts.append(len(slot_order).to_bytes(2, 'little'))
        for slot_idx in slot_order:
            parts.append(slot_idx.to_bytes(2, 'little'))
        parts.append(len(names).to_bytes(2, 'little'))
        for name in names:
            raw = name.encode('utf-8')
            parts.append(len(raw).to_bytes(2, 'little'))
            parts.append(raw)
        parts.append(len(consts).to_bytes(2, 'little'))
        for const in consts:
            parts.append(self._pack_const(const))
        parts.append(bytes(self._opcodes[name] for name in self._LOGICAL_OPS))
        parts.append(bytes(self._unary_codes[name] for name in self._UNARY_LOGICAL))
        parts.append(bytes(self._binary_codes[name] for name in self._BINARY_LOGICAL))
        parts.append(bytes(self._compare_codes[name] for name in self._COMPARE_LOGICAL))
        for kind in ('count', 'unaryop', 'binaryop', 'compareop'):
            add, xor = self._u8_keys[kind]
            parts.append(bytes([add, xor]))
        for kind in ('name', 'const', 'slot', 'jump'):
            add, xor = self._u16_keys[kind]
            parts.append(add.to_bytes(2, 'little'))
            parts.append(xor.to_bytes(2, 'little'))
        parts.append(seed.to_bytes(4, 'little'))
        parts.append(len(code).to_bytes(2, 'little'))
        parts.append(code)
        return b''.join(parts)


class _SemanticIslandRewriter(ast.NodeTransformer):
    """Lift decisive secret-centric closures into per-island bespoke semantics."""

    MAX_BODY_NODES = 480
    MAX_STMTS = 18

    def __init__(self, ng, slot_name):
        self.ng = ng
        self.slot_name = slot_name
        self.lifted = 0
        self._seeded = False
        self._secret_names = set()
        self._secret_slots = set()
        self.aux_entries = []

    def _seed_secret_bindings(self, tree):
        if self._seeded:
            return
        self._seeded = True
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            if not self._expr_has_secret_literal(node.value):
                continue
            target = node.targets[0]
            if isinstance(target, ast.Name):
                self._secret_names.add(target.id)
                continue
            slot_idx = self._slot_index(target)
            if slot_idx is not None:
                self._secret_slots.add(slot_idx)

    def _slot_index(self, node):
        if not isinstance(node, ast.Subscript):
            return None
        if not isinstance(node.value, ast.Name) or node.value.id != self.slot_name:
            return None
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, int):
            return sl.value
        return None

    def _expr_has_secret_literal(self, node):
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Constant):
                continue
            if isinstance(sub.value, str) and len(sub.value) >= 4:
                return True
            if isinstance(sub.value, bytes) and len(sub.value) >= 4:
                return True
        return False

    def _uses_secret_binding(self, node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                if sub.id in self._secret_names:
                    return True
                continue
            slot_idx = self._slot_index(sub)
            if slot_idx is not None and slot_idx in self._secret_slots:
                return True
        return False

    def _has_effect(self, node):
        nodes = node if isinstance(node, list) else [node]
        for root in nodes:
            for sub in ast.walk(root):
                if isinstance(sub, (ast.Assign, ast.AugAssign, ast.Return,
                                    ast.Raise, ast.Break, ast.Continue)):
                    return True
                if isinstance(sub, ast.Expr) and isinstance(sub.value, ast.Call):
                    return True
        return False

    def _count_state_writes(self, stmts):
        writes = set()
        reads = set()
        for stmt in stmts:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Name):
                    if isinstance(sub.ctx, ast.Store):
                        writes.add(('name', sub.id))
                    elif isinstance(sub.ctx, ast.Load):
                        reads.add(('name', sub.id))
                    continue
                slot_idx = self._slot_index(sub)
                if slot_idx is None:
                    continue
                if isinstance(sub.ctx, ast.Store):
                    writes.add(('slot', slot_idx))
                elif isinstance(sub.ctx, ast.Load):
                    reads.add(('slot', slot_idx))
        return len(writes & reads)

    def _decisive_body(self, stmts, whole_body):
        if not stmts:
            return False
        if not self._has_effect(stmts):
            return False
        node_count = sum(1 for stmt in stmts for _ in ast.walk(stmt))
        if node_count > self.MAX_BODY_NODES or len(stmts) > self.MAX_STMTS:
            return False
        secret_touch = any(
            self._expr_has_secret_literal(stmt) or self._uses_secret_binding(stmt)
            for stmt in stmts
        )
        branch_count = sum(
            1 for stmt in stmts for sub in ast.walk(stmt)
            if isinstance(sub, ast.If)
        )
        loop_count = sum(
            1 for stmt in stmts for sub in ast.walk(stmt)
            if isinstance(sub, ast.While)
        )
        call_count = sum(
            1 for stmt in stmts for sub in ast.walk(stmt)
            if isinstance(sub, ast.Call)
        )
        stateful = self._count_state_writes(stmts) > 0
        if not secret_touch:
            return False
        if whole_body and (loop_count or branch_count >= 2) and stateful:
            return True
        return (loop_count and branch_count and stateful) or \
            (branch_count >= 2 and call_count >= 2 and stateful)

    def _lift_region(self, stmts):
        if not stmts:
            return None
        compiler = _SemanticIslandCompiler(self.ng, self.slot_name)
        if not compiler.supports(stmts):
            return None
        payload = compiler.compile(stmts)
        self.aux_entries.append((compiler.island_id, compiler.aux_key))
        self.lifted += 1
        return ast.copy_location(
            ast.Expr(
                value=ast.Call(
                    func=ast.Name(id=_SEM_ISLAND_SENTINEL, ctx=ast.Load()),
                    args=[ast.Constant(value=payload)],
                    keywords=[],
                )
            ),
            stmts[0],
        )

    def _best_region(self, body):
        if not body:
            return None
        if self._decisive_body(body, whole_body=True):
            compiler = _SemanticIslandCompiler(self.ng, self.slot_name, randomize=False)
            if compiler.supports(body):
                return (0, len(body))
        best = None
        best_score = -1
        for start in range(len(body)):
            for end in range(start + 2, len(body) + 1):
                region = body[start:end]
                compiler = _SemanticIslandCompiler(self.ng, self.slot_name, randomize=False)
                if not compiler.supports(region):
                    continue
                if not self._decisive_body(region, whole_body=False):
                    continue
                score = sum(1 for stmt in region for _ in ast.walk(stmt))
                if score > best_score:
                    best_score = score
                    best = (start, end)
        return best

    def _rewrite_stmt(self, stmt):
        if isinstance(stmt, ast.FunctionDef):
            stmt.body = self._rewrite_body(stmt.body)
            return stmt
        if isinstance(stmt, ast.AsyncFunctionDef):
            stmt.body = self._rewrite_body(stmt.body)
            return stmt
        if isinstance(stmt, ast.ClassDef):
            stmt.body = self._rewrite_body(stmt.body)
            return stmt
        if isinstance(stmt, ast.If):
            stmt.body = self._rewrite_body(stmt.body)
            stmt.orelse = self._rewrite_body(stmt.orelse)
            return stmt
        if isinstance(stmt, ast.While):
            stmt.body = self._rewrite_body(stmt.body)
            stmt.orelse = self._rewrite_body(stmt.orelse)
            return stmt
        if isinstance(stmt, ast.For):
            stmt.body = self._rewrite_body(stmt.body)
            stmt.orelse = self._rewrite_body(stmt.orelse)
            return stmt
        if isinstance(stmt, ast.With):
            stmt.body = self._rewrite_body(stmt.body)
            return stmt
        if isinstance(stmt, ast.Try):
            stmt.body = self._rewrite_body(stmt.body)
            stmt.orelse = self._rewrite_body(stmt.orelse)
            stmt.finalbody = self._rewrite_body(stmt.finalbody)
            stmt.handlers = [self._rewrite_stmt(h) for h in stmt.handlers]
            return stmt
        if isinstance(stmt, ast.ExceptHandler):
            stmt.body = self._rewrite_body(stmt.body)
            return stmt
        return stmt

    def _rewrite_body(self, body):
        region = self._best_region(body)
        if region is None:
            return [self._rewrite_stmt(stmt) for stmt in body]
        start, end = region
        out = [self._rewrite_stmt(stmt) for stmt in body[:start]]
        lifted = self._lift_region(body[start:end])
        if lifted is None:
            return [self._rewrite_stmt(stmt) for stmt in body]
        out.append(lifted)
        out.extend(self._rewrite_stmt(stmt) for stmt in body[end:])
        return out

    def visit_Module(self, node):
        global _LAST_SEMANTIC_ISLAND_AUX
        self._seed_secret_bindings(node)
        node.body = self._rewrite_body(node.body)
        _LAST_SEMANTIC_ISLAND_AUX = list(self.aux_entries)
        return node


# ---------------------------------------------------------------------------
# Function Body Fusion (v6.0 / C6.A)
# ---------------------------------------------------------------------------
#
# Rationale
# ---------
# Red-team audit (2026-04-16) flagged that v5's protection is too concentrated
# in the container (encryption, integrity, anti-trace) while the *meaning* of
# the user program remains recoverable: after an analyst dumps the IR, the
# original function boundaries still survive as distinct IFunctionDef nodes,
# each with a coherent body. Semantic normalisation — producing a short
# faithful rewrite of the protected program — is therefore cheap even when
# literal source strings are scrubbed.
#
# This pass attacks that shape directly. Eligible top-level user functions
# have their *bodies* extracted and pasted as branches of a single module-
# level dispatcher `_pg_F(_fid, _args)`. The original `def foo(a, b):` is
# replaced with a trampoline of the same name and signature whose body is
# a single `return _pg_F(FID_FOO, (a, b))` — preserving Python-level
# reachability (decorators still apply; `_pg_D[K_foo]` still resolves).
#
# Impact on the IR: where v5 emitted N distinct IFunctionDef nodes each
# with a meaningful body, v6 emits N trampolines (1-line bodies) plus one
# giant IFunctionDef whose body is an if-chain keyed on an integer FID.
# The call graph "add calls double, double calls print" collapses into a
# single mega-dispatcher; recovering per-function structure requires the
# analyst to reverse the FID→branch mapping, undo the parameter-binding
# prologue, and then still face the per-branch CFF state machine.
#
# Eligibility (conservative — correctness over coverage):
#   - Top-level FunctionDef only (not inside ClassDef, not nested)
#   - No yield / yield from  (generators have suspension semantics)
#   - No nonlocal             (breaks if the enclosing scope is the body)
#   - No nested FunctionDef / AsyncFunctionDef / ClassDef / Lambda
#     (closures would lose their enclosing scope)
#   - Simple argument signature: no *args, no **kwargs, no kw-only,
#     defaults must be ast.Constant (constant-folding guarantees this
#     before the _ConstantUnfolder runs, since defaults are evaluated
#     at function-definition time)
#   - AsyncFunctionDef NOT eligible (await inside _pg_F would require
#     _pg_F itself to be async, which pollutes all other branches)
#
# Decorators are preserved on the trampoline, so @memoize / @staticmethod
# / user-defined decorators still apply at the same call site.
#
# `global NAME` declarations inside a fused body are re-declared inside
# _pg_F so writes still target module globals.
#
# Placement in the pipeline:
#   - AFTER CFF: per-function CFF is applied before fusion, so each fused
#     branch is itself a `while True: if state==N:` state machine.
#   - AFTER CallIndirector: indirection keys reference the trampoline by
#     name, so `_pg_D[K_foo] = foo` still resolves correctly after the
#     def-statement is replaced with a same-named trampoline.
#   - BEFORE ConstantUnfolder: FID constants and parameter-index constants
#     flow through unfolding into arithmetic chains, plus MBA expansion.
#
# Honest limits
# -------------
# This does NOT destroy the FID↔name correspondence — the trampoline emits
# its FID as a literal integer (subsequently unfolded by the constant
# unfolder / MBA pass). A determined analyst can still recover the mapping
# by: (1) reading each trampoline's body to extract its FID, (2) locating
# that FID's branch inside _pg_F, (3) unpacking the parameter-binding
# prologue, (4) unflattening the inner CFF. The goal is not to make this
# impossible; it is to make the "small faithful rewrite" attack require
# work proportional to the number of functions, not free.

class _FunctionFusion(ast.NodeTransformer):
    """Fuse eligible top-level function bodies into a single dispatcher."""

    def __init__(self, ng):
        self.ng = ng
        self._F = ng.temp()       # dispatcher name (_pg_F analog, opaque)
        self._FID = ng.temp()     # dispatcher fid parameter name
        self._A = ng.temp()       # dispatcher args parameter name
        # fid -> (renamed_fn_name, original_args, body_stmts, globals_set)
        self._fused = {}
        self._used_fids = set()
        # Telemetry: count of functions actually fused.
        self.fused_count = 0

    def _alloc_fid(self):
        rng = self.ng._rng
        while True:
            k = rng.randint(10**6, 10**9)
            if k not in self._used_fids:
                self._used_fids.add(k)
                return k

    def _is_eligible(self, fn):
        if not isinstance(fn, ast.FunctionDef):
            return False
        # Generator / nonlocal / nested-def scan
        for n in ast.walk(fn):
            if n is fn:
                continue
            if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Nonlocal)):
                return False
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef, ast.Lambda)):
                return False
        # Signature: reject *args, **kwargs, kw-only, non-constant defaults.
        a = fn.args
        if a.vararg is not None or a.kwarg is not None:
            return False
        if a.kwonlyargs:
            return False
        for d in a.defaults:
            if not isinstance(d, ast.Constant):
                return False
        # posonlyargs are fine; we unify them with regular args.
        return True

    def _collect_globals(self, body):
        """Return the set of names declared `global` anywhere in body."""
        g = set()
        for stmt in body:
            for n in ast.walk(stmt):
                if isinstance(n, ast.Global):
                    g.update(n.names)
        return g

    def visit_Module(self, node):
        new_body = []
        self._all_globals = set()
        for stmt in node.body:
            if isinstance(stmt, ast.FunctionDef) and self._is_eligible(stmt):
                fid = self._alloc_fid()
                globs = self._collect_globals(stmt.body)
                self._fused[fid] = (stmt.name, stmt.args, stmt.body, globs)
                self._all_globals.update(globs)
                new_body.append(self._make_trampoline(stmt, fid))
                self.fused_count += 1
            else:
                new_body.append(stmt)

        if self.fused_count == 0:
            return node

        dispatcher = self._build_dispatcher()
        # Dispatcher must be defined before any trampoline is *called*. Module-
        # level code runs top-to-bottom, so placing it at the head is safe.
        # (The trampoline defs themselves only reference `_F` by name; the
        # lookup happens at call time, not def time.)
        node.body = [dispatcher] + new_body
        return node

    def _make_trampoline(self, fn, fid):
        """Replace fn with a same-name same-signature trampoline."""
        # Collect the parameter names in positional order (posonly then args).
        pos_names = [a.arg for a in fn.args.posonlyargs] + \
                    [a.arg for a in fn.args.args]
        tuple_elts = [ast.Name(id=n, ctx=ast.Load()) for n in pos_names]
        args_tuple = ast.Tuple(elts=tuple_elts, ctx=ast.Load())
        call = ast.Call(
            func=ast.Name(id=self._F, ctx=ast.Load()),
            args=[ast.Constant(value=fid), args_tuple],
            keywords=[])
        return ast.FunctionDef(
            name=fn.name,
            args=fn.args,
            body=[ast.Return(value=call)],
            decorator_list=fn.decorator_list,
            returns=fn.returns,
            type_comment=getattr(fn, 'type_comment', None))

    def _build_dispatcher(self):
        """Assemble the `def _F(_FID, _A):` dispatcher with all fused bodies."""
        cases = []
        for fid, (name, args, body, globs) in self._fused.items():
            # No branch-local `global` declarations: Python requires globals
            # to be declared at the top of the enclosing function, before any
            # binding/use of the name. We hoist the union of all branch-level
            # globals to the dispatcher's body prologue below.
            prologue = []
            all_params = list(args.posonlyargs) + list(args.args)
            for i, a in enumerate(all_params):
                prologue.append(ast.Assign(
                    targets=[ast.Name(id=a.arg, ctx=ast.Store())],
                    value=ast.Subscript(
                        value=ast.Name(id=self._A, ctx=ast.Load()),
                        slice=ast.Constant(value=i),
                        ctx=ast.Load())))
            case_body = prologue + list(body)
            # Ensure the branch returns — if the body falls through (no
            # explicit return / CFF's `break` exits the inner state loop),
            # we must not fall through to sibling branches of the outer
            # if-chain (different FIDs) or to the dispatcher's tail.
            if not case_body or not isinstance(case_body[-1], ast.Return):
                case_body.append(ast.Return(value=ast.Constant(value=None)))
            test = _make_eq(self._FID, fid)
            cases.append((test, case_body))

        # Shuffle so FID order in the chain doesn't mirror source order.
        self.ng._rng.shuffle(cases)
        if_chain = _build_if_chain(cases)

        dispatcher_args = ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg=self._FID), ast.arg(arg=self._A)],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[])

        # Hoist globals to the dispatcher prologue. Union of all branches'
        # `global NAME` declarations. Python then treats each NAME as global
        # throughout _pg_F, so reads and writes in every fused branch target
        # the module dict consistently. Safe under identifier renaming: the
        # renamer assigns each original source name a single canonical mangled
        # name, so a fused branch's `global __yyy` refers to the module-level
        # `__yyy` that would have been the module-level `counter` before
        # renaming, and no other branch uses `__yyy` as a local (the renamer
        # assigns each source identifier ONE name module-wide).
        dispatcher_body = []
        if self._all_globals:
            dispatcher_body.append(ast.Global(names=sorted(self._all_globals)))
        dispatcher_body.append(if_chain)
        dispatcher_body.append(ast.Return(value=ast.Constant(value=None)))

        return ast.FunctionDef(
            name=self._F,
            args=dispatcher_args,
            body=dispatcher_body,
            decorator_list=[],
            returns=None)


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
        """Emit `(b'').__class__([b0, b1, ...])` — C17 bypass of
        `builtins.bytes` name resolution. Downstream transforms can still
        rewrite the individual ints; the overall shape survives."""
        return _bytes_ctor(ast.List(
            elts=[ast.Constant(value=b) for b in data],
            ctx=ast.Load()))

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
        plaintext = _bytes_ctor(ast.GeneratorExp(
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
                ifs=[], is_async=0)]))
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
            _co = compile(_pt.decode('utf-8'), '<pg_gate>', 'exec')
            types.FunctionType(_co, globals())()
        Returns a list of two statements.

        Gate payload is Python source text (not marshaled bytecode) so the
        same stub runs correctly on every target CPython minor. See the
        matching build-side comment in visit_If().

        FunctionType(co, globals())() is retained over exec(co, globals()):
        it dodges `builtins.exec = _hook` interception, and _sg_is_exec_safe
        guarantees the body has no FunctionDef/ClassDef/Global/Nonlocal, so
        running in a fresh function frame is semantically equivalent.
        """
        ng = self.ng
        v_co = ng.temp()
        types_imp = self._import_call('types')
        return [
            ast.Assign(
                targets=[ast.Name(id=v_co, ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id='compile', ctx=ast.Load()),
                    args=[
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id=v_pt, ctx=ast.Load()),
                                attr='decode', ctx=ast.Load()),
                            args=[ast.Constant(value='utf-8')],
                            keywords=[]),
                        ast.Constant(value='<pg_gate>'),
                        ast.Constant(value='exec'),
                    ],
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
        # not the whole secret.
        inlined_body = self._fragment_string_constants(inlined_body)

        # Track which const names we're now responsible for (so a later
        # pruning pass can drop their module-level assignments).
        if pw_name is not None:
            self._consumed_pw.add(pw_name)

        self._fired += 1
        # Emit a placeholder Try — .body is filled later by
        # finalize_gates() once we know whether to inline or extract.
        # Encryption is DEFERRED until after _apply_transforms has run
        # identifier renaming on the outer tree: the gate body references
        # user variables (e.g. `comp`) that the renamer mangles to
        # `__xyzN` everywhere *outside* an already-ciphertext blob. By
        # unparsing+encrypting at visit_If time, the ciphertext bakes in
        # the ORIGINAL names while the surrounding code uses renamed
        # ones, producing NameError at runtime. We now stash `inlined_body`
        # as raw AST in `_pending` and let `finalize_gates(renamer=…)`
        # apply the same renamer to the gate body, unparse, and encrypt.
        placeholder = ast.Try(
            body=[ast.Pass()],  # filler, replaced by finalize_gates
            handlers=[ast.ExceptHandler(
                type=ast.Name(id='Exception', ctx=ast.Load()),
                name=None,
                body=(list(node.orelse) if node.orelse else [ast.Pass()]))],
            orelse=[], finalbody=[])
        self._pending.append(
            (placeholder, guess_expr, pw, inlined_body))
        return ast.copy_location(placeholder, node)

    # -- Finalize: decide inline vs helper based on gate count --

    def _seal_pending(self, renamer=None):
        """Apply `renamer` to each pending gate body, unparse, and encrypt.

        Returns a list of (placeholder, guess_expr, salt, nonce, ct) tuples
        ready for finalize_gates() to dispatch between inline/call-site
        emission. Entries whose gate body fails to compile (post-rename)
        are dropped and the placeholder body is reset to Pass(), which
        causes the handler's else branch to run — the same safety net the
        pre-deferred code relied on.
        """
        sealed = []
        for (node, guess_expr, pw, body) in self._pending:
            if renamer is not None:
                # Walk the stored body AST through the renamer so names
                # baked into the ciphertext match post-rename names in
                # the outer tree. The renamer's `_map` has already been
                # populated by its run over the outer module, so any
                # user-defined name reused in the gate body (e.g.
                # `comp = "scissors"`) maps to the same mangled token
                # as the outer code's `if comp == …` comparisons.
                body = [renamer.visit(stmt) for stmt in body]
                # guess_expr was captured from the original If's left
                # operand (typically `Name(id='user')`) and stashed before
                # rename ran — so the outer rename pass never saw it.
                # Without this visit, the scrypt call at runtime reads
                # `Name('user')` which was renamed to `__xyzN` in the
                # outer tree, raising NameError and silently running the
                # else branch.
                guess_expr = renamer.visit(guess_expr)
            tb_module = ast.Module(body=body, type_ignores=[])
            ast.fix_missing_locations(tb_module)
            try:
                source = ast.unparse(tb_module)
                compile(source, '<pg_gate>', 'exec')
            except Exception:
                node.body = [ast.Pass()]
                continue
            payload = source.encode('utf-8', 'replace')

            salt_len  = self._rng.randint(
                self.SALT_LEN_MIN, self.SALT_LEN_MAX)
            nonce_len = self._rng.randint(
                self.NONCE_LEN_MIN, self.NONCE_LEN_MAX)
            salt  = bytes(self._rng.randint(0, 255) for _ in range(salt_len))
            nonce = bytes(self._rng.randint(0, 255) for _ in range(nonce_len))
            key = hashlib.scrypt(
                pw.encode('utf-8', 'replace'),
                salt=salt, n=self.KDF_N, r=self.KDF_R, p=self.KDF_P,
                maxmem=1073741824, dklen=32)
            ct_and_tag = _sg_seal(key, nonce, payload)
            sealed.append((node, guess_expr, salt, nonce, ct_and_tag))
        return sealed

    def finalize_gates(self, module, renamer=None):
        """Fill in the placeholder Try bodies recorded by visit_If().

        Strategy:
          * 1 gate  -> inline the scrypt+AEAD body.
          * 2+ gates -> install a shared module-level helper.

        `renamer`, if supplied, is an already-visited _IdentifierRenamer
        whose `_map` is propagated to gate bodies so cipher names match
        the renamed outer code.
        """
        if not self._pending:
            return
        # Propagate rename mappings into tracking sets so the post-pass
        # prune() can still find module-level const assignments (whose
        # target Names were mangled by the renamer after we recorded
        # them under their pre-rename keys).
        if renamer is not None:
            m = renamer._map
            self._const_strs = {m.get(k, k): v
                                for k, v in self._const_strs.items()}
            self._consumed_pw = {m.get(k, k) for k in self._consumed_pw}
        sealed = self._seal_pending(renamer=renamer)
        if not sealed:
            return
        if len(sealed) >= 2:
            self._install_helper(module)
            for (node, guess_expr, salt, nonce, ct) in sealed:
                node.body = self._build_callsite_body(
                    guess_expr, salt, nonce, ct)
        else:
            (node, guess_expr, salt, nonce, ct) = sealed[0]
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

def _apply_transforms(tree, ng, rename_identifiers=True, rewrite_secret_gates=True, obfuscate_strings=True, int_obfuscation=True):
    global _LAST_SEMANTIC_ISLAND_AUX
    _LAST_SEMANTIC_ISLAND_AUX = []
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
    # v6.7+: the old source-compile secret-gate path is intentionally
    # disabled in the main pipeline. Secret-bearing regions now move
    # onto the semantic-island VM after local-slot lifting so the
    # protected logic no longer survives as normal compare/jump/source
    # structure inside generic v5 IR.
    sgr = None

    if rename_identifiers:
        renamer = _IdentifierRenamer(ng)
        renamer.prepare(tree)
        tree = renamer.visit(tree)
        ast.fix_missing_locations(tree)
    else:
        renamer = None

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

    # Decompose simple f-strings before CFF/call indirection so the new
    # `str(x)` calls flow through the indirector and the newly-exposed
    # literal fragments flow through the string obfuscator.
    tree = _FStringDeformer().visit(tree)
    ast.fix_missing_locations(tree)

    # v6.0 / C6.B — lift per-function locals to `_s[idx]` subscripts BEFORE
    # fusion. This dissolves per-variable Name identity in the IR: every
    # local access becomes a uniform Subscript(Name('_s'), Constant(idx))
    # node, the string pool carries only one slot-list name per build, and
    # analysts can no longer partition locals by the Name they load from.
    # Gated on rename_identifiers because un-renamed interpreter locals
    # could collide with synthesized slot names.
    if rename_identifiers:
        slot_lifter = _LocalSlotLifter(ng)
        tree = slot_lifter.visit(tree)
        ast.fix_missing_locations(tree)

    # v6.7 semantic-island round: after renaming/attr-mangling/import
    # concealment and after local-slot lifting, small effectful If
    # regions can be lowered to a bespoke VM payload that carries slot
    # indices directly. This must happen BEFORE opaque predicates,
    # fusion, and CFF so the original gate/reward structure is still
    # available to the island compiler.
    if rename_identifiers:
        tree = _SemanticIslandRewriter(ng, slot_lifter._slot).visit(tree)
        ast.fix_missing_locations(tree)

    tree = _OpaquePredicateInjector(ng).visit(tree)
    ast.fix_missing_locations(tree)

    # v6.0 / C6.A — fuse eligible top-level function bodies into a single
    # mega-dispatcher BEFORE CFF. If we ran this after CFF, CFF would have
    # already pushed top-level FunctionDefs inside its while-dispatcher
    # branches, and visit_Module wouldn't see them. Running before CFF:
    #   - dissolves per-function bodies into a single _pg_F branch chain,
    #   - CFF then flattens _pg_F's giant dispatcher body, producing a
    #     state-machine inside a state-machine,
    #   - the trampoline defs become cheap wrappers that CFF also scrambles.
    # Gated on `rename_identifiers` because fusion shares one function-scope
    # namespace across all fused branches; without the renamer's unique-per-
    # source-identifier mapping, two functions' identically-named locals
    # would collide inside _pg_F. (Skipped for the interpreter source, which
    # runs with rename_identifiers=False for self-obfuscation correctness.)
    if rename_identifiers and isinstance(tree, ast.Module):
        tree = _FunctionFusion(ng).visit(tree)
        ast.fix_missing_locations(tree)

    tree = _CFFlattener(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _CallIndirector(ng).visit(tree)
    ast.fix_missing_locations(tree)

    # O4 (2026-04-16): skip int-obfuscation passes on callers that don't
    # benefit. For the interpreter, _ConstantUnfolder + _MBAObfuscator
    # rewrite small ints into (a|b)-(a&b) chains that a partial
    # evaluator folds back in seconds — MBA on raw int constants buys
    # minimal anti-static-analysis cost against a determined reverser
    # (the reduction rules are well-known) while inflating the
    # marshal-shipped bytecode by ~8 KB deflated per stub. User code
    # still gets these passes (unknown at analysis time, real variable
    # dataflow makes folding harder).
    if int_obfuscation:
        tree = _ConstantUnfolder(ng).visit(tree)
        ast.fix_missing_locations(tree)

        tree = _MBAObfuscator(ng).visit(tree)
        ast.fix_missing_locations(tree)

    # O3: caller (obfuscate_runtime.py for the interpreter source) can
    # skip this pass when it owns its own string encoder. For the
    # interpreter, `obfuscate_runtime.StringEncoder` emits a shared
    # `_decode(b'xored', b'key')` helper whose ciphertext/keys are
    # compact `bytes` literals — encoding is ~6x smaller than the
    # per-byte-BinOp form `_StringObfuscator` produces, and the cached
    # decoder is faster at runtime than re-XOR'ing every call site.
    if obfuscate_strings:
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
                       rewrite_secret_gates=True, obfuscate_strings=True,
                       int_obfuscation=True):
    """Apply transforms to an already-parsed AST tree.

    Set rename_identifiers=False when the caller handles its own
    identifier renaming (e.g. obfuscate_runtime.py).

    Set rewrite_secret_gates=False when transforming the interpreter
    itself — the rewriter mistakes `if op == 'IBreak':` dispatch branches
    for password gates and wraps them in scrypt-AEAD exec bodies that
    break generator/raise semantics.

    Set obfuscate_strings=False when the caller has its own string
    obfuscation pass (e.g. obfuscate_runtime.StringEncoder, which is
    cache-backed and emits smaller bytes literals).
    """
    ng = _NameGen(seed)
    return _apply_transforms(tree, ng,
                             rename_identifiers=rename_identifiers,
                             rewrite_secret_gates=rewrite_secret_gates,
                             obfuscate_strings=obfuscate_strings,
                             int_obfuscation=int_obfuscation)


def get_last_semantic_island_aux():
    return list(_LAST_SEMANTIC_ISLAND_AUX)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("usage: transform_ast.py <source.py>")
        sys.exit(2)
    with open(sys.argv[1]) as f:
        src = f.read()
    tree = transform_source(src)
    print(ast.unparse(tree))

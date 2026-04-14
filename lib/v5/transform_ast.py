"""PyGuard v5 build-time AST obfuscation transforms.

Applied to user Python source BEFORE IR compilation. The resulting AST is
semantically equivalent but structurally alien — control flow is flattened
into state-machine dispatchers, expressions are decomposed into chains of
temporaries, opaque predicates inject unreachable dead code, and constants
are unfolded into arithmetic expressions.

The interpreter doesn't need to change because the transformed AST is still
valid Python — it just *looks* nothing like the original.

Stdlib-only. Compatible with Python 3.8+.
"""

import ast
import builtins
import copy
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
        if len(node.body) >= 3:
            node.body = self._flatten_body(node.body)
        return node

    def visit_FunctionDef(self, node):
        if self._depth > 0:
            return node
        self._depth += 1
        if not self._has_yield(node) and len(node.body) >= 3:
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
        if isinstance(node.value, int) and 2 <= abs(node.value) <= 500:
            rng = self.ng._rng
            if rng.random() < 0.3:
                return self._unfold(node.value, rng)
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
    def __init__(self, ng):
        self.ng = ng

    def visit_BinOp(self, node):
        self.generic_visit(node)
        # MBA uses bitwise ops (^, &, ~) which only work on ints.
        # Only apply when both operands are provably integer.
        if self.ng._rng.random() < 0.15 and self._both_int(node.left, node.right):
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
        return node


# ---------------------------------------------------------------------------
# String Obfuscation
# ---------------------------------------------------------------------------

class _StringObfuscator(ast.NodeTransformer):
    def __init__(self, ng):
        self.ng = ng

    def visit_Constant(self, node):
        if not isinstance(node.value, str):
            return node
        if len(node.value) == 0 or len(node.value) > 100:
            return node
        if self.ng._rng.random() < 0.35:
            return self._encode(node.value)
        return node

    def _encode(self, s):
        raw = s.encode('utf-8')
        key = self.ng._rng.randint(1, 255)
        # Store pre-XOR'd bytes; XOR back at runtime to recover original
        encoded = [b ^ key for b in raw]
        elts = [ast.BinOp(left=ast.Constant(value=e), op=ast.BitXor(),
                           right=ast.Constant(value=key)) for e in encoded]
        return ast.Call(
            func=ast.Attribute(
                value=ast.Call(
                    func=ast.Name(id='bytes', ctx=ast.Load()),
                    args=[ast.List(elts=elts, ctx=ast.Load())],
                    keywords=[]),
                attr='decode', ctx=ast.Load()),
            args=[ast.Constant(value='utf-8')], keywords=[])


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

def _apply_transforms(tree, ng, rename_identifiers=True):
    """Apply all transforms in the correct order."""
    # Order matters:
    # 0. Identifier renaming FIRST (rename user names before any restructuring)
    # 1. Expression decomposition (before CFF restructures the code)
    # 2. Opaque predicates (add dead code branches)
    # 3. Control flow flattening (restructure into state machine)
    # 4. Constant unfolding (obfuscate numeric literals)
    # 5. MBA obfuscation (obfuscate arithmetic)
    # 6. String obfuscation (obfuscate string literals)
    if rename_identifiers:
        renamer = _IdentifierRenamer(ng)
        renamer.prepare(tree)
        tree = renamer.visit(tree)
        ast.fix_missing_locations(tree)

    tree = _ExprDecomposer(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _OpaquePredicateInjector(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _CFFlattener(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _ConstantUnfolder(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _MBAObfuscator(ng).visit(tree)
    ast.fix_missing_locations(tree)

    tree = _StringObfuscator(ng).visit(tree)
    ast.fix_missing_locations(tree)

    return tree


def transform_source(source, seed=None, rename_identifiers=True):
    """Apply all obfuscating AST transforms to Python source."""
    tree = ast.parse(source)
    ng = _NameGen(seed)
    return _apply_transforms(tree, ng, rename_identifiers=rename_identifiers)


def transform_ast_tree(tree, seed=None, rename_identifiers=True):
    """Apply transforms to an already-parsed AST tree.

    Set rename_identifiers=False when the caller handles its own
    identifier renaming (e.g. obfuscate_runtime.py).
    """
    ng = _NameGen(seed)
    return _apply_transforms(tree, ng, rename_identifiers=rename_identifiers)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("usage: transform_ast.py <source.py>")
        sys.exit(2)
    with open(sys.argv[1]) as f:
        src = f.read()
    tree = transform_source(src)
    print(ast.unparse(tree))
